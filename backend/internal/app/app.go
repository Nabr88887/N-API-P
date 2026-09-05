package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
	"n-api-p/internal/config"
	"n-api-p/internal/database"
	"n-api-p/internal/gateway"
	"n-api-p/internal/httpapi"
	"n-api-p/internal/observability"
	"n-api-p/internal/operations"
	"n-api-p/internal/policy"
	"n-api-p/internal/web"

	_ "github.com/jackc/pgx/v5/stdlib"
)

var ErrInvalidApplication = errors.New("invalid application configuration")

type Application struct {
	DB               *sql.DB
	Server           *http.Server
	Jobs             *audit.LifecycleJob
	recoverAuditGate func(context.Context, time.Time, time.Time) error
	now              func() time.Time
}

func (application *Application) Start(ctx context.Context) error {
	if application == nil || application.recoverAuditGate == nil {
		return ErrInvalidApplication
	}
	if ctx == nil {
		ctx = context.Background()
	}
	now := application.now
	if now == nil {
		now = time.Now
	}
	openedAt := now().UTC()
	if err := application.recoverAuditGate(ctx, openedAt, openedAt); err != nil {
		return fmt.Errorf("recover audit gate on startup: %w", err)
	}
	if application.Jobs == nil {
		return nil
	}
	go func() { _ = application.Jobs.Run(ctx) }()
	return nil
}

func New(cfg config.Config, secrets *config.Secrets) (*Application, error) {
	if strings.TrimSpace(cfg.DatabaseURL) == "" || secrets == nil || strings.TrimSpace(cfg.PortalOrigin) == "" {
		return nil, ErrInvalidApplication
	}
	db, err := sql.Open("pgx", cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	closeOnError := func(err error) (*Application, error) {
		_ = db.Close()
		return nil, err
	}
	repository := database.NewRepository(db)
	passwords := access.NewArgon2idPasswordHasher()
	metrics := observability.NewMetrics()

	authenticator, err := access.NewAuthenticationService(repository, passwords)
	if err != nil {
		return closeOnError(err)
	}
	sessions := access.NewSessionService(repository)
	reauthentication := access.NewReauthenticationService(repository, passwords)
	activation := access.NewActivationService(repository, passwords, access.NewActivationLimiter())
	sensitiveActions := access.NewSensitiveActionGuard(repository)
	passwordReset := access.NewPasswordResetService(repository, passwords, sensitiveActions)
	personalKeys := access.NewPersonalKeyService(repository)
	invitation := access.NewInvitationService(repository)
	administration := access.NewAdministrationService(repository)
	offboarding := access.NewOffboardingService(repository)
	serviceAccounts := access.NewServiceAccountService(repository)
	modelAllowlist, err := access.NewModelAllowlistService(repository)
	if err != nil {
		return closeOnError(err)
	}
	retention, err := access.NewRetentionPolicyService(repository, cfg.RawRetentionMaxDays)
	if err != nil {
		return closeOnError(err)
	}
	metadata, err := audit.NewMetadataService(repository)
	if err != nil {
		return closeOnError(err)
	}
	activeVersion, keyring := secrets.AuditKeyring()
	envelope, err := audit.NewEnvelopeService(activeVersion, keyring)
	if err != nil {
		return closeOnError(err)
	}
	rawView, err := audit.NewRawViewService(repository, envelope)
	if err != nil {
		return closeOnError(err)
	}
	investigations, err := audit.NewInvestigationService(repository, envelope)
	if err != nil {
		return closeOnError(err)
	}
	operationsService, err := operations.NewService(repository)
	if err != nil {
		return closeOnError(err)
	}
	lifecycle, err := audit.NewLifecycleJob(repository)
	if err != nil {
		return closeOnError(err)
	}
	lifecycle.SetMetrics(metrics)

	gate, err := audit.NewDegradedStateMachine(repository)
	if err != nil {
		return closeOnError(err)
	}
	gate.SetMetrics(metrics)
	capture, err := audit.NewInitialCaptureServiceWithGate(envelope, repository, gate)
	if err != nil {
		return closeOnError(err)
	}
	finalizer, err := audit.NewResponseFinalizationServiceWithGate(envelope, repository, gate)
	if err != nil {
		return closeOnError(err)
	}
	capture.SetMetrics(metrics)
	finalizer.SetMetrics(metrics)
	upstream, err := gateway.NewClient(gateway.NewAPIClientConfig{
		BaseURL: cfg.NewAPIBaseURL, Token: secrets.NewAPIToken(),
		ConnectTimeout: cfg.NewAPIConnectTimeout, TLSHandshakeTimeout: cfg.NewAPITLSHandshakeTimeout,
		ResponseHeaderTimeout: cfg.NewAPIResponseHeaderTimeout, IdleConnTimeout: cfg.NewAPIIdleConnTimeout,
		TotalTimeout: cfg.NewAPITotalTimeout,
	})
	if err != nil {
		return closeOnError(err)
	}
	policyResolver, err := policy.NewResolver(repository)
	if err != nil {
		return closeOnError(err)
	}
	limiter := gateway.NewInProcessLimiterWithMetrics(metrics)
	rejections, err := gateway.NewSecurityEventRejectionRecorder(repository)
	if err != nil {
		return closeOnError(err)
	}
	chat, err := gateway.NewChatProxyHandler(gateway.ChatProxyConfig{
		Upstream: upstream, Capture: capture, Finalizer: finalizer, Usage: repository,
		Policy: policyResolver, Limiter: limiter, Retention: timeDuration(cfg.RawRetentionDefaultDays), RetentionReader: retention.CurrentRetention,
		PriceReader:   policyResolver.Price,
		ResponseLimit: 4 << 20, Metrics: metrics, Rejections: rejections,
	})
	if err != nil {
		return closeOnError(err)
	}
	models, err := gateway.NewModelListHandler(upstream, policyResolver)
	if err != nil {
		return closeOnError(err)
	}
	bearer, err := gateway.NewBearerAuthenticationMiddleware(gateway.BearerAuthenticationConfig{
		Personal: personalKeys, Service: serviceAccounts, PersonalTeams: repository, Rejections: rejections,
	})
	if err != nil {
		return closeOnError(err)
	}
	v1, err := gateway.NewOpenAIV1Handler(models, chat)
	if err != nil {
		return closeOnError(err)
	}

	portal, err := httpapi.NewPortalRouter(httpapi.PortalRouterDependencies{
		Sessions: sessions, AllowedOrigin: cfg.PortalOrigin, Authenticator: authenticator,
		Activation: activation, PasswordReset: passwordReset, Identity: repository,
		Reauthentication: reauthentication, EmployeeKeys: personalKeys, OwnUsage: repository,
		Team: repository, Admin: httpapi.AdminPortalDependencies{
			Sessions: sessions, AllowedOrigin: cfg.PortalOrigin, Invitations: invitation,
			PasswordResets: passwordReset, ServiceKeys: serviceAccounts, ServiceKeyRevoke: serviceAccounts,
			Models: modelAllowlist, Retention: retention, Administration: administration,
			Audits: metadata, RawView: rawView, Operations: operationsService,
			Offboarding: offboarding, ServiceAccount: serviceAccounts, Identity: access.NewIdentityService(repository),
			SecurityEvents: administration, Investigations: investigations,
		},
	})
	if err != nil {
		return closeOnError(err)
	}
	operatorHealth, err := httpapi.NewOperatorHealthRouter(httpapi.OperatorHealthDependencies{
		Authorize: trustedOperatorRequest, Configuration: func(context.Context) error {
			if strings.TrimSpace(cfg.DatabaseURL) == "" || strings.TrimSpace(cfg.PortalOrigin) == "" || cfg.NewAPIBaseURL == nil || len(secrets.NewAPIToken()) == 0 {
				return ErrInvalidApplication
			}
			return nil
		},
		Database: func(ctx context.Context) error { return db.PingContext(ctx) },
		ActiveAuditKey: func(context.Context) error {
			version, keys := secrets.AuditKeyring()
			key, ok := keys[version]
			if !ok || len(key) != 32 {
				return ErrInvalidApplication
			}
			return nil
		}, ReadAuditGate: repository.ReadAuditGate,
		ObserveDeletionLag: repository.ObserveDeletionLag,
	})
	if err != nil {
		return closeOnError(err)
	}
	operatorMetrics, err := httpapi.NewOperatorMetricsRouter(httpapi.OperatorMetricsDependencies{Authorize: trustedOperatorRequest, Metrics: metrics})
	if err != nil {
		return closeOnError(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/v1/", bearer.Wrap(v1))
	mux.Handle("/health/", operatorHealth)
	mux.Handle("/metrics", operatorMetrics)
	mux.Handle("/api/", portal)
	assets, err := web.Assets()
	if err != nil {
		return closeOnError(err)
	}
	mux.Handle("/", embeddedAssets(assets))
	handler := observability.NewRequestIDMiddlewareWithMetrics(mux, observability.DefaultLogger(), metrics)
	return &Application{
		DB: db, Jobs: lifecycle, recoverAuditGate: gate.Recover, now: time.Now,
		Server: &http.Server{Addr: cfg.ListenAddress, Handler: handler},
	}, nil
}

func (application *Application) Close() error {
	if application == nil || application.DB == nil {
		return nil
	}
	return application.DB.Close()
}

func trustedOperatorRequest(request *http.Request) bool {
	if request == nil {
		return false
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(request.RemoteAddr))
	if err != nil {
		host = strings.TrimSpace(request.RemoteAddr)
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

func embeddedAssets(files fs.FS) http.Handler {
	server := http.FileServer(http.FS(files))
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		path := strings.TrimPrefix(request.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if _, err := fs.Stat(files, path); err != nil {
			request = request.Clone(request.Context())
			request.URL.Path = "/"
		}
		server.ServeHTTP(writer, request)
	})
}

func timeDuration(days int) time.Duration { return time.Duration(days) * 24 * time.Hour }
