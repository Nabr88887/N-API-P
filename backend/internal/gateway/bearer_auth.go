package gateway

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
	"n-api-p/internal/observability"
	"n-api-p/internal/policy"
)

type PersonalKeyAuthenticator interface {
	Authenticate(context.Context, string) (access.AuthenticatedPersonalKey, error)
}

type ServiceAccountKeyAuthenticator interface {
	Authenticate(context.Context, string) (access.AuthenticatedServiceAccountKey, error)
}

type PersonalTeamResolver interface {
	ResolvePersonalTeamID(context.Context, string) (string, error)
}

type BearerAuthenticationConfig struct {
	Personal      PersonalKeyAuthenticator
	Service       ServiceAccountKeyAuthenticator
	PersonalTeams PersonalTeamResolver
	Rejections    RejectionRecorder
	Now           func() time.Time
}

type BearerAuthenticationMiddleware struct {
	personal      PersonalKeyAuthenticator
	service       ServiceAccountKeyAuthenticator
	personalTeams PersonalTeamResolver
	rejections    RejectionRecorder
	now           func() time.Time
}

func NewBearerAuthenticationMiddleware(config BearerAuthenticationConfig) (*BearerAuthenticationMiddleware, error) {
	if config.Personal == nil || config.Service == nil || config.PersonalTeams == nil {
		return nil, errors.New("bearer authentication dependencies are required")
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &BearerAuthenticationMiddleware{
		personal: config.Personal, service: config.Service, personalTeams: config.PersonalTeams,
		rejections: config.Rejections, now: now,
	}, nil
}

func (middleware *BearerAuthenticationMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if middleware == nil || next == nil || request == nil {
			return
		}
		credential, ok := bearerCredential(request)
		if !ok {
			middleware.reject(request, RejectionCodeInvalidAPIKey)
			writeChatError(writer, "INVALID_API_KEY")
			return
		}

		caller, err := middleware.authenticate(request.Context(), credential)
		if err != nil {
			middleware.reject(request, RejectionCodeInvalidAPIKey)
			writeChatError(writer, "INVALID_API_KEY")
			return
		}
		if requestID, ok := observability.RequestIDFromContext(request.Context()); ok {
			caller.RequestID = requestID
		}
		if !validChatCaller(caller) {
			middleware.reject(request, RejectionCodeInvalidAPIKey)
			writeChatError(writer, "INVALID_API_KEY")
			return
		}
		request = request.WithContext(WithChatCaller(request.Context(), caller))
		next.ServeHTTP(writer, request)
	})
}

func (middleware *BearerAuthenticationMiddleware) authenticate(ctx context.Context, credential string) (ChatCaller, error) {
	personal, err := middleware.personal.Authenticate(ctx, credential)
	if err == nil {
		teamID, err := middleware.personalTeams.ResolvePersonalTeamID(ctx, personal.IdentityID)
		if err != nil || personal.KeyID == "" || personal.IdentityID == "" || teamID == "" {
			return ChatCaller{}, access.ErrInvalidAPIKey
		}
		caller := ChatCaller{
			KeyID: personal.KeyID, OwnerKind: audit.OwnerKindPersonal,
			IdentityID: personal.IdentityID, TeamID: teamID,
			TrafficOwner: TrafficOwner{Kind: TrafficOwnerEmployee, ID: personal.IdentityID},
		}
		return caller, nil
	}
	if !errors.Is(err, access.ErrInvalidAPIKey) {
		return ChatCaller{}, err
	}
	service, err := middleware.service.Authenticate(ctx, credential)
	if err != nil {
		return ChatCaller{}, err
	}
	caller := ChatCaller{
		KeyID: service.KeyID, OwnerKind: audit.OwnerKindService,
		ServiceAccountID: service.ServiceAccountID, ResponsibleIdentityID: service.ResponsibleIdentityID,
		TeamID:       service.TeamID,
		TrafficOwner: TrafficOwner{Kind: TrafficOwnerServiceAccount, ID: service.ServiceAccountID},
	}
	return caller, nil
}

func (middleware *BearerAuthenticationMiddleware) reject(request *http.Request, code RejectionErrorCode) {
	if middleware == nil || middleware.rejections == nil || request == nil {
		return
	}
	requestID, ok := observability.RequestIDFromContext(request.Context())
	if !ok || requestID == "" {
		return
	}
	_ = middleware.rejections.Record(request.Context(), Rejection{
		Class: RejectionAuthentication, RequestID: requestID, ObservedAt: middleware.now().UTC(), ErrorCode: code,
	})
}

func bearerCredential(request *http.Request) (string, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 {
		return "", false
	}
	parts := strings.Fields(values[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" || len(parts[1]) > 4096 {
		return "", false
	}
	for _, character := range parts[1] {
		if unicode.IsControl(character) {
			return "", false
		}
	}
	return parts[1], true
}

var _ ModelPolicy = (*policy.Resolver)(nil)
