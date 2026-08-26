package httpapi

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"n-api-p/internal/access"
	"n-api-p/internal/observability"
)

type PortalIdentityReader interface {
	ReadPortalIdentity(context.Context, string) (access.PortalIdentity, error)
}

type ActivationCompleter interface {
	Activate(context.Context, access.ActivateInput) error
}

type PortalIdentityResponse struct {
	ID      string   `json:"id"`
	Email   string   `json:"email"`
	Role    Role     `json:"role"`
	TeamIDs []string `json:"team_ids,omitempty"`
}

func NewPortalMeHandler(reader PortalIdentityReader) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := PortalSessionFromContext(request.Context())
		if !ok || session.IdentityID == "" {
			writeErrorResponse(writer, CodeAuthenticationRequired)
			return
		}
		identity, err := reader.ReadPortalIdentity(request.Context(), session.IdentityID)
		if errors.Is(err, access.ErrIdentityNotFound) {
			writeErrorResponse(writer, CodeAuthenticationRequired)
			return
		}
		if err != nil {
			writeErrorResponse(writer, CodeInternalError)
			return
		}
		writeJSON(writer, http.StatusOK, PortalIdentityResponse{
			ID: identity.ID, Email: identity.Email, Role: Role(identity.Role), TeamIDs: append([]string(nil), identity.TeamIDs...),
		})
	})
}

func NewActivationHandler(service ActivationCompleter) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var input CompleteActivationRequest
		if !decodeStrictJSON(writer, request, &input) {
			return
		}
		if strings.TrimSpace(input.Email) == "" || strings.TrimSpace(input.ActivationCode) == "" || input.Password == "" {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		err := service.Activate(request.Context(), access.ActivateInput{
			AttemptSource: trustedActivationSource(request), Email: input.Email,
			ActivationValue: input.ActivationCode, NewPassword: input.Password,
		})
		switch {
		case errors.Is(err, access.ErrActivationRejected):
			writeErrorResponse(writer, CodeInvalidCredentials)
		case errors.Is(err, access.ErrPasswordRejected):
			writeErrorResponse(writer, CodeInvalidRequest)
		case err != nil:
			writeErrorResponse(writer, CodeInternalError)
		default:
			writer.Header().Set("Cache-Control", "no-store")
			writer.WriteHeader(http.StatusNoContent)
		}
	})
}

func trustedActivationSource(request *http.Request) string {
	if request == nil {
		return ""
	}
	address := strings.TrimSpace(request.RemoteAddr)
	if host, _, err := net.SplitHostPort(address); err == nil {
		return host
	}
	return address
}

type PortalRouterDependencies struct {
	Sessions         PortalSessionService
	AllowedOrigin    string
	Authenticator    PortalAuthenticator
	Activation       ActivationCompleter
	PasswordReset    PasswordResetCompleter
	Identity         PortalIdentityReader
	Reauthentication PortalReauthenticationService
	EmployeeKeys     EmployeePersonalKeyService
	OwnUsage         OwnUsageReader
	Team             TeamPortalReader
	Admin            AdminPortalDependencies
}

var ErrPortalRouterDependencies = errors.New("portal router services are required")

// NewPortalRouter composes the anonymous portal endpoints with the existing
// role-scoped employee, team, and system-administration routers. Each scoped
// router retains its own CSRF/session middleware and authorization guard.
func NewPortalRouter(deps PortalRouterDependencies) (http.Handler, error) {
	if deps.Sessions == nil || deps.Authenticator == nil || deps.Activation == nil || deps.PasswordReset == nil || deps.Identity == nil || deps.Reauthentication == nil || deps.EmployeeKeys == nil || deps.OwnUsage == nil || deps.Team == nil {
		return nil, ErrPortalRouterDependencies
	}
	if deps.Admin.Sessions == nil {
		deps.Admin.Sessions = deps.Sessions
	}
	if deps.Admin.AllowedOrigin == "" {
		deps.Admin.AllowedOrigin = deps.AllowedOrigin
	}
	adminRouter, err := NewAdminPortalRouter(deps.Admin)
	if err != nil {
		return nil, err
	}
	employeeRouter, err := NewEmployeePortalRouter(deps.Sessions, deps.AllowedOrigin, deps.EmployeeKeys, deps.OwnUsage)
	if err != nil {
		return nil, err
	}
	teamRouter, err := NewTeamPortalRouter(deps.Sessions, deps.AllowedOrigin, deps.Team)
	if err != nil {
		return nil, err
	}
	sessionMiddleware, err := NewPortalSessionMiddleware(deps.Sessions, deps.AllowedOrigin)
	if err != nil {
		return nil, err
	}

	meRoute := routeByNameValue(RouteName("portal.me.get"))
	logoutRoute := routeByNameValue(RouteName("portal.session.delete_current"))
	reauthRoute := routeByNameValue(RouteName("portal.session.reauthenticate"))
	for _, route := range []Route{meRoute, logoutRoute, reauthRoute} {
		if route.Pattern == "" || route.Auth != AuthPortalSession || len(route.Roles) == 0 {
			return nil, ErrPortalRouterDependencies
		}
	}
	guard := NewAuthorizationGuard()
	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/activations", NewActivationHandler(deps.Activation))
	mux.Handle("POST /api/v1/sessions", NewLoginHandler(deps.Authenticator))
	mux.Handle("POST /api/v1/password-reset-completions", NewPasswordResetCompletionHandler(deps.PasswordReset))
	mux.Handle("GET /api/v1/me", sessionMiddleware.Wrap(guard.Wrap(meRoute, NewPortalMeHandler(deps.Identity))))
	mux.Handle("DELETE /api/v1/sessions/current", sessionMiddleware.Wrap(guard.Wrap(logoutRoute, NewLogoutHandler(deps.Sessions))))
	mux.Handle("POST /api/v1/sessions/current/reauthentications", sessionMiddleware.Wrap(guard.Wrap(reauthRoute, NewReauthenticationHandler(deps.Reauthentication))))
	mux.Handle("/api/v1/me/", employeeRouter)
	mux.Handle("GET /api/v1/teams/{teamID}/members", teamRouter)
	mux.Handle("GET /api/v1/teams/{teamID}/usage", teamRouter)
	mux.Handle("/api/v1/teams", adminRouter)
	mux.Handle("/api/v1/", adminRouter)
	return observability.NewRequestIDMiddleware(mux, observability.DefaultLogger()), nil
}
