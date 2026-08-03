package httpapi

import (
	"errors"
	"net/http"

	"n-api-p/internal/access"
)

// AuthorizationGuard enforces the role allowlist declared by the route
// inventory. Authentication mechanisms other than portal sessions remain the
// responsibility of their own boundary middleware.
type AuthorizationGuard struct{}

func NewAuthorizationGuard() *AuthorizationGuard {
	return &AuthorizationGuard{}
}

// Authorize checks a route against an already authenticated portal session.
// It deliberately fails closed when the session identity or role is invalid.
func (guard *AuthorizationGuard) Authorize(route Route, session access.ActivePortalSession) error {
	if route.Auth != AuthPortalSession {
		return nil
	}
	if session.IdentityID == "" || !roleAllowed(route.Roles, session.Role) {
		return access.ErrForbidden
	}
	return nil
}

// Wrap applies the portal-session role check at the handler boundary. The
// session middleware must run before this guard so that a valid session is
// available in the request context.
func (guard *AuthorizationGuard) Wrap(route Route, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if route.Auth != AuthPortalSession {
			next.ServeHTTP(writer, request)
			return
		}

		session, ok := PortalSessionFromContext(request.Context())
		if !ok {
			writeErrorResponse(writer, CodeAuthenticationRequired)
			return
		}
		if err := guard.Authorize(route, session); errors.Is(err, access.ErrForbidden) {
			writeErrorResponse(writer, CodeForbidden)
			return
		} else if err != nil {
			writeErrorResponse(writer, CodeInternalError)
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func roleAllowed(roles []Role, sessionRole access.Role) bool {
	for _, role := range roles {
		if string(role) == string(sessionRole) {
			return true
		}
	}
	return false
}
