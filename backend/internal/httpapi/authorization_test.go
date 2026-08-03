package httpapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"n-api-p/internal/access"
)

func TestAuthorizationGuardRoleMatrix(t *testing.T) {
	guard := NewAuthorizationGuard()
	roles := []Role{RoleEmployee, RoleTeamAdministrator, RoleSystemAdministrator}

	for _, route := range Routes() {
		if route.Auth != AuthPortalSession {
			continue
		}
		for _, role := range roles {
			wantAllowed := containsRole(route.Roles, role)
			t.Run(string(role)+"/"+string(route.Name), func(t *testing.T) {
				session := access.ActivePortalSession{SessionID: "session-1", IdentityID: "identity-1", Role: access.Role(role)}
				err := guard.Authorize(route, session)
				if wantAllowed {
					if err != nil {
						t.Fatalf("Authorize() error = %v, want nil", err)
					}
					return
				}
				if !errors.Is(err, access.ErrForbidden) {
					t.Fatalf("Authorize() error = %v, want access.ErrForbidden", err)
				}
			})
		}
	}
}

func TestAuthorizationGuardDeniesMissingOrMalformedSession(t *testing.T) {
	guard := NewAuthorizationGuard()
	route := routeByName(t, RouteName("admin.users.list"))

	for name, session := range map[string]access.ActivePortalSession{
		"missing identity": {Role: access.RoleSystemAdministrator},
		"unknown role":     {IdentityID: "identity-1", Role: access.Role("owner")},
		"empty role":       {IdentityID: "identity-1"},
	} {
		t.Run(name, func(t *testing.T) {
			err := guard.Authorize(route, session)
			if !errors.Is(err, access.ErrForbidden) {
				t.Fatalf("Authorize() error = %v, want access.ErrForbidden", err)
			}
		})
	}
}

func TestAuthorizationGuardWrapsProtectedRoute(t *testing.T) {
	guard := NewAuthorizationGuard()
	route := routeByName(t, RouteName("portal.team.members.list"))
	called := false
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		called = true
		writer.WriteHeader(http.StatusNoContent)
	})
	handler := guard.Wrap(route, next)

	denied := httptest.NewRecorder()
	deniedRequest := httptest.NewRequest(http.MethodGet, route.Pattern, nil)
	deniedRequest = deniedRequest.WithContext(context.WithValue(deniedRequest.Context(), portalSessionContextKey{}, access.ActivePortalSession{
		SessionID: "session-1", IdentityID: "identity-1", Role: access.RoleEmployee,
	}))
	handler.ServeHTTP(denied, deniedRequest)
	assertHTTPError(t, denied, http.StatusForbidden, CodeForbidden)
	if called {
		t.Fatal("next handler was called for denied role")
	}

	allowed := httptest.NewRecorder()
	allowedRequest := httptest.NewRequest(http.MethodGet, route.Pattern, nil)
	allowedRequest = allowedRequest.WithContext(context.WithValue(allowedRequest.Context(), portalSessionContextKey{}, access.ActivePortalSession{
		SessionID: "session-1", IdentityID: "identity-1", Role: access.RoleTeamAdministrator,
	}))
	handler.ServeHTTP(allowed, allowedRequest)
	if allowed.Code != http.StatusNoContent {
		t.Fatalf("allowed status = %d, want %d", allowed.Code, http.StatusNoContent)
	}
	if !called {
		t.Fatal("next handler was not called for allowed role")
	}
}

func TestAuthorizationGuardWrapsMissingSessionAsAuthenticationRequired(t *testing.T) {
	guard := NewAuthorizationGuard()
	route := routeByName(t, RouteName("portal.me.get"))
	handler := guard.Wrap(route, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler was called without a session")
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, route.Pattern, nil))
	assertHTTPError(t, recorder, http.StatusUnauthorized, CodeAuthenticationRequired)
}

func TestAuthorizationGuardLeavesNonPortalAuthToItsBoundary(t *testing.T) {
	guard := NewAuthorizationGuard()
	for _, route := range Routes() {
		if route.Auth == AuthPortalSession {
			continue
		}
		t.Run(string(route.Name), func(t *testing.T) {
			called := false
			handler := guard.Wrap(route, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				called = true
			}))
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(string(route.Method), route.Pattern, nil))
			if !called {
				t.Fatal("next handler was not called for non-portal auth boundary")
			}
		})
	}
}

func routeByName(t *testing.T, name RouteName) Route {
	t.Helper()
	for _, route := range Routes() {
		if route.Name == name {
			return route
		}
	}
	t.Fatalf("route %q not found", name)
	return Route{}
}

func containsRole(roles []Role, want Role) bool {
	for _, role := range roles {
		if role == want {
			return true
		}
	}
	return false
}
