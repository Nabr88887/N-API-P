package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"n-api-p/internal/access"
)

var middlewareNow = time.Date(2026, time.August, 3, 12, 0, 0, 0, time.UTC)

func TestPortalSessionCookieUsesStrictHostOnlySecurityAttributes(t *testing.T) {
	recorder := httptest.NewRecorder()
	WritePortalSessionCookie(recorder, access.PortalSession{Token: "opaque-session-token", CSRFToken: "opaque-csrf-token", ExpiresAt: middlewareNow.Add(12 * time.Hour)})
	cookies := recorder.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("cookies = %d, want session and CSRF cookies", len(cookies))
	}
	sessionCookie, csrfCookie := cookies[0], cookies[1]
	if sessionCookie.Name != PortalSessionCookieName || sessionCookie.Value != "opaque-session-token" || sessionCookie.Path != "/" {
		t.Fatalf("session cookie identity = %+v", sessionCookie)
	}
	if !sessionCookie.HttpOnly || !sessionCookie.Secure || sessionCookie.SameSite != http.SameSiteStrictMode || sessionCookie.Domain != "" {
		t.Fatalf("session cookie security attributes = %+v", sessionCookie)
	}
	if csrfCookie.Name != PortalCSRFCookieName || csrfCookie.Value != "opaque-csrf-token" || csrfCookie.Path != "/" || csrfCookie.HttpOnly || !csrfCookie.Secure || csrfCookie.SameSite != http.SameSiteStrictMode || csrfCookie.Domain != "" {
		t.Fatalf("CSRF cookie security attributes = %+v", csrfCookie)
	}
	if !sessionCookie.Expires.Equal(middlewareNow.Add(12*time.Hour)) || !csrfCookie.Expires.Equal(sessionCookie.Expires) {
		t.Fatalf("cookie expiries = (%v, %v)", sessionCookie.Expires, csrfCookie.Expires)
	}
}

func TestPortalSessionMiddlewareRejectsMissingInvalidAndUnavailableSessions(t *testing.T) {
	tests := []struct {
		name       string
		cookie     bool
		serviceErr error
		wantStatus int
		wantCode   ErrorCode
	}{
		{name: "missing cookie", wantStatus: 401, wantCode: CodeAuthenticationRequired},
		{name: "invalid or expired", cookie: true, serviceErr: access.ErrSessionInvalid, wantStatus: 401, wantCode: CodeAuthenticationRequired},
		{name: "repository unavailable", cookie: true, serviceErr: access.ErrSessionUnavailable, wantStatus: 500, wantCode: CodeInternalError},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fakePortalSessions{authenticateErr: test.serviceErr}
			middleware := newTestPortalMiddleware(t, service)
			request := httptest.NewRequest(http.MethodGet, "https://portal.example.internal/api/v1/me", nil)
			if test.cookie {
				request.AddCookie(&http.Cookie{Name: PortalSessionCookieName, Value: "session-token"})
			}
			recorder := httptest.NewRecorder()
			middleware.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("protected handler was called")
			})).ServeHTTP(recorder, request)
			assertHTTPError(t, recorder, test.wantStatus, test.wantCode)
		})
	}
}

func TestPortalSessionMiddlewareRequiresSameOriginAndCSRFForStateChanges(t *testing.T) {
	tests := []struct {
		name   string
		origin string
		csrf   string
		wantOK bool
	}{
		{name: "missing origin", csrf: "csrf-token"},
		{name: "cross origin", origin: "https://evil.example", csrf: "csrf-token"},
		{name: "missing csrf", origin: "https://portal.example.internal"},
		{name: "matching evidence", origin: "https://portal.example.internal", csrf: "csrf-token", wantOK: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := &fakePortalSessions{session: access.ActivePortalSession{SessionID: "session-1", IdentityID: "identity-1"}}
			middleware := newTestPortalMiddleware(t, service)
			request := httptest.NewRequest(http.MethodDelete, "https://portal.example.internal/api/v1/sessions/current", nil)
			request.AddCookie(&http.Cookie{Name: PortalSessionCookieName, Value: "session-token"})
			if test.origin != "" {
				request.Header.Set("Origin", test.origin)
			}
			if test.csrf != "" {
				request.Header.Set(CSRFHeaderName, test.csrf)
			}
			recorder := httptest.NewRecorder()
			called := false
			middleware.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(recorder, request)
			if test.wantOK {
				if !called || service.lastCSRF != test.csrf || !service.lastRequireCSRF {
					t.Fatalf("accepted request = (%v, %q, %v)", called, service.lastCSRF, service.lastRequireCSRF)
				}
				return
			}
			if called {
				t.Fatal("rejected request reached protected handler")
			}
			assertHTTPError(t, recorder, 403, CodeCSRFRejected)
		})
	}
}

func TestPortalSessionMiddlewareDoesNotRevealWhetherSessionOrCSRFWasInvalid(t *testing.T) {
	service := &fakePortalSessions{authenticateErr: access.ErrSessionInvalid}
	middleware := newTestPortalMiddleware(t, service)
	request := httptest.NewRequest(http.MethodPost, "https://portal.example.internal/api/v1/me/personal-keys", nil)
	request.AddCookie(&http.Cookie{Name: PortalSessionCookieName, Value: "possibly-valid-session"})
	request.Header.Set("Origin", "https://portal.example.internal")
	request.Header.Set(CSRFHeaderName, "wrong-csrf-token")
	recorder := httptest.NewRecorder()
	middleware.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("protected handler was called")
	})).ServeHTTP(recorder, request)
	assertHTTPError(t, recorder, http.StatusForbidden, CodeCSRFRejected)
}

func TestPortalSessionMiddlewareRequiresConfiguredHTTPSOrigin(t *testing.T) {
	for _, origin := range []string{"http://portal.example.internal", "https://portal.example.internal/path", "https://user@portal.example.internal"} {
		if _, err := NewPortalSessionMiddleware(&fakePortalSessions{}, origin); err == nil {
			t.Fatalf("NewPortalSessionMiddleware(%q) succeeded", origin)
		}
	}
}

func TestPortalSessionMiddlewareExposesAuthenticatedSessionToSafeRequest(t *testing.T) {
	service := &fakePortalSessions{session: access.ActivePortalSession{SessionID: "session-1", IdentityID: "identity-1", Role: access.RoleEmployee}}
	middleware := newTestPortalMiddleware(t, service)
	request := httptest.NewRequest(http.MethodGet, "https://portal.example.internal/api/v1/me", nil)
	request.AddCookie(&http.Cookie{Name: PortalSessionCookieName, Value: "session-token"})
	recorder := httptest.NewRecorder()
	middleware.Wrap(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		session, ok := PortalSessionFromContext(request.Context())
		if !ok || session.SessionID != "session-1" || session.IdentityID != "identity-1" {
			t.Fatalf("context session = (%+v, %v)", session, ok)
		}
	})).ServeHTTP(recorder, request)
	if service.lastRequireCSRF || service.lastCSRF != "" {
		t.Fatal("safe request required CSRF evidence")
	}
}

func TestLogoutHandlerRevokesSessionAndClearsCookie(t *testing.T) {
	service := &fakePortalSessions{session: access.ActivePortalSession{SessionID: "session-1", IdentityID: "identity-1"}}
	middleware := newTestPortalMiddleware(t, service)
	request := httptest.NewRequest(http.MethodDelete, "https://portal.example.internal/api/v1/sessions/current", nil)
	request.AddCookie(&http.Cookie{Name: PortalSessionCookieName, Value: "session-token"})
	request.Header.Set("Origin", "https://portal.example.internal")
	request.Header.Set(CSRFHeaderName, "csrf-token")
	recorder := httptest.NewRecorder()
	middleware.Wrap(NewLogoutHandler(service)).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || service.revokedSessionID != "session-1" {
		t.Fatalf("logout result = (%d, %q)", recorder.Code, service.revokedSessionID)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 2 || cookies[0].Name != PortalSessionCookieName || cookies[1].Name != PortalCSRFCookieName || cookies[0].MaxAge != -1 || cookies[1].MaxAge != -1 || !cookies[0].HttpOnly || cookies[1].HttpOnly || !cookies[0].Secure || !cookies[1].Secure || cookies[0].SameSite != http.SameSiteStrictMode || cookies[1].SameSite != http.SameSiteStrictMode {
		t.Fatalf("cleared cookie = %+v", cookies)
	}
}

func newTestPortalMiddleware(t *testing.T, service PortalSessionService) *PortalSessionMiddleware {
	t.Helper()
	middleware, err := NewPortalSessionMiddleware(service, "https://portal.example.internal")
	if err != nil {
		t.Fatalf("NewPortalSessionMiddleware() error = %v", err)
	}
	return middleware
}

func assertHTTPError(t *testing.T, recorder *httptest.ResponseRecorder, wantStatus int, wantCode ErrorCode) {
	t.Helper()
	if recorder.Code != wantStatus {
		t.Fatalf("status = %d, want %d", recorder.Code, wantStatus)
	}
	var envelope ErrorEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	if envelope.Error.Code != wantCode {
		t.Fatalf("error code = %q, want %q", envelope.Error.Code, wantCode)
	}
}

type fakePortalSessions struct {
	session          access.ActivePortalSession
	authenticateErr  error
	revokeErr        error
	lastToken        string
	lastCSRF         string
	lastRequireCSRF  bool
	revokedSessionID string
}

func (service *fakePortalSessions) Authenticate(_ context.Context, token, csrf string, requireCSRF bool) (access.ActivePortalSession, error) {
	service.lastToken = token
	service.lastCSRF = csrf
	service.lastRequireCSRF = requireCSRF
	return service.session, service.authenticateErr
}

func (service *fakePortalSessions) Revoke(_ context.Context, sessionID string) error {
	service.revokedSessionID = sessionID
	return service.revokeErr
}
