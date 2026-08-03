package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"n-api-p/internal/access"
)

func TestReauthenticationHandlerRotatesCookieWithoutReturningSecrets(t *testing.T) {
	service := &fakePortalReauthentication{session: access.PortalSession{
		ID: "new-session", IdentityID: "admin-1", Token: "new-token", CSRFToken: "new-csrf", ExpiresAt: middlewareNow.Add(5 * time.Minute),
	}}
	handler := NewReauthenticationHandler(service)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/current/reauthentications", bytes.NewBufferString(`{"password":"current-password"}`))
	request = request.WithContext(context.WithValue(request.Context(), portalSessionContextKey{}, access.ActivePortalSession{SessionID: "old-session", IdentityID: "admin-1"}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || service.input.SessionID != "old-session" || service.input.Password != "current-password" {
		t.Fatalf("response/input = (%d, %+v)", recorder.Code, service.input)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Value != "new-token" || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("rotated cookie = %+v", cookies)
	}
	if recorder.Header().Get(CSRFHeaderName) != "new-csrf" {
		t.Fatalf("rotated CSRF header = %q", recorder.Header().Get(CSRFHeaderName))
	}
	if bytes.Contains(recorder.Body.Bytes(), []byte("new-csrf")) || bytes.Contains(recorder.Body.Bytes(), []byte("current-password")) {
		t.Fatal("response exposed reauthentication secret")
	}
}

func TestReauthenticationHandlerMapsRejectedAndInvalidBodies(t *testing.T) {
	for name, body := range map[string]string{
		"empty password": `{"password":""}`,
		"unknown field":  `{"password":"current-password","secret":"leak"}`,
		"trailing value": `{"password":"current-password"}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			service := &fakePortalReauthentication{}
			handler := NewReauthenticationHandler(service)
			request := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/current/reauthentications", bytes.NewBufferString(body))
			request = request.WithContext(context.WithValue(request.Context(), portalSessionContextKey{}, access.ActivePortalSession{SessionID: "old-session", IdentityID: "admin-1"}))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
			if service.input.SessionID != "" {
				t.Fatal("invalid body reached reauthentication service")
			}
		})
	}

	service := &fakePortalReauthentication{err: access.ErrReauthenticationRejected}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/sessions/current/reauthentications", bytes.NewBufferString(`{"password":"wrong-password"}`))
	request = request.WithContext(context.WithValue(request.Context(), portalSessionContextKey{}, access.ActivePortalSession{SessionID: "old-session", IdentityID: "admin-1"}))
	recorder := httptest.NewRecorder()
	NewReauthenticationHandler(service).ServeHTTP(recorder, request)
	assertHTTPError(t, recorder, http.StatusUnauthorized, CodeInvalidCredentials)
}

type fakePortalReauthentication struct {
	session access.PortalSession
	input   access.ReauthenticationInput
	err     error
}

func (service *fakePortalReauthentication) Reauthenticate(_ context.Context, input access.ReauthenticationInput) (access.PortalSession, error) {
	service.input = input
	if service.err != nil {
		return access.PortalSession{}, service.err
	}
	return service.session, nil
}
