package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"n-api-p/internal/access"
)

func TestPasswordResetCodeHandlerReturnsSingleUseCodeOnlyOnIssuance(t *testing.T) {
	service := &fakePasswordResetService{issued: access.PasswordResetCode{
		Code: "one-time-code", Email: "employee@example.internal", ExpiresAt: time.Date(2026, 8, 1, 9, 30, 0, 0, time.UTC),
	}}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/users/employee-1/password-reset-codes", bytes.NewBufferString(`{"email":"employee@example.internal","manual_identity_verified":true,"compromise_response":true}`))
	grantUntil := middlewareNow.Add(time.Minute)
	request = request.WithContext(context.WithValue(request.Context(), portalSessionContextKey{}, access.ActivePortalSession{
		SessionID: "admin-session", IdentityID: "admin-1", Role: access.RoleSystemAdministrator, ReauthenticatedUntil: &grantUntil,
	}))
	recorder := httptest.NewRecorder()
	NewPasswordResetCodeHandler(service).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusCreated)
	}
	if service.issueInput.TargetIdentityID != "employee-1" || !service.issueInput.CompromiseResponse || !service.issueInput.ManualIdentityVerified {
		t.Fatalf("issue input = %+v", service.issueInput)
	}
	if !strings.Contains(recorder.Body.String(), "one-time-code") || strings.Contains(recorder.Body.String(), "new-password") {
		t.Fatalf("issuance response leaked or omitted expected values: %s", recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache header = %q", recorder.Header().Get("Cache-Control"))
	}
}

func TestPasswordResetCodeHandlerRejectsUnauthenticatedAndInvalidBodies(t *testing.T) {
	service := &fakePasswordResetService{}
	unauthenticated := httptest.NewRequest(http.MethodPost, "/api/v1/users/employee-1/password-reset-codes", bytes.NewBufferString(`{}`))
	recorder := httptest.NewRecorder()
	NewPasswordResetCodeHandler(service).ServeHTTP(recorder, unauthenticated)
	assertHTTPError(t, recorder, http.StatusUnauthorized, CodeAuthenticationRequired)

	for _, body := range []string{
		`{"email":"employee@example.internal","manual_identity_verified":true,"unknown":true}`,
		`{"email":"employee@example.internal","manual_identity_verified":true}{}`,
		`{"email":"","manual_identity_verified":true}`,
	} {
		t.Run(body, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/v1/users/employee-1/password-reset-codes", bytes.NewBufferString(body))
			request = request.WithContext(context.WithValue(request.Context(), portalSessionContextKey{}, access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator}))
			recorder := httptest.NewRecorder()
			NewPasswordResetCodeHandler(service).ServeHTTP(recorder, request)
			assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
		})
	}
}

func TestPasswordResetCompletionHandlerDoesNotReturnPasswordOrCode(t *testing.T) {
	service := &fakePasswordResetService{}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/password-reset-completions", bytes.NewBufferString(`{"email":"employee@example.internal","code":"one-time-code","new_password":"new-password"}`))
	recorder := httptest.NewRecorder()
	NewPasswordResetCompletionHandler(service).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || service.completionInput.Code != "one-time-code" || service.completionInput.NewPassword != "new-password" {
		t.Fatalf("completion result/input = (%d, %+v)", recorder.Code, service.completionInput)
	}
	if strings.Contains(recorder.Body.String(), "one-time-code") || strings.Contains(recorder.Body.String(), "new-password") {
		t.Fatal("completion response exposed reset secrets")
	}
}

func TestPasswordResetCompletionHandlerMapsRejectedCodeAndRejectsUnknownFields(t *testing.T) {
	service := &fakePasswordResetService{completeErr: access.ErrPasswordResetRejected}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/password-reset-completions", bytes.NewBufferString(`{"email":"employee@example.internal","code":"expired","new_password":"new-password"}`))
	recorder := httptest.NewRecorder()
	NewPasswordResetCompletionHandler(service).ServeHTTP(recorder, request)
	assertHTTPError(t, recorder, http.StatusUnauthorized, CodeInvalidCredentials)

	request = httptest.NewRequest(http.MethodPost, "/api/v1/password-reset-completions", bytes.NewBufferString(`{"email":"employee@example.internal","code":"code","new_password":"password","extra":"nope"}`))
	recorder = httptest.NewRecorder()
	NewPasswordResetCompletionHandler(service).ServeHTTP(recorder, request)
	assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)

	request = httptest.NewRequest(http.MethodPost, "/api/v1/password-reset-completions", bytes.NewBufferString(`{"email":"employee@example.internal","code":"","new_password":"password"}`))
	recorder = httptest.NewRecorder()
	NewPasswordResetCompletionHandler(service).ServeHTTP(recorder, request)
	assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
}

func TestPasswordResetCompletionHandlerMapsPasswordInitializationFailureToInternalError(t *testing.T) {
	service := &fakePasswordResetService{completeErr: access.ErrPasswordInitializationFailed}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/password-reset-completions", bytes.NewBufferString(`{"email":"employee@example.internal","code":"code","new_password":"new-password"}`))
	recorder := httptest.NewRecorder()
	NewPasswordResetCompletionHandler(service).ServeHTTP(recorder, request)
	assertHTTPError(t, recorder, http.StatusInternalServerError, CodeInternalError)
}

type fakePasswordResetService struct {
	issued          access.PasswordResetCode
	issueInput      access.PasswordResetIssueInput
	issueErr        error
	completionInput access.PasswordResetCompletionInput
	completeErr     error
}

func (service *fakePasswordResetService) IssueCode(_ context.Context, input access.PasswordResetIssueInput) (access.PasswordResetCode, error) {
	service.issueInput = input
	return service.issued, service.issueErr
}

func (service *fakePasswordResetService) Complete(_ context.Context, input access.PasswordResetCompletionInput) error {
	service.completionInput = input
	return service.completeErr
}
