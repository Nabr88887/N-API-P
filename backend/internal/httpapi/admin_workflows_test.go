package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
)

var adminWorkflowNow = time.Date(2026, time.August, 12, 9, 0, 0, 0, time.UTC)

func TestWriteAdminErrorMapsAuditUnavailable(t *testing.T) {
	recorder := httptest.NewRecorder()
	writeAdminError(recorder, access.ErrSecurityAuditUnavailable)
	assertHTTPError(t, recorder, http.StatusServiceUnavailable, CodeAuditUnavailable)
}

func TestAdminInvitationHandlerReturnsOneTimeActivationValue(t *testing.T) {
	service := &fakeAdminInvitationService{invitation: access.Invitation{
		IdentityID: "10000000-0000-0000-0000-000000000001",
		Email:      "employee@example.internal", ActivationValue: "activation-once",
		ExpiresAt: time.Date(2026, 8, 13, 1, 0, 0, 0, time.UTC),
	}}
	handler := withEmployeeSession(NewAdminInvitationCreateHandler(service), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/invitations", bytes.NewBufferString(`{"email":"employee@example.internal","team_id":"20000000-0000-0000-0000-000000000001"}`)))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusCreated, recorder.Body.String())
	}
	var response InvitationIssuance
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.ActivationCode != "activation-once" || service.input.Actor.Role != access.RoleSystemAdministrator {
		t.Fatalf("response/input = %#v / %#v", response, service.input)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestAdminInvitationHandlerRejectsTeamAdministrator(t *testing.T) {
	service := &fakeAdminInvitationService{}
	handler := withEmployeeSession(NewAdminInvitationCreateHandler(service), access.ActivePortalSession{IdentityID: "team-admin", Role: access.RoleTeamAdministrator})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/invitations", bytes.NewBufferString(`{"email":"employee@example.internal","team_id":"20000000-0000-0000-0000-000000000001"}`)))
	assertHTTPError(t, recorder, http.StatusForbidden, CodeForbidden)
	if service.called {
		t.Fatal("invitation service called for a denied role")
	}
}

func TestAdminPortalRouterRegistersDeclaredAdministrationResourceRoutes(t *testing.T) {
	grantUntil := time.Now().UTC().Add(time.Minute)
	session := access.ActivePortalSession{IdentityID: "20000000-0000-0000-0000-000000000001", Role: access.RoleSystemAdministrator, ReauthenticatedUntil: &grantUntil}
	sessions := &fakePortalSessions{session: session}
	invitations := &fakeAdminInvitationService{}
	administration := &fakeAdministrationService{
		invitationPage: access.AdministrationInvitationPage{Invitations: []access.AdministrationInvitation{{IdentityID: "10000000-0000-0000-0000-000000000001", Email: "member@example.internal", TeamID: "40000000-0000-0000-0000-000000000001", Status: access.IdentityStatusPending, ExpiresAt: adminWorkflowNow.Add(time.Hour), CreatedAt: adminWorkflowNow}}},
		account:        access.AdministrationAccount{ID: "10000000-0000-0000-0000-000000000001", Email: "member@example.internal", Role: access.RoleEmployee, Status: access.IdentityStatusActive, CreatedAt: adminWorkflowNow},
		team:           access.AdministrationTeam{ID: "40000000-0000-0000-0000-000000000001", Name: "Platform", Status: "active", CreatedAt: adminWorkflowNow},
		serviceAccount: access.ServiceAccount{ID: "50000000-0000-0000-0000-000000000001", TeamID: "40000000-0000-0000-0000-000000000001", ResponsibleIdentityID: "10000000-0000-0000-0000-000000000001", Name: "ci", Status: access.ServiceAccountStatusActive, CreatedAt: adminWorkflowNow},
	}
	audits := &fakeAuditMetadataService{record: audit.Metadata{ID: rawViewHTTPAuditID, ModelID: "gpt-test", CreatedAt: adminWorkflowNow, UpdatedAt: adminWorkflowNow}}
	serviceAccounts := &fakeAdminServiceAccountService{}
	offboarding := &fakeOffboardingService{}
	router, err := NewAdminPortalRouter(AdminPortalDependencies{
		Sessions: sessions, AllowedOrigin: "https://gateway.example.internal", Invitations: invitations,
		PasswordResets: &fakePasswordResetService{}, ServiceKeys: serviceAccounts, ServiceKeyRevoke: serviceAccounts,
		Models: &fakeAdminModelPolicyService{}, Retention: &fakeAdminRetentionPolicyService{}, Administration: administration,
		Audits: audits, RawView: &fakeRawViewService{view: audit.RawView{AuditID: rawViewHTTPAuditID, RequestJSON: json.RawMessage(`{}`), ResponseJSON: json.RawMessage(`{}`)}},
		Operations: &fakeOperationsService{}, Offboarding: offboarding, ServiceAccount: serviceAccounts, Identity: &adminIdentityServiceFake{}, SecurityEvents: administration,
		ElevatedAccess: &fakeElevatedAuditAccessService{}, ElevatedQuery: &fakeElevatedAuditQueryService{}, ElevatedExport: &fakeElevatedAuditExportService{},
	})
	if err != nil {
		t.Fatalf("NewAdminPortalRouter() error = %v", err)
	}
	tests := []struct {
		name, method, path, body string
		wantStatus               int
	}{
		{name: "list invitations", method: http.MethodGet, path: "/api/v1/invitations?limit=50", wantStatus: http.StatusOK},
		{name: "get account", method: http.MethodGet, path: "/api/v1/users/10000000-0000-0000-0000-000000000001", wantStatus: http.StatusOK},
		{name: "create team", method: http.MethodPost, path: "/api/v1/teams", body: `{"name":"Core"}`, wantStatus: http.StatusCreated},
		{name: "get team", method: http.MethodGet, path: "/api/v1/teams/40000000-0000-0000-0000-000000000001", wantStatus: http.StatusOK},
		{name: "update team", method: http.MethodPatch, path: "/api/v1/teams/40000000-0000-0000-0000-000000000001", body: `{"name":"Core"}`, wantStatus: http.StatusOK},
		{name: "get service account", method: http.MethodGet, path: "/api/v1/service-accounts/50000000-0000-0000-0000-000000000001", wantStatus: http.StatusOK},
		{name: "delete service account", method: http.MethodDelete, path: "/api/v1/service-accounts/50000000-0000-0000-0000-000000000001", body: `{"confirmed":true}`, wantStatus: http.StatusNoContent},
		{name: "list audits", method: http.MethodGet, path: "/api/v1/audits?limit=50", wantStatus: http.StatusOK},
		{name: "get audit", method: http.MethodGet, path: "/api/v1/audits/" + rawViewHTTPAuditID, wantStatus: http.StatusOK},
		{name: "inspect raw audit", method: http.MethodPost, path: "/api/v1/audits/" + rawViewHTTPAuditID + "/raw-views", body: `{"reason":"incident review"}`, wantStatus: http.StatusOK},
		{name: "operations health", method: http.MethodGet, path: "/api/v1/operations/health", wantStatus: http.StatusOK},
		{name: "operational events", method: http.MethodGet, path: "/api/v1/operations/events?limit=50", wantStatus: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(test.method, test.path, bytes.NewBufferString(test.body))
			request.AddCookie(&http.Cookie{Name: PortalSessionCookieName, Value: "session-token"})
			if stateChangingMethod(test.method) {
				request.Header.Set("Origin", "https://gateway.example.internal")
				request.Header.Set(CSRFHeaderName, "csrf-token")
			}
			router.ServeHTTP(recorder, request)
			if recorder.Code != test.wantStatus {
				t.Fatalf("status = %d, want %d: %s", recorder.Code, test.wantStatus, recorder.Body.String())
			}
		})
	}
	if !offboarding.serviceAccountCalled {
		t.Fatal("DELETE service account did not reuse the offboarding service")
	}
}

func TestAdminServiceAccountDeleteRequiresExplicitConfirmation(t *testing.T) {
	service := &fakeOffboardingService{}
	handler := withEmployeeSession(NewAdminServiceAccountDeleteHandler(service), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/api/v1/service-accounts/service-1", bytes.NewBufferString(`{"confirmed":false}`)))
	assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
	if service.serviceAccountCalled {
		t.Fatal("service account delete ran without confirmation")
	}
}

func TestAdminModelAllowlistHandlerRequiresConfirmationAndReauthentication(t *testing.T) {
	service := &fakeAdminModelPolicyService{err: access.ErrReauthenticationRequired}
	handler := withEmployeeSession(NewAdminModelAllowlistReplaceHandler(service), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPut, "/api/v1/model-allowlist", bytes.NewBufferString(`{"models":[],"confirmed":false}`)))
	assertHTTPError(t, recorder, http.StatusForbidden, CodeReauthenticationRequired)
	if !service.called {
		t.Fatal("model policy service was not called to audit the denied attempt")
	}

	service.called = false
	service.err = nil
	grantUntil := time.Now().UTC().Add(time.Minute)
	handler = withEmployeeSession(NewAdminModelAllowlistReplaceHandler(service), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator, ReauthenticatedUntil: &grantUntil})
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPut, "/api/v1/model-allowlist", bytes.NewBufferString(`{"models":[],"confirmed":true}`)))
	if recorder.Code != http.StatusOK || !service.input.Confirmed {
		t.Fatalf("status/input = %d / %#v", recorder.Code, service.input)
	}
}

func TestAdminRetentionHandlerRequiresExplicitConfirmation(t *testing.T) {
	service := &fakeAdminRetentionPolicyService{err: access.ErrRetentionConfirmationRequired}
	grantUntil := time.Now().UTC().Add(time.Minute)
	session := access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator, ReauthenticatedUntil: &grantUntil}
	handler := withEmployeeSession(NewAdminRetentionPolicyReplaceHandler(service), session)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPut, "/api/v1/retention-policy", bytes.NewBufferString(`{"days":3,"confirmed":false}`)))
	assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
	if !service.called {
		t.Fatal("retention service was not called to audit the denied attempt")
	}
}

func TestAdminServiceKeyHandlerRevealsCredentialOnlyOnCreate(t *testing.T) {
	service := &fakeAdminServiceAccountService{issuance: access.ServiceAccountKeyIssuance{Key: access.ServiceAccountKey{ID: "key-1", ServiceAccountID: "service-1", Name: "build"}, Credential: *mustGeneratedKey(t)}}
	handler := withEmployeeSession(NewAdminServiceKeyCreateHandler(service), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/service-accounts/service-1/keys", bytes.NewBufferString(`{"name":"build"}`)))
	if recorder.Code != http.StatusCreated || !service.called || !bytes.Contains(recorder.Body.Bytes(), []byte(`"credential":{"value"`)) {
		t.Fatalf("status/call/body = %d / %t / %s", recorder.Code, service.called, recorder.Body.String())
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestAdminServiceKeyListUsesBoundedOpaquePagination(t *testing.T) {
	service := &fakeAdminServiceAccountService{keyPage: access.ServiceAccountKeyPage{
		Keys:       []access.ServiceAccountKey{{ID: "key-1", ServiceAccountID: "service-1", Name: "build"}},
		NextCursor: "opaque-next",
	}}
	handler := withEmployeeSession(NewAdminServiceKeyListHandler(service), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/service-accounts/service-1/keys?limit=1&cursor=opaque-current", nil))
	if recorder.Code != http.StatusOK || service.keyListInput.ServiceAccountID != "service-1" || service.keyListCursor != "opaque-current" || service.keyListLimit != 1 {
		t.Fatalf("response/input = %d / %#v / %q / %d: %s", recorder.Code, service.keyListInput, service.keyListCursor, service.keyListLimit, recorder.Body.String())
	}
	var response PagedResponse[Key]
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || len(response.Data) != 1 || response.Pagination.NextCursor != "opaque-next" || !response.Pagination.HasMore {
		t.Fatalf("service key page = %#v, error = %v", response, err)
	}
}

func TestAdminSecurityEventListParsesFiltersAndRejectsInvalidTimeRange(t *testing.T) {
	service := &fakeAdministrationService{securityEventPage: access.AdministrationSecurityEventPage{Events: []access.AdministrationSecurityEvent{{ID: "event-1", EventType: "login", RequestID: "request-1", Outcome: access.SecurityEventSuccess, OccurredAt: adminWorkflowNow}}, NextCursor: "next-event"}}
	handler := withEmployeeSession(NewAdminSecurityEventListHandler(service), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/security-events?limit=1&event_type=login&outcome=success&from=2026-08-12T08:00:00Z&to=2026-08-12T10:00:00%2B00:00", nil))
	if recorder.Code != http.StatusOK || service.securityEventFilter.Limit != 1 || service.securityEventFilter.EventType == nil || *service.securityEventFilter.EventType != "login" || service.securityEventFilter.Outcome == nil || *service.securityEventFilter.Outcome != access.SecurityEventSuccess || service.securityEventFilter.From == nil || service.securityEventFilter.To == nil {
		t.Fatalf("response/filter = %d / %#v", recorder.Code, service.securityEventFilter)
	}
	var response PagedResponse[SecurityEventMetadata]
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || !response.Pagination.HasMore || response.Pagination.NextCursor != "next-event" {
		t.Fatalf("security event page = %#v, error = %v", response, err)
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/security-events?from=not-a-time", nil))
	assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/security-events?from=2026-08-12T10:00:00Z&to=2026-08-12T09:00:00Z", nil))
	assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
}

func TestAdminPasswordResetHandlerRequiresManualVerificationAndMapsCompromise(t *testing.T) {
	service := &fakePasswordResetService{issued: access.PasswordResetCode{Code: "reset-once", Email: "employee@example.internal", ExpiresAt: time.Now().UTC().Add(time.Minute)}, issueErr: access.ErrManualIdentityVerificationRequired}
	handler := withEmployeeSession(NewAdminPasswordResetCodeHandler(service), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/users/employee-1/password-reset-codes", bytes.NewBufferString(`{"email":"employee@example.internal","manual_identity_verified":false,"compromise_response":false}`))
	handler.ServeHTTP(recorder, request)
	assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
	if service.issueInput.ManualIdentityVerified {
		t.Fatal("manual verification was unexpectedly accepted")
	}

	service.issueErr = nil
	grantUntil := time.Now().UTC().Add(time.Minute)
	handler = withEmployeeSession(NewAdminPasswordResetCodeHandler(service), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator, ReauthenticatedUntil: &grantUntil})
	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "/api/v1/users/employee-1/password-reset-codes", bytes.NewBufferString(`{"email":"employee@example.internal","manual_identity_verified":true,"compromise_response":true}`))
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || service.issueInput.TargetIdentityID != "employee-1" || !service.issueInput.CompromiseResponse {
		t.Fatalf("response/input = %d / %#v", recorder.Code, service.issueInput)
	}
}

func TestAdminServiceKeyRevokeRequiresConfirmation(t *testing.T) {
	service := &fakeAdminServiceAccountService{}
	handler := withEmployeeSession(NewAdminServiceKeyRevokeHandler(service), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/service-accounts/service-1/keys/key-1", bytes.NewBufferString(`{"confirmed":false}`))
	handler.ServeHTTP(recorder, request)
	assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
	if service.revokeCalled {
		t.Fatal("service key revoke ran without confirmation")
	}

	recorder = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodDelete, "/api/v1/service-accounts/service-1/keys/key-1", bytes.NewBufferString(`{"confirmed":true}`))
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || !service.revokeCalled {
		t.Fatalf("revoke response/call = %d / %t", recorder.Code, service.revokeCalled)
	}
}

func TestAdminAccountListPassesBoundedFiltersAndRoleChangeRequestID(t *testing.T) {
	service := &fakeAdministrationService{accountPage: access.AdministrationAccountPage{Accounts: []access.AdministrationAccount{{ID: "10000000-0000-0000-0000-000000000001", Email: "member@example.internal", Role: access.RoleEmployee, Status: access.IdentityStatusActive, CreatedAt: time.Now().UTC()}}, NextCursor: "next-page"}}
	grantUntil := time.Now().UTC().Add(time.Minute)
	session := access.ActivePortalSession{IdentityID: "20000000-0000-0000-0000-000000000001", Role: access.RoleSystemAdministrator, ReauthenticatedUntil: &grantUntil}
	handler := withEmployeeSession(NewAdminAccountListHandler(service), session)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/users?limit=1&status=active&role=employee", nil))
	if recorder.Code != http.StatusOK || service.accountFilter.Limit != 1 || service.accountFilter.Status == nil || service.accountFilter.Role == nil {
		t.Fatalf("list response/filter = %d / %#v", recorder.Code, service.accountFilter)
	}
	var response PagedResponse[Account]
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil || !response.Pagination.HasMore || response.Pagination.NextCursor != "next-page" {
		t.Fatalf("account page = %#v, error = %v", response, err)
	}

	handler = withEmployeeSession(NewAdminAccountUpdateHandler(service, &fakeOffboardingService{}), session)
	recorder = httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/users/10000000-0000-0000-0000-000000000001", bytes.NewBufferString(`{"role":"team_administrator","confirmed":true}`))
	request.Header.Set("X-Request-ID", "30000000-0000-0000-0000-000000000001")
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || service.roleInput.Role != access.RoleTeamAdministrator || service.roleInput.RequestID != "30000000-0000-0000-0000-000000000001" || service.roleInput.Actor.ReauthenticatedUntil != &grantUntil {
		t.Fatalf("role response/input = %d / %#v", recorder.Code, service.roleInput)
	}
}

func TestAdminMembershipAndOffboardingRequireExplicitConfirmation(t *testing.T) {
	administration := &fakeAdministrationService{}
	offboarding := &fakeOffboardingService{}
	session := access.ActivePortalSession{IdentityID: "20000000-0000-0000-0000-000000000001", Role: access.RoleSystemAdministrator}
	handler := withEmployeeSession(NewAdminMembershipRemoveHandler(administration), session)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/api/v1/teams/40000000-0000-0000-0000-000000000001/members/10000000-0000-0000-0000-000000000001", bytes.NewBufferString(`{"confirmed":false}`)))
	assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
	if administration.membershipCalled {
		t.Fatal("membership removal ran without confirmation")
	}

	handler = withEmployeeSession(NewAdminAccountUpdateHandler(administration, offboarding), session)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPatch, "/api/v1/users/10000000-0000-0000-0000-000000000001", bytes.NewBufferString(`{"status":"disabled","confirmed":false}`)))
	assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
	if offboarding.employeeCalled {
		t.Fatal("employee offboarding ran without confirmation")
	}
}

func TestAdminAccountUpdateRejectsMixedChangesBeforeWriting(t *testing.T) {
	administration := &fakeAdministrationService{}
	offboarding := &fakeOffboardingService{}
	session := access.ActivePortalSession{IdentityID: "20000000-0000-0000-0000-000000000001", Role: access.RoleSystemAdministrator}
	handler := withEmployeeSession(NewAdminAccountUpdateHandler(administration, offboarding), session)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(
		http.MethodPatch,
		"/api/v1/users/10000000-0000-0000-0000-000000000001",
		bytes.NewBufferString(`{"role":"team_administrator","status":"disabled","confirmed":false}`),
	))

	assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
	if administration.roleCalled || offboarding.employeeCalled {
		t.Fatalf("mixed account update wrote partial state: role=%t offboarding=%t", administration.roleCalled, offboarding.employeeCalled)
	}
}

func TestAdminRoleAndTeamDisableRequireExplicitConfirmation(t *testing.T) {
	administration := &fakeAdministrationService{}
	offboarding := &fakeOffboardingService{}
	session := access.ActivePortalSession{IdentityID: "20000000-0000-0000-0000-000000000001", Role: access.RoleSystemAdministrator}

	handler := withEmployeeSession(NewAdminAccountUpdateHandler(administration, offboarding), session)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPatch, "/api/v1/users/10000000-0000-0000-0000-000000000001", bytes.NewBufferString(`{"role":"team_administrator","confirmed":false}`)))
	assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
	if administration.roleCalled {
		t.Fatal("role change ran without confirmation")
	}

	handler = withEmployeeSession(NewAdminTeamDisableHandler(offboarding), session)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/api/v1/teams/40000000-0000-0000-0000-000000000001", bytes.NewBufferString(`{"confirmed":false}`)))
	assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
	if offboarding.teamCalled {
		t.Fatal("team disable ran without confirmation")
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodDelete, "/api/v1/teams/40000000-0000-0000-0000-000000000001", bytes.NewBufferString(`{"confirmed":true}`)))
	if recorder.Code != http.StatusNoContent || !offboarding.teamCalled || offboarding.teamInput.TeamID != "40000000-0000-0000-0000-000000000001" {
		t.Fatalf("team disable response/input = %d / %#v", recorder.Code, offboarding.teamInput)
	}

	offboarding.teamCalled = false
	handler = withEmployeeSession(NewAdminTeamUpdateHandler(administration, offboarding), session)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPatch, "/api/v1/teams/40000000-0000-0000-0000-000000000001", bytes.NewBufferString(`{"status":"disabled","confirmed":false}`)))
	assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
	if offboarding.teamCalled {
		t.Fatal("team PATCH disabled the team without confirmation")
	}
}

func TestAdminServiceAccountRotateAndPolicyReads(t *testing.T) {
	service := &fakeAdminServiceAccountService{issuance: access.ServiceAccountKeyIssuance{Key: access.ServiceAccountKey{ID: "60000000-0000-0000-0000-000000000001", ServiceAccountID: "50000000-0000-0000-0000-000000000001", Name: "rotated"}, Credential: *mustGeneratedKey(t)}}
	administration := &fakeAdministrationService{serviceAccountPage: access.AdministrationServiceAccountPage{ServiceAccounts: []access.ServiceAccount{{ID: "50000000-0000-0000-0000-000000000001", TeamID: "40000000-0000-0000-0000-000000000001", ResponsibleIdentityID: "10000000-0000-0000-0000-000000000001", Name: "ci", Status: access.ServiceAccountStatusActive}}}}
	session := access.ActivePortalSession{IdentityID: "20000000-0000-0000-0000-000000000001", Role: access.RoleSystemAdministrator}
	handler := withEmployeeSession(NewAdminServiceAccountListHandler(administration), session)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/service-accounts?limit=50", nil))
	if recorder.Code != http.StatusOK || !bytes.Contains(recorder.Body.Bytes(), []byte(`"name":"ci"`)) {
		t.Fatalf("service account list = %d / %s", recorder.Code, recorder.Body.String())
	}

	handler = withEmployeeSession(NewAdminServiceKeyRotateHandler(service), session)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/service-accounts/50000000-0000-0000-0000-000000000001/keys/70000000-0000-0000-0000-000000000001/rotations", bytes.NewBufferString(`{"name":"rotated","confirmed":true}`)))
	if recorder.Code != http.StatusCreated || !service.rotateCalled || !bytes.Contains(recorder.Body.Bytes(), []byte(`"credential":{"value"`)) {
		t.Fatalf("rotate response = %d / %t / %s", recorder.Code, service.rotateCalled, recorder.Body.String())
	}

	models := &fakeAdminModelPolicyService{entries: []access.ModelAllowlistEntry{{ModelID: "gpt-test", Status: access.ModelStatusAllowed}}}
	handler = withEmployeeSession(NewAdminModelAllowlistGetHandler(models), session)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/model-allowlist", nil))
	if recorder.Code != http.StatusOK || !bytes.Contains(recorder.Body.Bytes(), []byte("gpt-test")) {
		t.Fatalf("model read response = %d / %s", recorder.Code, recorder.Body.String())
	}
}

func TestAdminServiceAccountCreateAndDisableRequireAdministratorConfirmation(t *testing.T) {
	serviceAccounts := &fakeAdminServiceAccountService{}
	offboarding := &fakeOffboardingService{}
	session := access.ActivePortalSession{IdentityID: "20000000-0000-0000-0000-000000000001", Role: access.RoleSystemAdministrator}

	handler := withEmployeeSession(NewAdminServiceAccountCreateHandler(serviceAccounts), session)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/service-accounts", bytes.NewBufferString(`{"team_id":"40000000-0000-0000-0000-000000000001","responsible_account_id":"10000000-0000-0000-0000-000000000001","name":"build-agent"}`))
	request.Header.Set("X-Request-ID", "30000000-0000-0000-0000-000000000001")
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || !serviceAccounts.called || serviceAccounts.createInput.RequestID != "30000000-0000-0000-0000-000000000001" {
		t.Fatalf("create response/input = %d / %#v", recorder.Code, serviceAccounts.createInput)
	}

	handler = withEmployeeSession(NewAdminServiceAccountUpdateHandler(offboarding), session)
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPatch, "/api/v1/service-accounts/50000000-0000-0000-0000-000000000001", bytes.NewBufferString(`{"status":"disabled","confirmed":false}`)))
	assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
	if offboarding.serviceAccountCalled {
		t.Fatal("service account was disabled without confirmation")
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPatch, "/api/v1/service-accounts/50000000-0000-0000-0000-000000000001", bytes.NewBufferString(`{"status":"disabled","confirmed":true}`)))
	if recorder.Code != http.StatusNoContent || !offboarding.serviceAccountCalled || offboarding.serviceAccountInput.ServiceAccountID != "50000000-0000-0000-0000-000000000001" {
		t.Fatalf("disable response/input = %d / %#v", recorder.Code, offboarding.serviceAccountInput)
	}
}

func TestAdminHandlersWriteOneErrorForMalformedJSON(t *testing.T) {
	session := access.ActivePortalSession{IdentityID: "20000000-0000-0000-0000-000000000001", Role: access.RoleSystemAdministrator}
	administration := &fakeAdministrationService{}
	offboarding := &fakeOffboardingService{}
	serviceAccounts := &fakeAdminServiceAccountService{}
	tests := []struct {
		name    string
		method  string
		path    string
		handler http.Handler
	}{
		{name: "team disable", method: http.MethodDelete, path: "/api/v1/teams/40000000-0000-0000-0000-000000000001", handler: NewAdminTeamDisableHandler(offboarding)},
		{name: "membership removal", method: http.MethodDelete, path: "/api/v1/teams/40000000-0000-0000-0000-000000000001/members/10000000-0000-0000-0000-000000000001", handler: NewAdminMembershipRemoveHandler(administration)},
		{name: "service account creation", method: http.MethodPost, path: "/api/v1/service-accounts", handler: NewAdminServiceAccountCreateHandler(serviceAccounts)},
		{name: "service key rotation", method: http.MethodPost, path: "/api/v1/service-accounts/50000000-0000-0000-0000-000000000001/keys/70000000-0000-0000-0000-000000000001/rotations", handler: NewAdminServiceKeyRotateHandler(serviceAccounts)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			withEmployeeSession(test.handler, session).ServeHTTP(recorder, httptest.NewRequest(test.method, test.path, bytes.NewBufferString(`{`)))
			assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
			if count := bytes.Count(recorder.Body.Bytes(), []byte(`"error"`)); count != 1 {
				t.Fatalf("malformed JSON wrote %d error envelopes: %s", count, recorder.Body.String())
			}
		})
	}
}

type fakeAdminInvitationService struct {
	invitation access.Invitation
	input      access.CreateInvitationInput
	called     bool
}

func (service *fakeAdminInvitationService) Create(_ context.Context, input access.CreateInvitationInput) (access.Invitation, error) {
	service.called = true
	service.input = input
	return service.invitation, nil
}

type fakeAdminModelPolicyService struct {
	input   access.ModelAllowlistChangeInput
	entries []access.ModelAllowlistEntry
	called  bool
	err     error
}

func (service *fakeAdminModelPolicyService) Get(context.Context, access.ActivePortalSession) ([]access.ModelAllowlistEntry, error) {
	return service.entries, service.err
}

func (service *fakeAdminModelPolicyService) Replace(_ context.Context, _ access.ActivePortalSession, input access.ModelAllowlistChangeInput) ([]access.ModelAllowlistEntry, error) {
	service.called = true
	service.input = input
	return nil, service.err
}

type fakeAdminRetentionPolicyService struct {
	input  access.RetentionPolicyChangeInput
	called bool
	err    error
}

func (service *fakeAdminRetentionPolicyService) Get(context.Context, access.ActivePortalSession) (access.RetentionPolicy, error) {
	return access.RetentionPolicy{Days: 7, MaximumDays: 30}, service.err
}

func (service *fakeAdminRetentionPolicyService) Change(_ context.Context, _ access.ActivePortalSession, input access.RetentionPolicyChangeInput) (access.RetentionPolicy, error) {
	service.called = true
	service.input = input
	return access.RetentionPolicy{Days: input.Days, MaximumDays: 30}, service.err
}

type fakeAdminServiceAccountService struct {
	issuance      access.ServiceAccountKeyIssuance
	accounts      []access.ServiceAccount
	keys          []access.ServiceAccountKey
	keyPage       access.ServiceAccountKeyPage
	keyListInput  access.ListServiceAccountKeysInput
	keyListCursor string
	keyListLimit  int
	called        bool
	revokeCalled  bool
	rotateCalled  bool
	createInput   access.CreateServiceAccountInput
}

func (service *fakeAdminServiceAccountService) Create(_ context.Context, input access.CreateServiceAccountInput) (access.ServiceAccount, error) {
	service.called = true
	service.createInput = input
	return access.ServiceAccount{Name: input.Name, TeamID: input.TeamID, ResponsibleIdentityID: input.ResponsibleIdentityID}, nil
}

func (service *fakeAdminServiceAccountService) List(context.Context, access.Actor) ([]access.ServiceAccount, error) {
	return service.accounts, nil
}

func (service *fakeAdminServiceAccountService) ListKeys(context.Context, access.ListServiceAccountKeysInput) ([]access.ServiceAccountKey, error) {
	return service.keys, nil
}

func (service *fakeAdminServiceAccountService) ListKeysPage(_ context.Context, input access.ListServiceAccountKeysInput, cursor string, limit int) (access.ServiceAccountKeyPage, error) {
	service.keyListInput = input
	service.keyListCursor = cursor
	service.keyListLimit = limit
	return service.keyPage, nil
}

func (service *fakeAdminServiceAccountService) RotateKey(context.Context, access.RotateServiceAccountKeyInput) (access.ServiceAccountKeyIssuance, error) {
	service.rotateCalled = true
	return service.issuance, nil
}

func (service *fakeAdminServiceAccountService) CreateKey(_ context.Context, input access.CreateServiceAccountKeyInput) (access.ServiceAccountKeyIssuance, error) {
	service.called = true
	if input.Actor.Role != access.RoleSystemAdministrator {
		return access.ServiceAccountKeyIssuance{}, access.ErrForbidden
	}
	return service.issuance, nil
}

type fakeAdministrationService struct {
	invitationPage      access.AdministrationInvitationPage
	accountPage         access.AdministrationAccountPage
	teamPage            access.AdministrationTeamPage
	serviceAccountPage  access.AdministrationServiceAccountPage
	securityEventPage   access.AdministrationSecurityEventPage
	securityEventFilter access.AdministrationSecurityEventFilter
	accountFilter       access.AdministrationAccountFilter
	roleInput           access.ChangeRoleInput
	roleCalled          bool
	membershipCalled    bool
	account             access.AdministrationAccount
	team                access.AdministrationTeam
	serviceAccount      access.ServiceAccount
}

func (service *fakeAdministrationService) ListInvitations(context.Context, access.Actor, access.AdministrationInvitationFilter) (access.AdministrationInvitationPage, error) {
	return service.invitationPage, nil
}

func (service *fakeAdministrationService) ListServiceAccounts(context.Context, access.Actor, access.AdministrationServiceAccountFilter) (access.AdministrationServiceAccountPage, error) {
	return service.serviceAccountPage, nil
}

func (service *fakeAdministrationService) ListSecurityEvents(_ context.Context, _ access.Actor, filter access.AdministrationSecurityEventFilter) (access.AdministrationSecurityEventPage, error) {
	service.securityEventFilter = filter
	return service.securityEventPage, nil
}

func (service *fakeAdministrationService) ListAccounts(_ context.Context, _ access.Actor, filter access.AdministrationAccountFilter) (access.AdministrationAccountPage, error) {
	service.accountFilter = filter
	return service.accountPage, nil
}

func (service *fakeAdministrationService) ListTeams(context.Context, access.Actor, access.AdministrationTeamFilter) (access.AdministrationTeamPage, error) {
	return service.teamPage, nil
}

func (service *fakeAdministrationService) GetAccount(context.Context, access.Actor, string) (access.AdministrationAccount, error) {
	return service.account, nil
}

func (service *fakeAdministrationService) GetTeam(context.Context, access.Actor, string) (access.AdministrationTeam, error) {
	return service.team, nil
}

func (service *fakeAdministrationService) GetServiceAccount(context.Context, access.Actor, string) (access.ServiceAccount, error) {
	return service.serviceAccount, nil
}

func (service *fakeAdministrationService) CreateTeam(_ context.Context, input access.CreateAdministrationTeamInput) (access.AdministrationTeam, error) {
	return access.AdministrationTeam{ID: "40000000-0000-0000-0000-000000000002", Name: input.Name, Status: "active", CreatedAt: adminWorkflowNow}, nil
}

func (service *fakeAdministrationService) UpdateTeam(_ context.Context, input access.UpdateAdministrationTeamInput) (access.AdministrationTeam, error) {
	return access.AdministrationTeam{ID: input.TeamID, Name: input.Name, Status: "active", CreatedAt: adminWorkflowNow}, nil
}

func (service *fakeAdministrationService) ChangeRole(_ context.Context, input access.ChangeRoleInput) error {
	service.roleCalled = true
	service.roleInput = input
	return nil
}

func (service *fakeAdministrationService) AddMembership(context.Context, access.ChangeMembershipInput) error {
	service.membershipCalled = true
	return nil
}

func (service *fakeAdministrationService) RemoveMembership(context.Context, access.ChangeMembershipInput) error {
	service.membershipCalled = true
	return nil
}

type fakeOffboardingService struct {
	employeeCalled       bool
	teamCalled           bool
	teamInput            access.DisableTeamInput
	serviceAccountCalled bool
	serviceAccountInput  access.DisableServiceAccountInput
}

func (service *fakeOffboardingService) DisableEmployee(context.Context, access.DisableEmployeeInput) error {
	service.employeeCalled = true
	return nil
}

func (service *fakeOffboardingService) DisableTeam(_ context.Context, input access.DisableTeamInput) error {
	service.teamCalled = true
	service.teamInput = input
	return nil
}
func (service *fakeOffboardingService) DisableServiceAccount(_ context.Context, input access.DisableServiceAccountInput) error {
	service.serviceAccountCalled = true
	service.serviceAccountInput = input
	return nil
}

func (service *fakeAdminServiceAccountService) RevokeKey(_ context.Context, input access.RevokeServiceAccountKeyInput) error {
	service.revokeCalled = true
	if input.Actor.Role != access.RoleSystemAdministrator {
		return access.ErrForbidden
	}
	return nil
}
