package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
)

func TestPortalRouterKeepsTeamAndAdminRoutesOnTheirDeclaredHandlers(t *testing.T) {
	const (
		teamID  = "40000000-0000-0000-0000-000000000001"
		userID  = "10000000-0000-0000-0000-000000000001"
		auditID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	)
	session := access.ActivePortalSession{SessionID: "session-1", IdentityID: "admin-1", Role: access.RoleSystemAdministrator}
	sessions := &fakePortalSessions{session: session}
	administration := &fakeAdministrationService{}
	teamReader := &fakeTeamPortalReader{}
	serviceAccounts := &fakeAdminServiceAccountService{}
	offboarding := &fakeOffboardingService{}
	router, err := NewPortalRouter(PortalRouterDependencies{
		Sessions: sessions, AllowedOrigin: "https://gateway.example.internal",
		Authenticator: &fakePortalAuthenticator{}, Activation: &fakeActivationCompleter{},
		PasswordReset: &fakePasswordResetService{}, Identity: &fakePortalIdentityReader{},
		Reauthentication: &fakePortalReauthentication{}, EmployeeKeys: &fakeEmployeePersonalKeys{},
		OwnUsage: &fakeOwnUsageReader{}, Team: teamReader,
		Admin: AdminPortalDependencies{
			Sessions: sessions, AllowedOrigin: "https://gateway.example.internal",
			Invitations: &fakeAdminInvitationService{}, PasswordResets: &fakePasswordResetService{},
			ServiceKeys: serviceAccounts, ServiceKeyRevoke: serviceAccounts,
			Models: &fakeAdminModelPolicyService{}, Retention: &fakeAdminRetentionPolicyService{},
			Administration: administration, Audits: &fakeAuditMetadataService{record: audit.Metadata{ID: auditID}},
			RawView:    &fakeRawViewService{view: audit.RawView{AuditID: auditID}},
			Operations: &fakeOperationsService{}, Offboarding: offboarding, ServiceAccount: serviceAccounts,
		},
	})
	if err != nil {
		t.Fatalf("NewPortalRouter() error = %v", err)
	}

	tests := []struct {
		name, method, path, body string
		wantStatus               int
	}{
		{name: "admin team list", method: http.MethodGet, path: "/api/v1/teams?limit=50", wantStatus: http.StatusOK},
		{name: "team members", method: http.MethodGet, path: "/api/v1/teams/" + teamID + "/members", wantStatus: http.StatusOK},
		{name: "team usage", method: http.MethodGet, path: "/api/v1/teams/" + teamID + "/usage", wantStatus: http.StatusOK},
		{name: "admin membership removal", method: http.MethodDelete, path: "/api/v1/teams/" + teamID + "/members/" + userID, body: `{"confirmed":true}`, wantStatus: http.StatusNoContent},
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
	if administration.membershipCalled != true {
		t.Fatal("admin membership removal did not reach administration handler")
	}
	if teamReader.memberCalls != 1 {
		t.Fatalf("team members calls = %d, want 1", teamReader.memberCalls)
	}
}

type fakeActivationCompleter struct{}

func (*fakeActivationCompleter) Activate(context.Context, access.ActivateInput) error { return nil }

type fakePortalIdentityReader struct{}

func (*fakePortalIdentityReader) ReadPortalIdentity(context.Context, string) (access.PortalIdentity, error) {
	return access.PortalIdentity{ID: "admin-1", Email: "admin@example.invalid", Role: access.RoleSystemAdministrator}, nil
}
