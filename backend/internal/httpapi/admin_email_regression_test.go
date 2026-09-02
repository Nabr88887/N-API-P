package httpapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"n-api-p/internal/access"
)

func TestAdminAccountUpdateChangesEmailByImmutableIdentityID(t *testing.T) {
	identities := &adminIdentityServiceFake{}
	handler := withEmployeeSession(NewAdminAccountUpdateHandler(adminRoleServiceFake{}, adminOffboardingServiceFake{}, identities), access.ActivePortalSession{IdentityID: "20000000-0000-0000-0000-000000000001", Role: access.RoleSystemAdministrator})
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/users/10000000-0000-0000-0000-000000000001", bytes.NewBufferString(`{"email":"new@example.internal"}`))
	request.Header.Set("X-Request-ID", "30000000-0000-0000-0000-000000000001")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent || identities.input.IdentityID != "10000000-0000-0000-0000-000000000001" || identities.input.Email != "new@example.internal" || identities.input.RequestID != "30000000-0000-0000-0000-000000000001" || identities.input.Actor.Role != access.RoleSystemAdministrator {
		t.Fatalf("response/input = %d/%+v", recorder.Code, identities.input)
	}
}

func TestAdminAccountUpdateRejectsEmailChangeForNonActiveIdentity(t *testing.T) {
	identities := &adminIdentityServiceFake{err: access.ErrInvalidEmailChange}
	handler := withEmployeeSession(NewAdminAccountUpdateHandler(adminRoleServiceFake{}, adminOffboardingServiceFake{}, identities), access.ActivePortalSession{IdentityID: "20000000-0000-0000-0000-000000000001", Role: access.RoleSystemAdministrator})
	request := httptest.NewRequest(http.MethodPatch, "/api/v1/users/10000000-0000-0000-0000-000000000001", bytes.NewBufferString(`{"email":"new@example.internal"}`))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
}

type adminIdentityServiceFake struct {
	input access.ChangeEmailInput
	err   error
}

func (fake *adminIdentityServiceFake) ChangeEmail(_ context.Context, input access.ChangeEmailInput) error {
	fake.input = input
	return fake.err
}

type adminRoleServiceFake struct{}

func (adminRoleServiceFake) ChangeRole(context.Context, access.ChangeRoleInput) error { return nil }

type adminOffboardingServiceFake struct{}

func (adminOffboardingServiceFake) DisableEmployee(context.Context, access.DisableEmployeeInput) error {
	return nil
}
