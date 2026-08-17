package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/operations"
)

func TestOperationsHealthHandlerReturnsOnlyAllowlistedCriticalComponents(t *testing.T) {
	now := time.Date(2026, time.August, 14, 10, 0, 0, 0, time.UTC)
	service := &fakeOperationsService{health: operations.Health{
		CheckedAt: now,
		Faults: []operations.FaultState{
			{Code: operations.FaultAuditUnavailable, Active: true, ChangedAt: now.Add(-time.Minute)},
			{Code: operations.FaultCode("SELECT password FROM identities"), Active: true, ChangedAt: now},
		},
	}}
	handler := withEmployeeSession(NewAdminOperationsHealthHandler(service), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/operations/health", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var response HealthResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.State != HealthStateUnhealthy || len(response.Components) != 1 || response.Components[0].Name != string(operations.FaultAuditUnavailable) {
		t.Fatalf("response = %#v", response)
	}
	if strings.Contains(recorder.Body.String(), "password") || strings.Contains(recorder.Body.String(), "SELECT") {
		t.Fatalf("response exposed untrusted detail: %s", recorder.Body.String())
	}
}

func TestOperationsHealthHandlerReturnsSafeDatabaseFaultWhenReadFails(t *testing.T) {
	service := &fakeOperationsService{err: errors.New("dial tcp /private/socket: password=secret")}
	handler := withEmployeeSession(NewAdminOperationsHealthHandler(service), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/operations/health", nil))

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"name":"database_unavailable"`) {
		t.Fatalf("status/body = %d / %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "password") || strings.Contains(recorder.Body.String(), "/private/socket") {
		t.Fatalf("response exposed internal error: %s", recorder.Body.String())
	}
}

func TestOperationalEventsHandlerReturnsBoundedContentFreePage(t *testing.T) {
	now := time.Date(2026, time.August, 14, 10, 0, 0, 0, time.UTC)
	service := &fakeOperationsService{page: operations.EventPage{
		Events: []operations.Event{
			{ID: "81000000-0000-0000-0000-000000000001", Fault: operations.FaultRawDeletionOverdue, Active: true, OccurredAt: now},
			{ID: "81000000-0000-0000-0000-000000000002", Fault: operations.FaultCode("C:\\secrets\\key"), Active: true, OccurredAt: now},
		},
		NextCursor: "opaque-next",
	}}
	handler := withEmployeeSession(NewAdminOperationalEventsHandler(service), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/operations/events?limit=25&cursor=opaque", nil))

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"event_type":"raw_deletion_overdue"`) || !strings.Contains(recorder.Body.String(), `"next_cursor":"opaque-next"`) {
		t.Fatalf("status/body = %d / %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "secrets") || service.input.Filter.Limit != 25 || service.input.Filter.Cursor != "opaque" {
		t.Fatalf("response/input = %s / %#v", recorder.Body.String(), service.input)
	}
}

func TestOperationsHandlersRejectLowerPrivilegeSessions(t *testing.T) {
	service := &fakeOperationsService{}
	for name, handler := range map[string]http.Handler{
		"health": NewAdminOperationsHealthHandler(service),
		"events": NewAdminOperationalEventsHandler(service),
	} {
		t.Run(name, func(t *testing.T) {
			wrapped := withEmployeeSession(handler, access.ActivePortalSession{IdentityID: "team-admin", Role: access.RoleTeamAdministrator})
			recorder := httptest.NewRecorder()
			wrapped.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/operations/"+name, nil))
			assertHTTPError(t, recorder, http.StatusForbidden, CodeForbidden)
		})
	}
}

func TestOperationalEventsHandlerRejectsInvalidFiltersBeforeServiceUse(t *testing.T) {
	tests := []string{
		"/api/v1/operations/events?limit=101",
		"/api/v1/operations/events?severity=stack_trace",
		"/api/v1/operations/events?from=not-a-time",
		"/api/v1/operations/events?from=2026-08-14T10%3A00%3A00Z&to=2026-08-14T09%3A00%3A00Z",
	}
	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			service := &fakeOperationsService{}
			handler := withEmployeeSession(NewAdminOperationalEventsHandler(service), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator})
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
			assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
			if service.listCalled {
				t.Fatal("operations service called for invalid filter")
			}
		})
	}
}

type fakeOperationsService struct {
	health     operations.Health
	page       operations.EventPage
	input      operations.ListEventsInput
	err        error
	listCalled bool
}

func (service *fakeOperationsService) Health(context.Context, operations.HealthInput) (operations.Health, error) {
	return service.health, service.err
}

func (service *fakeOperationsService) ListEvents(_ context.Context, input operations.ListEventsInput) (operations.EventPage, error) {
	service.listCalled = true
	service.input = input
	return service.page, service.err
}

var _ AdminOperationsService = (*fakeOperationsService)(nil)
