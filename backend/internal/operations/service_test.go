package operations

import (
	"context"
	"errors"
	"testing"
	"time"

	"n-api-p/internal/access"
)

var operationsTestNow = time.Date(2026, time.August, 14, 9, 30, 0, 0, time.UTC)

func TestServiceReturnsOnlyFourAllowlistedCriticalFaults(t *testing.T) {
	repository := &operationsRepositoryFake{faults: []FaultState{
		{Code: FaultAuditUnavailable, Active: true, ChangedAt: operationsTestNow.Add(-4 * time.Minute)},
		{Code: FaultRawDeletionOverdue, Active: true, ChangedAt: operationsTestNow.Add(-3 * time.Minute)},
		{Code: FaultRequiredKeyFailure, Active: true, ChangedAt: operationsTestNow.Add(-2 * time.Minute)},
		{Code: FaultDatabaseUnavailable, Active: true, ChangedAt: operationsTestNow.Add(-time.Minute)},
		{Code: FaultCode("SELECT secret FROM credentials"), Active: true, ChangedAt: operationsTestNow},
	}}
	service, err := NewService(repository)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	service.now = func() time.Time { return operationsTestNow }

	health, err := service.Health(context.Background(), HealthInput{Session: systemAdministratorSession()})
	if err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if !health.CheckedAt.Equal(operationsTestNow) || len(health.Faults) != 4 {
		t.Fatalf("health = %#v, want four allowlisted faults", health)
	}
	for _, fault := range health.Faults {
		if !fault.Active || !ValidFaultCode(fault.Code) {
			t.Fatalf("fault = %#v, want active allowlisted fault", fault)
		}
	}
}

func TestServiceListsBoundedContentFreeEventsAndFiltersUnknownCodes(t *testing.T) {
	repository := &operationsRepositoryFake{page: EventPage{
		Events: []Event{
			{ID: "81000000-0000-0000-0000-000000000001", Fault: FaultAuditUnavailable, Active: true, OccurredAt: operationsTestNow.Add(-time.Minute)},
			{ID: "81000000-0000-0000-0000-000000000002", Fault: FaultCode("C:\\secrets\\audit.key"), Active: true, OccurredAt: operationsTestNow},
		},
		NextCursor: "opaque-next",
	}}
	service, err := NewService(repository)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}

	page, err := service.ListEvents(context.Background(), ListEventsInput{
		Session: systemAdministratorSession(),
		Filter:  EventFilter{Limit: 50, Cursor: "opaque-current"},
	})
	if err != nil {
		t.Fatalf("ListEvents() error = %v", err)
	}
	if len(page.Events) != 1 || page.Events[0].Fault != FaultAuditUnavailable || page.NextCursor != "opaque-next" {
		t.Fatalf("page = %#v, want one allowlisted event and preserved cursor", page)
	}
	if repository.filter.Limit != 50 || repository.filter.Cursor != "opaque-current" {
		t.Fatalf("repository filter = %#v", repository.filter)
	}
}

func TestServiceRejectsUnauthorizedAndInvalidOperationalRequests(t *testing.T) {
	service, err := NewService(&operationsRepositoryFake{})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	employee := access.ActivePortalSession{IdentityID: "employee-1", Role: access.RoleEmployee}
	if _, err := service.Health(context.Background(), HealthInput{Session: employee}); !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("Health() error = %v, want ErrForbidden", err)
	}
	if _, err := service.ListEvents(context.Background(), ListEventsInput{Session: systemAdministratorSession(), Filter: EventFilter{Limit: 101}}); !errors.Is(err, ErrInvalidEventFilter) {
		t.Fatalf("ListEvents() error = %v, want ErrInvalidEventFilter", err)
	}
}

func TestServiceRecordsOnlyContentFreeAllowlistedTransitions(t *testing.T) {
	repository := &operationsRepositoryFake{}
	service, err := NewService(repository)
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	if err := service.RecordFault(context.Background(), FaultRequiredKeyFailure, true, operationsTestNow); err != nil {
		t.Fatalf("RecordFault() error = %v", err)
	}
	if repository.recorded.Fault != FaultRequiredKeyFailure || !repository.recorded.Active || !repository.recorded.OccurredAt.Equal(operationsTestNow) {
		t.Fatalf("recorded transition = %#v", repository.recorded)
	}
	if err := service.RecordFault(context.Background(), FaultCode("database password=secret"), true, operationsTestNow); !errors.Is(err, ErrInvalidFault) {
		t.Fatalf("RecordFault() error = %v, want ErrInvalidFault", err)
	}
}

func systemAdministratorSession() access.ActivePortalSession {
	return access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator}
}

type operationsRepositoryFake struct {
	faults   []FaultState
	page     EventPage
	filter   EventFilter
	recorded FaultTransition
	err      error
}

func (repository *operationsRepositoryFake) ReadCriticalFaults(context.Context) ([]FaultState, error) {
	return repository.faults, repository.err
}

func (repository *operationsRepositoryFake) ListOperationalEvents(_ context.Context, filter EventFilter) (EventPage, error) {
	repository.filter = filter
	return repository.page, repository.err
}

func (repository *operationsRepositoryFake) AppendFaultTransition(_ context.Context, transition FaultTransition) error {
	repository.recorded = transition
	return repository.err
}

var _ Repository = (*operationsRepositoryFake)(nil)
