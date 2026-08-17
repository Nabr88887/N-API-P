//go:build integration

package database

import (
	"context"
	"testing"
	"time"

	"n-api-p/internal/operations"
)

func TestRepositoryPersistsAndPagesAllowlistedOperationalFaults(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	repository := NewRepository(db)
	now := time.Date(2026, time.August, 14, 11, 0, 0, 0, time.UTC)
	transitions := []operations.FaultTransition{
		{Fault: operations.FaultRequiredKeyFailure, Active: true, OccurredAt: now.Add(-3 * time.Minute)},
		{Fault: operations.FaultDatabaseUnavailable, Active: true, OccurredAt: now.Add(-2 * time.Minute)},
		{Fault: operations.FaultDatabaseUnavailable, Active: false, OccurredAt: now.Add(-time.Minute)},
	}
	for _, transition := range transitions {
		if err := repository.AppendFaultTransition(context.Background(), transition); err != nil {
			t.Fatalf("AppendFaultTransition(%#v) error = %v", transition, err)
		}
	}

	faults, err := repository.ReadCriticalFaults(context.Background())
	if err != nil {
		t.Fatalf("ReadCriticalFaults() error = %v", err)
	}
	active := make(map[operations.FaultCode]bool, len(faults))
	for _, fault := range faults {
		active[fault.Code] = fault.Active
	}
	if !active[operations.FaultRequiredKeyFailure] || active[operations.FaultDatabaseUnavailable] {
		t.Fatalf("active faults = %#v", active)
	}

	first, err := repository.ListOperationalEvents(context.Background(), operations.EventFilter{Limit: 2})
	if err != nil {
		t.Fatalf("ListOperationalEvents() first error = %v", err)
	}
	if len(first.Events) != 2 || first.NextCursor == "" || first.Events[0].Fault != operations.FaultDatabaseUnavailable || first.Events[0].Active {
		t.Fatalf("first event page = %#v", first)
	}
	second, err := repository.ListOperationalEvents(context.Background(), operations.EventFilter{Limit: 2, Cursor: first.NextCursor})
	if err != nil {
		t.Fatalf("ListOperationalEvents() second error = %v", err)
	}
	if len(second.Events) != 1 || second.NextCursor != "" || second.Events[0].Fault != operations.FaultRequiredKeyFailure || !second.Events[0].Active {
		t.Fatalf("second event page = %#v", second)
	}
}
