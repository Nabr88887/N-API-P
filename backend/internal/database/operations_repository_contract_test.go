package database

import (
	"strings"
	"testing"
)

func TestOperationalQueriesUseExistingContentFreeIndexedState(t *testing.T) {
	healthQuery := strings.ToLower(readCriticalFaultsSQL)
	for _, required := range []string{"audit_gate_state", "gate_changed_at", "deletion_overdue_since", "operational_fault", "required_key_failure", "database_unavailable"} {
		if !strings.Contains(healthQuery, required) {
			t.Fatalf("health query missing %q", required)
		}
	}

	eventQuery := strings.ToLower(listOperationalEventsSQL)
	for _, required := range []string{"id::text", "detail_code", "outcome", "occurred_at", "order by occurred_at desc, id desc", "limit"} {
		if !strings.Contains(eventQuery, required) {
			t.Fatalf("event query missing %q", required)
		}
	}
	for _, forbidden := range []string{"ciphertext", "wrapped_data_key", "reason", "password", "token", "select *"} {
		if strings.Contains(eventQuery, forbidden) {
			t.Fatalf("event query exposes forbidden field %q", forbidden)
		}
	}
}

func TestOperationalTransitionInsertIsParameterizedAndContentFree(t *testing.T) {
	query := strings.ToLower(appendOperationalEventSQL)
	for _, required := range []string{"security_events", "operational_fault", "detail_code", "occurred_at", "$1", "$2", "$3"} {
		if !strings.Contains(query, required) {
			t.Fatalf("transition query missing %q", required)
		}
	}
	for _, forbidden := range []string{"reason,", "actor_identity_id", "target_audit_id", "ciphertext", "secret"} {
		if strings.Contains(query, forbidden) {
			t.Fatalf("transition query contains forbidden field %q", forbidden)
		}
	}
}

func TestOperationalTransitionTimestampParameterIsExplicitlyTyped(t *testing.T) {
	query := strings.ToLower(appendOperationalEventSQL)
	if strings.Count(query, "$3::timestamptz") != 2 {
		t.Fatalf("operational transition query must cast its timestamp parameter in both uses: %s", appendOperationalEventSQL)
	}
}
