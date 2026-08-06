//go:build integration

package database

import (
	"context"
	"n-api-p/internal/audit"
	"testing"
	"time"
)

func TestRepositoryAuditGatePersistsFailureAndRecoversAfterReconciliation(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)
	completedAt := fixture.now.Add(time.Minute)

	if err := repository.MarkAuditIncompleteAndBlock(context.Background(), fixture.auditID, fixture.requestID, audit.GateReasonFinalizationPersistence, completedAt); err != nil {
		t.Fatalf("MarkAuditIncompleteAndBlock() error = %v", err)
	}
	var captureStatus, outcome, errorCode string
	if err := db.QueryRow(`SELECT capture_status, outcome, error_code FROM audit_records WHERE id = $1`, fixture.auditID).Scan(&captureStatus, &outcome, &errorCode); err != nil {
		t.Fatalf("read failed audit: %v", err)
	}
	if captureStatus != string(audit.CaptureStatusIncomplete) || outcome != string(audit.AuditOutcomeLocalError) || errorCode != audit.GateReasonFinalizationPersistence {
		t.Fatalf("failed audit state = (%q, %q, %q), want incomplete/local_error/finalization reason", captureStatus, outcome, errorCode)
	}
	blocked, err := repository.ReadAuditGate(context.Background())
	if err != nil {
		t.Fatalf("ReadAuditGate() blocked error = %v", err)
	}
	if blocked.State != audit.AuditGateStateBlocked || blocked.ReasonCode != audit.GateReasonFinalizationPersistence {
		t.Fatalf("blocked gate = (%q, %q), want blocked/finalization reason", blocked.State, blocked.ReasonCode)
	}

	staleAuditID := "84000000-0000-0000-0000-000000000020"
	staleRequestID := "87000000-0000-0000-0000-000000000020"
	insertPendingAudit(t, db, staleAuditID, staleRequestID, fixture, fixture.now)
	openedAt := fixture.now.Add(3 * time.Minute)
	if err := repository.ReconcileAndOpenAuditGate(context.Background(), fixture.now.Add(2*time.Minute), openedAt); err != nil {
		t.Fatalf("ReconcileAndOpenAuditGate() error = %v", err)
	}
	var staleStatus, staleOutcome, staleCode string
	if err := db.QueryRow(`SELECT capture_status, outcome, error_code FROM audit_records WHERE id = $1`, staleAuditID).Scan(&staleStatus, &staleOutcome, &staleCode); err != nil {
		t.Fatalf("read reconciled audit: %v", err)
	}
	if staleStatus != string(audit.CaptureStatusIncomplete) || staleOutcome != string(audit.AuditOutcomeLocalError) || staleCode != audit.GateReasonProcessRestart {
		t.Fatalf("reconciled audit state = (%q, %q, %q), want incomplete/local_error/process restart", staleStatus, staleOutcome, staleCode)
	}
	open, err := repository.ReadAuditGate(context.Background())
	if err != nil {
		t.Fatalf("ReadAuditGate() open error = %v", err)
	}
	if open.State != audit.AuditGateStateOpen || open.ReasonCode != "" || open.LastPersistenceProbeAt == nil || !open.LastPersistenceProbeAt.Equal(openedAt) {
		t.Fatalf("open gate = %+v, want open with probe timestamp", open)
	}
}

func TestRepositoryAuditGateRecoveryRollsBackWhenProbeWriteFails(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)
	staleAuditID := "84000000-0000-0000-0000-000000000021"
	staleRequestID := "87000000-0000-0000-0000-000000000021"
	insertPendingAudit(t, db, staleAuditID, staleRequestID, fixture, fixture.now)
	mustExec(t, db, `CREATE FUNCTION reject_audit_gate_open() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.audit_gate_state = 'open' THEN RAISE EXCEPTION 'synthetic probe failure'; END IF; RETURN NEW; END $$`)
	mustExec(t, db, `CREATE TRIGGER reject_audit_gate_open BEFORE UPDATE ON operational_state FOR EACH ROW EXECUTE FUNCTION reject_audit_gate_open()`)

	err := repository.ReconcileAndOpenAuditGate(context.Background(), fixture.now.Add(time.Minute), fixture.now.Add(2*time.Minute))
	if err == nil {
		t.Fatal("ReconcileAndOpenAuditGate() succeeded despite synthetic probe failure")
	}
	var status, outcome string
	if err := db.QueryRow(`SELECT capture_status, outcome FROM audit_records WHERE id = $1`, staleAuditID).Scan(&status, &outcome); err != nil {
		t.Fatalf("read rolled-back stale audit: %v", err)
	}
	if status != string(audit.CaptureStatusPending) || outcome != string(audit.AuditOutcomePending) {
		t.Fatalf("rolled-back stale audit = (%q, %q), want pending/pending", status, outcome)
	}
}
