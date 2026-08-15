//go:build integration

package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"testing"
	"time"

	"n-api-p/internal/access"
)

func TestPasswordResetRepositoryAtomicallyConsumesRoutineResetAndPreservesPersonalKey(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	insertPasswordResetFixtures(t, db, "51000000-0000-0000-0000-000000000001", "52000000-0000-0000-0000-000000000001")
	repository := NewRepository(db)
	codeHash := []byte("routine-reset-hash")
	record := passwordResetRecord("51000000-0000-0000-0000-000000000001", codeHash, false)
	if err := repository.IssuePasswordResetCode(context.Background(), record); err != nil {
		t.Fatalf("IssuePasswordResetCode() error = %v", err)
	}
	candidate, err := repository.PreparePasswordReset(context.Background(), access.PasswordResetLookup{
		Email: record.Email, CodeHash: codeHash, CheckedAt: accessNow,
	})
	if err != nil {
		t.Fatalf("PreparePasswordReset() error = %v", err)
	}
	completion := passwordResetCompletion(candidate, codeHash, "routine-password-hash", "61000000-0000-0000-0000-000000000001", accessNow)
	if err := repository.CompletePasswordReset(context.Background(), completion); err != nil {
		t.Fatalf("CompletePasswordReset() error = %v", err)
	}
	assertPasswordResetState(t, db, record, "routine-password-hash", "active")
	if err := repository.CompletePasswordReset(context.Background(), completion); !errors.Is(err, access.ErrPasswordResetRejected) {
		t.Fatalf("reused CompletePasswordReset() error = %v, want ErrPasswordResetRejected", err)
	}
}

func TestPasswordResetRepositoryCompromiseRevokesSessionsAndPersonalKeys(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	insertPasswordResetFixtures(t, db, "51000000-0000-0000-0000-000000000002", "52000000-0000-0000-0000-000000000002")
	repository := NewRepository(db)
	codeHash := []byte("compromise-reset-hash")
	record := passwordResetRecord("51000000-0000-0000-0000-000000000002", codeHash, true)
	if err := repository.IssuePasswordResetCode(context.Background(), record); err != nil {
		t.Fatalf("IssuePasswordResetCode() error = %v", err)
	}
	candidate, err := repository.PreparePasswordReset(context.Background(), access.PasswordResetLookup{Email: record.Email, CodeHash: codeHash, CheckedAt: accessNow})
	if err != nil {
		t.Fatalf("PreparePasswordReset() error = %v", err)
	}
	if err := repository.CompletePasswordReset(context.Background(), passwordResetCompletion(candidate, codeHash, "compromise-password-hash", "61000000-0000-0000-0000-000000000002", accessNow)); err != nil {
		t.Fatalf("CompletePasswordReset() error = %v", err)
	}
	assertPasswordResetState(t, db, record, "compromise-password-hash", "revoked")
}

func TestPasswordResetRepositoryRejectsUntrustedIssuerAndEmailMismatch(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	repository := NewRepository(db)
	record := passwordResetRecord("51000000-0000-0000-0000-000000000003", []byte("rejected-reset-hash"), false)
	record.IssuedByIdentityID = accessEmployeeID
	if err := repository.IssuePasswordResetCode(context.Background(), record); !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("untrusted issuer error = %v, want ErrForbidden", err)
	}
	record.IssuedByIdentityID = accessAdminID
	record.Email = "other@example.internal"
	if err := repository.IssuePasswordResetCode(context.Background(), record); !errors.Is(err, access.ErrPasswordResetRejected) {
		t.Fatalf("email mismatch error = %v, want ErrPasswordResetRejected", err)
	}
	var codeCount int
	if err := db.QueryRow(`SELECT count(*) FROM one_time_codes WHERE id = $1`, record.CodeID).Scan(&codeCount); err != nil {
		t.Fatalf("query rejected reset code: %v", err)
	}
	if codeCount != 0 {
		t.Fatalf("rejected reset code count = %d, want 0", codeCount)
	}
}

func TestPasswordResetRepositorySerializesIssuanceAndCompletionWithoutDeadlock(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	insertPasswordResetFixtures(t, db, "51000000-0000-0000-0000-000000000004", "52000000-0000-0000-0000-000000000004")
	repository := NewRepository(db)
	oldHash := []byte("old-reset-hash")
	oldRecord := passwordResetRecord("53000000-0000-0000-0000-000000000004", oldHash, false)
	if err := repository.IssuePasswordResetCode(context.Background(), oldRecord); err != nil {
		t.Fatalf("issue old password reset code: %v", err)
	}
	candidate, err := repository.PreparePasswordReset(context.Background(), access.PasswordResetLookup{
		Email: oldRecord.Email, CodeHash: oldHash, CheckedAt: accessNow,
	})
	if err != nil {
		t.Fatalf("prepare old password reset: %v", err)
	}

	serializedAt := accessNow.Add(time.Second)
	newRecord := passwordResetRecord("53000000-0000-0000-0000-000000000005", []byte("new-reset-hash"), false)
	newRecord.CreatedAt = serializedAt
	newRecord.ExpiresAt = serializedAt.Add(30 * time.Minute)
	errorsByCall := runConcurrent(2, func(index int) error {
		if index == 0 {
			return repository.CompletePasswordReset(context.Background(), passwordResetCompletion(candidate, oldHash, "serialized-password-hash", "61000000-0000-0000-0000-000000000004", serializedAt))
		}
		return repository.IssuePasswordResetCode(context.Background(), newRecord)
	})
	if errorsByCall[1] != nil {
		t.Fatalf("concurrent IssuePasswordResetCode() error = %v", errorsByCall[1])
	}
	if errorsByCall[0] != nil && !errors.Is(errorsByCall[0], access.ErrPasswordResetRejected) {
		t.Fatalf("concurrent CompletePasswordReset() error = %v, want nil or ErrPasswordResetRejected", errorsByCall[0])
	}

	var activeCodeID string
	if err := db.QueryRow(`SELECT id::text FROM one_time_codes WHERE identity_id = $1 AND purpose = 'password_reset' AND used_at IS NULL AND revoked_at IS NULL`, accessEmployeeID).Scan(&activeCodeID); err != nil {
		t.Fatalf("query active password reset code: %v", err)
	}
	if activeCodeID != newRecord.CodeID {
		t.Fatalf("active password reset code = %q, want %q", activeCodeID, newRecord.CodeID)
	}
}

func TestPasswordResetRepositoryRollsBackCompletionWhenSecurityEventFails(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	insertPasswordResetFixtures(t, db, "51000000-0000-0000-0000-000000000006", "52000000-0000-0000-0000-000000000006")
	repository := NewRepository(db)
	codeHash := []byte("rollback-reset-hash")
	record := passwordResetRecord("51000000-0000-0000-0000-000000000006", codeHash, true)
	if err := repository.IssuePasswordResetCode(context.Background(), record); err != nil {
		t.Fatalf("IssuePasswordResetCode() error = %v", err)
	}
	candidate, err := repository.PreparePasswordReset(context.Background(), access.PasswordResetLookup{Email: record.Email, CodeHash: codeHash, CheckedAt: accessNow})
	if err != nil {
		t.Fatalf("PreparePasswordReset() error = %v", err)
	}
	mustExec(t, db, `CREATE FUNCTION reject_password_reset_completion_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type = 'password_reset_completed' THEN RAISE EXCEPTION 'synthetic password reset event failure'; END IF; RETURN NEW; END $$`)
	mustExec(t, db, `CREATE TRIGGER reject_password_reset_completion_event BEFORE INSERT ON security_events FOR EACH ROW EXECUTE FUNCTION reject_password_reset_completion_event()`)

	completion := passwordResetCompletion(candidate, codeHash, "rolled-back-password-hash", "61000000-0000-0000-0000-000000000006", accessNow)
	if err := repository.CompletePasswordReset(context.Background(), completion); err == nil {
		t.Fatal("CompletePasswordReset() with rejected security event succeeded")
	}

	var passwordHash, keyStatus string
	var sessionRevoked, codeUsed bool
	if err := db.QueryRow(`SELECT password_hash FROM identities WHERE id = $1`, record.TargetIdentityID).Scan(&passwordHash); err != nil {
		t.Fatalf("query rolled-back password: %v", err)
	}
	if err := db.QueryRow(`SELECT revoked_at IS NOT NULL FROM sessions WHERE id = $1`, "51000000-0000-0000-0000-000000000006").Scan(&sessionRevoked); err != nil {
		t.Fatalf("query rolled-back session: %v", err)
	}
	if err := db.QueryRow(`SELECT used_at IS NOT NULL FROM one_time_codes WHERE id = $1`, record.CodeID).Scan(&codeUsed); err != nil {
		t.Fatalf("query rolled-back reset code: %v", err)
	}
	if err := db.QueryRow(`SELECT status FROM api_keys WHERE id = $1`, "52000000-0000-0000-0000-000000000006").Scan(&keyStatus); err != nil {
		t.Fatalf("query rolled-back personal key: %v", err)
	}
	if passwordHash != "old-password-hash" || sessionRevoked || codeUsed || keyStatus != "active" {
		t.Fatalf("completion event failure left password/session/code/key = %q/%t/%t/%q", passwordHash, sessionRevoked, codeUsed, keyStatus)
	}
}

func passwordResetRecord(codeID string, codeHash []byte, revokeKeys bool) access.PasswordResetCodeRecord {
	return access.PasswordResetCodeRecord{
		CodeID: codeID, TargetIdentityID: accessEmployeeID, Email: "employee@example.internal",
		CodeHash: codeHash, ExpiresAt: accessNow.Add(30 * time.Minute), CreatedAt: accessNow,
		IssuedByIdentityID: accessAdminID, RevokePersonalKeysOnUse: revokeKeys,
		Event: access.SecurityEvent{ID: codeID, EventType: "password_reset_issued", ActorIdentityID: accessAdminID, TargetIdentityID: accessEmployeeID, RequestID: codeID, Outcome: access.SecurityEventSuccess, DetailCode: passwordResetDetail(revokeKeys), OccurredAt: accessNow},
	}
}

func passwordResetCompletion(candidate access.PasswordResetCandidate, codeHash []byte, passwordHash, eventID string, resetAt time.Time) access.PasswordResetCompletionRecord {
	return access.PasswordResetCompletionRecord{
		CodeID: candidate.CodeID, IdentityID: candidate.IdentityID, Email: candidate.Email,
		CodeHash: codeHash, PasswordHash: passwordHash, ResetAt: resetAt,
		RevokePersonalKeysOnUse: candidate.RevokePersonalKeysOnUse,
		Event:                   access.SecurityEvent{ID: eventID, EventType: "password_reset_completed", TargetIdentityID: candidate.IdentityID, RequestID: eventID, Outcome: access.SecurityEventSuccess, DetailCode: passwordResetDetail(candidate.RevokePersonalKeysOnUse), OccurredAt: resetAt},
	}
}

func passwordResetDetail(compromise bool) string {
	if compromise {
		return "compromise_response"
	}
	return "routine_recovery"
}

func insertPasswordResetFixtures(t *testing.T, db *sql.DB, sessionID, keyID string) {
	t.Helper()
	mustExec(t, db, `UPDATE identities SET password_hash = 'old-password-hash' WHERE id = $1`, accessEmployeeID)
	tokenHash := sha256.Sum256([]byte(sessionID + "-token"))
	csrfHash := sha256.Sum256([]byte(sessionID + "-csrf"))
	mustExec(t, db, `INSERT INTO sessions (id, identity_id, token_hash, csrf_token_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES ($1, $2, $3, $4, $5, $5, $6, $7)`, sessionID, accessEmployeeID, tokenHash[:], csrfHash[:], accessNow, accessNow.Add(time.Hour), accessNow.Add(12*time.Hour))
	mustExec(t, db, `INSERT INTO api_keys (id, identity_id, kind, name, prefix, verification_hash, status, created_at) VALUES ($1, $2, 'personal', 'reset-fixture', 'nap_reset', $3, 'active', $4)`, keyID, accessEmployeeID, []byte(keyID+"-hash"), accessNow)
}

func assertPasswordResetState(t *testing.T, db queryRower, record access.PasswordResetCodeRecord, passwordHash, keyStatus string) {
	t.Helper()
	var gotPassword, gotKeyStatus string
	var sessionsRevoked, codeUsed bool
	if err := db.QueryRow(`SELECT password_hash FROM identities WHERE id = $1`, record.TargetIdentityID).Scan(&gotPassword); err != nil {
		t.Fatalf("query reset password: %v", err)
	}
	if err := db.QueryRow(`SELECT count(*) = count(*) FILTER (WHERE revoked_at IS NOT NULL) FROM sessions WHERE identity_id = $1`, record.TargetIdentityID).Scan(&sessionsRevoked); err != nil {
		t.Fatalf("query reset sessions: %v", err)
	}
	if err := db.QueryRow(`SELECT used_at IS NOT NULL FROM one_time_codes WHERE id = $1`, record.CodeID).Scan(&codeUsed); err != nil {
		t.Fatalf("query reset code: %v", err)
	}
	if err := db.QueryRow(`SELECT status FROM api_keys WHERE identity_id = $1 AND name = 'reset-fixture'`, record.TargetIdentityID).Scan(&gotKeyStatus); err != nil {
		t.Fatalf("query reset key: %v", err)
	}
	if gotPassword != passwordHash || !sessionsRevoked || !codeUsed || gotKeyStatus != keyStatus {
		t.Fatalf("reset state = password %q, sessions revoked %t, code used %t, key %q", gotPassword, sessionsRevoked, codeUsed, gotKeyStatus)
	}
}
