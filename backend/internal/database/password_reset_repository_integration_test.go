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
	completion := access.PasswordResetCompletionRecord{
		CodeID: candidate.CodeID, IdentityID: candidate.IdentityID, Email: candidate.Email,
		CodeHash: codeHash, PasswordHash: "routine-password-hash", ResetAt: accessNow,
		RevokePersonalKeysOnUse: candidate.RevokePersonalKeysOnUse,
	}
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
	if err := repository.CompletePasswordReset(context.Background(), access.PasswordResetCompletionRecord{
		CodeID: candidate.CodeID, IdentityID: candidate.IdentityID, Email: candidate.Email,
		CodeHash: codeHash, PasswordHash: "compromise-password-hash", ResetAt: accessNow,
		RevokePersonalKeysOnUse: true,
	}); err != nil {
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
			return repository.CompletePasswordReset(context.Background(), access.PasswordResetCompletionRecord{
				CodeID: candidate.CodeID, IdentityID: candidate.IdentityID, Email: candidate.Email,
				CodeHash: oldHash, PasswordHash: "serialized-password-hash", ResetAt: serializedAt,
				RevokePersonalKeysOnUse: candidate.RevokePersonalKeysOnUse,
			})
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

func passwordResetRecord(codeID string, codeHash []byte, revokeKeys bool) access.PasswordResetCodeRecord {
	return access.PasswordResetCodeRecord{
		CodeID: codeID, TargetIdentityID: accessEmployeeID, Email: "employee@example.internal",
		CodeHash: codeHash, ExpiresAt: accessNow.Add(30 * time.Minute), CreatedAt: accessNow,
		IssuedByIdentityID: accessAdminID, RevokePersonalKeysOnUse: revokeKeys,
	}
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
