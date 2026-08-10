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

func TestAuthenticationRepositorySerializesFiveFailuresAndAllowsExpiryRecovery(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	mustExec(t, db, `UPDATE identities SET password_hash = $1 WHERE id = $2`, "stored-password-hash", accessEmployeeID)
	repository := NewRepository(db)
	candidate, err := repository.FindLoginCandidate(context.Background(), access.LoginLookup{Email: "employee@example.internal", CheckedAt: accessNow})
	if err != nil {
		t.Fatalf("FindLoginCandidate() error = %v", err)
	}

	errorsByCall := runConcurrent(20, func(int) error {
		return repository.CompleteLogin(context.Background(), access.LoginCompletion{
			Candidate: candidate, AttemptedAt: accessNow, VerifiedPasswordHash: candidate.PasswordHash,
		})
	})
	successes := 0
	lockedErrors := 0
	for _, completionErr := range errorsByCall {
		if completionErr == nil {
			successes++
		} else if errors.Is(completionErr, access.ErrInvalidCredentials) {
			lockedErrors++
		} else {
			t.Fatalf("CompleteLogin() error = %v, want invalid credentials after lock", completionErr)
		}
	}
	if successes != 5 || lockedErrors != 15 {
		t.Fatalf("failure completion results = (%d successes, %d locked), want (5, 15)", successes, lockedErrors)
	}

	var failedAttempts int
	var lockedUntil time.Time
	if err := db.QueryRow(`SELECT failed_login_attempts, locked_until FROM identities WHERE id = $1`, accessEmployeeID).Scan(&failedAttempts, &lockedUntil); err != nil {
		t.Fatalf("query lock state: %v", err)
	}
	if failedAttempts != 5 || !lockedUntil.Equal(accessNow.Add(15*time.Minute)) {
		t.Fatalf("lock state = (%d, %v), want (5, %v)", failedAttempts, lockedUntil, accessNow.Add(15*time.Minute))
	}
	var lockoutEvents int
	if err := db.QueryRow(`SELECT count(*) FROM security_events WHERE event_type = 'login_lockout' AND target_identity_id = $1`, accessEmployeeID).Scan(&lockoutEvents); err != nil {
		t.Fatalf("query login lockout events: %v", err)
	}
	if lockoutEvents != 1 {
		t.Fatalf("login lockout events = %d, want exactly one", lockoutEvents)
	}

	recoveredCandidate, err := repository.FindLoginCandidate(context.Background(), access.LoginLookup{Email: "employee@example.internal", CheckedAt: lockedUntil})
	if err != nil {
		t.Fatalf("FindLoginCandidate() at expiry error = %v", err)
	}
	recovery := access.LoginCompletion{
		Candidate: recoveredCandidate, AttemptedAt: lockedUntil, VerifiedPasswordHash: recoveredCandidate.PasswordHash,
		PasswordValid: true,
		Session: access.LoginSessionRecord{
			ID: "31000000-0000-0000-0000-000000000001", IdentityID: accessEmployeeID,
			TokenHash: []byte("token-hash-1"), CSRFTokenHash: []byte("csrf-hash-1"),
			CreatedAt: lockedUntil, LastSeenAt: lockedUntil,
			IdleExpiresAt: lockedUntil.Add(30 * time.Minute), AbsoluteExpiresAt: lockedUntil.Add(12 * time.Hour),
		},
	}
	if err := repository.CompleteLogin(context.Background(), recovery); err != nil {
		t.Fatalf("CompleteLogin() at exact lock expiry error = %v", err)
	}
	var resetAttempts int
	var resetWindow, resetLock sql.NullTime
	if err := db.QueryRow(`SELECT failed_login_attempts, failed_login_window_started_at, locked_until FROM identities WHERE id = $1`, accessEmployeeID).Scan(&resetAttempts, &resetWindow, &resetLock); err != nil {
		t.Fatalf("query reset state: %v", err)
	}
	if resetAttempts != 0 || resetWindow.Valid || resetLock.Valid {
		t.Fatalf("failure state after recovery = (%d, %v, %v), want cleared", resetAttempts, resetWindow, resetLock)
	}
}

func TestAuthenticationRepositoryStoresIndependentSessionHashesAndRollsBack(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	mustExec(t, db, `UPDATE identities SET password_hash = $1 WHERE id = $2`, "stored-password-hash", accessEmployeeID)
	repository := NewRepository(db)
	service, err := access.NewAuthenticationService(repository, integrationPasswordCodec{})
	if err != nil {
		t.Fatalf("NewAuthenticationService() error = %v", err)
	}

	first, err := service.Login(context.Background(), access.LoginInput{Email: " employee@example.internal ", Password: "correct-password"})
	if err != nil {
		t.Fatalf("first Login() error = %v", err)
	}
	second, err := service.Login(context.Background(), access.LoginInput{Email: "employee@example.internal", Password: "correct-password"})
	if err != nil {
		t.Fatalf("second Login() error = %v", err)
	}
	if first.Token == second.Token || first.CSRFToken == second.CSRFToken {
		t.Fatal("successful logins reused session material")
	}
	rows, err := db.Query(`SELECT token_hash, csrf_token_hash FROM sessions WHERE identity_id = $1`, accessEmployeeID)
	if err != nil {
		t.Fatalf("query stored sessions: %v", err)
	}
	defer rows.Close()
	wantHashes := make(map[string]bool, 2)
	for _, session := range []access.PortalSession{first, second} {
		tokenHash := sha256.Sum256([]byte(session.Token))
		csrfHash := sha256.Sum256([]byte(session.CSRFToken))
		wantHashes[string(tokenHash[:])+string(csrfHash[:])] = true
	}
	storedCount := 0
	for rows.Next() {
		var tokenHash, csrfHash []byte
		if err := rows.Scan(&tokenHash, &csrfHash); err != nil {
			t.Fatalf("scan stored session: %v", err)
		}
		storedCount++
		if !wantHashes[string(tokenHash)+string(csrfHash)] {
			t.Fatal("database did not store SHA-256 session hashes")
		}
		if string(tokenHash) == first.Token || string(tokenHash) == second.Token ||
			string(csrfHash) == first.CSRFToken || string(csrfHash) == second.CSRFToken {
			t.Fatal("database stored plaintext session material")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate stored sessions: %v", err)
	}
	if storedCount != 2 {
		t.Fatalf("stored session count = %d, want 2", storedCount)
	}

	mustExec(t, db, `CREATE FUNCTION reject_auth_session() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic session failure'; END $$`)
	mustExec(t, db, `CREATE TRIGGER reject_auth_session BEFORE INSERT ON sessions FOR EACH ROW EXECUTE FUNCTION reject_auth_session()`)
	if _, err := service.Login(context.Background(), access.LoginInput{Email: "employee@example.internal", Password: "correct-password"}); !errors.Is(err, access.ErrAuthenticationUnavailable) {
		t.Fatalf("Login() with session insert failure error = %v, want ErrAuthenticationUnavailable", err)
	}
	var attempts int
	if err := db.QueryRow(`SELECT failed_login_attempts FROM identities WHERE id = $1`, accessEmployeeID).Scan(&attempts); err != nil {
		t.Fatalf("query failure state after rollback: %v", err)
	}
	if attempts != 0 {
		t.Fatalf("failure attempts after successful-password rollback = %d, want 0", attempts)
	}
	var sessionCount int
	if err := db.QueryRow(`SELECT count(*) FROM sessions WHERE identity_id = $1`, accessEmployeeID).Scan(&sessionCount); err != nil {
		t.Fatalf("query session count after rollback: %v", err)
	}
	if sessionCount != 2 {
		t.Fatalf("session count after rollback = %d, want 2", sessionCount)
	}
}

type integrationPasswordCodec struct{}

func (integrationPasswordCodec) Initialize(string) (string, error) { return "dummy-password-hash", nil }

func (integrationPasswordCodec) Verify(plaintext, encodedHash string) (bool, error) {
	return plaintext == "correct-password" && encodedHash == "stored-password-hash", nil
}
