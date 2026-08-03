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

func TestSessionRepositoryAtomicallyValidatesCSRFAndCapsIdleTouch(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	repository := NewRepository(db)
	tokenHash := sha256.Sum256([]byte("session-token"))
	csrfHash := sha256.Sum256([]byte("csrf-token"))
	absoluteExpiry := accessNow.Add(20 * time.Minute)
	insertRepositorySession(t, db, "33000000-0000-0000-0000-000000000001", tokenHash[:], csrfHash[:], accessNow.Add(-time.Minute), accessNow.Add(10*time.Minute), absoluteExpiry)

	wrongCSRF := sha256.Sum256([]byte("wrong-csrf"))
	_, err := repository.UsePortalSession(context.Background(), access.PortalSessionUse{
		TokenHash: tokenHash[:], CSRFTokenHash: wrongCSRF[:], UsedAt: accessNow, IdleExpiresAt: accessNow.Add(30 * time.Minute),
	})
	if !errors.Is(err, access.ErrSessionInvalid) {
		t.Fatalf("UsePortalSession() wrong CSRF error = %v, want ErrSessionInvalid", err)
	}
	assertSessionTimes(t, db, "33000000-0000-0000-0000-000000000001", accessNow.Add(-time.Minute), accessNow.Add(10*time.Minute))

	session, err := repository.UsePortalSession(context.Background(), access.PortalSessionUse{
		TokenHash: tokenHash[:], CSRFTokenHash: csrfHash[:], UsedAt: accessNow, IdleExpiresAt: accessNow.Add(30 * time.Minute),
	})
	if err != nil {
		t.Fatalf("UsePortalSession() error = %v", err)
	}
	if session.IdentityID != accessEmployeeID || session.Role != access.RoleEmployee || !session.IdleExpiresAt.Equal(absoluteExpiry) {
		t.Fatalf("active session = %+v", session)
	}
	assertSessionTimes(t, db, session.SessionID, accessNow, absoluteExpiry)
}

func TestSessionRepositoryRejectsIdleAbsoluteRevokedAndDisabledSessions(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	repository := NewRepository(db)
	tests := []struct {
		name        string
		id          string
		token       string
		idleExpiry  time.Time
		absolute    time.Time
		revokedAt   *time.Time
		disableUser bool
	}{
		{name: "idle exact expiry", id: "33000000-0000-0000-0000-000000000010", token: "idle-token", idleExpiry: accessNow, absolute: accessNow.Add(time.Hour)},
		{name: "absolute exact expiry", id: "33000000-0000-0000-0000-000000000011", token: "absolute-token", idleExpiry: accessNow, absolute: accessNow},
		{name: "revoked", id: "33000000-0000-0000-0000-000000000012", token: "revoked-token", idleExpiry: accessNow.Add(time.Hour), absolute: accessNow.Add(2 * time.Hour), revokedAt: timePointerDatabase(accessNow.Add(-time.Minute))},
		{name: "disabled identity", id: "33000000-0000-0000-0000-000000000013", token: "disabled-token", idleExpiry: accessNow.Add(time.Hour), absolute: accessNow.Add(2 * time.Hour), disableUser: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.disableUser {
				mustExec(t, db, `UPDATE identities SET status = 'disabled', disabled_at = $1 WHERE id = $2`, accessNow, accessEmployeeID)
				t.Cleanup(func() {
					mustExec(t, db, `UPDATE identities SET status = 'active', disabled_at = NULL WHERE id = $1`, accessEmployeeID)
				})
			}
			tokenHash := sha256.Sum256([]byte(test.token))
			csrfHash := sha256.Sum256([]byte("csrf-token"))
			insertRepositorySession(t, db, test.id, tokenHash[:], csrfHash[:], accessNow.Add(-time.Hour), test.idleExpiry, test.absolute)
			if test.revokedAt != nil {
				mustExec(t, db, `UPDATE sessions SET revoked_at = $1 WHERE id = $2`, *test.revokedAt, test.id)
			}
			_, err := repository.UsePortalSession(context.Background(), access.PortalSessionUse{
				TokenHash: tokenHash[:], UsedAt: accessNow, IdleExpiresAt: accessNow.Add(30 * time.Minute),
			})
			if !errors.Is(err, access.ErrSessionInvalid) {
				t.Fatalf("UsePortalSession() error = %v, want ErrSessionInvalid", err)
			}
		})
	}
}

func TestSessionRepositoryConcurrentTouchesNeverRegressAndLogoutRevokes(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	repository := NewRepository(db)
	tokenHash := sha256.Sum256([]byte("session-token"))
	csrfHash := sha256.Sum256([]byte("csrf-token"))
	sessionID := "33000000-0000-0000-0000-000000000020"
	insertRepositorySession(t, db, sessionID, tokenHash[:], csrfHash[:], accessNow.Add(-time.Minute), accessNow.Add(10*time.Minute), accessNow.Add(12*time.Hour))

	times := []time.Time{accessNow.Add(time.Minute), accessNow.Add(5 * time.Minute)}
	errorsByCall := runConcurrent(2, func(index int) error {
		_, err := repository.UsePortalSession(context.Background(), access.PortalSessionUse{
			TokenHash: tokenHash[:], UsedAt: times[index], IdleExpiresAt: times[index].Add(30 * time.Minute),
		})
		return err
	})
	for _, err := range errorsByCall {
		if err != nil {
			t.Fatalf("concurrent UsePortalSession() error = %v", err)
		}
	}
	assertSessionTimes(t, db, sessionID, times[1], times[1].Add(30*time.Minute))

	if err := repository.RevokePortalSession(context.Background(), access.PortalSessionRevocation{SessionID: sessionID, RevokedAt: times[1]}); err != nil {
		t.Fatalf("RevokePortalSession() error = %v", err)
	}
	_, err := repository.UsePortalSession(context.Background(), access.PortalSessionUse{
		TokenHash: tokenHash[:], UsedAt: times[1], IdleExpiresAt: times[1].Add(30 * time.Minute),
	})
	if !errors.Is(err, access.ErrSessionInvalid) {
		t.Fatalf("UsePortalSession() after logout error = %v, want ErrSessionInvalid", err)
	}
}

func insertRepositorySession(t *testing.T, db *sql.DB, id string, tokenHash, csrfHash []byte, createdAt, idleExpiry, absoluteExpiry time.Time) {
	t.Helper()
	mustExec(t, db, `INSERT INTO sessions (id, identity_id, token_hash, csrf_token_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES ($1, $2, $3, $4, $5, $5, $6, $7)`, id, accessEmployeeID, tokenHash, csrfHash, createdAt, idleExpiry, absoluteExpiry)
}

func assertSessionTimes(t *testing.T, db *sql.DB, sessionID string, wantLastSeen, wantIdleExpiry time.Time) {
	t.Helper()
	var lastSeen, idleExpiry time.Time
	if err := db.QueryRow(`SELECT last_seen_at, idle_expires_at FROM sessions WHERE id = $1`, sessionID).Scan(&lastSeen, &idleExpiry); err != nil {
		t.Fatalf("query session times: %v", err)
	}
	if !lastSeen.Equal(wantLastSeen) || !idleExpiry.Equal(wantIdleExpiry) {
		t.Fatalf("session times = (%v, %v), want (%v, %v)", lastSeen, idleExpiry, wantLastSeen, wantIdleExpiry)
	}
}

func timePointerDatabase(value time.Time) *time.Time { return &value }
