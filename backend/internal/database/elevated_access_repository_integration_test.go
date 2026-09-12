//go:build integration

package database

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
)

func TestElevatedAuditGrantRepositoryBindsAndInvalidatesAcrossSessionLifecycle(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	now := fixture.now.Add(time.Minute)
	sessionID := "85000000-0000-0000-0000-000000000030"
	insertElevatedAuditSession(t, db, fixture.identityID, sessionID, now)
	repository := NewRepository(db)
	grant := elevatedAuditTestGrant("85000000-0000-0000-0000-000000000031", fixture.identityID, sessionID, now, "lifecycle test")
	if err := repository.CreateElevatedAuditGrant(context.Background(), grant, elevatedAuditIssuedEvent(grant, "86000000-0000-0000-0000-000000000031", "87000000-0000-0000-0000-000000000031")); err != nil {
		t.Fatalf("CreateElevatedAuditGrant() error = %v", err)
	}
	if _, err := repository.FindElevatedAuditGrant(context.Background(), audit.ElevatedAuditGrantLookup{ActorIdentityID: fixture.identityID, SessionID: sessionID, At: now}); err != nil {
		t.Fatalf("FindElevatedAuditGrant() before lifecycle change error = %v", err)
	}

	mustExec(t, db, `UPDATE identities SET role = 'employee' WHERE id = $1`, fixture.identityID)
	if _, err := repository.FindElevatedAuditGrant(context.Background(), audit.ElevatedAuditGrantLookup{ActorIdentityID: fixture.identityID, SessionID: sessionID, At: now}); !errors.Is(err, audit.ErrElevatedAuditGrantNotFound) {
		t.Fatalf("FindElevatedAuditGrant() after role removal error = %v, want ErrElevatedAuditGrantNotFound", err)
	}
	mustExec(t, db, `UPDATE identities SET role = 'system_administrator', status = 'active', disabled_at = NULL WHERE id = $1`, fixture.identityID)
	if err := repository.RevokePortalSession(context.Background(), access.PortalSessionRevocation{SessionID: sessionID, RevokedAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("RevokePortalSession() error = %v", err)
	}
	mustExec(t, db, `UPDATE identities SET status = 'disabled', disabled_at = $1 WHERE id = $2`, now.Add(2*time.Minute), fixture.identityID)
	mustExec(t, db, `UPDATE identities SET status = 'active', disabled_at = NULL WHERE id = $1`, fixture.identityID)
	if _, err := repository.FindElevatedAuditGrant(context.Background(), audit.ElevatedAuditGrantLookup{ActorIdentityID: fixture.identityID, SessionID: sessionID, At: now.Add(3 * time.Minute)}); !errors.Is(err, audit.ErrElevatedAuditGrantNotFound) {
		t.Fatalf("FindElevatedAuditGrant() after restored identity error = %v, want ErrElevatedAuditGrantNotFound", err)
	}
}

func TestElevatedAuditGrantRepositorySerializesConcurrentIssuanceAndSupersession(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	now := fixture.now.Add(time.Minute)
	sessionID := "85000000-0000-0000-0000-000000000040"
	insertElevatedAuditSession(t, db, fixture.identityID, sessionID, now)
	repository := NewRepository(db)
	grants := []audit.ElevatedAuditGrant{
		elevatedAuditTestGrant("85000000-0000-0000-0000-000000000041", fixture.identityID, sessionID, now, "concurrent one"),
		elevatedAuditTestGrant("85000000-0000-0000-0000-000000000042", fixture.identityID, sessionID, now, "concurrent two"),
	}
	requestIDs := []string{"87000000-0000-0000-0000-000000000041", "87000000-0000-0000-0000-000000000042"}
	errorsByCall := runConcurrent(2, func(index int) error {
		return repository.CreateElevatedAuditGrant(context.Background(), grants[index], elevatedAuditIssuedEvent(grants[index], "86000000-0000-0000-0000-00000000004"+string(rune('1'+index)), requestIDs[index]))
	})
	for _, err := range errorsByCall {
		if err != nil {
			t.Fatalf("concurrent CreateElevatedAuditGrant() error = %v", err)
		}
	}
	var activeCount, revokedCount, supersededEvents int
	if err := db.QueryRow(`SELECT count(*) FILTER (WHERE revoked_at IS NULL), count(*) FILTER (WHERE revoked_at IS NOT NULL) FROM elevated_audit_grants WHERE actor_identity_id = $1 AND session_id = $2`, fixture.identityID, sessionID).Scan(&activeCount, &revokedCount); err != nil {
		t.Fatalf("count concurrent grants: %v", err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM security_events WHERE event_type = 'audit_grant_revoked' AND detail_code = 'superseded' AND session_id = $1`, sessionID).Scan(&supersededEvents); err != nil {
		t.Fatalf("count supersession events: %v", err)
	}
	if activeCount != 1 || revokedCount != 1 || supersededEvents != 1 {
		t.Fatalf("concurrent grant state = active %d, revoked %d, superseded events %d; want 1, 1, 1", activeCount, revokedCount, supersededEvents)
	}
	active, err := repository.FindElevatedAuditGrant(context.Background(), audit.ElevatedAuditGrantLookup{ActorIdentityID: fixture.identityID, SessionID: sessionID, At: now})
	if err != nil {
		t.Fatalf("FindElevatedAuditGrant() after concurrent issuance error = %v", err)
	}
	if active.ID != grants[0].ID && active.ID != grants[1].ID {
		t.Fatalf("active grant ID = %s, want one concurrent grant", active.ID)
	}
}

func insertElevatedAuditSession(t *testing.T, db *sql.DB, identityID, sessionID string, issuedAt time.Time) {
	t.Helper()
	mustExec(t, db, `INSERT INTO sessions (id, identity_id, token_hash, csrf_token_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at, reauthenticated_until) VALUES ($1, $2, $3, $4, $5, $5, $6, $7, $8)`, sessionID, identityID, []byte("elevated-session-token-"+sessionID), []byte("elevated-session-csrf-"+sessionID), issuedAt.Add(-time.Hour), issuedAt.Add(time.Hour), issuedAt.Add(12*time.Hour), issuedAt.Add(time.Hour))
}

func elevatedAuditTestGrant(id, actorIdentityID, sessionID string, issuedAt time.Time, purpose string) audit.ElevatedAuditGrant {
	return audit.ElevatedAuditGrant{ID: id, ActorIdentityID: actorIdentityID, SessionID: sessionID, Purpose: purpose, IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(12 * time.Hour)}
}

func elevatedAuditIssuedEvent(grant audit.ElevatedAuditGrant, eventID, requestID string) access.SecurityEvent {
	return access.SecurityEvent{ID: eventID, EventType: "audit_grant_issued", ActorIdentityID: grant.ActorIdentityID, SessionID: grant.SessionID, GrantID: grant.ID, RequestID: requestID, Outcome: access.SecurityEventSuccess, Reason: grant.Purpose, DetailCode: "issued", OccurredAt: grant.IssuedAt}
}
