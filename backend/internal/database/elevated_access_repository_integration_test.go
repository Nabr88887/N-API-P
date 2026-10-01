//go:build integration

package database

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

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

func TestElevatedAuditGrantRepositoryRejectsDisabledIdentityAndCompromisedSession(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	now := fixture.now.Add(time.Minute)
	repository := NewRepository(db)

	disabledSessionID := "85000000-0000-0000-0000-000000000052"
	insertElevatedAuditSession(t, db, fixture.identityID, disabledSessionID, now)
	disabledGrant := elevatedAuditTestGrant("85000000-0000-0000-0000-000000000053", fixture.identityID, disabledSessionID, now, "disabled identity")
	if err := repository.CreateElevatedAuditGrant(context.Background(), disabledGrant, elevatedAuditIssuedEvent(disabledGrant, "86000000-0000-0000-0000-000000000053", "87000000-0000-0000-0000-000000000053")); err != nil {
		t.Fatalf("CreateElevatedAuditGrant() disabled identity fixture error = %v", err)
	}
	mustExec(t, db, `UPDATE identities SET status = 'disabled', disabled_at = $1 WHERE id = $2`, now, fixture.identityID)
	if _, err := repository.FindElevatedAuditGrant(context.Background(), audit.ElevatedAuditGrantLookup{ActorIdentityID: fixture.identityID, SessionID: disabledSessionID, At: now}); !errors.Is(err, audit.ErrElevatedAuditGrantNotFound) {
		t.Fatalf("FindElevatedAuditGrant() for disabled identity error = %v, want ErrElevatedAuditGrantNotFound", err)
	}
	mustExec(t, db, `UPDATE identities SET status = 'active', disabled_at = NULL WHERE id = $1`, fixture.identityID)

	compromisedSessionID := "85000000-0000-0000-0000-000000000054"
	insertElevatedAuditSession(t, db, fixture.identityID, compromisedSessionID, now)
	compromisedGrant := elevatedAuditTestGrant("85000000-0000-0000-0000-000000000055", fixture.identityID, compromisedSessionID, now, "compromise response")
	if err := repository.CreateElevatedAuditGrant(context.Background(), compromisedGrant, elevatedAuditIssuedEvent(compromisedGrant, "86000000-0000-0000-0000-000000000055", "87000000-0000-0000-0000-000000000055")); err != nil {
		t.Fatalf("CreateElevatedAuditGrant() compromised session fixture error = %v", err)
	}
	mustExec(t, db, `UPDATE sessions SET revoked_at = $1, reauthenticated_until = NULL WHERE id = $2`, now.Add(time.Minute), compromisedSessionID)
	if _, err := repository.FindElevatedAuditGrant(context.Background(), audit.ElevatedAuditGrantLookup{ActorIdentityID: fixture.identityID, SessionID: compromisedSessionID, At: now.Add(time.Minute)}); !errors.Is(err, audit.ErrElevatedAuditGrantNotFound) {
		t.Fatalf("FindElevatedAuditGrant() for compromised session error = %v, want ErrElevatedAuditGrantNotFound", err)
	}
}

func TestElevatedAuditGrantRepositoryInvalidatesOnLogoutAndRestoreSessionRevocation(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	now := fixture.now.Add(time.Minute)
	repository := NewRepository(db)

	logoutSessionID := "85000000-0000-0000-0000-000000000047"
	insertElevatedAuditSession(t, db, fixture.identityID, logoutSessionID, now)
	logoutGrant := elevatedAuditTestGrant("85000000-0000-0000-0000-000000000047", fixture.identityID, logoutSessionID, now, "logout invalidation")
	if err := repository.CreateElevatedAuditGrant(context.Background(), logoutGrant, elevatedAuditIssuedEvent(logoutGrant, "86000000-0000-0000-0000-000000000047", "87000000-0000-0000-0000-000000000047")); err != nil {
		t.Fatalf("CreateElevatedAuditGrant() logout fixture error = %v", err)
	}
	if err := repository.RevokePortalSession(context.Background(), access.PortalSessionRevocation{SessionID: logoutSessionID, RevokedAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("RevokePortalSession() error = %v", err)
	}
	if _, err := repository.FindElevatedAuditGrant(context.Background(), audit.ElevatedAuditGrantLookup{ActorIdentityID: fixture.identityID, SessionID: logoutSessionID, At: now.Add(time.Minute)}); !errors.Is(err, audit.ErrElevatedAuditGrantNotFound) {
		t.Fatalf("FindElevatedAuditGrant() after logout error = %v, want ErrElevatedAuditGrantNotFound", err)
	}

	restoreSessionID := "85000000-0000-0000-0000-000000000048"
	insertElevatedAuditSession(t, db, fixture.identityID, restoreSessionID, now)
	restoreGrant := elevatedAuditTestGrant("85000000-0000-0000-0000-000000000048", fixture.identityID, restoreSessionID, now, "restore invalidation")
	if err := repository.CreateElevatedAuditGrant(context.Background(), restoreGrant, elevatedAuditIssuedEvent(restoreGrant, "86000000-0000-0000-0000-000000000048", "87000000-0000-0000-0000-000000000048")); err != nil {
		t.Fatalf("CreateElevatedAuditGrant() restore fixture error = %v", err)
	}
	mustExec(t, db, `UPDATE sessions SET revoked_at = $1, reauthenticated_until = NULL WHERE id = $2`, now.Add(2*time.Minute), restoreSessionID)
	if _, err := repository.FindElevatedAuditGrant(context.Background(), audit.ElevatedAuditGrantLookup{ActorIdentityID: fixture.identityID, SessionID: restoreSessionID, At: now.Add(2 * time.Minute)}); !errors.Is(err, audit.ErrElevatedAuditGrantNotFound) {
		t.Fatalf("FindElevatedAuditGrant() after restore session invalidation error = %v, want ErrElevatedAuditGrantNotFound", err)
	}
}

func TestElevatedAuditGrantIsRevokedByRoleChangeAndDoesNotResurrect(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	now := fixture.now.Add(time.Minute)
	sessionID := "85000000-0000-0000-0000-000000000050"
	insertElevatedAuditSession(t, db, fixture.identityID, sessionID, now)
	repository := NewRepository(db)
	grant := elevatedAuditTestGrant("85000000-0000-0000-0000-000000000051", fixture.identityID, sessionID, now, "role transition")
	if err := repository.CreateElevatedAuditGrant(context.Background(), grant, elevatedAuditIssuedEvent(grant, "86000000-0000-0000-0000-000000000051", "87000000-0000-0000-0000-000000000051")); err != nil {
		t.Fatalf("CreateElevatedAuditGrant() error = %v", err)
	}
	if err := repository.ChangeIdentityRole(context.Background(), access.RoleChange{
		EventID: "86000000-0000-0000-0000-000000000052", IdentityID: fixture.identityID, Role: access.RoleEmployee,
		ActorIdentityID: fixture.identityID, RequestID: "87000000-0000-0000-0000-000000000052", ChangedAt: now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("ChangeIdentityRole() error = %v", err)
	}
	if _, err := repository.FindElevatedAuditGrant(context.Background(), audit.ElevatedAuditGrantLookup{ActorIdentityID: fixture.identityID, SessionID: sessionID, At: now.Add(time.Minute)}); !errors.Is(err, audit.ErrElevatedAuditGrantRevoked) {
		t.Fatalf("FindElevatedAuditGrant() after role removal error = %v, want ErrElevatedAuditGrantRevoked", err)
	}
	mustExec(t, db, `UPDATE identities SET role = 'system_administrator', status = 'active', disabled_at = NULL WHERE id = $1`, fixture.identityID)
	if _, err := repository.FindElevatedAuditGrant(context.Background(), audit.ElevatedAuditGrantLookup{ActorIdentityID: fixture.identityID, SessionID: sessionID, At: now.Add(2 * time.Minute)}); !errors.Is(err, audit.ErrElevatedAuditGrantRevoked) {
		t.Fatalf("FindElevatedAuditGrant() after role restore error = %v, want ErrElevatedAuditGrantRevoked", err)
	}
	var revokedEvents int
	if err := db.QueryRow(`SELECT count(*) FROM security_events WHERE event_type = 'audit_grant_revoked' AND grant_id = $1 AND detail_code = 'identity_role_changed'`, grant.ID).Scan(&revokedEvents); err != nil {
		t.Fatalf("count role-change grant events: %v", err)
	}
	if revokedEvents != 1 {
		t.Fatalf("role-change grant revocation events = %d, want 1", revokedEvents)
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
	eventIDs := []string{"86000000-0000-0000-0000-000000000041", "86000000-0000-0000-0000-000000000042"}
	errorsByCall := runConcurrent(2, func(index int) error {
		return repository.CreateElevatedAuditGrant(context.Background(), grants[index], elevatedAuditIssuedEvent(grants[index], eventIDs[index], requestIDs[index]))
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
	revokedAt := now.Add(2 * time.Minute)
	if err := repository.RevokeElevatedAuditGrant(context.Background(), active.ID, fixture.identityID, sessionID, revokedAt, access.SecurityEvent{
		ID: "86000000-0000-0000-0000-000000000043", EventType: "audit_grant_revoked", ActorIdentityID: fixture.identityID,
		SessionID: sessionID, GrantID: active.ID, RequestID: "87000000-0000-0000-0000-000000000043",
		Outcome: access.SecurityEventSuccess, OccurredAt: revokedAt,
	}); err != nil {
		t.Fatalf("RevokeElevatedAuditGrant() after concurrent issuance error = %v", err)
	}
	if _, err := repository.FindElevatedAuditGrant(context.Background(), audit.ElevatedAuditGrantLookup{ActorIdentityID: fixture.identityID, SessionID: sessionID, At: revokedAt}); !errors.Is(err, audit.ErrElevatedAuditGrantRevoked) {
		t.Fatalf("FindElevatedAuditGrant() after revoking concurrent winner error = %v, want ErrElevatedAuditGrantRevoked", err)
	}
	if err := db.QueryRow(`SELECT count(*) FILTER (WHERE revoked_at IS NULL), count(*) FILTER (WHERE revoked_at IS NOT NULL) FROM elevated_audit_grants WHERE actor_identity_id = $1 AND session_id = $2`, fixture.identityID, sessionID).Scan(&activeCount, &revokedCount); err != nil {
		t.Fatalf("count grants after revoking concurrent winner: %v", err)
	}
	if activeCount != 0 || revokedCount != 2 {
		t.Fatalf("grant state after revoking concurrent winner = active %d, revoked %d; want 0, 2", activeCount, revokedCount)
	}
}

func TestElevatedAuditGrantRepositoryRollsBackGrantAndSupersessionWhenEventWriteFails(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	now := fixture.now.Add(time.Minute)
	sessionID := "85000000-0000-0000-0000-000000000044"
	insertElevatedAuditSession(t, db, fixture.identityID, sessionID, now)
	conflictingEventID := "86000000-0000-0000-0000-000000000044"
	conflictingRequestID := "87000000-0000-0000-0000-000000000044"
	repository := NewRepository(db)
	previous := elevatedAuditTestGrant("85000000-0000-0000-0000-000000000044", fixture.identityID, sessionID, now, "existing authority")
	if err := repository.CreateElevatedAuditGrant(context.Background(), previous, elevatedAuditIssuedEvent(previous, conflictingEventID, conflictingRequestID)); err != nil {
		t.Fatalf("create existing grant: %v", err)
	}
	grant := elevatedAuditTestGrant("85000000-0000-0000-0000-000000000045", fixture.identityID, sessionID, now.Add(time.Minute), "event atomicity")
	grant.ExpiresAt = previous.ExpiresAt
	event := elevatedAuditIssuedEvent(grant, conflictingEventID, "87000000-0000-0000-0000-000000000045")
	err := repository.CreateElevatedAuditGrant(context.Background(), grant, event)
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != "23505" || postgresError.ConstraintName != "security_events_pkey" {
		t.Fatalf("issuance error = %v, want security event primary-key conflict", err)
	}
	var grantCount, activeCount, revokedCount, failedEvents int
	if err := db.QueryRow(`SELECT count(*) FROM elevated_audit_grants WHERE id = $1`, grant.ID).Scan(&grantCount); err != nil {
		t.Fatalf("count failed grant insert: %v", err)
	}
	if err := db.QueryRow(`SELECT count(*) FILTER (WHERE revoked_at IS NULL), count(*) FILTER (WHERE revoked_at IS NOT NULL) FROM elevated_audit_grants WHERE actor_identity_id = $1 AND session_id = $2`, fixture.identityID, sessionID).Scan(&activeCount, &revokedCount); err != nil {
		t.Fatalf("count failed grant transaction state: %v", err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM security_events WHERE request_id = $1`, event.RequestID).Scan(&failedEvents); err != nil {
		t.Fatalf("count rolled-back issuance and supersession events: %v", err)
	}
	if grantCount != 0 || activeCount != 1 || revokedCount != 0 || failedEvents != 0 {
		t.Fatalf("failed transaction = new %d, active %d, revoked %d, failed events %d; want 0, 1, 0, 0", grantCount, activeCount, revokedCount, failedEvents)
	}
	active, err := repository.FindElevatedAuditGrant(context.Background(), audit.ElevatedAuditGrantLookup{ActorIdentityID: fixture.identityID, SessionID: sessionID, At: grant.IssuedAt})
	if err != nil || active.ID != previous.ID || active.Purpose != previous.Purpose || !active.ExpiresAt.Equal(previous.ExpiresAt) {
		t.Fatalf("previous authority changed after rollback: grant=%+v error=%v", active, err)
	}
	var originalEventUnchanged bool
	if err := db.QueryRow(`SELECT event_type = 'audit_grant_issued' AND grant_id = $2 AND request_id = $3 AND reason = $4 AND detail_code = 'issued' AND occurred_at = $5 FROM security_events WHERE id = $1`, conflictingEventID, previous.ID, conflictingRequestID, previous.Purpose, now).Scan(&originalEventUnchanged); err != nil || !originalEventUnchanged {
		t.Fatalf("original event unchanged = %v, error = %v", originalEventUnchanged, err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("database connection after failed grant transaction: %v", err)
	}
}

func TestElevatedAuditGrantRepositoryCancellationDuringLockWaitReleasesConnection(t *testing.T) {
	db, schemaName := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	now := fixture.now.Add(time.Minute)
	sessionID := "85000000-0000-0000-0000-000000000046"
	insertElevatedAuditSession(t, db, fixture.identityID, sessionID, now)
	bulkDB := openTestDatabase(t, databaseURLWithSearchPath(t, testDatabaseURL(t), schemaName))
	bulkDB.SetMaxOpenConns(1)
	bulkDB.SetMaxIdleConns(1)
	repository := NewRepository(bulkDB)
	grant := elevatedAuditTestGrant("85000000-0000-0000-0000-000000000046", fixture.identityID, sessionID, now, "cancellation")
	fixtureContext, stopFixture := context.WithTimeout(context.Background(), 15*time.Second)
	defer stopFixture()
	blocker, err := db.BeginTx(fixtureContext, nil)
	if err != nil {
		t.Fatalf("begin session-lock fixture: %v", err)
	}
	defer func() {
		if err := blocker.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			t.Errorf("release session-lock fixture: %v", err)
		}
	}()
	var lockedSessionID string
	if err := blocker.QueryRowContext(fixtureContext, `SELECT id::text FROM sessions WHERE id = $1 FOR UPDATE`, sessionID).Scan(&lockedSessionID); err != nil || lockedSessionID != sessionID {
		t.Fatalf("lock target session: id=%s error=%v", lockedSessionID, err)
	}
	var backendPID int
	if err := bulkDB.QueryRowContext(fixtureContext, `SELECT pg_backend_pid()`).Scan(&backendPID); err != nil {
		t.Fatalf("identify single-connection backend: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		result <- repository.CreateElevatedAuditGrant(ctx, grant, elevatedAuditIssuedEvent(grant, "86000000-0000-0000-0000-000000000046", "87000000-0000-0000-0000-000000000046"))
	}()
	defer func() {
		cancel()
		select {
		case <-finished:
		case <-time.After(5 * time.Second):
			t.Error("grant issuance goroutine did not stop")
		}
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	waitContext, stopWaiting := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopWaiting()
	for {
		var waiting bool
		if err := db.QueryRowContext(waitContext, `SELECT cardinality(pg_blocking_pids($1)) > 0`, backendPID).Scan(&waiting); err != nil {
			t.Fatalf("observe actual PostgreSQL lock wait: %v", err)
		}
		if waiting {
			break
		}
		select {
		case err := <-result:
			t.Fatalf("issuance returned before observed lock wait: %v", err)
		case <-waitContext.Done():
			t.Fatal("issuance never reached PostgreSQL lock wait")
		case <-ticker.C:
		}
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("issuance after in-flight cancellation = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight cancellation did not return")
	}
	checkContext, stopChecking := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopChecking()
	var grantCount, eventCount int
	if err := bulkDB.QueryRowContext(checkContext, `SELECT count(*) FROM elevated_audit_grants WHERE id = $1`, grant.ID).Scan(&grantCount); err != nil {
		t.Fatalf("count canceled grant insert: %v", err)
	}
	if err := bulkDB.QueryRowContext(checkContext, `SELECT count(*) FROM security_events WHERE grant_id = $1`, grant.ID).Scan(&eventCount); err != nil {
		t.Fatalf("count canceled grant events: %v", err)
	}
	if grantCount != 0 || eventCount != 0 || bulkDB.Stats().InUse != 0 {
		t.Fatalf("canceled grant rows/events/connections = %d/%d/%d, want 0/0/0", grantCount, eventCount, bulkDB.Stats().InUse)
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
