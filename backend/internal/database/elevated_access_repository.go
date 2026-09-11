package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
)

const insertElevatedAuditGrantSQL = `
INSERT INTO elevated_audit_grants (
    id, actor_identity_id, session_id, purpose, issued_at, expires_at
) VALUES ($1, $2, $3, $4, $5, $6)`

const verifyElevatedAuditGrantSessionSQL = `
SELECT sessions.identity_id::text, sessions.absolute_expires_at
FROM sessions
JOIN identities ON identities.id = sessions.identity_id
WHERE sessions.id = $1
  AND sessions.identity_id = $2
  AND identities.status = 'active'
  AND identities.role = 'system_administrator'
  AND sessions.revoked_at IS NULL
  AND sessions.idle_expires_at > $3
  AND sessions.absolute_expires_at > $3
  AND sessions.reauthenticated_until > $3
FOR UPDATE`

const supersedeElevatedAuditGrantsSQL = `
WITH superseded AS (
    UPDATE elevated_audit_grants
    SET revoked_at = $3
    WHERE actor_identity_id = $1 AND session_id = $2 AND revoked_at IS NULL
    RETURNING id, purpose
)
INSERT INTO security_events (
    id, event_type, actor_identity_id, session_id, grant_id,
    request_id, outcome, reason, detail_code, occurred_at
)
SELECT gen_random_uuid(), 'audit_grant_revoked', $1, $2, id,
       $4, 'success', purpose, 'superseded', $3
FROM superseded`

const findElevatedAuditGrantSQL = `
SELECT grants.id::text, grants.actor_identity_id::text, grants.session_id::text,
       grants.purpose, grants.issued_at, grants.expires_at, grants.revoked_at
FROM elevated_audit_grants AS grants
JOIN sessions ON sessions.id = grants.session_id
JOIN identities ON identities.id = grants.actor_identity_id
WHERE grants.actor_identity_id = $1
  AND grants.session_id = $2
  AND grants.revoked_at IS NULL
  AND grants.expires_at > $3
  AND sessions.revoked_at IS NULL
  AND sessions.identity_id = grants.actor_identity_id
  AND sessions.idle_expires_at > $3
  AND sessions.absolute_expires_at > $3
  AND identities.status = 'active'
  AND identities.role = 'system_administrator'
ORDER BY grants.issued_at DESC, grants.id DESC
LIMIT 1`

const findElevatedAuditGrantStateSQL = `
SELECT grants.revoked_at, grants.expires_at
FROM elevated_audit_grants AS grants
WHERE grants.actor_identity_id = $1
  AND grants.session_id = $2
ORDER BY grants.issued_at DESC, grants.id DESC
LIMIT 1`

const revokeElevatedAuditGrantSQL = `
UPDATE elevated_audit_grants
SET revoked_at = $4
WHERE id = $1
  AND actor_identity_id = $2
  AND session_id = $3
  AND revoked_at IS NULL`

func (r *Repository) CreateElevatedAuditGrant(ctx context.Context, grant audit.ElevatedAuditGrant, event access.SecurityEvent) (err error) {
	if r == nil || r.db == nil || !validElevatedAuditGrant(grant) || !validElevatedAuditGrantEvent(event, grant) {
		return audit.ErrInvalidElevatedAuditAccess
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin elevated audit grant transaction: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("roll back elevated audit grant transaction: %w", rollbackErr))
		}
	}()

	var sessionIdentity string
	var sessionAbsoluteExpiresAt time.Time
	err = tx.QueryRowContext(ctx, verifyElevatedAuditGrantSessionSQL, grant.SessionID, grant.ActorIdentityID, grant.IssuedAt.UTC()).Scan(&sessionIdentity, &sessionAbsoluteExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return audit.ErrElevatedAuditForbidden
	}
	if err != nil {
		return fmt.Errorf("verify elevated audit grant session: %w", err)
	}
	if sessionIdentity != grant.ActorIdentityID || grant.ExpiresAt.After(sessionAbsoluteExpiresAt) {
		return audit.ErrElevatedAuditForbidden
	}
	if _, err := tx.ExecContext(ctx, supersedeElevatedAuditGrantsSQL, grant.ActorIdentityID, grant.SessionID, grant.IssuedAt.UTC(), event.RequestID); err != nil {
		return fmt.Errorf("supersede elevated audit grants: %w", err)
	}
	if _, err := tx.ExecContext(ctx, insertElevatedAuditGrantSQL, grant.ID, grant.ActorIdentityID, grant.SessionID, grant.Purpose, grant.IssuedAt.UTC(), grant.ExpiresAt.UTC()); err != nil {
		return fmt.Errorf("insert elevated audit grant: %w", err)
	}
	if err := appendSecurityEventTx(ctx, tx, event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit elevated audit grant transaction: %w", err)
	}
	committed = true
	return nil
}

func (r *Repository) FindElevatedAuditGrant(ctx context.Context, lookup audit.ElevatedAuditGrantLookup) (audit.ElevatedAuditGrant, error) {
	if r == nil || r.db == nil || !validUUID(lookup.ActorIdentityID) || !validUUID(lookup.SessionID) || lookup.At.IsZero() {
		return audit.ElevatedAuditGrant{}, audit.ErrInvalidElevatedAuditAccess
	}
	var grant audit.ElevatedAuditGrant
	err := r.db.QueryRowContext(ctx, findElevatedAuditGrantSQL, lookup.ActorIdentityID, lookup.SessionID, lookup.At.UTC()).Scan(
		&grant.ID, &grant.ActorIdentityID, &grant.SessionID, &grant.Purpose, &grant.IssuedAt, &grant.ExpiresAt, &grant.RevokedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		var revokedAt sql.NullTime
		var expiresAt time.Time
		stateErr := r.db.QueryRowContext(ctx, findElevatedAuditGrantStateSQL, lookup.ActorIdentityID, lookup.SessionID).Scan(&revokedAt, &expiresAt)
		if stateErr != nil && !errors.Is(stateErr, sql.ErrNoRows) {
			return audit.ElevatedAuditGrant{}, fmt.Errorf("read elevated grant state: %w", stateErr)
		}
		if stateErr == nil {
			if revokedAt.Valid {
				return audit.ElevatedAuditGrant{}, audit.ErrElevatedAuditGrantRevoked
			}
			if !expiresAt.After(lookup.At.UTC()) {
				return audit.ElevatedAuditGrant{}, audit.ErrElevatedAuditGrantExpired
			}
		}
		return audit.ElevatedAuditGrant{}, audit.ErrElevatedAuditGrantNotFound
	}
	if err != nil {
		return audit.ElevatedAuditGrant{}, fmt.Errorf("find elevated audit grant: %w", err)
	}
	return grant, nil
}

func (r *Repository) RevokeElevatedAuditGrant(ctx context.Context, grantID, actorIdentityID, sessionID string, revokedAt time.Time, event access.SecurityEvent) (err error) {
	if r == nil || r.db == nil || !validUUID(grantID) || !validUUID(actorIdentityID) || !validUUID(sessionID) || revokedAt.IsZero() || !validElevatedAuditRevokeEvent(event, grantID, actorIdentityID, sessionID) {
		return audit.ErrInvalidElevatedAuditAccess
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin elevated audit grant revocation transaction: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("roll back elevated audit grant revocation transaction: %w", rollbackErr))
		}
	}()

	result, err := tx.ExecContext(ctx, revokeElevatedAuditGrantSQL, grantID, actorIdentityID, sessionID, revokedAt.UTC())
	if err != nil {
		return fmt.Errorf("revoke elevated audit grant: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count revoked elevated audit grants: %w", err)
	}
	if affected != 1 {
		return audit.ErrElevatedAuditGrantNotFound
	}
	if err := appendSecurityEventTx(ctx, tx, event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit elevated audit grant revocation transaction: %w", err)
	}
	committed = true
	return nil
}

func validElevatedAuditGrant(grant audit.ElevatedAuditGrant) bool {
	return validUUID(grant.ID) && validUUID(grant.ActorIdentityID) && validUUID(grant.SessionID) &&
		strings.TrimSpace(grant.Purpose) == grant.Purpose && len([]rune(grant.Purpose)) > 0 && len([]rune(grant.Purpose)) <= 500 &&
		!grant.IssuedAt.IsZero() && grant.ExpiresAt.After(grant.IssuedAt) && grant.ExpiresAt.Sub(grant.IssuedAt) <= 24*time.Hour && grant.RevokedAt == nil
}

func validElevatedAuditGrantEvent(event access.SecurityEvent, grant audit.ElevatedAuditGrant) bool {
	return validUUID(event.ID) && event.EventType == "audit_grant_issued" && event.ActorIdentityID == grant.ActorIdentityID &&
		event.SessionID == grant.SessionID && event.GrantID == grant.ID && validUUID(event.RequestID) &&
		event.Outcome == access.SecurityEventSuccess && event.Reason == grant.Purpose && !event.OccurredAt.IsZero()
}

func validElevatedAuditRevokeEvent(event access.SecurityEvent, grantID, actorIdentityID, sessionID string) bool {
	return validUUID(event.ID) && event.EventType == "audit_grant_revoked" && event.ActorIdentityID == actorIdentityID &&
		event.SessionID == sessionID && event.GrantID == grantID && validUUID(event.RequestID) &&
		event.Outcome == access.SecurityEventSuccess && !event.OccurredAt.IsZero()
}
