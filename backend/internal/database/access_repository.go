package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"n-api-p/internal/access"
)

const (
	postgresUniqueViolation       = "23505"
	identityEmailUniqueConstraint = "identities_email_key"
)

const selectActiveAdministratorSQL = `
SELECT role, status
FROM identities
WHERE id = $1
FOR SHARE`

const selectActiveAdministratorReadOnlySQL = `
SELECT role, status
FROM identities
WHERE id = $1`

const selectActiveTeamSQL = `
SELECT status
FROM teams
WHERE id = $1
FOR SHARE`

const insertInvitedIdentitySQL = `
INSERT INTO identities (
    id,
    email,
    role,
    status,
    created_at,
    updated_at
) VALUES ($1, $2, $3, $4, $5, $5)`

const insertInvitationMembershipSQL = `
INSERT INTO memberships (
    identity_id,
    team_id,
    created_at
) VALUES ($1, $2, $3)`

const insertActivationCodeSQL = `
INSERT INTO one_time_codes (
    id,
    identity_id,
    email,
    purpose,
    code_hash,
    expires_at,
    created_at,
    issued_by_identity_id
) VALUES ($1, $2, $3, 'activation', $4, $5, $6, $7)`

const findLoginCandidateSQL = `
SELECT id::text, email, status, password_hash, failed_login_attempts,
       failed_login_window_started_at, locked_until
FROM identities
WHERE email = $1`

const readPortalIdentitySQL = `
SELECT id::text, email, role
FROM identities
WHERE id = $1
  AND status = 'active'`

const readPortalIdentityTeamsSQL = `
SELECT m.team_id::text
FROM memberships AS m
JOIN teams AS t ON t.id = m.team_id
WHERE m.identity_id = $1
  AND t.status = 'active'
ORDER BY m.team_id`

const lockLoginIdentitySQL = `
SELECT status, password_hash, failed_login_attempts,
       failed_login_window_started_at, locked_until
FROM identities
WHERE id = $1
FOR UPDATE`

const updateLoginFailureSQL = `
UPDATE identities
SET failed_login_attempts = $1,
    failed_login_window_started_at = $2,
    locked_until = $3,
    updated_at = $4
WHERE id = $5`

const insertLoginLockoutEventSQL = `
INSERT INTO security_events (
    id, event_type, target_identity_id, request_id, outcome, detail_code, occurred_at
) VALUES (
    gen_random_uuid(), 'login_lockout', $1, gen_random_uuid(), 'success', 'account_locked', $2
)`

const resetLoginFailureSQL = `
UPDATE identities
SET failed_login_attempts = 0,
    failed_login_window_started_at = NULL,
    locked_until = NULL,
    updated_at = $1
WHERE id = $2`

const insertLoginSessionSQL = `
INSERT INTO sessions (
    id, identity_id, token_hash, csrf_token_hash, created_at,
    last_seen_at, idle_expires_at, absolute_expires_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

const usePortalSessionSQL = `
UPDATE sessions AS s
SET last_seen_at = GREATEST(s.last_seen_at, $2),
    idle_expires_at = LEAST(
        s.absolute_expires_at,
        GREATEST(s.idle_expires_at, $3)
    )
FROM identities AS i
WHERE s.token_hash = $1
  AND ($4::bytea IS NULL OR s.csrf_token_hash = $4)
  AND s.identity_id = i.id
  AND i.status = 'active'
  AND s.revoked_at IS NULL
  AND s.idle_expires_at > $2
  AND s.absolute_expires_at > $2
RETURNING s.id::text, s.identity_id::text,
          (SELECT role FROM identities WHERE id = s.identity_id),
          s.idle_expires_at, s.absolute_expires_at,
          s.reauthenticated_until`

const findReauthenticationCandidateSQL = `
SELECT s.id::text, s.identity_id::text, i.role, i.password_hash,
       s.idle_expires_at, s.absolute_expires_at
FROM sessions AS s
JOIN identities AS i ON i.id = s.identity_id
WHERE s.id = $1
  AND i.status = 'active'
  AND s.revoked_at IS NULL
  AND s.idle_expires_at > $2
  AND s.absolute_expires_at > $2`

const lockReauthenticationSessionSQL = `
SELECT s.identity_id::text, i.status, i.role, i.password_hash,
       s.idle_expires_at, s.absolute_expires_at
FROM sessions AS s
JOIN identities AS i ON i.id = s.identity_id
WHERE s.id = $1
FOR UPDATE`

const insertReauthenticatedSessionSQL = `
INSERT INTO sessions (
    id, identity_id, token_hash, csrf_token_hash, created_at,
    last_seen_at, idle_expires_at, absolute_expires_at, reauthenticated_until
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`

const insertSecurityEventSQL = `
INSERT INTO security_events (
    id, event_type, actor_identity_id, target_identity_id, target_service_account_id, target_key_id, target_audit_id,
    request_id, outcome, reason, detail_code, occurred_at
) VALUES (
    $1, $2, NULLIF($3, '')::uuid, NULLIF($4, '')::uuid, NULLIF($5, '')::uuid, NULLIF($6, '')::uuid, NULLIF($7, '')::uuid,
    $8, $9, NULLIF($10, ''), NULLIF($11, ''), $12
)`

// Lifecycle events use detail_code for the bounded non-secret key prefix.
// Complete credentials and verification hashes never cross this boundary.
const insertCredentialLifecycleEventSQL = `
INSERT INTO security_events (
    id, event_type, actor_identity_id, target_identity_id, target_service_account_id, target_key_id,
    request_id, outcome, detail_code, occurred_at
) VALUES (
    gen_random_uuid(), $1, NULLIF($2, '')::uuid, NULLIF($3, '')::uuid,
    NULLIF($4, '')::uuid, NULLIF($5, '')::uuid, $6, $7, $8, $9
)`

const revokePortalSessionSQL = `
UPDATE sessions
SET revoked_at = $1
WHERE id = $2
  AND revoked_at IS NULL`

const selectPasswordResetTargetSQL = `
SELECT email, status, role
FROM identities
WHERE id = $1
FOR UPDATE`

const revokePasswordResetCodesSQL = `
UPDATE one_time_codes
SET revoked_at = $1
WHERE identity_id = $2
  AND purpose = 'password_reset'
  AND used_at IS NULL
  AND revoked_at IS NULL`

const insertPasswordResetCodeSQL = `
INSERT INTO one_time_codes (
    id, identity_id, email, purpose, code_hash, expires_at, created_at,
    issued_by_identity_id, revoke_personal_keys_on_use
) VALUES ($1, $2, $3, 'password_reset', $4, $5, $6, $7, $8)`

const preparePasswordResetSQL = `
SELECT c.id::text, c.identity_id::text, c.email, c.revoke_personal_keys_on_use
FROM one_time_codes AS c
JOIN identities AS i ON i.id = c.identity_id
WHERE c.email = $1
  AND c.code_hash = $2
  AND c.purpose = 'password_reset'
  AND c.used_at IS NULL
  AND c.revoked_at IS NULL
  AND c.expires_at > $3
  AND i.email = $1
  AND i.status = 'active'`

const lockPasswordResetCodeSQL = `
SELECT identity_id::text, email, revoke_personal_keys_on_use
FROM one_time_codes
WHERE id = $1
  AND identity_id = $2
  AND email = $3
  AND code_hash = $4
  AND purpose = 'password_reset'
  AND used_at IS NULL
  AND revoked_at IS NULL
  AND expires_at > $5
FOR UPDATE`

const lockPasswordResetIdentitySQL = `
SELECT id::text
FROM identities
WHERE id = $1
  AND email = $2
  AND role = 'employee'
  AND status = 'active'
FOR UPDATE`

const updatePasswordResetIdentitySQL = `
UPDATE identities
SET password_hash = $1,
    failed_login_attempts = 0,
    failed_login_window_started_at = NULL,
    locked_until = NULL,
    updated_at = $2
WHERE id = $3
  AND email = $4
  AND status = 'active'`

const revokeIdentitySessionsForPasswordResetSQL = `
UPDATE sessions
SET revoked_at = $1
WHERE identity_id = $2
  AND revoked_at IS NULL`

const revokeIdentityPersonalKeysForPasswordResetSQL = `
UPDATE api_keys
SET status = 'revoked',
    revoked_at = $1
WHERE identity_id = $2
  AND kind = 'personal'
  AND status = 'active'
  AND revoked_at IS NULL`

const consumePasswordResetCodeSQL = `
UPDATE one_time_codes
SET used_at = $1
WHERE id = $2
  AND used_at IS NULL
  AND revoked_at IS NULL`

const revokeSiblingPasswordResetCodesSQL = `
UPDATE one_time_codes
SET revoked_at = $1
WHERE identity_id = $2
  AND id <> $3
  AND purpose = 'password_reset'
  AND used_at IS NULL
  AND revoked_at IS NULL`

func (r *Repository) FindLoginCandidate(ctx context.Context, lookup access.LoginLookup) (access.LoginCandidate, error) {
	var (
		candidate       access.LoginCandidate
		passwordHash    sql.NullString
		windowStartedAt sql.NullTime
		lockedUntil     sql.NullTime
	)
	err := r.db.QueryRowContext(ctx, findLoginCandidateSQL, lookup.Email).Scan(
		&candidate.IdentityID, &candidate.Email, &candidate.Status, &passwordHash,
		&candidate.FailedAttempts, &windowStartedAt, &lockedUntil,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return access.LoginCandidate{}, nil
	}
	if err != nil {
		return access.LoginCandidate{}, fmt.Errorf("query login candidate: %w", err)
	}
	candidate.Found = true
	candidate.PasswordHash = passwordHash.String
	if windowStartedAt.Valid {
		value := windowStartedAt.Time
		candidate.FailureWindowStartedAt = &value
	}
	if lockedUntil.Valid {
		value := lockedUntil.Time
		candidate.LockedUntil = &value
	}
	return candidate, nil
}

func (r *Repository) ReadPortalIdentity(ctx context.Context, identityID string) (access.PortalIdentity, error) {
	var identity access.PortalIdentity
	if strings.TrimSpace(identityID) == "" {
		return access.PortalIdentity{}, access.ErrIdentityNotFound
	}
	if err := r.db.QueryRowContext(ctx, readPortalIdentitySQL, identityID).Scan(&identity.ID, &identity.Email, &identity.Role); errors.Is(err, sql.ErrNoRows) {
		return access.PortalIdentity{}, access.ErrIdentityNotFound
	} else if err != nil {
		return access.PortalIdentity{}, fmt.Errorf("read portal identity: %w", err)
	}
	rows, err := r.db.QueryContext(ctx, readPortalIdentityTeamsSQL, identity.ID)
	if err != nil {
		return access.PortalIdentity{}, fmt.Errorf("read portal identity teams: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var teamID string
		if err := rows.Scan(&teamID); err != nil {
			return access.PortalIdentity{}, fmt.Errorf("scan portal identity team: %w", err)
		}
		identity.TeamIDs = append(identity.TeamIDs, teamID)
	}
	if err := rows.Err(); err != nil {
		return access.PortalIdentity{}, fmt.Errorf("read portal identity teams: %w", err)
	}
	return identity, nil
}

func (r *Repository) CompleteLogin(ctx context.Context, completion access.LoginCompletion) error {
	return r.withTransaction(ctx, "complete login", func(tx *sql.Tx) error {
		var (
			status          string
			passwordHash    sql.NullString
			failedAttempts  int
			windowStartedAt sql.NullTime
			lockedUntil     sql.NullTime
		)
		err := tx.QueryRowContext(ctx, lockLoginIdentitySQL, completion.Candidate.IdentityID).Scan(
			&status, &passwordHash, &failedAttempts, &windowStartedAt, &lockedUntil,
		)
		if errors.Is(err, sql.ErrNoRows) {
			return access.ErrInvalidCredentials
		}
		if err != nil {
			return fmt.Errorf("lock login identity: %w", err)
		}
		if status != string(access.IdentityStatusActive) || passwordHash.String != completion.VerifiedPasswordHash {
			return access.ErrInvalidCredentials
		}
		if lockedUntil.Valid && lockedUntil.Time.After(completion.AttemptedAt) {
			return access.ErrInvalidCredentials
		}

		if !completion.PasswordValid {
			var started *time.Time
			if windowStartedAt.Valid {
				value := windowStartedAt.Time
				started = &value
			}
			attempts, nextStarted, nextLocked := access.AdvanceLoginFailure(failedAttempts, started, completion.AttemptedAt)
			if _, err := tx.ExecContext(ctx, updateLoginFailureSQL, attempts, nextStarted, nextLocked, completion.AttemptedAt, completion.Candidate.IdentityID); err != nil {
				return fmt.Errorf("record login failure: %w", err)
			}
			if nextLocked != nil {
				if _, err := tx.ExecContext(ctx, insertLoginLockoutEventSQL, completion.Candidate.IdentityID, completion.AttemptedAt); err != nil {
					return fmt.Errorf("append login lockout security event: %w", err)
				}
			}
			return nil
		}

		if _, err := tx.ExecContext(ctx, resetLoginFailureSQL, completion.AttemptedAt, completion.Candidate.IdentityID); err != nil {
			return fmt.Errorf("reset login failures: %w", err)
		}
		if _, err := tx.ExecContext(ctx, insertLoginSessionSQL,
			completion.Session.ID, completion.Candidate.IdentityID,
			completion.Session.TokenHash, completion.Session.CSRFTokenHash,
			completion.Session.CreatedAt, completion.Session.LastSeenAt,
			completion.Session.IdleExpiresAt, completion.Session.AbsoluteExpiresAt,
		); err != nil {
			return fmt.Errorf("insert login session: %w", err)
		}
		return nil
	})
}

func (r *Repository) UsePortalSession(ctx context.Context, use access.PortalSessionUse) (access.ActivePortalSession, error) {
	var csrfHash any
	if use.CSRFTokenHash != nil {
		csrfHash = use.CSRFTokenHash
	}
	var session access.ActivePortalSession
	var reauthenticatedUntil sql.NullTime
	err := r.db.QueryRowContext(
		ctx,
		usePortalSessionSQL,
		use.TokenHash,
		use.UsedAt,
		use.IdleExpiresAt,
		csrfHash,
	).Scan(
		&session.SessionID,
		&session.IdentityID,
		&session.Role,
		&session.IdleExpiresAt,
		&session.AbsoluteExpiresAt,
		&reauthenticatedUntil,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return access.ActivePortalSession{}, access.ErrSessionInvalid
	}
	if err != nil {
		return access.ActivePortalSession{}, fmt.Errorf("use portal session: %w", err)
	}
	if reauthenticatedUntil.Valid {
		value := reauthenticatedUntil.Time
		session.ReauthenticatedUntil = &value
	}
	return session, nil
}

func (r *Repository) FindReauthenticationCandidate(ctx context.Context, lookup access.ReauthenticationLookup) (access.ReauthenticationCandidate, error) {
	var (
		candidate    access.ReauthenticationCandidate
		passwordHash sql.NullString
	)
	err := r.db.QueryRowContext(ctx, findReauthenticationCandidateSQL, lookup.SessionID, lookup.CheckedAt).Scan(
		&candidate.SessionID, &candidate.IdentityID, &candidate.Role, &passwordHash,
		&candidate.IdleExpiresAt, &candidate.AbsoluteExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return access.ReauthenticationCandidate{}, access.ErrReauthenticationRejected
	}
	if err != nil {
		return access.ReauthenticationCandidate{}, fmt.Errorf("find reauthentication candidate: %w", err)
	}
	candidate.PasswordHash = passwordHash.String
	return candidate, nil
}

func (r *Repository) RotatePortalSession(ctx context.Context, rotation access.PortalSessionRotation) error {
	return r.withTransaction(ctx, "rotate portal session for reauthentication", func(tx *sql.Tx) error {
		var (
			identityID        string
			status            string
			role              access.Role
			passwordHash      sql.NullString
			idleExpiresAt     time.Time
			absoluteExpiresAt time.Time
		)
		err := tx.QueryRowContext(ctx, lockReauthenticationSessionSQL, rotation.ExistingSessionID).Scan(
			&identityID, &status, &role, &passwordHash, &idleExpiresAt, &absoluteExpiresAt,
		)
		if errors.Is(err, sql.ErrNoRows) {
			return access.ErrReauthenticationRejected
		}
		if err != nil {
			return fmt.Errorf("lock reauthentication session: %w", err)
		}
		if identityID != rotation.IdentityID || status != string(access.IdentityStatusActive) ||
			passwordHash.String != rotation.ExpectedPasswordHash ||
			!idleExpiresAt.After(rotation.RotatedAt) || !absoluteExpiresAt.After(rotation.RotatedAt) {
			return access.ErrReauthenticationRejected
		}

		result, err := tx.ExecContext(ctx, revokePortalSessionSQL, rotation.RotatedAt, rotation.ExistingSessionID)
		if err != nil {
			return fmt.Errorf("revoke previous portal session: %w", err)
		}
		if affected, err := result.RowsAffected(); err != nil {
			return fmt.Errorf("count revoked previous portal session: %w", err)
		} else if affected != 1 {
			return access.ErrReauthenticationRejected
		}
		if _, err := tx.ExecContext(ctx, insertReauthenticatedSessionSQL,
			rotation.NewSession.ID, rotation.NewSession.IdentityID,
			rotation.NewSession.TokenHash, rotation.NewSession.CSRFTokenHash,
			rotation.NewSession.CreatedAt, rotation.NewSession.LastSeenAt,
			rotation.NewSession.IdleExpiresAt, rotation.NewSession.AbsoluteExpiresAt,
			rotation.ReauthenticatedUntil,
		); err != nil {
			return fmt.Errorf("insert reauthenticated session: %w", err)
		}
		return nil
	})
}

func (r *Repository) AppendSecurityEvent(ctx context.Context, event access.SecurityEvent) error {
	_, err := r.db.ExecContext(ctx, insertSecurityEventSQL,
		event.ID, event.EventType, event.ActorIdentityID, event.TargetIdentityID,
		event.TargetServiceAccountID, event.TargetKeyID, event.TargetAuditID,
		event.RequestID, event.Outcome, event.Reason, event.DetailCode, event.OccurredAt,
	)
	if err != nil {
		return fmt.Errorf("append security event: %w", err)
	}
	return nil
}

func appendCredentialLifecycleEvent(ctx context.Context, tx *sql.Tx, event access.CredentialLifecycleEvent) error {
	if err := event.Validate(); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, insertCredentialLifecycleEventSQL,
		event.Action, event.ActorIdentityID, event.TargetIdentityID, event.TargetServiceAccountID,
		event.TargetKeyID, event.RequestID, event.Outcome, event.KeyPrefix, event.OccurredAt,
	); err != nil {
		return fmt.Errorf("append credential lifecycle event: %w", err)
	}
	return nil
}

func (r *Repository) RevokePortalSession(ctx context.Context, revocation access.PortalSessionRevocation) error {
	result, err := r.db.ExecContext(ctx, revokePortalSessionSQL, revocation.RevokedAt, revocation.SessionID)
	if err != nil {
		return fmt.Errorf("revoke portal session: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count revoked portal sessions: %w", err)
	}
	if affected != 1 {
		return access.ErrSessionInvalid
	}
	return nil
}

func (r *Repository) IssuePasswordResetCode(ctx context.Context, record access.PasswordResetCodeRecord) error {
	return r.withTransaction(ctx, "issue password reset code", func(tx *sql.Tx) error {
		if err := requireActiveSystemAdministrator(ctx, tx, record.IssuedByIdentityID); err != nil {
			return err
		}

		var email, status, role string
		err := tx.QueryRowContext(ctx, selectPasswordResetTargetSQL, record.TargetIdentityID).Scan(&email, &status, &role)
		if errors.Is(err, sql.ErrNoRows) {
			return access.ErrPasswordResetRejected
		}
		if err != nil {
			return fmt.Errorf("query password reset target: %w", err)
		}
		if status != string(access.IdentityStatusActive) || role != string(access.RoleEmployee) || email != record.Email {
			return access.ErrPasswordResetRejected
		}

		if _, err := tx.ExecContext(ctx, revokePasswordResetCodesSQL, record.CreatedAt, record.TargetIdentityID); err != nil {
			return fmt.Errorf("revoke previous password reset codes: %w", err)
		}
		if _, err := tx.ExecContext(ctx, insertPasswordResetCodeSQL,
			record.CodeID, record.TargetIdentityID, record.Email, record.CodeHash,
			record.ExpiresAt, record.CreatedAt, record.IssuedByIdentityID,
			record.RevokePersonalKeysOnUse,
		); err != nil {
			return fmt.Errorf("insert password reset code: %w", err)
		}
		if err := appendSecurityEventTx(ctx, tx, record.Event); err != nil {
			return err
		}
		return nil
	})
}

func (r *Repository) PreparePasswordReset(ctx context.Context, lookup access.PasswordResetLookup) (access.PasswordResetCandidate, error) {
	var candidate access.PasswordResetCandidate
	err := r.db.QueryRowContext(ctx, preparePasswordResetSQL, lookup.Email, lookup.CodeHash, lookup.CheckedAt).Scan(
		&candidate.CodeID, &candidate.IdentityID, &candidate.Email, &candidate.RevokePersonalKeysOnUse,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return access.PasswordResetCandidate{}, access.ErrPasswordResetRejected
	}
	if err != nil {
		return access.PasswordResetCandidate{}, fmt.Errorf("query password reset candidate: %w", err)
	}
	return candidate, nil
}

func (r *Repository) CompletePasswordReset(ctx context.Context, record access.PasswordResetCompletionRecord) error {
	return r.withTransaction(ctx, "complete password reset", func(tx *sql.Tx) error {
		var lockedIdentityID string
		err := tx.QueryRowContext(ctx, lockPasswordResetIdentitySQL, record.IdentityID, record.Email).Scan(&lockedIdentityID)
		if errors.Is(err, sql.ErrNoRows) {
			return access.ErrPasswordResetRejected
		}
		if err != nil {
			return fmt.Errorf("lock password reset identity: %w", err)
		}

		var (
			identityID string
			email      string
			revokeKeys bool
		)
		err = tx.QueryRowContext(ctx, lockPasswordResetCodeSQL,
			record.CodeID, lockedIdentityID, record.Email, record.CodeHash, record.ResetAt,
		).Scan(&identityID, &email, &revokeKeys)
		if errors.Is(err, sql.ErrNoRows) {
			return access.ErrPasswordResetRejected
		}
		if err != nil {
			return fmt.Errorf("lock password reset code: %w", err)
		}
		if identityID != record.IdentityID || email != record.Email || record.RevokePersonalKeysOnUse != revokeKeys {
			return access.ErrPasswordResetRejected
		}

		result, err := tx.ExecContext(ctx, updatePasswordResetIdentitySQL,
			record.PasswordHash, record.ResetAt, record.IdentityID, record.Email,
		)
		if err != nil {
			return fmt.Errorf("update reset password: %w", err)
		}
		if affected, err := result.RowsAffected(); err != nil {
			return fmt.Errorf("count reset password update: %w", err)
		} else if affected != 1 {
			return access.ErrPasswordResetRejected
		}

		if _, err := tx.ExecContext(ctx, revokeIdentitySessionsForPasswordResetSQL, record.ResetAt, record.IdentityID); err != nil {
			return fmt.Errorf("revoke portal sessions for password reset: %w", err)
		}
		if record.RevokePersonalKeysOnUse {
			if _, err := tx.ExecContext(ctx, revokeIdentityPersonalKeysForPasswordResetSQL, record.ResetAt, record.IdentityID); err != nil {
				return fmt.Errorf("revoke personal keys for password reset: %w", err)
			}
		}
		result, err = tx.ExecContext(ctx, consumePasswordResetCodeSQL, record.ResetAt, record.CodeID)
		if err != nil {
			return fmt.Errorf("consume password reset code: %w", err)
		}
		if affected, err := result.RowsAffected(); err != nil {
			return fmt.Errorf("count consumed password reset code: %w", err)
		} else if affected != 1 {
			return access.ErrPasswordResetRejected
		}
		if _, err := tx.ExecContext(ctx, revokeSiblingPasswordResetCodesSQL, record.ResetAt, record.IdentityID, record.CodeID); err != nil {
			return fmt.Errorf("revoke sibling password reset codes: %w", err)
		}
		return appendSecurityEventTx(ctx, tx, record.Event)
	})
}

func (r *Repository) CreateInvitation(ctx context.Context, record access.InvitationRecord) error {
	return r.withTransaction(ctx, "create invitation", func(tx *sql.Tx) error {
		if err := requireActiveSystemAdministrator(ctx, tx, record.IssuedByIdentityID); err != nil {
			return err
		}
		if err := requireActiveTeam(ctx, tx, record.TeamID); err != nil {
			return err
		}

		if _, err := tx.ExecContext(
			ctx,
			insertInvitedIdentitySQL,
			record.IdentityID,
			record.Email,
			record.Role,
			record.Status,
			record.CreatedAt,
		); err != nil {
			if isIdentityEmailConflict(err) {
				return access.ErrEmailAlreadyExists
			}
			return fmt.Errorf("insert invited identity: %w", err)
		}

		if _, err := tx.ExecContext(
			ctx,
			insertInvitationMembershipSQL,
			record.IdentityID,
			record.TeamID,
			record.CreatedAt,
		); err != nil {
			return fmt.Errorf("insert invitation membership: %w", err)
		}

		if _, err := tx.ExecContext(
			ctx,
			insertActivationCodeSQL,
			record.ActivationID,
			record.IdentityID,
			record.Email,
			record.ActivationHash,
			record.ExpiresAt,
			record.CreatedAt,
			record.IssuedByIdentityID,
		); err != nil {
			return fmt.Errorf("insert activation code: %w", err)
		}
		if err := appendSecurityEventTx(ctx, tx, record.Event); err != nil {
			return err
		}
		return nil
	})
}

const prepareActivationSQL = `
SELECT
    c.id::text,
    c.identity_id::text
FROM one_time_codes AS c
JOIN identities AS i ON i.id = c.identity_id
WHERE c.email = $1
  AND c.code_hash = $2
  AND c.purpose = 'activation'
  AND c.used_at IS NULL
  AND c.revoked_at IS NULL
  AND c.expires_at > $3
  AND i.email = $1
  AND i.status = 'pending'
  AND i.password_hash IS NULL`

func (r *Repository) PrepareActivation(ctx context.Context, lookup access.ActivationLookup) (access.ActivationCandidate, error) {
	var candidate access.ActivationCandidate
	err := r.db.QueryRowContext(
		ctx,
		prepareActivationSQL,
		lookup.Email,
		lookup.ActivationHash,
		lookup.CheckedAt,
	).Scan(&candidate.CodeID, &candidate.IdentityID)
	if errors.Is(err, sql.ErrNoRows) {
		return access.ActivationCandidate{}, access.ErrActivationRejected
	}
	if err != nil {
		return access.ActivationCandidate{}, fmt.Errorf("query activation candidate: %w", err)
	}
	return candidate, nil
}

const lockActivationIdentitySQL = `
SELECT
    id::text
FROM identities
WHERE id = $1
  AND email = $2
  AND status = 'pending'
  AND password_hash IS NULL
FOR UPDATE`

const lockActivationCodeSQL = `
SELECT
    id::text
FROM one_time_codes
WHERE id = $1
  AND identity_id = $2
  AND email = $3
  AND code_hash = $4
  AND purpose = 'activation'
  AND used_at IS NULL
  AND revoked_at IS NULL
  AND expires_at > $5
FOR UPDATE`

const activateIdentitySQL = `
UPDATE identities
SET password_hash = $1,
    status = 'active',
    updated_at = $2
WHERE id = $3
  AND status = 'pending'`

const consumeActivationCodeSQL = `
UPDATE one_time_codes
SET used_at = $1
WHERE id = $2
  AND used_at IS NULL
  AND revoked_at IS NULL`

const revokeSiblingActivationCodesSQL = `
UPDATE one_time_codes
SET revoked_at = $1
WHERE identity_id = $2
  AND id <> $3
  AND purpose = 'activation'
  AND used_at IS NULL
  AND revoked_at IS NULL`

func (r *Repository) ActivateIdentity(ctx context.Context, record access.ActivationRecord) error {
	return r.withTransaction(ctx, "activate identity", func(tx *sql.Tx) error {
		var identityID string
		err := tx.QueryRowContext(
			ctx,
			lockActivationIdentitySQL,
			record.Candidate.IdentityID,
			record.Email,
		).Scan(&identityID)
		if errors.Is(err, sql.ErrNoRows) {
			return access.ErrActivationRejected
		}
		if err != nil {
			return fmt.Errorf("lock activation identity: %w", err)
		}

		var codeID string
		err = tx.QueryRowContext(
			ctx,
			lockActivationCodeSQL,
			record.Candidate.CodeID,
			identityID,
			record.Email,
			record.ActivationHash,
			record.ActivatedAt,
		).Scan(&codeID)
		if errors.Is(err, sql.ErrNoRows) {
			return access.ErrActivationRejected
		}
		if err != nil {
			return fmt.Errorf("lock activation code: %w", err)
		}

		result, err := tx.ExecContext(ctx, activateIdentitySQL, record.PasswordHash, record.ActivatedAt, identityID)
		if err != nil {
			return fmt.Errorf("activate pending identity: %w", err)
		}
		if affected, err := result.RowsAffected(); err != nil {
			return fmt.Errorf("count activated identities: %w", err)
		} else if affected != 1 {
			return access.ErrActivationRejected
		}

		result, err = tx.ExecContext(ctx, consumeActivationCodeSQL, record.ActivatedAt, codeID)
		if err != nil {
			return fmt.Errorf("consume activation code: %w", err)
		}
		if affected, err := result.RowsAffected(); err != nil {
			return fmt.Errorf("count consumed activation codes: %w", err)
		} else if affected != 1 {
			return access.ErrActivationRejected
		}

		if _, err := tx.ExecContext(
			ctx,
			revokeSiblingActivationCodesSQL,
			record.ActivatedAt,
			identityID,
			codeID,
		); err != nil {
			return fmt.Errorf("revoke sibling activation codes: %w", err)
		}
		return appendSecurityEventTx(ctx, tx, record.Event)
	})
}

const updateIdentityEmailSQL = `
UPDATE identities
SET email = $1,
    updated_at = $2
WHERE id = $3
  AND status = 'active'`

const lockIdentityForEmailChangeSQL = `
SELECT status
FROM identities
WHERE id = $1
FOR UPDATE`

const revokeIdentityActivationCodesSQL = `
UPDATE one_time_codes
SET revoked_at = $1
WHERE identity_id = $2
  AND purpose = 'activation'
  AND used_at IS NULL
  AND revoked_at IS NULL`

func (r *Repository) ChangeIdentityEmail(ctx context.Context, record access.EmailChangeRecord) error {
	return r.withTransaction(ctx, "change identity email", func(tx *sql.Tx) error {
		if err := requireActiveSystemAdministrator(ctx, tx, record.ChangedByIdentityID); err != nil {
			return err
		}

		var status string
		err := tx.QueryRowContext(ctx, lockIdentityForEmailChangeSQL, record.IdentityID).Scan(&status)
		if errors.Is(err, sql.ErrNoRows) {
			return access.ErrIdentityNotFound
		}
		if err != nil {
			return fmt.Errorf("lock identity for email change: %w", err)
		}
		if status != string(access.IdentityStatusActive) {
			return access.ErrInvalidEmailChange
		}

		result, err := tx.ExecContext(ctx, updateIdentityEmailSQL, record.Email, record.ChangedAt, record.IdentityID)
		if err != nil {
			if isIdentityEmailConflict(err) {
				return access.ErrEmailAlreadyExists
			}
			return fmt.Errorf("update identity email: %w", err)
		}
		if affected, err := result.RowsAffected(); err != nil {
			return fmt.Errorf("count updated identities: %w", err)
		} else if affected != 1 {
			return access.ErrIdentityNotFound
		}

		if _, err := tx.ExecContext(
			ctx,
			revokeIdentityActivationCodesSQL,
			record.ChangedAt,
			record.IdentityID,
		); err != nil {
			return fmt.Errorf("revoke identity activation codes: %w", err)
		}
		return appendSecurityEventTx(ctx, tx, record.Event)
	})
}

type transactionQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func requireActiveSystemAdministrator(ctx context.Context, queryer transactionQueryer, identityID string) error {
	return requireActiveSystemAdministratorWithQuery(ctx, queryer, identityID, selectActiveAdministratorSQL)
}

func requireActiveSystemAdministratorReadOnly(ctx context.Context, queryer transactionQueryer, identityID string) error {
	return requireActiveSystemAdministratorWithQuery(ctx, queryer, identityID, selectActiveAdministratorReadOnlySQL)
}

func requireActiveSystemAdministratorWithQuery(ctx context.Context, queryer transactionQueryer, identityID, query string) error {
	var role string
	var status string
	err := queryer.QueryRowContext(ctx, query, identityID).Scan(&role, &status)
	if errors.Is(err, sql.ErrNoRows) {
		return access.ErrForbidden
	}
	if err != nil {
		return fmt.Errorf("query issuing administrator: %w", err)
	}
	if role != string(access.RoleSystemAdministrator) || status != string(access.IdentityStatusActive) {
		return access.ErrForbidden
	}
	return nil
}

func requireActiveTeam(ctx context.Context, queryer transactionQueryer, teamID string) error {
	var status string
	err := queryer.QueryRowContext(ctx, selectActiveTeamSQL, teamID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return access.ErrInvalidInvitation
	}
	if err != nil {
		return fmt.Errorf("query invitation team: %w", err)
	}
	if status != "active" {
		return access.ErrInvalidInvitation
	}
	return nil
}

func (r *Repository) withTransaction(ctx context.Context, operation string, run func(*sql.Tx) error) (err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin %s transaction: %w", operation, err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("roll back %s transaction: %w", operation, rollbackErr))
		}
	}()

	if err := run(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit %s transaction: %w", operation, err)
	}
	committed = true
	return nil
}

func isIdentityEmailConflict(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) &&
		postgresError.Code == postgresUniqueViolation &&
		postgresError.ConstraintName == identityEmailUniqueConstraint
}
