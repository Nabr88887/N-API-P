package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"n-api-p/internal/access"
)

const lockActiveEmployeeForDisableSQL = `
SELECT id::text
FROM identities
WHERE id = $1
  AND role = 'employee'
  AND status = 'active'
FOR UPDATE`

const disableEmployeeSQL = `
UPDATE identities
SET status = 'disabled',
    updated_at = $1,
    disabled_at = $1
WHERE id = $2
  AND role = 'employee'
  AND status = 'active'`

const revokeEmployeeSessionsSQL = `
UPDATE sessions
SET revoked_at = $1
WHERE identity_id = $2
  AND revoked_at IS NULL`

const revokeEmployeePersonalKeysSQL = `
WITH revoked AS (
    UPDATE api_keys
    SET status = 'revoked',
        revoked_at = $1
    WHERE identity_id = $2
      AND kind = 'personal'
      AND status = 'active'
    RETURNING id::text, identity_id::text, prefix
)
INSERT INTO security_events (
    id, event_type, actor_identity_id, target_identity_id, target_key_id,
    request_id, outcome, detail_code, occurred_at
)
SELECT gen_random_uuid(), 'personal_key_offboarding_revoked', NULLIF($3, '')::uuid,
       identity_id::uuid, id::uuid, $4, 'success', prefix, $1
FROM revoked`

const revokeResponsibleServiceAccountKeysSQL = `
WITH revoked AS (
    UPDATE api_keys AS k
    SET status = 'revoked',
        revoked_at = $1
    FROM service_accounts AS sa
    WHERE k.service_account_id = sa.id
      AND sa.responsible_identity_id = $2
      AND k.kind = 'service'
      AND k.status = 'active'
    RETURNING k.id::text, k.service_account_id::text, k.prefix
)
INSERT INTO security_events (
    id, event_type, actor_identity_id, target_service_account_id, target_key_id,
    request_id, outcome, detail_code, occurred_at
)
SELECT gen_random_uuid(), 'service_key_offboarding_revoked', NULLIF($3, '')::uuid,
       service_account_id::uuid, id::uuid, $4, 'success', prefix, $1
FROM revoked`

const lockActiveTeamForDisableSQL = `
SELECT id::text
FROM teams
WHERE id = $1
  AND status = 'active'
FOR UPDATE`

const disableTeamSQL = `
UPDATE teams
SET status = 'disabled',
    updated_at = $1,
    disabled_at = $1
WHERE id = $2
  AND status = 'active'`

const revokeTeamServiceAccountKeysSQL = `
WITH revoked AS (
    UPDATE api_keys AS k
    SET status = 'revoked',
        revoked_at = $1
    FROM service_accounts AS sa
    WHERE k.service_account_id = sa.id
      AND sa.team_id = $2
      AND k.kind = 'service'
      AND k.status = 'active'
    RETURNING k.id::text, k.service_account_id::text, k.prefix
)
INSERT INTO security_events (
    id, event_type, actor_identity_id, target_service_account_id, target_key_id,
    request_id, outcome, detail_code, occurred_at
)
SELECT gen_random_uuid(), 'service_key_offboarding_revoked', NULLIF($3, '')::uuid,
       service_account_id::uuid, id::uuid, $4, 'success', prefix, $1
FROM revoked`

const lockActiveServiceAccountForDisableSQL = `
SELECT id::text
FROM service_accounts
WHERE id = $1
  AND status = 'active'
FOR UPDATE`

const disableServiceAccountSQL = `
UPDATE service_accounts
SET status = 'disabled',
    updated_at = $1,
    disabled_at = $1
WHERE id = $2
  AND status = 'active'`

const revokeDisabledServiceAccountKeysSQL = `
WITH revoked AS (
    UPDATE api_keys
    SET status = 'revoked',
        revoked_at = $1
    WHERE service_account_id = $2
      AND kind = 'service'
      AND status = 'active'
    RETURNING id::text, service_account_id::text, prefix
)
INSERT INTO security_events (
    id, event_type, actor_identity_id, target_service_account_id, target_key_id,
    request_id, outcome, detail_code, occurred_at
)
SELECT gen_random_uuid(), 'service_key_offboarding_revoked', NULLIF($3, '')::uuid,
       service_account_id::uuid, id::uuid, $4, 'success', prefix, $1
FROM revoked`

func (r *Repository) DisableEmployee(ctx context.Context, record access.EmployeeDisablement) error {
	return r.withTransaction(ctx, "disable employee", func(tx *sql.Tx) error {
		if err := requireActiveSystemAdministrator(ctx, tx, record.ActorIdentityID); err != nil {
			return err
		}
		if err := lockActiveOffboardingTarget(ctx, tx, lockActiveEmployeeForDisableSQL, record.IdentityID, "employee"); err != nil {
			return err
		}
		if err := updateOffboardingTarget(ctx, tx, disableEmployeeSQL, record.DisabledAt, record.IdentityID, "employee"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, revokeEmployeeSessionsSQL, record.DisabledAt, record.IdentityID); err != nil {
			return fmt.Errorf("revoke employee sessions: %w", err)
		}
		if _, err := tx.ExecContext(ctx, revokeEmployeePersonalKeysSQL, record.DisabledAt, record.IdentityID, record.ActorIdentityID, record.RequestID); err != nil {
			return fmt.Errorf("revoke employee personal keys: %w", err)
		}
		if _, err := tx.ExecContext(ctx, revokeResponsibleServiceAccountKeysSQL, record.DisabledAt, record.IdentityID, record.ActorIdentityID, record.RequestID); err != nil {
			return fmt.Errorf("revoke responsible employee service account keys: %w", err)
		}
		return nil
	})
}

func (r *Repository) DisableTeam(ctx context.Context, record access.TeamDisablement) error {
	return r.withTransaction(ctx, "disable team", func(tx *sql.Tx) error {
		if err := requireActiveSystemAdministrator(ctx, tx, record.ActorIdentityID); err != nil {
			return err
		}
		if err := lockActiveOffboardingTarget(ctx, tx, lockActiveTeamForDisableSQL, record.TeamID, "team"); err != nil {
			return err
		}
		if err := updateOffboardingTarget(ctx, tx, disableTeamSQL, record.DisabledAt, record.TeamID, "team"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, revokeTeamServiceAccountKeysSQL, record.DisabledAt, record.TeamID, record.ActorIdentityID, record.RequestID); err != nil {
			return fmt.Errorf("revoke team service account keys: %w", err)
		}
		return nil
	})
}

func (r *Repository) DisableServiceAccount(ctx context.Context, record access.ServiceAccountDisablement) error {
	return r.withTransaction(ctx, "disable service account", func(tx *sql.Tx) error {
		if err := requireActiveSystemAdministrator(ctx, tx, record.ActorIdentityID); err != nil {
			return err
		}
		if err := lockActiveOffboardingTarget(ctx, tx, lockActiveServiceAccountForDisableSQL, record.ServiceAccountID, "service account"); err != nil {
			return err
		}
		if err := updateOffboardingTarget(ctx, tx, disableServiceAccountSQL, record.DisabledAt, record.ServiceAccountID, "service account"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, revokeDisabledServiceAccountKeysSQL, record.DisabledAt, record.ServiceAccountID, record.ActorIdentityID, record.RequestID); err != nil {
			return fmt.Errorf("revoke disabled service account keys: %w", err)
		}
		return nil
	})
}

func lockActiveOffboardingTarget(ctx context.Context, tx *sql.Tx, query, targetID, kind string) error {
	var id string
	if err := tx.QueryRowContext(ctx, query, targetID).Scan(&id); errors.Is(err, sql.ErrNoRows) {
		return access.ErrInvalidOffboardingTarget
	} else if err != nil {
		return fmt.Errorf("lock active %s: %w", kind, err)
	}
	return nil
}

func updateOffboardingTarget(ctx context.Context, tx *sql.Tx, query string, disabledAt time.Time, targetID, kind string) error {
	result, err := tx.ExecContext(ctx, query, disabledAt, targetID)
	if err != nil {
		return fmt.Errorf("disable %s: %w", kind, err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count disabled %s: %w", kind, err)
	}
	if affected != 1 {
		return access.ErrInvalidOffboardingTarget
	}
	return nil
}
