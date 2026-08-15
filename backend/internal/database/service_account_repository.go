package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"

	"n-api-p/internal/access"
)

const (
	serviceAccountNameUniqueConstraint    = "service_accounts_team_id_name_key"
	serviceAccountKeyNameUniqueConstraint = "api_keys_service_account_id_name_key"
)

const selectServiceAccountOwnerSQL = `
SELECT t.status, i.status, i.role
FROM teams AS t
JOIN memberships AS m
  ON m.team_id = t.id
 AND m.identity_id = $2
JOIN identities AS i ON i.id = m.identity_id
WHERE t.id = $1
FOR SHARE OF t, i`

const insertServiceAccountSQL = `
INSERT INTO service_accounts (
    id,
    team_id,
    responsible_identity_id,
    name,
    status,
    created_at,
    updated_at
) VALUES ($1, $2, $3, $4, 'active', $5, $5)`

const listServiceAccountsSQL = `
SELECT
    id::text,
    team_id::text,
    responsible_identity_id::text,
    name,
    status,
    created_at,
    updated_at,
    disabled_at
FROM service_accounts
ORDER BY created_at DESC, id DESC`

const lockActiveServiceAccountOwnerSQL = `
SELECT sa.team_id::text, sa.responsible_identity_id::text
FROM service_accounts AS sa
JOIN teams AS t ON t.id = sa.team_id
JOIN identities AS i ON i.id = sa.responsible_identity_id
JOIN memberships AS m
  ON m.team_id = sa.team_id
 AND m.identity_id = sa.responsible_identity_id
WHERE sa.id = $1
  AND sa.status = 'active'
  AND t.status = 'active'
  AND i.status = 'active'
  AND i.role = 'employee'
FOR UPDATE OF sa, t, i`

const countActiveServiceAccountKeysSQL = `
SELECT count(*)
FROM api_keys
WHERE service_account_id = $1
  AND kind = 'service'
  AND status = 'active'`

const insertServiceAccountKeySQL = `
INSERT INTO api_keys (
    id,
    service_account_id,
    kind,
    name,
    prefix,
    verification_hash,
    status,
    created_at
) VALUES ($1, $2, 'service', $3, $4, $5, 'active', $6)`

const listServiceAccountKeysSQL = `
SELECT
    k.id::text,
    k.service_account_id::text,
    sa.team_id::text,
    sa.responsible_identity_id::text,
    k.name,
    k.prefix,
    k.status,
    k.created_at,
    k.last_used_at,
    k.revoked_at
FROM api_keys AS k
JOIN service_accounts AS sa ON sa.id = k.service_account_id
WHERE k.service_account_id = $1
  AND k.kind = 'service'
ORDER BY k.created_at DESC, k.id DESC`

const lockActiveServiceAccountKeySQL = `
SELECT id::text, prefix
FROM api_keys
WHERE id = $1
  AND service_account_id = $2
  AND kind = 'service'
  AND status = 'active'
FOR UPDATE`

const revokeServiceAccountKeySQL = `
UPDATE api_keys
SET status = 'revoked',
    revoked_at = $1
WHERE id = $2
  AND service_account_id = $3
  AND kind = 'service'
  AND status = 'active'
RETURNING id::text, prefix`

const findServiceAccountKeyCandidatesSQL = `
SELECT
    k.id::text,
    k.service_account_id::text,
    k.verification_hash
FROM api_keys AS k
JOIN service_accounts AS sa ON sa.id = k.service_account_id
JOIN teams AS t ON t.id = sa.team_id
JOIN identities AS i ON i.id = sa.responsible_identity_id
JOIN memberships AS m
  ON m.team_id = sa.team_id
 AND m.identity_id = sa.responsible_identity_id
WHERE k.prefix = $1
  AND k.kind = 'service'
  AND k.status = 'active'
  AND sa.status = 'active'
  AND t.status = 'active'
  AND i.status = 'active'
  AND i.role = 'employee'
ORDER BY k.id`

const recordServiceAccountKeyUseSQL = `
UPDATE api_keys AS k
SET last_used_at = GREATEST(COALESCE(k.last_used_at, $1), $1)
FROM service_accounts AS sa,
     teams AS t,
     identities AS i,
     memberships AS m
WHERE k.id = $2
  AND k.kind = 'service'
  AND k.status = 'active'
  AND sa.id = k.service_account_id
  AND sa.status = 'active'
  AND t.id = sa.team_id
  AND t.status = 'active'
  AND i.id = sa.responsible_identity_id
  AND i.status = 'active'
  AND i.role = 'employee'
  AND m.team_id = sa.team_id
  AND m.identity_id = sa.responsible_identity_id
RETURNING k.id::text,
          sa.id::text,
          sa.team_id::text,
          sa.responsible_identity_id::text`

type serviceAccountOwner struct {
	TeamID                string
	ResponsibleIdentityID string
}

func (r *Repository) CreateServiceAccount(ctx context.Context, record access.ServiceAccountRecord) error {
	return r.withTransaction(ctx, "create service account", func(tx *sql.Tx) error {
		if err := requireActiveSystemAdministrator(ctx, tx, record.CreatedByIdentityID); err != nil {
			return err
		}
		if err := requireValidServiceAccountOwner(ctx, tx, record.TeamID, record.ResponsibleIdentityID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, insertServiceAccountSQL,
			record.ID, record.TeamID, record.ResponsibleIdentityID, record.Name, record.CreatedAt,
		)
		if err != nil {
			if isServiceAccountNameConflict(err) {
				return access.ErrServiceAccountNameConflict
			}
			return fmt.Errorf("insert service account: %w", err)
		}
		return appendSecurityEventTx(ctx, tx, record.Event)
	})
}

func (r *Repository) ListServiceAccounts(ctx context.Context, actorIdentityID string) (accounts []access.ServiceAccount, err error) {
	err = r.withTransaction(ctx, "list service accounts", func(tx *sql.Tx) error {
		if err := requireActiveSystemAdministrator(ctx, tx, actorIdentityID); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, listServiceAccountsSQL)
		if err != nil {
			return fmt.Errorf("query service accounts: %w", err)
		}
		var scanErr error
		accounts, scanErr = scanServiceAccounts(rows)
		return scanErr
	})
	return accounts, err
}

func (r *Repository) CreateServiceAccountKey(ctx context.Context, record access.ServiceAccountKeyRecord) (access.ServiceAccountKey, error) {
	if record.Kind != access.ServiceAccountKeyKind {
		return access.ServiceAccountKey{}, access.ErrInvalidServiceAccountKey
	}
	var key access.ServiceAccountKey
	err := r.withTransaction(ctx, "create service account key", func(tx *sql.Tx) error {
		if err := requireActiveSystemAdministrator(ctx, tx, record.CreatedByIdentityID); err != nil {
			return err
		}
		owner, err := lockActiveServiceAccountOwner(ctx, tx, record.ServiceAccountID)
		if err != nil {
			return err
		}
		if err := requireServiceAccountKeyCapacity(ctx, tx, record.ServiceAccountID); err != nil {
			return err
		}
		if err := insertServiceAccountKey(ctx, tx, record); err != nil {
			return err
		}
		key = serviceAccountKeyFromRecord(record, owner)
		event, err := record.Lifecycle.ForKey(record.ID, record.Prefix)
		if err != nil {
			return err
		}
		if err := appendCredentialLifecycleEvent(ctx, tx, event); err != nil {
			return err
		}
		return nil
	})
	return key, err
}

func (r *Repository) ListServiceAccountKeys(ctx context.Context, serviceAccountID, actorIdentityID string) (keys []access.ServiceAccountKey, err error) {
	err = r.withTransaction(ctx, "list service account keys", func(tx *sql.Tx) error {
		if err := requireActiveSystemAdministrator(ctx, tx, actorIdentityID); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, listServiceAccountKeysSQL, serviceAccountID)
		if err != nil {
			return fmt.Errorf("query service account keys: %w", err)
		}
		var scanErr error
		keys, scanErr = scanServiceAccountKeys(rows)
		return scanErr
	})
	return keys, err
}

func scanServiceAccounts(rows *sql.Rows) (accounts []access.ServiceAccount, err error) {
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close service account rows: %w", closeErr))
		}
	}()
	for rows.Next() {
		var account access.ServiceAccount
		var disabledAt sql.NullTime
		if err := rows.Scan(
			&account.ID, &account.TeamID, &account.ResponsibleIdentityID,
			&account.Name, &account.Status, &account.CreatedAt, &account.UpdatedAt, &disabledAt,
		); err != nil {
			return nil, fmt.Errorf("scan service account: %w", err)
		}
		if disabledAt.Valid {
			value := disabledAt.Time
			account.DisabledAt = &value
		}
		accounts = append(accounts, account)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate service accounts: %w", err)
	}
	return accounts, nil
}

func scanServiceAccountKeys(rows *sql.Rows) (keys []access.ServiceAccountKey, err error) {
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close service account key rows: %w", closeErr))
		}
	}()
	for rows.Next() {
		var key access.ServiceAccountKey
		var lastUsedAt, revokedAt sql.NullTime
		if err := rows.Scan(
			&key.ID, &key.ServiceAccountID, &key.TeamID, &key.ResponsibleIdentityID,
			&key.Name, &key.Prefix, &key.Status, &key.CreatedAt, &lastUsedAt, &revokedAt,
		); err != nil {
			return nil, fmt.Errorf("scan service account key: %w", err)
		}
		if lastUsedAt.Valid {
			value := lastUsedAt.Time
			key.LastUsedAt = &value
		}
		if revokedAt.Valid {
			value := revokedAt.Time
			key.RevokedAt = &value
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate service account keys: %w", err)
	}
	return keys, nil
}

func (r *Repository) RotateServiceAccountKey(ctx context.Context, rotation access.ServiceAccountKeyRotation) (access.ServiceAccountKey, error) {
	if rotation.NewKey.Kind != access.ServiceAccountKeyKind || rotation.NewKey.ServiceAccountID != rotation.ServiceAccountID {
		return access.ServiceAccountKey{}, access.ErrInvalidServiceAccountKey
	}
	var key access.ServiceAccountKey
	err := r.withTransaction(ctx, "rotate service account key", func(tx *sql.Tx) error {
		if err := requireActiveSystemAdministrator(ctx, tx, rotation.NewKey.CreatedByIdentityID); err != nil {
			return err
		}
		owner, err := lockActiveServiceAccountOwner(ctx, tx, rotation.ServiceAccountID)
		if err != nil {
			return err
		}
		var oldKeyID, oldPrefix string
		if err := tx.QueryRowContext(ctx, lockActiveServiceAccountKeySQL, rotation.OldKeyID, rotation.ServiceAccountID).Scan(&oldKeyID, &oldPrefix); errors.Is(err, sql.ErrNoRows) {
			return access.ErrServiceAccountKeyNotFound
		} else if err != nil {
			return fmt.Errorf("lock service account key: %w", err)
		}
		result, err := tx.ExecContext(ctx, revokeServiceAccountKeySQL, rotation.RevokedAt, oldKeyID, rotation.ServiceAccountID)
		if err != nil {
			return fmt.Errorf("revoke rotated service account key: %w", err)
		}
		if affected, err := result.RowsAffected(); err != nil {
			return fmt.Errorf("count revoked rotated service account keys: %w", err)
		} else if affected != 1 {
			return access.ErrServiceAccountKeyNotFound
		}
		if err := requireServiceAccountKeyCapacity(ctx, tx, rotation.ServiceAccountID); err != nil {
			return err
		}
		if err := insertServiceAccountKey(ctx, tx, rotation.NewKey); err != nil {
			return err
		}
		key = serviceAccountKeyFromRecord(rotation.NewKey, owner)
		revokedEvent, err := rotation.RevokedLifecycle.ForKey(oldKeyID, oldPrefix)
		if err != nil {
			return err
		}
		if err := appendCredentialLifecycleEvent(ctx, tx, revokedEvent); err != nil {
			return err
		}
		createdEvent, err := rotation.CreatedLifecycle.ForKey(rotation.NewKey.ID, rotation.NewKey.Prefix)
		if err != nil {
			return err
		}
		if err := appendCredentialLifecycleEvent(ctx, tx, createdEvent); err != nil {
			return err
		}
		return nil
	})
	return key, err
}

func (r *Repository) RevokeServiceAccountKey(ctx context.Context, revocation access.ServiceAccountKeyRevocation) error {
	return r.withTransaction(ctx, "revoke service account key", func(tx *sql.Tx) error {
		if err := requireActiveSystemAdministrator(ctx, tx, revocation.ActorIdentityID); err != nil {
			return err
		}
		var keyID, prefix string
		err := tx.QueryRowContext(ctx, revokeServiceAccountKeySQL, revocation.RevokedAt, revocation.KeyID, revocation.ServiceAccountID).Scan(&keyID, &prefix)
		if errors.Is(err, sql.ErrNoRows) {
			return access.ErrServiceAccountKeyNotFound
		}
		if err != nil {
			return fmt.Errorf("revoke service account key: %w", err)
		}
		event, err := revocation.Lifecycle.ForKey(keyID, prefix)
		if err != nil {
			return err
		}
		return appendCredentialLifecycleEvent(ctx, tx, event)
	})
}

func (r *Repository) FindServiceAccountKeyCandidates(ctx context.Context, prefix string) (candidates []access.ServiceAccountKeyAuthenticationCandidate, err error) {
	rows, err := r.db.QueryContext(ctx, findServiceAccountKeyCandidatesSQL, prefix)
	if err != nil {
		return nil, fmt.Errorf("query service account key candidates: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close service account key candidate rows: %w", closeErr))
		}
	}()
	for rows.Next() {
		var candidate access.ServiceAccountKeyAuthenticationCandidate
		if err := rows.Scan(&candidate.KeyID, &candidate.ServiceAccountID, &candidate.VerificationHash); err != nil {
			return nil, fmt.Errorf("scan service account key candidate: %w", err)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate service account key candidates: %w", err)
	}
	return candidates, nil
}

func (r *Repository) RecordServiceAccountKeyUse(ctx context.Context, use access.ServiceAccountKeyUse) (access.AuthenticatedServiceAccountKey, error) {
	var authenticated access.AuthenticatedServiceAccountKey
	err := r.db.QueryRowContext(ctx, recordServiceAccountKeyUseSQL, use.UsedAt, use.KeyID).Scan(
		&authenticated.KeyID,
		&authenticated.ServiceAccountID,
		&authenticated.TeamID,
		&authenticated.ResponsibleIdentityID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return access.AuthenticatedServiceAccountKey{}, access.ErrInvalidAPIKey
	}
	if err != nil {
		return access.AuthenticatedServiceAccountKey{}, fmt.Errorf("record service account key use: %w", err)
	}
	return authenticated, nil
}

func requireValidServiceAccountOwner(ctx context.Context, queryer transactionQueryer, teamID, responsibleIdentityID string) error {
	var teamStatus, identityStatus, role string
	err := queryer.QueryRowContext(ctx, selectServiceAccountOwnerSQL, teamID, responsibleIdentityID).Scan(&teamStatus, &identityStatus, &role)
	if errors.Is(err, sql.ErrNoRows) {
		return access.ErrInvalidServiceAccount
	}
	if err != nil {
		return fmt.Errorf("query service account owner: %w", err)
	}
	if teamStatus != "active" || identityStatus != string(access.IdentityStatusActive) || role != string(access.RoleEmployee) {
		return access.ErrInvalidServiceAccount
	}
	return nil
}

func lockActiveServiceAccountOwner(ctx context.Context, tx *sql.Tx, serviceAccountID string) (serviceAccountOwner, error) {
	var owner serviceAccountOwner
	err := tx.QueryRowContext(ctx, lockActiveServiceAccountOwnerSQL, serviceAccountID).Scan(&owner.TeamID, &owner.ResponsibleIdentityID)
	if errors.Is(err, sql.ErrNoRows) {
		return serviceAccountOwner{}, access.ErrInvalidServiceAccount
	}
	if err != nil {
		return serviceAccountOwner{}, fmt.Errorf("lock service account owner: %w", err)
	}
	return owner, nil
}

func requireServiceAccountKeyCapacity(ctx context.Context, tx *sql.Tx, serviceAccountID string) error {
	var activeCount int
	if err := tx.QueryRowContext(ctx, countActiveServiceAccountKeysSQL, serviceAccountID).Scan(&activeCount); err != nil {
		return fmt.Errorf("count active service account keys: %w", err)
	}
	if activeCount >= access.MaxActiveServiceAccountKeys {
		return access.ErrServiceAccountKeyLimitReached
	}
	return nil
}

func insertServiceAccountKey(ctx context.Context, tx *sql.Tx, record access.ServiceAccountKeyRecord) error {
	_, err := tx.ExecContext(ctx, insertServiceAccountKeySQL,
		record.ID, record.ServiceAccountID, record.Name, record.Prefix,
		record.VerificationHash, record.CreatedAt,
	)
	if err != nil {
		if isServiceAccountKeyNameConflict(err) {
			return access.ErrServiceAccountKeyNameConflict
		}
		return fmt.Errorf("insert service account key: %w", err)
	}
	return nil
}

func serviceAccountKeyFromRecord(record access.ServiceAccountKeyRecord, owner serviceAccountOwner) access.ServiceAccountKey {
	return access.ServiceAccountKey{
		ID: record.ID, ServiceAccountID: record.ServiceAccountID,
		TeamID: owner.TeamID, ResponsibleIdentityID: owner.ResponsibleIdentityID,
		Name: record.Name, Prefix: record.Prefix, Status: access.ServiceAccountKeyStatusActive, CreatedAt: record.CreatedAt,
	}
}

func isServiceAccountNameConflict(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) &&
		postgresError.Code == postgresUniqueViolation &&
		postgresError.ConstraintName == serviceAccountNameUniqueConstraint
}

func isServiceAccountKeyNameConflict(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) &&
		postgresError.Code == postgresUniqueViolation &&
		postgresError.ConstraintName == serviceAccountKeyNameUniqueConstraint
}
