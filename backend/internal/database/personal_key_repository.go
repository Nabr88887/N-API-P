package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"

	"n-api-p/internal/access"
)

const personalKeyNameUniqueConstraint = "api_keys_identity_id_name_key"

const lockPersonalKeyOwnerSQL = `
SELECT status
FROM identities
WHERE id = $1
FOR UPDATE`

const countActivePersonalKeysSQL = `
SELECT count(*)
FROM api_keys
WHERE identity_id = $1
  AND kind = 'personal'
  AND status = 'active'`

const insertPersonalKeySQL = `
INSERT INTO api_keys (
    id,
    identity_id,
    kind,
    name,
    prefix,
    verification_hash,
    status,
    created_at
) VALUES ($1, $2, 'personal', $3, $4, $5, 'active', $6)`

const listPersonalKeysSQL = `
SELECT
    id::text,
    identity_id::text,
    name,
    prefix,
    status,
    created_at,
    last_used_at,
    revoked_at
FROM api_keys
WHERE identity_id = $1
  AND kind = 'personal'
ORDER BY created_at DESC, id DESC`

const revokePersonalKeySQL = `
UPDATE api_keys
SET status = 'revoked',
    revoked_at = $1
WHERE id = $2
  AND identity_id = $3
  AND kind = 'personal'
  AND status = 'active'`

const findPersonalKeyCandidatesSQL = `
SELECT
    k.id::text,
    k.identity_id::text,
    k.verification_hash
FROM api_keys AS k
JOIN identities AS i ON i.id = k.identity_id
WHERE k.prefix = $1
  AND k.kind = 'personal'
  AND k.status = 'active'
  AND i.status = 'active'
ORDER BY k.id`

const recordPersonalKeyUseSQL = `
UPDATE api_keys AS k
SET last_used_at = GREATEST(COALESCE(k.last_used_at, $1), $1)
FROM identities AS i
WHERE k.id = $2
  AND k.kind = 'personal'
  AND k.status = 'active'
  AND i.id = k.identity_id
  AND i.status = 'active'
RETURNING k.id::text, k.identity_id::text`

func (r *Repository) CreatePersonalKey(ctx context.Context, record access.PersonalKeyRecord) error {
	return r.withTransaction(ctx, "create personal key", func(tx *sql.Tx) error {
		var status access.IdentityStatus
		err := tx.QueryRowContext(ctx, lockPersonalKeyOwnerSQL, record.IdentityID).Scan(&status)
		if errors.Is(err, sql.ErrNoRows) {
			return access.ErrForbidden
		}
		if err != nil {
			return fmt.Errorf("lock personal key owner: %w", err)
		}
		if status != access.IdentityStatusActive {
			return access.ErrForbidden
		}

		var activeCount int
		if err := tx.QueryRowContext(ctx, countActivePersonalKeysSQL, record.IdentityID).Scan(&activeCount); err != nil {
			return fmt.Errorf("count active personal keys: %w", err)
		}
		if activeCount >= access.MaxActivePersonalKeys {
			return access.ErrPersonalKeyLimitReached
		}

		_, err = tx.ExecContext(ctx, insertPersonalKeySQL,
			record.ID, record.IdentityID, record.Name, record.Prefix,
			record.VerificationHash, record.CreatedAt,
		)
		if err != nil {
			if isPersonalKeyNameConflict(err) {
				return access.ErrPersonalKeyNameConflict
			}
			return fmt.Errorf("insert personal key: %w", err)
		}
		return nil
	})
}

func (r *Repository) ListPersonalKeys(ctx context.Context, identityID string) (keys []access.PersonalKey, err error) {
	rows, err := r.db.QueryContext(ctx, listPersonalKeysSQL, identityID)
	if err != nil {
		return nil, fmt.Errorf("query personal keys: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close personal key rows: %w", closeErr))
		}
	}()

	for rows.Next() {
		var (
			key        access.PersonalKey
			lastUsedAt sql.NullTime
			revokedAt  sql.NullTime
		)
		if err := rows.Scan(
			&key.ID, &key.IdentityID, &key.Name, &key.Prefix, &key.Status,
			&key.CreatedAt, &lastUsedAt, &revokedAt,
		); err != nil {
			return nil, fmt.Errorf("scan personal key: %w", err)
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
		return nil, fmt.Errorf("iterate personal keys: %w", err)
	}
	return keys, nil
}

func (r *Repository) RevokePersonalKey(ctx context.Context, revocation access.PersonalKeyRevocation) error {
	result, err := r.db.ExecContext(ctx, revokePersonalKeySQL, revocation.RevokedAt, revocation.KeyID, revocation.IdentityID)
	if err != nil {
		return fmt.Errorf("revoke personal key: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count revoked personal keys: %w", err)
	}
	if affected != 1 {
		return access.ErrPersonalKeyNotFound
	}
	return nil
}

func (r *Repository) FindPersonalKeyCandidates(ctx context.Context, prefix string) (candidates []access.PersonalKeyAuthenticationCandidate, err error) {
	rows, err := r.db.QueryContext(ctx, findPersonalKeyCandidatesSQL, prefix)
	if err != nil {
		return nil, fmt.Errorf("query personal key candidates: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close personal key candidate rows: %w", closeErr))
		}
	}()

	for rows.Next() {
		var candidate access.PersonalKeyAuthenticationCandidate
		if err := rows.Scan(&candidate.KeyID, &candidate.IdentityID, &candidate.VerificationHash); err != nil {
			return nil, fmt.Errorf("scan personal key candidate: %w", err)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate personal key candidates: %w", err)
	}
	return candidates, nil
}

func (r *Repository) RecordPersonalKeyUse(ctx context.Context, use access.PersonalKeyUse) (access.AuthenticatedPersonalKey, error) {
	var authenticated access.AuthenticatedPersonalKey
	err := r.db.QueryRowContext(ctx, recordPersonalKeyUseSQL, use.UsedAt, use.KeyID).Scan(
		&authenticated.KeyID,
		&authenticated.IdentityID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return access.AuthenticatedPersonalKey{}, access.ErrInvalidAPIKey
	}
	if err != nil {
		return access.AuthenticatedPersonalKey{}, fmt.Errorf("record personal key use: %w", err)
	}
	return authenticated, nil
}

func isPersonalKeyNameConflict(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) &&
		postgresError.Code == postgresUniqueViolation &&
		postgresError.ConstraintName == personalKeyNameUniqueConstraint
}
