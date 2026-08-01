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
	postgresUniqueViolation       = "23505"
	identityEmailUniqueConstraint = "identities_email_key"
)

const selectActiveAdministratorSQL = `
SELECT role, status
FROM identities
WHERE id = $1
FOR SHARE`

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
		return nil
	})
}

const updateIdentityEmailSQL = `
UPDATE identities
SET email = $1,
    updated_at = $2
WHERE id = $3`

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
		return nil
	})
}

type transactionQueryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func requireActiveSystemAdministrator(ctx context.Context, queryer transactionQueryer, identityID string) error {
	var role string
	var status string
	err := queryer.QueryRowContext(ctx, selectActiveAdministratorSQL, identityID).Scan(&role, &status)
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
