package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"n-api-p/internal/access"
)

const readRetentionPolicySQL = `
SELECT raw_retention_days, updated_at
FROM operational_state
WHERE id = 1`

const lockRetentionPolicySQL = `
SELECT raw_retention_days
FROM operational_state
WHERE id = 1
FOR UPDATE`

const shortenRawRetentionSQL = `
UPDATE audit_raw_content
SET expires_at = created_at + ($1 * INTERVAL '1 day')
WHERE expires_at > $2`

const updateRetentionPolicySQL = `
UPDATE operational_state
SET raw_retention_days = $1,
    updated_at = $2
WHERE id = 1`

func (r *Repository) ReadRetentionPolicy(ctx context.Context) (access.RetentionPolicy, error) {
	var policy access.RetentionPolicy
	if err := r.db.QueryRowContext(ctx, readRetentionPolicySQL).Scan(&policy.Days, &policy.UpdatedAt); err != nil {
		return access.RetentionPolicy{}, fmt.Errorf("read retention policy: %w", err)
	}
	return policy, nil
}

func (r *Repository) ChangeRetentionPolicy(ctx context.Context, change access.RetentionPolicyChange) (policy access.RetentionPolicy, err error) {
	if err := change.Validate(); err != nil {
		return access.RetentionPolicy{}, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return access.RetentionPolicy{}, fmt.Errorf("begin retention policy transaction: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("roll back retention policy transaction: %w", rollbackErr))
		}
	}()

	if err := requireActiveSystemAdministrator(ctx, tx, change.Event.ActorIdentityID); err != nil {
		return access.RetentionPolicy{}, err
	}
	var previousDays int
	if err := tx.QueryRowContext(ctx, lockRetentionPolicySQL).Scan(&previousDays); err != nil {
		return access.RetentionPolicy{}, fmt.Errorf("lock retention policy: %w", err)
	}
	if change.Days < previousDays {
		if _, err := tx.ExecContext(ctx, shortenRawRetentionSQL, change.Days, change.ChangedAt.UTC()); err != nil {
			return access.RetentionPolicy{}, fmt.Errorf("shorten raw retention: %w", err)
		}
	}
	result, err := tx.ExecContext(ctx, updateRetentionPolicySQL, change.Days, change.ChangedAt.UTC())
	if err != nil {
		return access.RetentionPolicy{}, fmt.Errorf("update retention policy: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil {
		return access.RetentionPolicy{}, fmt.Errorf("count retention policy update: %w", err)
	} else if affected != 1 {
		return access.RetentionPolicy{}, fmt.Errorf("update retention policy: %w", sql.ErrNoRows)
	}

	event := change.Event
	event.DetailCode = retentionChangeDetail(previousDays, change.Days)
	if err := appendSecurityEventTx(ctx, tx, event); err != nil {
		return access.RetentionPolicy{}, err
	}
	if err := tx.Commit(); err != nil {
		return access.RetentionPolicy{}, fmt.Errorf("commit retention policy transaction: %w", err)
	}
	committed = true
	return access.RetentionPolicy{Days: change.Days, MaximumDays: change.MaximumDays, UpdatedAt: change.ChangedAt.UTC()}, nil
}

func appendSecurityEventTx(ctx context.Context, tx *sql.Tx, event access.SecurityEvent) error {
	if _, err := tx.ExecContext(ctx, insertSecurityEventSQL,
		event.ID, event.EventType, event.ActorIdentityID, event.TargetIdentityID,
		event.TargetServiceAccountID, event.TargetKeyID, event.TargetAuditID,
		event.RequestID, event.Outcome, event.Reason, event.DetailCode, event.OccurredAt,
	); err != nil {
		return fmt.Errorf("append security event in transaction: %w", err)
	}
	return nil
}

func retentionChangeDetail(previousDays, newDays int) string {
	switch {
	case newDays < previousDays:
		return fmt.Sprintf("shortened_%d_to_%d_days", previousDays, newDays)
	case newDays > previousDays:
		return fmt.Sprintf("lengthened_%d_to_%d_days", previousDays, newDays)
	default:
		return fmt.Sprintf("unchanged_%d_days", newDays)
	}
}

var _ access.RetentionPolicyRepository = (*Repository)(nil)
