package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"n-api-p/internal/audit"
	"n-api-p/internal/operations"
	"time"
)

const readVisibleRawContentSQL = `
SELECT
    raw.audit_id::text,
    raw.content_kind,
    raw.compression,
    raw.ciphertext,
    raw.cipher_nonce,
    raw.wrapped_data_key,
    raw.wrap_nonce,
    raw.key_version,
    records.owner_kind,
    COALESCE(records.identity_id::text, ''),
    COALESCE(records.service_account_id::text, ''),
    COALESCE(records.responsible_identity_id::text, ''),
    records.team_id::text,
    raw.created_at,
    raw.expires_at
FROM audit_raw_content AS raw
JOIN audit_records AS records ON records.id = raw.audit_id
WHERE raw.audit_id = $1
  AND raw.content_kind = $2
  AND raw.expires_at > $3`

const observeDeletionLagSQL = `
WITH lag AS (
    SELECT min(expires_at) AS oldest_expired_at
    FROM audit_raw_content
    WHERE expires_at <= $1
), updated AS (
    UPDATE operational_state
    SET deletion_overdue_since = CASE
            WHEN lag.oldest_expired_at < $1 - INTERVAL '1 hour'
                THEN lag.oldest_expired_at + INTERVAL '1 hour'
            ELSE NULL
        END,
        updated_at = $1
    FROM lag
    WHERE operational_state.id = 1
    RETURNING lag.oldest_expired_at, operational_state.deletion_overdue_since
)
SELECT oldest_expired_at, deletion_overdue_since
FROM updated`

const lockDeletionOverdueSQL = `
SELECT deletion_overdue_since
FROM operational_state
WHERE id = 1
FOR UPDATE`

const deleteExpiredRawContentSQL = `
DELETE FROM audit_raw_content
WHERE expires_at <= $1`

const markLifecycleCleanupSQL = `
UPDATE operational_state
SET last_cleanup_at = $1,
    deletion_overdue_since = NULL,
    updated_at = $1
WHERE id = 1`

const purgeRevokedVerificationHashesSQL = `
UPDATE api_keys
SET verification_hash = NULL
WHERE status = 'revoked'
  AND revoked_at IS NOT NULL
  AND revoked_at <= $1
  AND verification_hash IS NOT NULL`

const purgeExpiredUsageSQL = `
DELETE FROM usage_records
WHERE created_at <= $1`

const purgeExpiredOperationalEventsSQL = `
DELETE FROM security_events
WHERE event_type = 'operational_fault'
  AND retain_until <= $1`

const purgeExpiredSecurityEventsSQL = `
DELETE FROM security_events
WHERE event_type <> 'operational_fault'
  AND retain_until <= $1`

const purgeExpiredAuditMetadataSQL = `
DELETE FROM audit_records AS records
WHERE records.created_at <= $1
  AND NOT EXISTS (SELECT 1 FROM audit_raw_content raw WHERE raw.audit_id = records.id)
  AND NOT EXISTS (SELECT 1 FROM usage_records usage WHERE usage.audit_id = records.id)
  AND NOT EXISTS (SELECT 1 FROM security_events events WHERE events.target_audit_id = records.id)`

const purgeExpiredServiceAccountsSQL = `
DELETE FROM service_accounts AS accounts
WHERE accounts.status = 'disabled'
  AND accounts.disabled_at IS NOT NULL
  AND accounts.disabled_at <= $1
  AND NOT EXISTS (SELECT 1 FROM api_keys keys WHERE keys.service_account_id = accounts.id)
  AND NOT EXISTS (SELECT 1 FROM audit_records records WHERE records.service_account_id = accounts.id)
  AND NOT EXISTS (SELECT 1 FROM usage_records usage WHERE usage.service_account_id = accounts.id)
  AND NOT EXISTS (SELECT 1 FROM security_events events WHERE events.target_service_account_id = accounts.id)`

const purgeExpiredRevokedKeysSQL = `
DELETE FROM api_keys AS keys
WHERE keys.status = 'revoked'
  AND keys.revoked_at IS NOT NULL
  AND keys.revoked_at <= $1
  AND NOT EXISTS (SELECT 1 FROM audit_records records WHERE records.key_id = keys.id)
  AND NOT EXISTS (SELECT 1 FROM usage_records usage WHERE usage.key_id = keys.id)
  AND NOT EXISTS (SELECT 1 FROM security_events events WHERE events.target_key_id = keys.id)`

const purgeExpiredDisabledIdentitiesSQL = `
DELETE FROM identities AS identities
WHERE identities.status = 'disabled'
  AND identities.disabled_at IS NOT NULL
  AND identities.disabled_at <= $1
  AND NOT EXISTS (SELECT 1 FROM memberships memberships WHERE memberships.identity_id = identities.id)
  AND NOT EXISTS (SELECT 1 FROM api_keys keys WHERE keys.identity_id = identities.id)
  AND NOT EXISTS (SELECT 1 FROM service_accounts accounts WHERE accounts.responsible_identity_id = identities.id)
  AND NOT EXISTS (SELECT 1 FROM audit_records records WHERE records.identity_id = identities.id OR records.responsible_identity_id = identities.id)
  AND NOT EXISTS (SELECT 1 FROM usage_records usage WHERE usage.identity_id = identities.id OR usage.responsible_identity_id = identities.id)
  AND NOT EXISTS (SELECT 1 FROM security_events events WHERE events.actor_identity_id = identities.id OR events.target_identity_id = identities.id)
  AND NOT EXISTS (SELECT 1 FROM one_time_codes codes WHERE codes.identity_id = identities.id OR codes.issued_by_identity_id = identities.id)`

func (r *Repository) ReadRawContent(ctx context.Context, lookup audit.RawContentLookup) (audit.RawContentRecord, error) {
	if lookup.AuditID == "" || lookup.VisibleAt.IsZero() || (lookup.ContentKind != audit.ContentKindRequest && lookup.ContentKind != audit.ContentKindResponse) {
		return audit.RawContentRecord{}, audit.ErrInvalidLifecycle
	}
	var record audit.RawContentRecord
	err := r.db.QueryRowContext(ctx, readVisibleRawContentSQL, lookup.AuditID, lookup.ContentKind, lookup.VisibleAt.UTC()).Scan(
		&record.AuditID,
		&record.ContentKind,
		&record.Content.Compression,
		&record.Content.Ciphertext,
		&record.Content.CipherNonce,
		&record.Content.WrappedDataKey,
		&record.Content.WrapNonce,
		&record.Content.KeyVersion,
		&record.OwnerKind,
		&record.IdentityID,
		&record.ServiceAccountID,
		&record.ResponsibleIdentityID,
		&record.TeamID,
		&record.CreatedAt,
		&record.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return audit.RawContentRecord{}, audit.ErrRawContentUnavailable
	}
	if err != nil {
		return audit.RawContentRecord{}, fmt.Errorf("read visible raw content: %w", err)
	}
	return record, nil
}

func (r *Repository) ObserveDeletionLag(ctx context.Context, observedAt time.Time) (state audit.DeletionLagState, err error) {
	if observedAt.IsZero() {
		return audit.DeletionLagState{}, audit.ErrInvalidLifecycle
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return audit.DeletionLagState{}, fmt.Errorf("begin deletion lag observation: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("roll back deletion lag observation: %w", rollbackErr))
		}
	}()
	previousOverdue, err := lockDeletionOverdue(ctx, tx)
	if err != nil {
		return audit.DeletionLagState{}, err
	}
	var oldestExpiredAt, overdueSince sql.NullTime
	if err := tx.QueryRowContext(ctx, observeDeletionLagSQL, observedAt.UTC()).Scan(&oldestExpiredAt, &overdueSince); err != nil {
		return audit.DeletionLagState{}, fmt.Errorf("observe raw deletion lag: %w", err)
	}
	state = audit.DeletionLagState{Critical: overdueSince.Valid, ObservedAt: observedAt.UTC()}
	if oldestExpiredAt.Valid {
		value := oldestExpiredAt.Time
		state.OldestExpiredAt = &value
	}
	if overdueSince.Valid {
		value := overdueSince.Time
		state.OverdueSince = &value
	}
	if !previousOverdue.Valid && overdueSince.Valid {
		if err := appendOperationalEventTx(ctx, tx, operations.FaultTransition{
			Fault: operations.FaultRawDeletionOverdue, Active: true, OccurredAt: observedAt.UTC(),
		}); err != nil {
			return audit.DeletionLagState{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return audit.DeletionLagState{}, fmt.Errorf("commit deletion lag observation: %w", err)
	}
	committed = true
	return state, nil
}

func (r *Repository) DeleteExpiredRawContent(ctx context.Context, expiredAt time.Time) (deleted int64, err error) {
	if expiredAt.IsZero() {
		return 0, audit.ErrInvalidLifecycle
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin raw cleanup transaction: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("roll back raw cleanup transaction: %w", rollbackErr))
		}
	}()
	previousOverdue, err := lockDeletionOverdue(ctx, tx)
	if err != nil {
		return 0, err
	}

	result, err := tx.ExecContext(ctx, deleteExpiredRawContentSQL, expiredAt.UTC())
	if err != nil {
		return 0, fmt.Errorf("delete expired raw content: %w", err)
	}
	deleted, err = result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count deleted raw content: %w", err)
	}
	result, err = tx.ExecContext(ctx, markLifecycleCleanupSQL, expiredAt.UTC())
	if err != nil {
		return 0, fmt.Errorf("record raw cleanup completion: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil {
		return 0, fmt.Errorf("count cleanup state updates: %w", err)
	} else if affected != 1 {
		return 0, fmt.Errorf("record raw cleanup completion: %w", sql.ErrNoRows)
	}
	if previousOverdue.Valid {
		if err := appendOperationalEventTx(ctx, tx, operations.FaultTransition{
			Fault: operations.FaultRawDeletionOverdue, Active: false, OccurredAt: expiredAt.UTC(),
		}); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit raw cleanup transaction: %w", err)
	}
	committed = true
	return deleted, nil
}

func lockDeletionOverdue(ctx context.Context, tx *sql.Tx) (sql.NullTime, error) {
	var overdue sql.NullTime
	if err := tx.QueryRowContext(ctx, lockDeletionOverdueSQL).Scan(&overdue); err != nil {
		return sql.NullTime{}, fmt.Errorf("lock deletion lag state: %w", err)
	}
	return overdue, nil
}

func (r *Repository) PurgeRevokedVerificationHashes(ctx context.Context, purgeAt time.Time) (int64, error) {
	if purgeAt.IsZero() {
		return 0, audit.ErrInvalidLifecycle
	}
	result, err := r.db.ExecContext(ctx, purgeRevokedVerificationHashesSQL, purgeAt.UTC())
	if err != nil {
		return 0, fmt.Errorf("purge revoked verification hashes: %w", err)
	}
	purged, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("count purged verification hashes: %w", err)
	}
	return purged, nil
}

func (r *Repository) PurgeExpiredMetadata(ctx context.Context, purgeAt time.Time) (result audit.MetadataPurgeResult, err error) {
	if purgeAt.IsZero() {
		return audit.MetadataPurgeResult{}, audit.ErrInvalidLifecycle
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return audit.MetadataPurgeResult{}, fmt.Errorf("begin metadata cleanup transaction: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("roll back metadata cleanup transaction: %w", rollbackErr))
		}
	}()
	retentionAt := purgeAt.UTC()
	if _, err := tx.ExecContext(ctx, "SELECT set_config('n_api_p.retention_maintenance', 'on', true)"); err != nil {
		return audit.MetadataPurgeResult{}, fmt.Errorf("enable metadata retention maintenance: %w", err)
	}
	usageResult, err := tx.ExecContext(ctx, purgeExpiredUsageSQL, retentionAt.Add(-365*24*time.Hour))
	if err != nil {
		return audit.MetadataPurgeResult{}, fmt.Errorf("purge expired usage metadata: %w", err)
	}
	if result.UsageRows, err = usageResult.RowsAffected(); err != nil {
		return audit.MetadataPurgeResult{}, fmt.Errorf("count expired usage metadata: %w", err)
	}
	operationalResult, err := tx.ExecContext(ctx, purgeExpiredOperationalEventsSQL, retentionAt)
	if err != nil {
		return audit.MetadataPurgeResult{}, fmt.Errorf("purge expired operational metadata: %w", err)
	}
	if result.OperationalLogRows, err = operationalResult.RowsAffected(); err != nil {
		return audit.MetadataPurgeResult{}, fmt.Errorf("count expired operational metadata: %w", err)
	}
	securityResult, err := tx.ExecContext(ctx, purgeExpiredSecurityEventsSQL, retentionAt)
	if err != nil {
		return audit.MetadataPurgeResult{}, fmt.Errorf("purge expired security metadata: %w", err)
	}
	if result.SecurityEventRows, err = securityResult.RowsAffected(); err != nil {
		return audit.MetadataPurgeResult{}, fmt.Errorf("count expired security metadata: %w", err)
	}
	auditResult, err := tx.ExecContext(ctx, purgeExpiredAuditMetadataSQL, retentionAt.Add(-730*24*time.Hour))
	if err != nil {
		return audit.MetadataPurgeResult{}, fmt.Errorf("purge expired audit metadata: %w", err)
	}
	if result.AuditRows, err = auditResult.RowsAffected(); err != nil {
		return audit.MetadataPurgeResult{}, fmt.Errorf("count expired audit metadata: %w", err)
	}
	serviceResult, err := tx.ExecContext(ctx, purgeExpiredServiceAccountsSQL, retentionAt.Add(-730*24*time.Hour))
	if err != nil {
		return audit.MetadataPurgeResult{}, fmt.Errorf("purge expired service-account ownership: %w", err)
	}
	if result.OwnershipRows, err = serviceResult.RowsAffected(); err != nil {
		return audit.MetadataPurgeResult{}, fmt.Errorf("count expired service-account ownership: %w", err)
	}
	keyResult, err := tx.ExecContext(ctx, purgeExpiredRevokedKeysSQL, retentionAt.Add(-730*24*time.Hour))
	if err != nil {
		return audit.MetadataPurgeResult{}, fmt.Errorf("purge expired revoked-key ownership: %w", err)
	}
	keyRows, err := keyResult.RowsAffected()
	if err != nil {
		return audit.MetadataPurgeResult{}, fmt.Errorf("count expired revoked-key ownership: %w", err)
	}
	result.OwnershipRows += keyRows
	identityResult, err := tx.ExecContext(ctx, purgeExpiredDisabledIdentitiesSQL, retentionAt.Add(-730*24*time.Hour))
	if err != nil {
		return audit.MetadataPurgeResult{}, fmt.Errorf("purge expired identity ownership: %w", err)
	}
	identityRows, err := identityResult.RowsAffected()
	if err != nil {
		return audit.MetadataPurgeResult{}, fmt.Errorf("count expired identity ownership: %w", err)
	}
	result.OwnershipRows += identityRows
	if err := tx.Commit(); err != nil {
		return audit.MetadataPurgeResult{}, fmt.Errorf("commit metadata cleanup transaction: %w", err)
	}
	committed = true
	return result, nil
}

var _ audit.LifecycleRepository = (*Repository)(nil)
