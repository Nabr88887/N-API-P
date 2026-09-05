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
WITH candidates AS (
    SELECT id
    FROM usage_records
    WHERE created_at <= $1
    ORDER BY created_at, id
    LIMIT $2
)
DELETE FROM usage_records AS usage
USING candidates
WHERE usage.id = candidates.id`

const purgeExpiredOperationalEventsSQL = `
SELECT n_api_p_purge_security_events($1, 'operational', $2)`

const purgeExpiredSecurityEventsSQL = `
SELECT n_api_p_purge_security_events($1, 'security', $2)`

const purgeExpiredAuditMetadataSQL = `
WITH candidates AS (
    SELECT records.id
    FROM audit_records AS records
    WHERE records.created_at <= $1
      AND NOT EXISTS (SELECT 1 FROM audit_raw_content raw WHERE raw.audit_id = records.id)
      AND NOT EXISTS (SELECT 1 FROM usage_records usage WHERE usage.audit_id = records.id)
      AND NOT EXISTS (SELECT 1 FROM security_events events WHERE events.target_audit_id = records.id)
    ORDER BY records.created_at, records.id
    LIMIT $2
)
DELETE FROM audit_records AS records
USING candidates
WHERE records.id = candidates.id`

const purgeExpiredServiceAccountsSQL = `
WITH candidates AS (
    SELECT accounts.id
    FROM service_accounts AS accounts
    WHERE accounts.status = 'disabled'
      AND accounts.disabled_at IS NOT NULL
      AND accounts.disabled_at <= $1
      AND NOT EXISTS (SELECT 1 FROM api_keys keys WHERE keys.service_account_id = accounts.id)
      AND NOT EXISTS (SELECT 1 FROM audit_records records WHERE records.service_account_id = accounts.id)
      AND NOT EXISTS (SELECT 1 FROM usage_records usage WHERE usage.service_account_id = accounts.id)
      AND NOT EXISTS (SELECT 1 FROM security_events events WHERE events.target_service_account_id = accounts.id)
    ORDER BY accounts.disabled_at, accounts.id
    LIMIT $2
)
DELETE FROM service_accounts AS accounts
USING candidates
WHERE accounts.id = candidates.id`

const purgeExpiredRevokedKeysSQL = `
WITH candidates AS (
    SELECT keys.id
    FROM api_keys AS keys
    WHERE keys.status = 'revoked'
      AND keys.revoked_at IS NOT NULL
      AND keys.revoked_at <= $1
      AND NOT EXISTS (SELECT 1 FROM audit_records records WHERE records.key_id = keys.id)
      AND NOT EXISTS (SELECT 1 FROM usage_records usage WHERE usage.key_id = keys.id)
      AND NOT EXISTS (SELECT 1 FROM security_events events WHERE events.target_key_id = keys.id)
    ORDER BY keys.revoked_at, keys.id
    LIMIT $2
)
DELETE FROM api_keys AS keys
USING candidates
WHERE keys.id = candidates.id`

const purgeExpiredDisabledIdentitiesSQL = `
WITH candidates AS (
    SELECT identities.id
    FROM identities AS identities
    WHERE identities.status = 'disabled'
      AND identities.disabled_at IS NOT NULL
      AND identities.disabled_at <= $1
      AND NOT EXISTS (SELECT 1 FROM memberships memberships WHERE memberships.identity_id = identities.id)
      AND NOT EXISTS (SELECT 1 FROM sessions sessions WHERE sessions.identity_id = identities.id)
      AND NOT EXISTS (SELECT 1 FROM one_time_codes codes WHERE codes.identity_id = identities.id OR codes.issued_by_identity_id = identities.id)
      AND NOT EXISTS (SELECT 1 FROM model_allowlist models WHERE models.updated_by_identity_id = identities.id)
      AND NOT EXISTS (SELECT 1 FROM api_keys keys WHERE keys.identity_id = identities.id)
      AND NOT EXISTS (SELECT 1 FROM service_accounts accounts WHERE accounts.responsible_identity_id = identities.id)
      AND NOT EXISTS (SELECT 1 FROM audit_records records WHERE records.identity_id = identities.id OR records.responsible_identity_id = identities.id)
      AND NOT EXISTS (SELECT 1 FROM usage_records usage WHERE usage.identity_id = identities.id OR usage.responsible_identity_id = identities.id)
      AND NOT EXISTS (SELECT 1 FROM security_events events WHERE events.actor_identity_id = identities.id OR events.target_identity_id = identities.id)
    ORDER BY identities.disabled_at, identities.id
    LIMIT $2
)
DELETE FROM identities AS identities
USING candidates
WHERE identities.id = candidates.id`

const purgeExpiredIdentitySessionsSQL = `
WITH candidates AS (
    SELECT sessions.id
    FROM sessions
    JOIN identities ON identities.id = sessions.identity_id
    WHERE identities.status = 'disabled'
      AND identities.disabled_at IS NOT NULL
      AND identities.disabled_at <= $1
    ORDER BY sessions.id
    LIMIT $2
)
DELETE FROM sessions
USING candidates
WHERE sessions.id = candidates.id`

const purgeExpiredInvestigationCasesSQL = `
WITH candidates AS (
    SELECT cases.id
    FROM investigation_cases AS cases
    WHERE cases.status = 'closed'
      AND cases.closed_at IS NOT NULL
      AND cases.closed_at <= $1
      AND NOT EXISTS (
          SELECT 1
          FROM security_events AS events
          WHERE events.investigation_case_id = cases.id
      )
    ORDER BY cases.created_at, cases.id
    LIMIT $2
)
DELETE FROM investigation_cases AS cases
USING candidates
WHERE cases.id = candidates.id`

const purgeExpiredIdentityCodesSQL = `
WITH candidates AS (
    SELECT codes.id
    FROM one_time_codes AS codes
    WHERE EXISTS (
        SELECT 1
        FROM identities
        WHERE identities.status = 'disabled'
          AND identities.disabled_at IS NOT NULL
          AND identities.disabled_at <= $1
          AND (identities.id = codes.identity_id OR identities.id = codes.issued_by_identity_id)
    )
    ORDER BY codes.id
    LIMIT $2
)
DELETE FROM one_time_codes AS codes
USING candidates
WHERE codes.id = candidates.id`

const clearExpiredModelPolicyUpdatersSQL = `
WITH candidates AS (
    SELECT models.model_id
    FROM model_allowlist AS models
    JOIN identities ON identities.id = models.updated_by_identity_id
    WHERE identities.status = 'disabled'
      AND identities.disabled_at IS NOT NULL
      AND identities.disabled_at <= $1
    ORDER BY models.model_id
    LIMIT $2
)
UPDATE model_allowlist AS models
SET updated_by_identity_id = NULL
FROM candidates
WHERE models.model_id = candidates.model_id`

const purgeExpiredIdentityMembershipsSQL = `
WITH candidates AS (
    SELECT memberships.identity_id, memberships.team_id
    FROM memberships
    JOIN identities ON identities.id = memberships.identity_id
    WHERE identities.status = 'disabled'
      AND identities.disabled_at IS NOT NULL
      AND identities.disabled_at <= $1
      AND NOT EXISTS (
          SELECT 1
          FROM service_accounts
          WHERE service_accounts.responsible_identity_id = memberships.identity_id
            AND service_accounts.team_id = memberships.team_id
      )
    ORDER BY memberships.identity_id, memberships.team_id
    LIMIT $2
)
DELETE FROM memberships
USING candidates
WHERE memberships.identity_id = candidates.identity_id
  AND memberships.team_id = candidates.team_id`

const metadataPurgeBatchSize = 1000

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
	retentionAt := purgeAt.UTC()
	usageCutoff := retentionAt.AddDate(-1, 0, 0)
	ownershipCutoff := retentionAt.AddDate(-2, 0, 0)
	var purgeErrors []error

	if result.UsageRows, err = purgeMetadataRows(ctx, r.db, purgeExpiredUsageSQL, usageCutoff); err != nil {
		purgeErrors = append(purgeErrors, fmt.Errorf("purge expired usage metadata: %w", err))
	}
	if result.OperationalLogRows, err = purgeSecurityEvents(ctx, r.db, purgeExpiredOperationalEventsSQL, retentionAt); err != nil {
		purgeErrors = append(purgeErrors, fmt.Errorf("purge expired operational metadata: %w", err))
	}
	if result.SecurityEventRows, err = purgeSecurityEvents(ctx, r.db, purgeExpiredSecurityEventsSQL, retentionAt); err != nil {
		purgeErrors = append(purgeErrors, fmt.Errorf("purge expired security metadata: %w", err))
	}
	if result.AuditRows, err = purgeMetadataRows(ctx, r.db, purgeExpiredAuditMetadataSQL, ownershipCutoff); err != nil {
		purgeErrors = append(purgeErrors, fmt.Errorf("purge expired audit metadata: %w", err))
	}
	if result.OwnershipRows, err = r.purgeExpiredOwnership(ctx, ownershipCutoff); err != nil {
		purgeErrors = append(purgeErrors, err)
	}

	return result, errors.Join(purgeErrors...)
}

type metadataPurgeExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

type metadataPurgeQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func purgeMetadataRows(ctx context.Context, executor metadataPurgeExecutor, query string, cutoff time.Time) (int64, error) {
	result, err := executor.ExecContext(ctx, query, cutoff, metadataPurgeBatchSize)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func purgeSecurityEvents(ctx context.Context, querier metadataPurgeQuerier, query string, cutoff time.Time) (int64, error) {
	var purged int64
	if err := querier.QueryRowContext(ctx, query, cutoff, metadataPurgeBatchSize).Scan(&purged); err != nil {
		return 0, err
	}
	return purged, nil
}

func (r *Repository) purgeExpiredOwnership(ctx context.Context, cutoff time.Time) (purged int64, err error) {
	var purgeErrors []error
	for _, purge := range []struct {
		name  string
		query string
		count bool
	}{
		{name: "investigation cases", query: purgeExpiredInvestigationCasesSQL},
		{name: "identity sessions", query: purgeExpiredIdentitySessionsSQL},
		{name: "identity one-time codes", query: purgeExpiredIdentityCodesSQL},
		{name: "model-policy updater references", query: clearExpiredModelPolicyUpdatersSQL},
		{name: "revoked-key ownership", query: purgeExpiredRevokedKeysSQL, count: true},
		{name: "service-account ownership", query: purgeExpiredServiceAccountsSQL, count: true},
		{name: "identity memberships", query: purgeExpiredIdentityMembershipsSQL},
		{name: "identity ownership", query: purgeExpiredDisabledIdentitiesSQL, count: true},
	} {
		rows, purgeErr := purgeMetadataRows(ctx, r.db, purge.query, cutoff)
		if purgeErr != nil {
			purgeErrors = append(purgeErrors, fmt.Errorf("purge expired %s: %w", purge.name, purgeErr))
			continue
		}
		if purge.count {
			purged += rows
		}
	}
	return purged, errors.Join(purgeErrors...)
}

var _ audit.LifecycleRepository = (*Repository)(nil)
