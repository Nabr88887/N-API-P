package database

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"n-api-p/internal/audit"
	"n-api-p/internal/operations"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

const MaxPageSize = 100
const maxAuditQuerySize = MaxPageSize + 1

var ErrInvalidPageSize = errors.New("page size must be between 1 and 100")

type Repository struct {
	db *sql.DB
}

func NewRepository(db *sql.DB) *Repository {
	return &Repository{db: db}
}

type AuditCursor struct {
	CreatedAt time.Time
	ID        string
}

type AuditListFilter struct {
	IdentityID    *string
	TeamID        *string
	CaptureStatus *string
	ModelID       *string
	Cursor        *AuditCursor
	Limit         int
}

type AuditRecord struct {
	ID                    string
	RequestID             string
	KeyID                 string
	OwnerKind             string
	IdentityID            sql.NullString
	ServiceAccountID      sql.NullString
	ResponsibleIdentityID sql.NullString
	TeamID                string
	ModelID               string
	CaptureStatus         string
	Outcome               string
	UpstreamRequestID     sql.NullString
	UpstreamHTTPStatus    sql.NullInt64
	ErrorCode             sql.NullString
	FinishReason          sql.NullString
	ObservedRequestBytes  int64
	ObservedResponseBytes int64
	CreatedAt             time.Time
	UpdatedAt             time.Time
	CompletedAt           sql.NullTime
}

const listAuditRecordsSQL = `
SELECT
    id::text,
    request_id::text,
    key_id::text,
    owner_kind,
    identity_id::text,
    service_account_id::text,
    responsible_identity_id::text,
    team_id::text,
    model_id,
    capture_status,
    outcome,
    upstream_request_id,
    upstream_http_status,
    error_code,
    finish_reason,
    observed_request_bytes,
    observed_response_bytes,
    created_at,
    updated_at,
    completed_at
FROM audit_records
WHERE ($1::uuid IS NULL OR identity_id = $1)
  AND ($2::uuid IS NULL OR team_id = $2)
  AND ($3::text IS NULL OR capture_status = $3)
  AND ($4::text IS NULL OR model_id = $4)
  AND ($5::timestamptz IS NULL OR (created_at, id) < ($5, $6::uuid))
ORDER BY created_at DESC, id DESC
LIMIT $7`

const getAuditRecordSQL = `
SELECT
    id::text,
    request_id::text,
    key_id::text,
    owner_kind,
    identity_id::text,
    service_account_id::text,
    responsible_identity_id::text,
    team_id::text,
    model_id,
    capture_status,
    outcome,
    upstream_request_id,
    upstream_http_status,
    error_code,
    finish_reason,
    observed_request_bytes,
    observed_response_bytes,
    created_at,
    updated_at,
    completed_at
FROM audit_records
WHERE id = $1`

func (r *Repository) ListAuditRecords(ctx context.Context, filter AuditListFilter) (records []AuditRecord, err error) {
	if filter.Limit < 1 || filter.Limit > MaxPageSize {
		return nil, ErrInvalidPageSize
	}
	return r.listAuditRecords(ctx, filter)
}

func (r *Repository) listAuditRecords(ctx context.Context, filter AuditListFilter) (records []AuditRecord, err error) {
	if filter.Limit < 1 || filter.Limit > maxAuditQuerySize {
		return nil, ErrInvalidPageSize
	}

	var cursorTime any
	var cursorID any
	if filter.Cursor != nil {
		cursorTime = filter.Cursor.CreatedAt
		cursorID = filter.Cursor.ID
	}

	rows, err := r.db.QueryContext(
		ctx,
		listAuditRecordsSQL,
		optionalString(filter.IdentityID),
		optionalString(filter.TeamID),
		optionalString(filter.CaptureStatus),
		optionalString(filter.ModelID),
		cursorTime,
		cursorID,
		filter.Limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query audit records: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close audit record rows: %w", closeErr))
		}
	}()

	for rows.Next() {
		var record AuditRecord
		if err := rows.Scan(
			&record.ID,
			&record.RequestID,
			&record.KeyID,
			&record.OwnerKind,
			&record.IdentityID,
			&record.ServiceAccountID,
			&record.ResponsibleIdentityID,
			&record.TeamID,
			&record.ModelID,
			&record.CaptureStatus,
			&record.Outcome,
			&record.UpstreamRequestID,
			&record.UpstreamHTTPStatus,
			&record.ErrorCode,
			&record.FinishReason,
			&record.ObservedRequestBytes,
			&record.ObservedResponseBytes,
			&record.CreatedAt,
			&record.UpdatedAt,
			&record.CompletedAt,
		); err != nil {
			return nil, fmt.Errorf("scan audit record: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit records: %w", err)
	}
	return records, nil
}

func (r *Repository) ListAuditMetadata(ctx context.Context, filter audit.MetadataFilter) (audit.MetadataPage, error) {
	if filter.Limit < 1 || filter.Limit > audit.MaxMetadataPageSize {
		return audit.MetadataPage{}, audit.ErrInvalidMetadataRequest
	}
	cursor, err := decodeAuditMetadataCursor(filter.Cursor)
	if err != nil {
		return audit.MetadataPage{}, audit.ErrInvalidMetadataRequest
	}
	databaseFilter := AuditListFilter{
		IdentityID: filter.IdentityID, TeamID: filter.TeamID, ModelID: filter.ModelID,
		Cursor: cursor, Limit: filter.Limit + 1,
	}
	if filter.CaptureStatus != nil {
		value := string(*filter.CaptureStatus)
		databaseFilter.CaptureStatus = &value
	}
	records, err := r.listAuditRecords(ctx, databaseFilter)
	if err != nil {
		if isAuditMetadataDatabaseUnavailable(err) {
			return audit.MetadataPage{}, fmt.Errorf("%w: %w", audit.ErrMetadataUnavailable, err)
		}
		return audit.MetadataPage{}, err
	}
	page := audit.MetadataPage{Records: make([]audit.Metadata, 0, min(len(records), filter.Limit))}
	for index, record := range records {
		if index == filter.Limit {
			last := records[index-1]
			page.NextCursor = encodeAuditMetadataCursor(AuditCursor{CreatedAt: last.CreatedAt, ID: last.ID})
			break
		}
		page.Records = append(page.Records, auditMetadata(record))
	}
	return page, nil
}

func (r *Repository) GetAuditMetadata(ctx context.Context, auditID string) (audit.Metadata, error) {
	record, err := scanAuditRecord(r.db.QueryRowContext(ctx, getAuditRecordSQL, auditID))
	if errors.Is(err, sql.ErrNoRows) {
		return audit.Metadata{}, audit.ErrMetadataNotFound
	}
	if err != nil {
		if isAuditMetadataDatabaseUnavailable(err) {
			return audit.Metadata{}, fmt.Errorf("%w: %w", audit.ErrMetadataUnavailable, err)
		}
		return audit.Metadata{}, fmt.Errorf("get audit metadata: %w", err)
	}
	return auditMetadata(record), nil
}

func isAuditMetadataDatabaseUnavailable(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, sql.ErrConnDone) || errors.Is(err, driver.ErrBadConn) || errors.Is(err, pgconn.ErrConnClosed) {
		return true
	}
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) {
		switch postgresError.Code {
		case "53300", "57P01", "57P02", "57P03", "57P05":
			return true
		default:
			return strings.HasPrefix(postgresError.Code, "08")
		}
	}
	var connectError *pgconn.ConnectError
	var networkError *net.OpError
	return errors.As(err, &connectError) || errors.As(err, &networkError)
}

type auditRecordScanner interface {
	Scan(...any) error
}

func scanAuditRecord(scanner auditRecordScanner) (AuditRecord, error) {
	var record AuditRecord
	err := scanner.Scan(
		&record.ID, &record.RequestID, &record.KeyID, &record.OwnerKind,
		&record.IdentityID, &record.ServiceAccountID, &record.ResponsibleIdentityID,
		&record.TeamID, &record.ModelID, &record.CaptureStatus, &record.Outcome,
		&record.UpstreamRequestID, &record.UpstreamHTTPStatus, &record.ErrorCode,
		&record.FinishReason, &record.ObservedRequestBytes, &record.ObservedResponseBytes,
		&record.CreatedAt, &record.UpdatedAt, &record.CompletedAt,
	)
	return record, err
}

func auditMetadata(record AuditRecord) audit.Metadata {
	metadata := audit.Metadata{
		ID: record.ID, RequestID: record.RequestID, KeyID: record.KeyID, OwnerKind: audit.OwnerKind(record.OwnerKind),
		IdentityID: record.IdentityID.String, ServiceAccountID: record.ServiceAccountID.String,
		ResponsibleIdentityID: record.ResponsibleIdentityID.String, TeamID: record.TeamID, ModelID: record.ModelID,
		CaptureStatus: audit.CaptureStatus(record.CaptureStatus), Outcome: audit.AuditOutcome(record.Outcome),
		UpstreamRequestID: record.UpstreamRequestID.String, ErrorCode: record.ErrorCode.String,
		FinishReason: record.FinishReason.String, ObservedRequestBytes: record.ObservedRequestBytes,
		ObservedResponseBytes: record.ObservedResponseBytes, CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
	}
	if record.UpstreamHTTPStatus.Valid {
		value := int(record.UpstreamHTTPStatus.Int64)
		metadata.UpstreamHTTPStatus = &value
	}
	if record.CompletedAt.Valid {
		value := record.CompletedAt.Time
		metadata.CompletedAt = &value
	}
	return metadata
}

func encodeAuditMetadataCursor(cursor AuditCursor) string {
	payload, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeAuditMetadataCursor(value string) (*AuditCursor, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if len(value) > 512 {
		return nil, audit.ErrInvalidMetadataRequest
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, audit.ErrInvalidMetadataRequest
	}
	var cursor AuditCursor
	if err := json.Unmarshal(payload, &cursor); err != nil || cursor.CreatedAt.IsZero() || !validAuditMetadataUUID(cursor.ID) {
		return nil, audit.ErrInvalidMetadataRequest
	}
	return &cursor, nil
}

func validAuditMetadataUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}

var _ audit.MetadataRepository = (*Repository)(nil)

const insertPendingAuditSQL = `
INSERT INTO audit_records (
    id,
    request_id,
    key_id,
    owner_kind,
    identity_id,
    service_account_id,
    responsible_identity_id,
    team_id,
    model_id,
    capture_status,
    outcome,
    observed_request_bytes,
    observed_response_bytes,
    created_at,
    updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending', 'pending', $10, 0, $11, $11)`

const insertRequestContentSQL = `
INSERT INTO audit_raw_content (
    audit_id,
    content_kind,
    compression,
    ciphertext,
    cipher_nonce,
    wrapped_data_key,
    wrap_nonce,
    key_version,
    created_at,
    expires_at
) VALUES ($1, 'request', $2, $3, $4, $5, $6, $7, $8, $9)`

const updateFinalAuditSQL = `
UPDATE audit_records
SET capture_status = $3,
    outcome = $4,
    upstream_request_id = $5,
    upstream_http_status = $6,
    error_code = $7,
    finish_reason = $8,
    observed_response_bytes = $9,
    updated_at = $10,
    completed_at = $10
WHERE id = $1
  AND request_id = $2
  AND capture_status = 'pending'
  AND outcome = 'pending'`

const insertResponseContentSQL = `
INSERT INTO audit_raw_content (
    audit_id,
    content_kind,
    compression,
    ciphertext,
    cipher_nonce,
    wrapped_data_key,
    wrap_nonce,
    key_version,
    created_at,
    expires_at
) SELECT
    $1,
    'response',
    $2,
    $3,
    $4,
    $5,
    $6,
    $7,
    created_at,
    expires_at
FROM audit_raw_content
WHERE audit_id = $1 AND content_kind = 'request'`

const readAuditGateSQL = `
SELECT audit_gate_state, audit_gate_reason_code, gate_changed_at, last_persistence_probe_at
FROM operational_state
WHERE id = 1`

const lockAuditGateStateSQL = `
SELECT audit_gate_state
FROM operational_state
WHERE id = 1
FOR UPDATE`

const blockAuditGateSQL = `
UPDATE operational_state
SET audit_gate_state = 'blocked',
    audit_gate_reason_code = $1,
    gate_changed_at = $2,
    updated_at = $2
WHERE id = 1`

const markAuditIncompleteSQL = `
UPDATE audit_records
SET capture_status = 'incomplete',
    outcome = 'local_error',
    error_code = $3,
    updated_at = $4,
    completed_at = $4
WHERE id = $1
  AND request_id = $2
  AND (
      (capture_status = 'pending' AND outcome = 'pending')
      OR (capture_status = 'complete' AND outcome IN ('success', 'upstream_error'))
      OR (capture_status = 'truncated' AND outcome IN ('success', 'upstream_error', 'local_error'))
      OR (capture_status = 'incomplete' AND outcome IN ('cancelled', 'local_error'))
  )`

const reconcileStalePendingSQL = `
UPDATE audit_records
SET capture_status = 'incomplete',
    outcome = 'local_error',
    error_code = $1,
    updated_at = $3,
    completed_at = $3
WHERE capture_status = 'pending'
  AND outcome = 'pending'
  AND updated_at < $2`

const openAuditGateSQL = `
UPDATE operational_state
SET audit_gate_state = 'open',
    audit_gate_reason_code = NULL,
    gate_changed_at = $1,
    last_persistence_probe_at = $1,
    updated_at = $1
WHERE id = 1`

func (r *Repository) CreatePendingAudit(ctx context.Context, input audit.PendingAudit) (err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin pending audit transaction: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("roll back pending audit transaction: %w", rollbackErr))
		}
	}()

	if _, err := tx.ExecContext(
		ctx,
		insertPendingAuditSQL,
		input.ID,
		input.RequestID,
		input.KeyID,
		string(input.OwnerKind),
		optionalAuditOwnerID(input.IdentityID),
		optionalAuditOwnerID(input.ServiceAccountID),
		optionalAuditOwnerID(input.ResponsibleIdentityID),
		input.TeamID,
		input.ModelID,
		input.ObservedRequestBytes,
		input.CreatedAt,
	); err != nil {
		return fmt.Errorf("insert pending audit record: %w", err)
	}

	content := input.RequestContent
	if _, err := tx.ExecContext(
		ctx,
		insertRequestContentSQL,
		input.ID,
		content.Compression,
		content.Ciphertext,
		content.CipherNonce,
		content.WrappedDataKey,
		content.WrapNonce,
		content.KeyVersion,
		input.CreatedAt,
		input.ExpiresAt,
	); err != nil {
		return fmt.Errorf("insert encrypted request content: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit pending audit transaction: %w", err)
	}
	committed = true
	return nil
}

func (r *Repository) FinalizeAudit(ctx context.Context, input audit.FinalAudit) (err error) {
	if err := audit.ValidateFinalizationStatus(input.CaptureStatus, input.Outcome); err != nil {
		return err
	}
	if (input.CaptureStatus == audit.CaptureStatusComplete || input.CaptureStatus == audit.CaptureStatusTruncated) && input.ResponseContent == nil {
		return audit.ErrInvalidFinalization
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin final audit transaction: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("roll back final audit transaction: %w", rollbackErr))
		}
	}()

	result, err := tx.ExecContext(
		ctx,
		updateFinalAuditSQL,
		input.ID,
		input.RequestID,
		string(input.CaptureStatus),
		string(input.Outcome),
		optionalStringValue(input.UpstreamRequestID),
		optionalIntValue(input.UpstreamHTTPStatus),
		optionalStringValue(input.ErrorCode),
		optionalStringValue(input.FinishReason),
		input.ObservedResponseBytes,
		input.CompletedAt,
	)
	if err != nil {
		return fmt.Errorf("update pending audit record: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect final audit transition: %w", err)
	}
	if rows != 1 {
		return audit.ErrAuditNotPending
	}

	if input.ResponseContent != nil {
		content := input.ResponseContent
		result, err := tx.ExecContext(
			ctx,
			insertResponseContentSQL,
			input.ID,
			content.Compression,
			content.Ciphertext,
			content.CipherNonce,
			content.WrappedDataKey,
			content.WrapNonce,
			content.KeyVersion,
		)
		if err != nil {
			return fmt.Errorf("insert encrypted response content: %w", err)
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return fmt.Errorf("inspect response content insert: %w", err)
		}
		if rows != 1 {
			return fmt.Errorf("%w: request content missing", audit.ErrAuditNotPending)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit final audit transaction: %w", err)
	}
	committed = true
	return nil
}

func (r *Repository) ReadAuditGate(ctx context.Context) (audit.AuditGateSnapshot, error) {
	var snapshot audit.AuditGateSnapshot
	var reason sql.NullString
	var lastProbe sql.NullTime
	if err := r.db.QueryRowContext(ctx, readAuditGateSQL).Scan(&snapshot.State, &reason, &snapshot.ChangedAt, &lastProbe); err != nil {
		return audit.AuditGateSnapshot{}, fmt.Errorf("read audit gate: %w", err)
	}
	if reason.Valid {
		snapshot.ReasonCode = reason.String
	}
	if lastProbe.Valid {
		value := lastProbe.Time
		snapshot.LastPersistenceProbeAt = &value
	}
	return snapshot, nil
}

func (r *Repository) BlockAuditGate(ctx context.Context, reason string, changedAt time.Time) (err error) {
	if err := audit.ValidateGateReason(reason); err != nil || changedAt.IsZero() {
		return audit.ErrInvalidDegradedStateMachine
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin audit gate block: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("roll back audit gate block: %w", rollbackErr))
		}
	}()
	if err := blockAuditGateTx(ctx, tx, reason, changedAt.UTC()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit audit gate block: %w", err)
	}
	committed = true
	return nil
}

func (r *Repository) MarkAuditIncompleteAndBlock(ctx context.Context, auditID, requestID, reason string, completedAt time.Time) (err error) {
	if auditID == "" || requestID == "" || completedAt.IsZero() {
		return audit.ErrInvalidDegradedStateMachine
	}
	if err := audit.ValidateGateReason(reason); err != nil {
		return err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin audit failure transaction: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("roll back audit failure transaction: %w", rollbackErr))
		}
	}()

	if _, err := tx.ExecContext(ctx, markAuditIncompleteSQL, auditID, requestID, reason, completedAt.UTC()); err != nil {
		return fmt.Errorf("mark failed audit incomplete: %w", err)
	}
	if err := blockAuditGateTx(ctx, tx, reason, completedAt.UTC()); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit audit failure transaction: %w", err)
	}
	committed = true
	return nil
}

func (r *Repository) ReconcileAndOpenAuditGate(ctx context.Context, staleBefore, openedAt time.Time) (err error) {
	if staleBefore.IsZero() || openedAt.IsZero() || staleBefore.After(openedAt) {
		return audit.ErrInvalidDegradedStateMachine
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin audit recovery transaction: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("roll back audit recovery transaction: %w", rollbackErr))
		}
	}()

	if _, err := tx.ExecContext(ctx, reconcileStalePendingSQL, audit.GateReasonProcessRestart, staleBefore.UTC(), openedAt.UTC()); err != nil {
		return fmt.Errorf("reconcile stale audits: %w", err)
	}
	previousState, err := lockAuditGateState(ctx, tx)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, openAuditGateSQL, openedAt.UTC())
	if err != nil {
		return fmt.Errorf("probe and open audit gate: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect audit gate recovery: %w", err)
	}
	if rows != 1 {
		return fmt.Errorf("probe and open audit gate: %w", sql.ErrNoRows)
	}
	if previousState == audit.AuditGateStateBlocked {
		if err := appendOperationalEventTx(ctx, tx, operations.FaultTransition{
			Fault: operations.FaultAuditUnavailable, Active: false, OccurredAt: openedAt.UTC(),
		}); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit audit recovery transaction: %w", err)
	}
	committed = true
	return nil
}

func blockAuditGateTx(ctx context.Context, tx *sql.Tx, reason string, changedAt time.Time) error {
	previousState, err := lockAuditGateState(ctx, tx)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, blockAuditGateSQL, reason, changedAt.UTC())
	if err != nil {
		return fmt.Errorf("persist audit gate block: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("inspect audit gate block: %w", err)
	}
	if rows != 1 {
		return fmt.Errorf("persist audit gate block: %w", sql.ErrNoRows)
	}
	if previousState != audit.AuditGateStateBlocked {
		if err := appendOperationalEventTx(ctx, tx, operations.FaultTransition{
			Fault: operations.FaultAuditUnavailable, Active: true, OccurredAt: changedAt.UTC(),
		}); err != nil {
			return err
		}
	}
	return nil
}

func lockAuditGateState(ctx context.Context, tx *sql.Tx) (audit.AuditGateState, error) {
	var state audit.AuditGateState
	if err := tx.QueryRowContext(ctx, lockAuditGateStateSQL).Scan(&state); err != nil {
		return "", fmt.Errorf("lock audit gate state: %w", err)
	}
	return state, nil
}

func optionalAuditOwnerID(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func optionalStringValue(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func optionalIntValue(value *int) any {
	if value == nil {
		return nil
	}
	return *value
}

func optionalString(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}
