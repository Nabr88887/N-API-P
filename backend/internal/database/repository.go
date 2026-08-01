package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const MaxPageSize = 100

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

func (r *Repository) ListAuditRecords(ctx context.Context, filter AuditListFilter) (records []AuditRecord, err error) {
	if filter.Limit < 1 || filter.Limit > MaxPageSize {
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

type EncryptedRawContent struct {
	Compression    string
	Ciphertext     []byte
	CipherNonce    []byte
	WrappedDataKey []byte
	WrapNonce      []byte
	KeyVersion     int
	ExpiresAt      time.Time
}

type CreatePendingAuditInput struct {
	ID                    string
	RequestID             string
	KeyID                 string
	OwnerKind             string
	IdentityID            *string
	ServiceAccountID      *string
	ResponsibleIdentityID *string
	TeamID                string
	ModelID               string
	ObservedRequestBytes  int64
	CreatedAt             time.Time
	RequestContent        EncryptedRawContent
}

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

func (r *Repository) CreatePendingAudit(ctx context.Context, input CreatePendingAuditInput) (err error) {
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
		input.OwnerKind,
		optionalString(input.IdentityID),
		optionalString(input.ServiceAccountID),
		optionalString(input.ResponsibleIdentityID),
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
		content.ExpiresAt,
	); err != nil {
		return fmt.Errorf("insert encrypted request content: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit pending audit transaction: %w", err)
	}
	committed = true
	return nil
}

func optionalString(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}
