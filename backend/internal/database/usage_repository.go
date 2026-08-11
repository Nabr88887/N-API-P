package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"n-api-p/internal/usage"
)

type UsageCursor struct {
	CreatedAt time.Time
	ID        string
}

type UsageListFilter struct {
	IdentityID string
	Cursor     *UsageCursor
	Limit      int
}

type UsageRecord struct {
	ID               string
	AuditID          string
	RequestID        string
	KeyID            string
	IdentityID       string
	ServiceAccountID sql.NullString
	TeamID           string
	ModelID          string
	Outcome          string
	UsageReported    bool
	InputTokens      sql.NullInt64
	OutputTokens     sql.NullInt64
	TotalTokens      sql.NullInt64
	PriceVersion     sql.NullString
	CalculatedAmount sql.NullString
	CreatedAt        time.Time
}

const listOwnUsageRecordsSQL = `
SELECT id::text, audit_id::text, request_id::text, key_id::text,
       identity_id::text, service_account_id::text, team_id::text, model_id, outcome, usage_reported,
       input_tokens, output_tokens, total_tokens, price_version,
       calculated_amount::text, created_at
FROM usage_records
WHERE identity_id = $1
  AND owner_kind = 'personal'
  AND ($2::timestamptz IS NULL OR (created_at, id) < ($2, $3::uuid))
ORDER BY created_at DESC, id DESC
LIMIT $4`

func (r *Repository) ListUsageRecords(ctx context.Context, filter UsageListFilter) (records []UsageRecord, err error) {
	if r == nil || r.db == nil || filter.IdentityID == "" || filter.Limit < 1 || filter.Limit > MaxPageSize+1 {
		return nil, ErrInvalidPageSize
	}
	var cursorTime any
	var cursorID any
	if filter.Cursor != nil {
		cursorTime = filter.Cursor.CreatedAt
		cursorID = filter.Cursor.ID
	}
	rows, err := r.db.QueryContext(ctx, listOwnUsageRecordsSQL, filter.IdentityID, cursorTime, cursorID, filter.Limit)
	if err != nil {
		return nil, fmt.Errorf("query own usage records: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close own usage rows: %w", closeErr))
		}
	}()
	for rows.Next() {
		var record UsageRecord
		if err := scanUsageRecord(rows, &record); err != nil {
			return nil, fmt.Errorf("scan own usage record: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate own usage records: %w", err)
	}
	return records, nil
}

type usageRecordScanner interface {
	Scan(...any) error
}

func scanUsageRecord(scanner usageRecordScanner, record *UsageRecord) error {
	return scanner.Scan(&record.ID, &record.AuditID, &record.RequestID, &record.KeyID,
		&record.IdentityID, &record.ServiceAccountID, &record.TeamID, &record.ModelID,
		&record.Outcome, &record.UsageReported, &record.InputTokens,
		&record.OutputTokens, &record.TotalTokens, &record.PriceVersion,
		&record.CalculatedAmount, &record.CreatedAt)
}

const insertUsageRecordSQL = `
INSERT INTO usage_records (
    id,
    audit_id,
    request_id,
    key_id,
    owner_kind,
    identity_id,
    service_account_id,
    responsible_identity_id,
    team_id,
    model_id,
    upstream_request_id,
    outcome,
    usage_reported,
    input_tokens,
    output_tokens,
    total_tokens,
    price_version,
    input_unit_price,
    output_unit_price,
    calculated_amount,
    created_at
) SELECT
    $1,
    audit.id,
    audit.request_id,
    audit.key_id,
    audit.owner_kind,
    audit.identity_id,
    audit.service_account_id,
    audit.responsible_identity_id,
    audit.team_id,
    audit.model_id,
    audit.upstream_request_id,
    audit.outcome,
    $13,
    $14,
    $15,
    $16,
    $17,
    $18,
    $19,
    $20,
    $21
FROM audit_records AS audit
WHERE audit.id = $2::uuid
  AND audit.request_id = $3::uuid
  AND audit.key_id = $4::uuid
  AND audit.owner_kind = $5
  AND audit.identity_id IS NOT DISTINCT FROM $6::uuid
  AND audit.service_account_id IS NOT DISTINCT FROM $7::uuid
  AND audit.responsible_identity_id IS NOT DISTINCT FROM $8::uuid
  AND audit.team_id = $9::uuid
  AND audit.model_id = $10
  AND audit.capture_status IN ('complete', 'truncated', 'incomplete')
  AND audit.completed_at IS NOT NULL
  AND audit.upstream_request_id IS NOT DISTINCT FROM NULLIF($11::text, '')
  AND audit.outcome = $12`

func (r *Repository) CreateUsageRecord(ctx context.Context, record usage.Record) error {
	if r == nil || r.db == nil || record.Validate() != nil {
		return usage.ErrInvalidRecord
	}
	var inputTokens, outputTokens, totalTokens any
	if record.Usage != nil {
		inputTokens = record.Usage.InputTokens
		outputTokens = record.Usage.OutputTokens
		totalTokens = record.Usage.TotalTokens
	}
	var priceVersion, inputUnitPrice, outputUnitPrice, calculatedAmount any
	if record.Price != nil {
		priceVersion = record.Price.Version
		inputUnitPrice = record.Price.InputUnitPrice
		outputUnitPrice = record.Price.OutputUnitPrice
		calculatedAmount = record.CalculatedAmount
	}
	result, err := r.db.ExecContext(
		ctx,
		insertUsageRecordSQL,
		record.ID,
		record.AuditID,
		record.RequestID,
		record.KeyID,
		string(record.OwnerKind),
		optionalAuditOwnerID(record.IdentityID),
		optionalAuditOwnerID(record.ServiceAccountID),
		optionalAuditOwnerID(record.ResponsibleIdentityID),
		record.TeamID,
		record.ModelID,
		record.UpstreamRequestID,
		string(record.Outcome),
		record.UsageReported,
		inputTokens,
		outputTokens,
		totalTokens,
		priceVersion,
		inputUnitPrice,
		outputUnitPrice,
		calculatedAmount,
		record.CreatedAt,
	)
	if err == nil {
		rows, rowsErr := result.RowsAffected()
		if rowsErr != nil {
			return fmt.Errorf("inspect usage record insert: %w", rowsErr)
		}
		if rows != 1 {
			return usage.ErrInvalidRecord
		}
		return nil
	}
	if isUsageRecordConflict(err) {
		return errors.Join(usage.ErrUsageAlreadyRecorded, fmt.Errorf("insert usage record: %w", err))
	}
	return fmt.Errorf("insert usage record: %w", err)
}

func isUsageRecordConflict(err error) bool {
	var postgresError *pgconn.PgError
	if !errors.As(err, &postgresError) || postgresError.Code != postgresUniqueViolation {
		return false
	}
	switch postgresError.ConstraintName {
	case "usage_records_audit_id_key", "usage_records_request_id_key":
		return true
	default:
		return false
	}
}
