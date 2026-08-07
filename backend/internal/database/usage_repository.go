package database

import (
	"context"
	"errors"
	"fmt"
	"n-api-p/internal/usage"

	"github.com/jackc/pgx/v5/pgconn"
)

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
