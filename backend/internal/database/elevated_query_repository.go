package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"n-api-p/internal/audit"
)

const listElevatedAuditCandidatesSQL = `
SELECT records.id::text, records.request_id::text, records.owner_kind,
       COALESCE(records.identity_id::text, ''), COALESCE(records.service_account_id::text, ''),
       COALESCE(records.responsible_identity_id::text, ''), records.team_id::text, records.model_id,
       records.capture_status, records.outcome, records.upstream_request_id,
       records.upstream_http_status, records.error_code, records.finish_reason,
       records.observed_request_bytes, records.observed_response_bytes,
       records.created_at, records.updated_at, records.completed_at,
       usage.usage_reported, usage.input_tokens, usage.output_tokens, usage.total_tokens
FROM audit_records AS records
LEFT JOIN usage_records AS usage ON usage.audit_id = records.id
WHERE ($1::uuid IS NULL OR records.identity_id = $1 OR records.responsible_identity_id = $1)
  AND ($2::uuid IS NULL OR records.service_account_id = $2)
  AND ($3::uuid IS NULL OR records.responsible_identity_id = $3)
  AND ($4::timestamptz IS NULL OR records.created_at >= $4)
  AND ($5::timestamptz IS NULL OR records.created_at < $5)
  AND ($6::text IS NULL OR records.model_id = $6)
  AND ($7::text IS NULL OR records.capture_status = $7)
	  AND ($8::text IS NULL OR records.outcome = $8)
	  AND ($9::text IS NULL OR records.owner_kind = $9)
	  AND ($10::uuid[] IS NULL OR records.id = ANY($10::uuid[]))
	  AND EXISTS (
      SELECT 1
      FROM audit_raw_content AS raw
      WHERE raw.audit_id = records.id
	        AND raw.expires_at > $11
	  )
	  AND ($12::timestamptz IS NULL OR (records.created_at, records.id) < ($12, $13::uuid))
  AND records.created_at <= $15
ORDER BY records.created_at DESC, records.id DESC
LIMIT $14`

func (r *Repository) ListElevatedAuditCandidates(ctx context.Context, selection audit.ElevatedAuditSelection) ([]audit.ElevatedAuditCandidate, error) {
	if r == nil || r.db == nil || !validElevatedAuditSelection(selection) {
		return nil, audit.ErrInvalidElevatedAuditQuery
	}
	var cursorTime any
	var cursorID any
	if selection.Cursor != nil {
		cursorTime = selection.Cursor.CreatedAt.UTC()
		cursorID = selection.Cursor.ID
	}
	auditIDs, err := optionalElevatedAuditIDs(selection.AuditIDs)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, listElevatedAuditCandidatesSQL,
		optionalElevatedAuditID(selection.IdentityID), optionalElevatedAuditID(selection.ServiceAccountID), optionalElevatedAuditID(selection.ResponsibleIdentityID),
		optionalElevatedAuditTime(selection.From), optionalElevatedAuditTime(selection.To), optionalElevatedAuditString(selection.ModelID),
		optionalElevatedAuditCaptureStatus(selection.CaptureStatus), optionalElevatedAuditOutcome(selection.Outcome), optionalElevatedAuditOwnerKind(selection.OwnerKind),
		auditIDs, selection.VisibleAt.UTC(), cursorTime, cursorID, selection.Limit, selection.SnapshotAt.UTC(),
	)
	if err != nil {
		return nil, fmt.Errorf("query elevated audit candidates: %w", err)
	}
	defer rows.Close()
	var candidates []audit.ElevatedAuditCandidate
	for rows.Next() {
		var metadata audit.Metadata
		var upstreamRequestID, errorCode, finishReason sql.NullString
		var upstreamHTTPStatus sql.NullInt64
		var completedAt sql.NullTime
		var usageReported sql.NullBool
		var inputTokens, outputTokens, totalTokens sql.NullInt64
		if err := rows.Scan(
			&metadata.ID, &metadata.RequestID, &metadata.OwnerKind, &metadata.IdentityID, &metadata.ServiceAccountID,
			&metadata.ResponsibleIdentityID, &metadata.TeamID, &metadata.ModelID, &metadata.CaptureStatus, &metadata.Outcome,
			&upstreamRequestID, &upstreamHTTPStatus, &errorCode, &finishReason, &metadata.ObservedRequestBytes,
			&metadata.ObservedResponseBytes, &metadata.CreatedAt, &metadata.UpdatedAt, &completedAt,
			&usageReported, &inputTokens, &outputTokens, &totalTokens,
		); err != nil {
			return nil, fmt.Errorf("scan elevated audit candidate: %w", err)
		}
		metadata.UpstreamRequestID = upstreamRequestID.String
		metadata.ErrorCode = errorCode.String
		metadata.FinishReason = finishReason.String
		if upstreamHTTPStatus.Valid {
			value := int(upstreamHTTPStatus.Int64)
			metadata.UpstreamHTTPStatus = &value
		}
		if completedAt.Valid {
			value := completedAt.Time
			metadata.CompletedAt = &value
		}
		candidate := audit.ElevatedAuditCandidate{Metadata: metadata}
		if usageReported.Valid && usageReported.Bool {
			if !inputTokens.Valid || !outputTokens.Valid || !totalTokens.Valid {
				return nil, errors.New("elevated audit usage record is incomplete")
			}
			candidate.Usage = &audit.AuditUsage{InputTokens: inputTokens.Int64, OutputTokens: outputTokens.Int64, TotalTokens: totalTokens.Int64}
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate elevated audit candidates: %w", err)
	}
	return candidates, nil
}

func validElevatedAuditSelection(selection audit.ElevatedAuditSelection) bool {
	if selection.Limit < 1 || selection.Limit > audit.ElevatedAuditMaxQueryPageSize+1 || selection.VisibleAt.IsZero() || selection.SnapshotAt.IsZero() || selection.SnapshotAt.After(selection.VisibleAt) {
		return false
	}
	for _, value := range []*string{selection.IdentityID, selection.ServiceAccountID, selection.ResponsibleIdentityID} {
		if value != nil && !validUUID(strings.TrimSpace(*value)) {
			return false
		}
	}
	if selection.ModelID != nil && strings.TrimSpace(*selection.ModelID) == "" {
		return false
	}
	if selection.From != nil && selection.To != nil && !selection.From.Before(*selection.To) {
		return false
	}
	if selection.Cursor != nil && (!validUUID(selection.Cursor.ID) || selection.Cursor.CreatedAt.IsZero()) {
		return false
	}
	if len(selection.AuditIDs) > audit.MaxElevatedAuditBatchIDs {
		return false
	}
	for _, auditID := range selection.AuditIDs {
		if !validUUID(auditID) {
			return false
		}
	}
	if selection.CaptureStatus != nil && !validDatabaseCaptureStatus(*selection.CaptureStatus) {
		return false
	}
	if selection.Outcome != nil && !validDatabaseAuditOutcome(*selection.Outcome) {
		return false
	}
	return selection.OwnerKind == nil || *selection.OwnerKind == audit.OwnerKindPersonal || *selection.OwnerKind == audit.OwnerKindService
}

func optionalElevatedAuditIDs(values []string) (any, error) {
	if len(values) == 0 {
		return nil, nil
	}
	encoded := make(pgtype.FlatArray[pgtype.UUID], len(values))
	for index, value := range values {
		if err := encoded[index].Scan(value); err != nil {
			return nil, audit.ErrInvalidElevatedAuditQuery
		}
	}
	return encoded, nil
}

func validDatabaseCaptureStatus(status audit.CaptureStatus) bool {
	switch status {
	case audit.CaptureStatusPending, audit.CaptureStatusComplete, audit.CaptureStatusTruncated, audit.CaptureStatusIncomplete:
		return true
	default:
		return false
	}
}

func validDatabaseAuditOutcome(outcome audit.AuditOutcome) bool {
	switch outcome {
	case audit.AuditOutcomePending, audit.AuditOutcomeSuccess, audit.AuditOutcomeUpstreamError, audit.AuditOutcomeCancelled, audit.AuditOutcomeLocalError:
		return true
	default:
		return false
	}
}

func optionalElevatedAuditID(value *string) any {
	if value == nil || strings.TrimSpace(*value) == "" {
		return nil
	}
	return strings.TrimSpace(*value)
}

func optionalElevatedAuditTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC()
}

func optionalElevatedAuditString(value *string) any {
	if value == nil {
		return nil
	}
	return strings.TrimSpace(*value)
}

func optionalElevatedAuditCaptureStatus(value *audit.CaptureStatus) any {
	if value == nil {
		return nil
	}
	return string(*value)
}

func optionalElevatedAuditOutcome(value *audit.AuditOutcome) any {
	if value == nil {
		return nil
	}
	return string(*value)
}

func optionalElevatedAuditOwnerKind(value *audit.OwnerKind) any {
	if value == nil {
		return nil
	}
	return string(*value)
}
