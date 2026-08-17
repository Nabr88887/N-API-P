package database

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"n-api-p/internal/operations"
)

const readCriticalFaultsSQL = `
WITH state_faults AS (
    SELECT
        'audit_unavailable'::text AS fault_code,
        (audit_gate_state = 'blocked') AS active,
        gate_changed_at AS changed_at
    FROM operational_state
    WHERE id = 1
    UNION ALL
    SELECT
        'raw_deletion_overdue'::text AS fault_code,
        (deletion_overdue_since IS NOT NULL) AS active,
        COALESCE(deletion_overdue_since, updated_at) AS changed_at
    FROM operational_state
    WHERE id = 1
), latest_event_faults AS (
    SELECT DISTINCT ON (detail_code)
        detail_code AS fault_code,
        (outcome = 'failure') AS active,
        occurred_at AS changed_at
    FROM security_events
    WHERE event_type = 'operational_fault'
      AND detail_code IN ('required_key_failure', 'database_unavailable')
      AND outcome IN ('failure', 'success')
    ORDER BY detail_code, occurred_at DESC, id DESC
)
SELECT fault_code, active, changed_at FROM state_faults
UNION ALL
SELECT fault_code, active, changed_at FROM latest_event_faults
ORDER BY fault_code`

const listOperationalEventsSQL = `
SELECT
    id::text,
    detail_code,
    outcome,
    occurred_at
FROM security_events
WHERE event_type = 'operational_fault'
  AND detail_code IN ('audit_unavailable', 'raw_deletion_overdue', 'required_key_failure', 'database_unavailable')
  AND outcome IN ('failure', 'success')
  AND ($1::boolean IS NULL OR (outcome = 'failure') = $1)
  AND ($2::timestamptz IS NULL OR occurred_at >= $2)
  AND ($3::timestamptz IS NULL OR occurred_at <= $3)
  AND ($4::timestamptz IS NULL OR (occurred_at, id) < ($4, $5::uuid))
ORDER BY occurred_at DESC, id DESC
LIMIT $6`

const appendOperationalEventSQL = `
INSERT INTO security_events (
    id, event_type, request_id, outcome, detail_code, occurred_at
) VALUES (
    gen_random_uuid(), 'operational_fault', gen_random_uuid(), $2, $1, $3
)`

type operationalEventCursor struct {
	OccurredAt time.Time
	ID         string
}

func (r *Repository) ReadCriticalFaults(ctx context.Context) (faults []operations.FaultState, err error) {
	rows, err := r.db.QueryContext(ctx, readCriticalFaultsSQL)
	if err != nil {
		return nil, fmt.Errorf("query critical faults: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close critical fault rows: %w", closeErr))
		}
	}()
	for rows.Next() {
		var fault operations.FaultState
		if err := rows.Scan(&fault.Code, &fault.Active, &fault.ChangedAt); err != nil {
			return nil, fmt.Errorf("scan critical fault: %w", err)
		}
		if operations.ValidFaultCode(fault.Code) {
			faults = append(faults, fault)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate critical faults: %w", err)
	}
	return faults, nil
}

func (r *Repository) ListOperationalEvents(ctx context.Context, filter operations.EventFilter) (page operations.EventPage, err error) {
	if filter.Limit < 1 || filter.Limit > operations.MaxEventPageSize {
		return operations.EventPage{}, operations.ErrInvalidEventFilter
	}
	cursor, err := decodeOperationalEventCursor(filter.Cursor)
	if err != nil {
		return operations.EventPage{}, operations.ErrInvalidEventFilter
	}
	var cursorTime, cursorID any
	if cursor != nil {
		cursorTime, cursorID = cursor.OccurredAt, cursor.ID
	}
	rows, err := r.db.QueryContext(ctx, listOperationalEventsSQL,
		optionalBool(filter.Active), optionalTime(filter.From), optionalTime(filter.To),
		cursorTime, cursorID, filter.Limit+1,
	)
	if err != nil {
		return operations.EventPage{}, fmt.Errorf("query operational events: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close operational event rows: %w", closeErr))
		}
	}()
	page.Events = make([]operations.Event, 0, filter.Limit)
	for rows.Next() {
		var event operations.Event
		var outcome string
		if err := rows.Scan(&event.ID, &event.Fault, &outcome, &event.OccurredAt); err != nil {
			return operations.EventPage{}, fmt.Errorf("scan operational event: %w", err)
		}
		if len(page.Events) == filter.Limit {
			last := page.Events[len(page.Events)-1]
			page.NextCursor = encodeOperationalEventCursor(operationalEventCursor{OccurredAt: last.OccurredAt, ID: last.ID})
			break
		}
		event.Active = outcome == "failure"
		if operations.ValidFaultCode(event.Fault) {
			page.Events = append(page.Events, event)
		}
	}
	if err := rows.Err(); err != nil {
		return operations.EventPage{}, fmt.Errorf("iterate operational events: %w", err)
	}
	return page, nil
}

func (r *Repository) AppendFaultTransition(ctx context.Context, transition operations.FaultTransition) error {
	if !operations.ValidFaultCode(transition.Fault) || transition.OccurredAt.IsZero() {
		return operations.ErrInvalidFault
	}
	if _, err := r.db.ExecContext(ctx, appendOperationalEventSQL, transition.Fault, operationalOutcome(transition.Active), transition.OccurredAt.UTC()); err != nil {
		return fmt.Errorf("append operational event: %w", err)
	}
	return nil
}

func appendOperationalEventTx(ctx context.Context, tx *sql.Tx, transition operations.FaultTransition) error {
	if !operations.ValidFaultCode(transition.Fault) || transition.OccurredAt.IsZero() {
		return operations.ErrInvalidFault
	}
	if _, err := tx.ExecContext(ctx, appendOperationalEventSQL, transition.Fault, operationalOutcome(transition.Active), transition.OccurredAt.UTC()); err != nil {
		return fmt.Errorf("append operational event: %w", err)
	}
	return nil
}

func operationalOutcome(active bool) string {
	if active {
		return "failure"
	}
	return "success"
}

func optionalBool(value *bool) any {
	if value == nil {
		return nil
	}
	return *value
}

func optionalTime(value *time.Time) any {
	if value == nil {
		return nil
	}
	return value.UTC()
}

func encodeOperationalEventCursor(cursor operationalEventCursor) string {
	payload, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeOperationalEventCursor(value string) (*operationalEventCursor, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if len(value) > 512 {
		return nil, operations.ErrInvalidEventFilter
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, operations.ErrInvalidEventFilter
	}
	var cursor operationalEventCursor
	if err := json.Unmarshal(payload, &cursor); err != nil || cursor.OccurredAt.IsZero() || !validAuditMetadataUUID(cursor.ID) {
		return nil, operations.ErrInvalidEventFilter
	}
	return &cursor, nil
}

var _ operations.Repository = (*Repository)(nil)
