package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"n-api-p/internal/access"
	"n-api-p/internal/audit"
	"strings"
	"time"
)

const findInvestigationCandidatesSQL = `
SELECT records.id::text, records.capture_status, records.created_at, MAX(raw.expires_at)
FROM audit_records AS records
JOIN audit_raw_content AS raw ON raw.audit_id = records.id AND raw.expires_at > $3
JOIN identities AS subjects ON subjects.id = $1 AND subjects.role = 'employee'
WHERE (records.identity_id = $1 OR records.responsible_identity_id = $1)
  AND records.created_at >= $4
  AND records.created_at < $5
GROUP BY records.id, records.capture_status, records.created_at
ORDER BY records.created_at ASC, records.id ASC
LIMIT $2`

const insertInvestigationCaseSQL = `
INSERT INTO investigation_cases (
    id, subject_identity_id, policy_concern, reason, start_at, end_at,
    status, created_by_identity_id, created_at
) VALUES ($1, $2, $3, $4, $5, $6, 'open', $7, $8)`

const insertInvestigationCaseAuditSQL = `
INSERT INTO investigation_case_audits (
    case_id, audit_id, ordinal, capture_status, audit_created_at, raw_expires_at
) VALUES ($1, $2, $3, $4, $5, $6)`

const insertInvestigationGrantSQL = `
INSERT INTO investigation_access_grants (
    id, case_id, actor_identity_id, session_id, issued_at, expires_at
) VALUES ($1, $2, $3, $4, $5, $6)`

const listInvestigationCasesSQL = `
SELECT id::text, subject_identity_id::text, policy_concern, reason, start_at, end_at,
       status, created_by_identity_id::text, created_at, COALESCE(closed_by_identity_id::text, ''),
       closed_at, COALESCE(disposition, ''), COALESCE(closure_note, '')
FROM investigation_cases
WHERE ($1::text = '' OR status = $1)
  AND ($2::timestamptz IS NULL OR (created_at, id) < ($2, $3::uuid))
ORDER BY created_at DESC, id DESC
LIMIT $4`

const getInvestigationCaseSQL = `
SELECT id::text, subject_identity_id::text, policy_concern, reason, start_at, end_at,
       status, created_by_identity_id::text, created_at, COALESCE(closed_by_identity_id::text, ''),
       closed_at, COALESCE(disposition, ''), COALESCE(closure_note, '')
FROM investigation_cases
WHERE id = $1`

const listInvestigationCandidatesSQL = `
SELECT audit_id::text, capture_status, audit_created_at, raw_expires_at
FROM investigation_case_audits
WHERE case_id = $1
ORDER BY ordinal ASC`

const findInvestigationGrantSQL = `
SELECT grants.id::text, grants.case_id::text, grants.actor_identity_id::text,
       grants.session_id::text, grants.issued_at, grants.expires_at
FROM investigation_access_grants AS grants
JOIN investigation_cases AS cases ON cases.id = grants.case_id AND cases.status = 'open'
JOIN sessions AS sessions ON sessions.id = grants.session_id
WHERE grants.case_id = $1
  AND grants.actor_identity_id = $2
  AND grants.session_id = $3
  AND grants.revoked_at IS NULL
  AND grants.expires_at > $4
	AND sessions.revoked_at IS NULL
	AND sessions.identity_id = grants.actor_identity_id
	AND sessions.idle_expires_at > $4
  AND sessions.absolute_expires_at > $4`

const verifyInvestigationGrantSessionSQL = `
SELECT sessions.identity_id::text, sessions.absolute_expires_at
FROM sessions
JOIN identities ON identities.id = sessions.identity_id
WHERE sessions.id = $1
  AND sessions.identity_id = $2
  AND identities.status = 'active'
	AND identities.role = 'system_administrator'
	AND sessions.revoked_at IS NULL
	AND sessions.idle_expires_at > $3
	AND sessions.absolute_expires_at > $3
	AND sessions.reauthenticated_until > $3
FOR SHARE`

const lockInvestigationCaseSQL = `
SELECT subject_identity_id::text, status
FROM investigation_cases
WHERE id = $1
FOR UPDATE`

const closeInvestigationCaseSQL = `
UPDATE investigation_cases
SET status = 'closed', closed_by_identity_id = $2, closed_at = $3,
    disposition = $4, closure_note = NULLIF($5, '')
WHERE id = $1 AND status = 'open'`

const revokeInvestigationGrantsSQL = `
UPDATE investigation_access_grants
SET revoked_at = $2
WHERE case_id = $1 AND revoked_at IS NULL`

func (r *Repository) FindInvestigationCandidates(ctx context.Context, query audit.InvestigationCandidateQuery) ([]audit.InvestigationCandidate, error) {
	if r == nil || r.db == nil || !validInvestigationCandidateQuery(query) {
		return nil, audit.ErrInvalidInvestigation
	}
	return scanInvestigationCandidates(ctx, r.db, query)
}

func (r *Repository) CreateInvestigationCase(ctx context.Context, create audit.InvestigationCaseCreate) (err error) {
	if r == nil || r.db == nil || !validInvestigationCreate(create) {
		return audit.ErrInvalidInvestigation
	}
	if !validInvestigationCandidateQuery(create.CandidateQuery) ||
		create.CandidateQuery.SubjectIdentityID != create.Case.SubjectIdentityID ||
		!create.CandidateQuery.StartAt.Equal(create.Case.StartAt) ||
		!create.CandidateQuery.EndAt.Equal(create.Case.EndAt) ||
		!create.CandidateQuery.VisibleAt.Equal(create.Case.CreatedAt) {
		return audit.ErrInvalidInvestigation
	}
	if create.Case.CreatedBy != create.Grant.ActorIdentityID || create.Grant.IssuedAt != create.Case.CreatedAt ||
		create.Event.ActorIdentityID != create.Case.CreatedBy || create.Event.TargetIdentityID != create.Case.SubjectIdentityID ||
		create.Event.OccurredAt != create.Case.CreatedAt {
		return audit.ErrInvalidInvestigation
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin investigation case transaction: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, fmt.Errorf("roll back investigation case transaction: %w", rollbackErr))
		}
	}()
	candidates, err := scanInvestigationCandidates(ctx, tx, create.CandidateQuery)
	if err != nil {
		return fmt.Errorf("select investigation snapshot: %w", err)
	}
	if len(candidates) > 100 {
		return audit.ErrInvestigationScopeTooBroad
	}
	if len(candidates) == 0 {
		return audit.ErrInvestigationNoCandidates
	}
	if !sameInvestigationCandidates(candidates, create.Candidates) {
		return audit.ErrInvestigationSnapshotChanged
	}
	var sessionIdentity string
	var sessionAbsoluteExpiresAt time.Time
	if err := tx.QueryRowContext(ctx, verifyInvestigationGrantSessionSQL, create.Grant.SessionID, create.Grant.ActorIdentityID, create.Grant.IssuedAt).Scan(&sessionIdentity, &sessionAbsoluteExpiresAt); errors.Is(err, sql.ErrNoRows) {
		return audit.ErrInvestigationForbidden
	} else if err != nil {
		return fmt.Errorf("check investigation session for case: %w", err)
	}
	if create.Grant.ExpiresAt.After(sessionAbsoluteExpiresAt) {
		return audit.ErrInvestigationForbidden
	}
	if _, err := tx.ExecContext(ctx, insertInvestigationCaseSQL,
		create.Case.ID, create.Case.SubjectIdentityID, create.Case.PolicyConcern, create.Case.Reason,
		create.Case.StartAt, create.Case.EndAt, create.Case.CreatedBy, create.Case.CreatedAt,
	); err != nil {
		return fmt.Errorf("insert investigation case: %w", err)
	}
	for ordinal, candidate := range candidates {
		if _, err := tx.ExecContext(ctx, insertInvestigationCaseAuditSQL,
			create.Case.ID, candidate.AuditID, ordinal+1, candidate.CaptureStatus, candidate.CreatedAt, candidate.ExpiresAt,
		); err != nil {
			return fmt.Errorf("insert investigation candidate: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, insertInvestigationGrantSQL,
		create.Grant.ID, create.Grant.CaseID, create.Grant.ActorIdentityID, create.Grant.SessionID, create.Grant.IssuedAt, create.Grant.ExpiresAt,
	); err != nil {
		return fmt.Errorf("insert investigation grant: %w", err)
	}
	if err := appendSecurityEventTx(ctx, tx, create.Event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit investigation case transaction: %w", err)
	}
	committed = true
	return nil
}

func (r *Repository) ListInvestigationCases(ctx context.Context, filter audit.InvestigationCaseListFilter) (page audit.InvestigationCasePage, err error) {
	if r == nil || r.db == nil || filter.Limit < 1 || filter.Limit > 100 {
		return audit.InvestigationCasePage{}, audit.ErrInvalidInvestigation
	}
	var cursorAt any
	var cursorID any
	if strings.TrimSpace(filter.Cursor) != "" {
		decodedAt, decodedID, decodeErr := decodeInvestigationCursor(filter.Cursor)
		if decodeErr != nil {
			return audit.InvestigationCasePage{}, audit.ErrInvalidInvestigation
		}
		cursorAt, cursorID = decodedAt, decodedID
	}
	rows, err := r.db.QueryContext(ctx, listInvestigationCasesSQL, string(filter.Status), cursorAt, cursorID, filter.Limit+1)
	if err != nil {
		return audit.InvestigationCasePage{}, fmt.Errorf("list investigation cases: %w", err)
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		caseRecord, scanErr := scanInvestigationCase(rows)
		if scanErr != nil {
			return audit.InvestigationCasePage{}, fmt.Errorf("scan investigation case: %w", scanErr)
		}
		page.Cases = append(page.Cases, caseRecord)
	}
	if err := rows.Err(); err != nil {
		return audit.InvestigationCasePage{}, fmt.Errorf("iterate investigation cases: %w", err)
	}
	if len(page.Cases) > filter.Limit {
		last := page.Cases[filter.Limit-1]
		page.Cases = page.Cases[:filter.Limit]
		page.NextCursor = encodeInvestigationCursor(last.CreatedAt, last.ID)
	}
	return page, nil
}

func (r *Repository) GetInvestigationCase(ctx context.Context, caseID string) (audit.InvestigationCase, error) {
	if r == nil || r.db == nil || !validUUID(caseID) {
		return audit.InvestigationCase{}, audit.ErrInvalidInvestigation
	}
	caseRecord, err := scanInvestigationCase(r.db.QueryRowContext(ctx, getInvestigationCaseSQL, caseID))
	if errors.Is(err, sql.ErrNoRows) {
		return audit.InvestigationCase{}, audit.ErrInvestigationNotFound
	}
	if err != nil {
		return audit.InvestigationCase{}, fmt.Errorf("get investigation case: %w", err)
	}
	return caseRecord, nil
}

func (r *Repository) ListInvestigationCandidates(ctx context.Context, caseID string) ([]audit.InvestigationCandidate, error) {
	if r == nil || r.db == nil || !validUUID(caseID) {
		return nil, audit.ErrInvalidInvestigation
	}
	rows, err := r.db.QueryContext(ctx, listInvestigationCandidatesSQL, caseID)
	if err != nil {
		return nil, fmt.Errorf("list investigation candidates: %w", err)
	}
	defer rows.Close()
	var candidates []audit.InvestigationCandidate
	for rows.Next() {
		var candidate audit.InvestigationCandidate
		if err := rows.Scan(&candidate.AuditID, &candidate.CaptureStatus, &candidate.CreatedAt, &candidate.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan investigation candidate: %w", err)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate investigation candidates: %w", err)
	}
	return candidates, nil
}

func (r *Repository) CreateInvestigationAccessGrant(ctx context.Context, grant audit.AccessGrant, event access.SecurityEvent) (err error) {
	if r == nil || r.db == nil || !validInvestigationGrant(grant) {
		return audit.ErrInvalidInvestigation
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin investigation grant transaction: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, rollbackErr)
		}
	}()
	var status string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM investigation_cases WHERE id = $1 FOR SHARE`, grant.CaseID).Scan(&status); errors.Is(err, sql.ErrNoRows) {
		return audit.ErrInvestigationNotFound
	} else if err != nil {
		return fmt.Errorf("check investigation case for grant: %w", err)
	} else if status != string(audit.InvestigationCaseOpen) {
		return audit.ErrInvestigationClosed
	}
	var sessionIdentity string
	var sessionAbsoluteExpiresAt time.Time
	if err := tx.QueryRowContext(ctx, verifyInvestigationGrantSessionSQL, grant.SessionID, grant.ActorIdentityID, grant.IssuedAt).Scan(&sessionIdentity, &sessionAbsoluteExpiresAt); errors.Is(err, sql.ErrNoRows) {
		return audit.ErrInvestigationForbidden
	} else if err != nil {
		return fmt.Errorf("check investigation session for grant: %w", err)
	}
	if grant.ExpiresAt.After(sessionAbsoluteExpiresAt) {
		return audit.ErrInvestigationForbidden
	}
	if _, err := tx.ExecContext(ctx, insertInvestigationGrantSQL, grant.ID, grant.CaseID, grant.ActorIdentityID, grant.SessionID, grant.IssuedAt, grant.ExpiresAt); err != nil {
		return fmt.Errorf("insert investigation grant: %w", err)
	}
	if err := appendSecurityEventTx(ctx, tx, event); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit investigation grant transaction: %w", err)
	}
	committed = true
	return nil
}

func (r *Repository) FindInvestigationAccessGrant(ctx context.Context, lookup audit.AccessGrantLookup) (audit.AccessGrant, error) {
	if r == nil || r.db == nil || !validUUID(lookup.CaseID) || !validUUID(lookup.ActorIdentityID) || !validUUID(lookup.SessionID) || lookup.At.IsZero() {
		return audit.AccessGrant{}, audit.ErrInvalidInvestigation
	}
	var grant audit.AccessGrant
	err := r.db.QueryRowContext(ctx, findInvestigationGrantSQL, lookup.CaseID, lookup.ActorIdentityID, lookup.SessionID, lookup.At).Scan(
		&grant.ID, &grant.CaseID, &grant.ActorIdentityID, &grant.SessionID, &grant.IssuedAt, &grant.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return audit.AccessGrant{}, audit.ErrInvestigationGrantNotFound
	}
	if err != nil {
		return audit.AccessGrant{}, fmt.Errorf("find investigation grant: %w", err)
	}
	return grant, nil
}

func (r *Repository) CloseInvestigationCase(ctx context.Context, closure audit.InvestigationCaseClosure, events ...access.SecurityEvent) (err error) {
	if r == nil || r.db == nil || !validUUID(closure.CaseID) || !validUUID(closure.Actor.IdentityID) || !validUUID(closure.Actor.SessionID) || closure.ClosedAt.IsZero() || len(events) != 1 {
		return audit.ErrInvalidInvestigation
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin investigation closure transaction: %w", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
			err = errors.Join(err, rollbackErr)
		}
	}()
	var sessionIdentity string
	var sessionAbsoluteExpiresAt time.Time
	if err := tx.QueryRowContext(ctx, verifyInvestigationGrantSessionSQL, closure.Actor.SessionID, closure.Actor.IdentityID, closure.ClosedAt).Scan(&sessionIdentity, &sessionAbsoluteExpiresAt); errors.Is(err, sql.ErrNoRows) {
		return audit.ErrInvestigationForbidden
	} else if err != nil {
		return fmt.Errorf("check investigation session for closure: %w", err)
	}
	var subjectID, status string
	if err := tx.QueryRowContext(ctx, lockInvestigationCaseSQL, closure.CaseID).Scan(&subjectID, &status); errors.Is(err, sql.ErrNoRows) {
		return audit.ErrInvestigationNotFound
	} else if err != nil {
		return fmt.Errorf("lock investigation case: %w", err)
	} else if status != string(audit.InvestigationCaseOpen) {
		return audit.ErrInvestigationClosed
	}
	result, err := tx.ExecContext(ctx, closeInvestigationCaseSQL, closure.CaseID, closure.Actor.IdentityID, closure.ClosedAt.UTC(), closure.Disposition, strings.TrimSpace(closure.Note))
	if err != nil {
		return fmt.Errorf("close investigation case: %w", err)
	}
	if affected, err := result.RowsAffected(); err != nil || affected != 1 {
		if err != nil {
			return fmt.Errorf("inspect investigation closure: %w", err)
		}
		return audit.ErrInvestigationClosed
	}
	if _, err := tx.ExecContext(ctx, revokeInvestigationGrantsSQL, closure.CaseID, closure.ClosedAt.UTC()); err != nil {
		return fmt.Errorf("revoke investigation grants: %w", err)
	}
	if err := appendSecurityEventTx(ctx, tx, events[0]); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit investigation closure transaction: %w", err)
	}
	committed = true
	return nil
}

type investigationScanner interface{ Scan(...any) error }

func scanInvestigationCase(scanner investigationScanner) (audit.InvestigationCase, error) {
	var result audit.InvestigationCase
	var status, disposition string
	var closedBy string
	var closedAt sql.NullTime
	if err := scanner.Scan(&result.ID, &result.SubjectIdentityID, &result.PolicyConcern, &result.Reason, &result.StartAt, &result.EndAt, &status, &result.CreatedBy, &result.CreatedAt, &closedBy, &closedAt, &disposition, &result.ClosureNote); err != nil {
		return audit.InvestigationCase{}, err
	}
	result.Status = audit.InvestigationCaseStatus(status)
	result.ClosedBy = closedBy
	result.Disposition = audit.InvestigationDisposition(disposition)
	if closedAt.Valid {
		value := closedAt.Time
		result.ClosedAt = &value
	}
	return result, nil
}

func scanInvestigationCandidates(ctx context.Context, queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, query audit.InvestigationCandidateQuery) ([]audit.InvestigationCandidate, error) {
	rows, err := queryer.QueryContext(ctx, findInvestigationCandidatesSQL, query.SubjectIdentityID, query.Limit, query.VisibleAt, query.StartAt, query.EndAt)
	if err != nil {
		return nil, fmt.Errorf("query investigation candidates: %w", err)
	}
	defer rows.Close()
	var candidates []audit.InvestigationCandidate
	for rows.Next() {
		var candidate audit.InvestigationCandidate
		if err := rows.Scan(&candidate.AuditID, &candidate.CaptureStatus, &candidate.CreatedAt, &candidate.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan investigation candidate: %w", err)
		}
		candidates = append(candidates, candidate)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate investigation candidates: %w", err)
	}
	return candidates, nil
}

func validInvestigationCandidateQuery(query audit.InvestigationCandidateQuery) bool {
	return validUUID(query.SubjectIdentityID) && !query.StartAt.IsZero() && !query.EndAt.IsZero() && !query.VisibleAt.IsZero() && query.StartAt.Before(query.EndAt) && query.Limit == 101
}

func validInvestigationCreate(create audit.InvestigationCaseCreate) bool {
	return validUUID(create.Case.ID) && validUUID(create.Case.SubjectIdentityID) && validUUID(create.Case.CreatedBy) && create.Case.Status == audit.InvestigationCaseOpen && validInvestigationTextDB(create.Case.PolicyConcern) && validInvestigationTextDB(create.Case.Reason) && !create.Case.CreatedAt.IsZero() && validInvestigationGrant(create.Grant) && create.Grant.CaseID == create.Case.ID && create.Event.InvestigationCaseID == create.Case.ID
}

func validInvestigationGrant(grant audit.AccessGrant) bool {
	return validUUID(grant.ID) && validUUID(grant.CaseID) && validUUID(grant.ActorIdentityID) && validUUID(grant.SessionID) && !grant.IssuedAt.IsZero() && grant.ExpiresAt.After(grant.IssuedAt) && grant.ExpiresAt.Sub(grant.IssuedAt) <= 30*time.Minute
}

func validInvestigationTextDB(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len([]rune(value)) <= 500
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}

func encodeInvestigationCursor(at time.Time, id string) string {
	return at.UTC().Format(time.RFC3339Nano) + "." + id
}

func decodeInvestigationCursor(value string) (time.Time, string, error) {
	separator := strings.LastIndex(value, ".")
	if separator <= 0 || separator == len(value)-1 || !validUUID(value[separator+1:]) {
		return time.Time{}, "", audit.ErrInvalidInvestigation
	}
	at, err := time.Parse(time.RFC3339Nano, value[:separator])
	if err != nil || at.IsZero() {
		return time.Time{}, "", audit.ErrInvalidInvestigation
	}
	return at, value[separator+1:], nil
}

func sameInvestigationCandidates(left, right []audit.InvestigationCandidate) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index].AuditID != right[index].AuditID ||
			left[index].CaptureStatus != right[index].CaptureStatus ||
			!left[index].CreatedAt.Equal(right[index].CreatedAt) ||
			!left[index].ExpiresAt.Equal(right[index].ExpiresAt) {
			return false
		}
	}
	return true
}

var _ audit.InvestigationRepository = (*Repository)(nil)
