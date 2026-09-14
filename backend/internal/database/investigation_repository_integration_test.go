//go:build integration

package database

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
)

func TestRepositoryRejectsInitialGrantBoundToAnotherSessionIdentity(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	subjectIdentityID := "82000000-0000-0000-0000-000000000002"
	subjectKeyID := "83000000-0000-0000-0000-000000000002"
	subjectAuditID := "84000000-0000-0000-0000-000000000002"
	subjectRequestID := "87000000-0000-0000-0000-000000000002"
	insertEmployeeAuditCandidate(t, db, fixture, subjectIdentityID, subjectKeyID, subjectAuditID, subjectRequestID)
	otherIdentityID := "82000000-0000-0000-0000-000000000003"
	sessionID := "85000000-0000-0000-0000-000000000001"
	now := fixture.now.Add(time.Minute)
	mustExec(t, db, `INSERT INTO identities (id, email, role, status) VALUES ($1, $2, 'system_administrator', 'active')`, otherIdentityID, "other-auditor@example.internal")
	mustExec(t, db, `INSERT INTO sessions (id, identity_id, token_hash, csrf_token_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at, reauthenticated_until) VALUES ($1, $2, $3, $4, $5, $5, $6, $7, $8)`, sessionID, otherIdentityID, []byte("session-token-hash"), []byte("session-csrf-hash"), fixture.now.Add(-time.Hour), now.Add(time.Hour), now.Add(12*time.Hour), now.Add(time.Hour))

	caseID := "83000000-0000-0000-0000-000000000010"
	grantID := "85000000-0000-0000-0000-000000000010"
	repository := NewRepository(db)
	err := repository.CreateInvestigationCase(context.Background(), audit.InvestigationCaseCreate{
		Case: audit.InvestigationCase{
			ID: caseID, SubjectIdentityID: subjectIdentityID, PolicyConcern: "policy concern", Reason: "investigation reason",
			StartAt: fixture.now.Add(-time.Hour), EndAt: now, Status: audit.InvestigationCaseOpen, CreatedBy: fixture.identityID, CreatedAt: now,
		},
		Candidates: []audit.InvestigationCandidate{{AuditID: subjectAuditID, CaptureStatus: audit.CaptureStatusPending, CreatedAt: fixture.now, ExpiresAt: fixture.now.Add(24 * time.Hour)}},
		Grant:      audit.AccessGrant{ID: grantID, CaseID: caseID, ActorIdentityID: fixture.identityID, SessionID: sessionID, IssuedAt: now, ExpiresAt: now.Add(30 * time.Minute)},
		Event: access.SecurityEvent{
			ID: "86000000-0000-0000-0000-000000000010", EventType: "investigation_case", ActorIdentityID: fixture.identityID,
			TargetIdentityID: subjectIdentityID, InvestigationCaseID: caseID, RequestID: fixture.requestID,
			Outcome: access.SecurityEventSuccess, Reason: "investigation reason", DetailCode: "case_created", OccurredAt: now,
		},
		CandidateQuery: audit.InvestigationCandidateQuery{
			SubjectIdentityID: subjectIdentityID, StartAt: fixture.now.Add(-time.Hour), EndAt: now, VisibleAt: now, Limit: 101,
		},
	})
	if !errors.Is(err, audit.ErrInvestigationForbidden) {
		t.Fatalf("CreateInvestigationCase() error = %v, want ErrInvestigationForbidden", err)
	}
	assertInvestigationRowCount(t, db, "investigation_cases", caseID, 0)
	assertInvestigationRowCount(t, db, "investigation_access_grants", grantID, 0)
}

func TestRepositoryCapsInitialGrantAtSessionAbsoluteExpiry(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	subjectIdentityID := "82000000-0000-0000-0000-000000000002"
	subjectKeyID := "83000000-0000-0000-0000-000000000002"
	subjectAuditID := "84000000-0000-0000-0000-000000000002"
	subjectRequestID := "87000000-0000-0000-0000-000000000002"
	insertEmployeeAuditCandidate(t, db, fixture, subjectIdentityID, subjectKeyID, subjectAuditID, subjectRequestID)
	sessionID := "85000000-0000-0000-0000-000000000011"
	now := fixture.now.Add(time.Minute)
	mustExec(t, db, `INSERT INTO sessions (id, identity_id, token_hash, csrf_token_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at, reauthenticated_until) VALUES ($1, $2, $3, $4, $5, $5, $6, $7, $8)`, sessionID, fixture.identityID, []byte("session-token-hash-2"), []byte("session-csrf-hash-2"), fixture.now.Add(-time.Hour), now.Add(5*time.Minute), now.Add(10*time.Minute), now.Add(time.Hour))

	caseID := "83000000-0000-0000-0000-000000000011"
	grantID := "85000000-0000-0000-0000-000000000012"
	repository := NewRepository(db)
	err := repository.CreateInvestigationCase(context.Background(), audit.InvestigationCaseCreate{
		Case: audit.InvestigationCase{
			ID: caseID, SubjectIdentityID: subjectIdentityID, PolicyConcern: "policy concern", Reason: "investigation reason",
			StartAt: fixture.now.Add(-time.Hour), EndAt: now, Status: audit.InvestigationCaseOpen, CreatedBy: fixture.identityID, CreatedAt: now,
		},
		Candidates: []audit.InvestigationCandidate{{AuditID: subjectAuditID, CaptureStatus: audit.CaptureStatusPending, CreatedAt: fixture.now, ExpiresAt: fixture.now.Add(24 * time.Hour)}},
		Grant:      audit.AccessGrant{ID: grantID, CaseID: caseID, ActorIdentityID: fixture.identityID, SessionID: sessionID, IssuedAt: now, ExpiresAt: now.Add(30 * time.Minute)},
		Event: access.SecurityEvent{
			ID: "86000000-0000-0000-0000-000000000011", EventType: "investigation_case", ActorIdentityID: fixture.identityID,
			TargetIdentityID: subjectIdentityID, InvestigationCaseID: caseID, RequestID: fixture.requestID,
			Outcome: access.SecurityEventSuccess, Reason: "investigation reason", DetailCode: "case_created", OccurredAt: now,
		},
		CandidateQuery: audit.InvestigationCandidateQuery{
			SubjectIdentityID: subjectIdentityID, StartAt: fixture.now.Add(-time.Hour), EndAt: now, VisibleAt: now, Limit: 101,
		},
	})
	if !errors.Is(err, audit.ErrInvestigationForbidden) {
		t.Fatalf("CreateInvestigationCase() error = %v, want ErrInvestigationForbidden", err)
	}
	assertInvestigationRowCount(t, db, "investigation_cases", caseID, 0)
	assertInvestigationRowCount(t, db, "investigation_access_grants", grantID, 0)
}

func insertEmployeeAuditCandidate(t *testing.T, db *sql.DB, fixture auditPolicyFixture, identityID, keyID, auditID, requestID string) {
	t.Helper()
	mustExec(t, db, `INSERT INTO identities (id, email, role, status) VALUES ($1, $2, 'employee', 'active')`, identityID, "subject-employee@example.internal")
	mustExec(t, db, `INSERT INTO api_keys (id, identity_id, kind, name, prefix, verification_hash, status, created_at) VALUES ($1, $2, 'personal', 'subject-key', 'nap_subject', $3, 'active', $4)`, keyID, identityID, []byte("subject-key-hash"), fixture.now)
	mustExec(t, db, `INSERT INTO audit_records (id, request_id, key_id, owner_kind, identity_id, team_id, model_id, capture_status, outcome, observed_request_bytes, observed_response_bytes, created_at, updated_at) VALUES ($1, $2, $3, 'personal', $4, $5, 'gpt-test', 'pending', 'pending', 128, 0, $6, $6)`, auditID, requestID, keyID, identityID, fixture.teamID, fixture.now)
	mustExec(t, db, `INSERT INTO audit_raw_content (audit_id, content_kind, compression, ciphertext, cipher_nonce, wrapped_data_key, wrap_nonce, key_version, created_at, expires_at) VALUES ($1, 'request', 'gzip', $2, $3, $4, $5, 1, $6, $7)`, auditID, []byte("encrypted-subject-request-payload-and-tag"), make([]byte, 12), []byte("wrapped-subject-data-key-and-tag"), make([]byte, 12), fixture.now, fixture.now.Add(24*time.Hour))
}

func TestRepositoryOnlySelectsEmployeeInvestigationSubjects(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	insertRequestRawContent(t, db, fixture)
	candidates, err := NewRepository(db).FindInvestigationCandidates(context.Background(), audit.InvestigationCandidateQuery{
		SubjectIdentityID: fixture.identityID, StartAt: fixture.now.Add(-time.Hour), EndAt: fixture.now.Add(time.Minute), VisibleAt: fixture.now.Add(time.Minute), Limit: 101,
	})
	if err != nil {
		t.Fatalf("FindInvestigationCandidates() error = %v", err)
	}
	if len(candidates) != 0 {
		t.Fatalf("administrator subject candidates = %d, want none", len(candidates))
	}
}

func TestRepositoryRejectsInvestigationClosureWithoutCurrentReauthentication(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	caseID := "83000000-0000-0000-0000-000000000012"
	sessionID := "85000000-0000-0000-0000-000000000013"
	now := fixture.now.Add(time.Minute)
	mustExec(t, db, `INSERT INTO investigation_cases (id, subject_identity_id, policy_concern, reason, start_at, end_at, created_by_identity_id, created_at) VALUES ($1, $2, 'policy concern', 'investigation reason', $3, $4, $2, $4)`, caseID, fixture.identityID, fixture.now.Add(-time.Hour), now)
	mustExec(t, db, `INSERT INTO sessions (id, identity_id, token_hash, csrf_token_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES ($1, $2, $3, $4, $5, $5, $6, $7)`, sessionID, fixture.identityID, []byte("closure-session-token"), []byte("closure-session-csrf"), fixture.now, now.Add(time.Hour), now.Add(12*time.Hour))
	err := NewRepository(db).CloseInvestigationCase(context.Background(), audit.InvestigationCaseClosure{
		CaseID:      caseID,
		Actor:       access.ActivePortalSession{SessionID: sessionID, IdentityID: fixture.identityID, Role: access.RoleSystemAdministrator},
		Disposition: audit.InvestigationInconclusive, ClosedAt: now, Confirmed: true,
	}, access.SecurityEvent{
		ID: "86000000-0000-0000-0000-000000000012", EventType: "investigation_case", ActorIdentityID: fixture.identityID,
		TargetIdentityID: fixture.identityID, InvestigationCaseID: caseID, RequestID: fixture.requestID,
		Outcome: access.SecurityEventSuccess, DetailCode: "case_closed", OccurredAt: now,
	})
	if !errors.Is(err, audit.ErrInvestigationForbidden) {
		t.Fatalf("CloseInvestigationCase() error = %v, want ErrInvestigationForbidden", err)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM investigation_cases WHERE id = $1`, caseID).Scan(&status); err != nil {
		t.Fatalf("read investigation case status: %v", err)
	}
	if status != string(audit.InvestigationCaseOpen) {
		t.Fatalf("case status = %q, want open after rejected closure", status)
	}
}

func assertInvestigationRowCount(t *testing.T, db *sql.DB, tableName, id string, want int) {
	t.Helper()
	var query string
	switch tableName {
	case "investigation_cases":
		query = "SELECT count(*) FROM investigation_cases WHERE id = $1"
	case "investigation_access_grants":
		query = "SELECT count(*) FROM investigation_access_grants WHERE id = $1"
	default:
		t.Fatalf("unsupported investigation row-count table %q", tableName)
	}
	var got int
	if err := db.QueryRow(query, id).Scan(&got); err != nil {
		t.Fatalf("count %s rows: %v", tableName, err)
	}
	if got != want {
		t.Fatalf("%s row count = %d, want %d", tableName, got, want)
	}
}
