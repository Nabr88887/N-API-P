//go:build integration

package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
)

func TestInvestigationAcceptanceConcurrentCreation(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	_, create := seedInvestigationAcceptance(t, db)
	repository := NewRepository(db)
	second := create
	second.Case.ID = "88000000-0000-0000-0000-000000000102"
	second.Grant.ID = "85000000-0000-0000-0000-000000000103"
	second.Grant.CaseID = second.Case.ID
	second.Event.ID = "86000000-0000-0000-0000-000000000102"
	second.Event.InvestigationCaseID = second.Case.ID
	creates := []audit.InvestigationCaseCreate{create, second}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make([]error, len(creates))
	var workers sync.WaitGroup
	for index, input := range creates {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			results[index] = repository.CreateInvestigationCase(ctx, input)
		}()
	}
	close(start)
	workers.Wait()
	for index, input := range creates {
		if results[index] != nil {
			t.Fatalf("concurrent creation %d: %v", index, results[index])
		}
		assertInvestigationRowCount(t, db, "investigation_cases", input.Case.ID, 1)
		assertInvestigationSnapshot(t, repository, input.Case.ID, input.Candidates)
		assertInvestigationGrant(t, repository, input.Grant, input.Case.CreatedAt, true)
		assertInvestigationEventCount(t, db, input.Case.ID, "case_created", 1)
	}
}

func TestInvestigationAcceptanceSubjectAttribution(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	subject, create := seedInvestigationAcceptance(t, db)
	const serviceID = "89000000-0000-0000-0000-000000000102"
	const serviceKeyID = "83000000-0000-0000-0000-000000000102"
	const serviceAuditID = "84000000-0000-0000-0000-000000000102"
	const otherIdentityID = "82000000-0000-0000-0000-000000000103"
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, subject.identityID, subject.teamID)
	mustExec(t, db, `INSERT INTO service_accounts (id, team_id, responsible_identity_id, name, status) VALUES ($1, $2, $3, 'investigation-service', 'active')`, serviceID, subject.teamID, subject.identityID)
	mustExec(t, db, `INSERT INTO api_keys (id, service_account_id, kind, name, prefix, verification_hash, status) VALUES ($1, $2, 'service', 'investigation-service-key', 'nap_investigation', $3, 'active')`, serviceKeyID, serviceID, []byte("synthetic-service-hash"))
	mustExec(t, db, `INSERT INTO audit_records (id, request_id, key_id, owner_kind, service_account_id, responsible_identity_id, team_id, model_id, capture_status, outcome, observed_request_bytes, observed_response_bytes, created_at, updated_at) VALUES ($1, $2, $3, 'service', $4, $5, $6, 'gpt-test', 'pending', 'pending', 128, 0, $7, $7)`, serviceAuditID, "87000000-0000-0000-0000-000000000102", serviceKeyID, serviceID, subject.identityID, subject.teamID, subject.now)
	serviceFixture := subject
	serviceFixture.auditID = serviceAuditID
	insertRequestRawContent(t, db, serviceFixture)
	other := subject
	other.identityID = otherIdentityID
	other.keyID = "83000000-0000-0000-0000-000000000103"
	mustExec(t, db, `INSERT INTO identities (id, email, role, status) VALUES ($1, 'other-investigation-subject@example.internal', 'employee', 'active')`, other.identityID)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, other.identityID, other.teamID)
	mustExec(t, db, `INSERT INTO api_keys (id, identity_id, kind, name, prefix, verification_hash, status) VALUES ($1, $2, 'personal', 'other-subject', 'nap_other', $3, 'active')`, other.keyID, other.identityID, []byte("synthetic-other-hash"))
	otherCandidate := insertInvestigationAcceptanceCandidate(t, db, other, 103)
	mustExec(t, db, `UPDATE service_accounts SET responsible_identity_id = $2 WHERE id = $1`, serviceID, other.identityID)
	repository := NewRepository(db)
	candidates, err := repository.FindInvestigationCandidates(context.Background(), create.CandidateQuery)
	if err != nil {
		t.Fatalf("find personal and responsible-employee candidates: %v", err)
	}
	want := append(append([]audit.InvestigationCandidate{}, create.Candidates...), audit.InvestigationCandidate{
		AuditID: serviceAuditID, CaptureStatus: audit.CaptureStatusPending, CreatedAt: subject.now, ExpiresAt: subject.now.Add(24 * time.Hour),
	})
	assertInvestigationCandidatesEqual(t, candidates, want)
	otherQuery := create.CandidateQuery
	otherQuery.SubjectIdentityID = other.identityID
	otherCandidates, err := repository.FindInvestigationCandidates(context.Background(), otherQuery)
	if err != nil {
		t.Fatalf("find other employee candidates: %v", err)
	}
	assertInvestigationCandidatesEqual(t, otherCandidates, []audit.InvestigationCandidate{otherCandidate})
	create.Candidates = candidates
	mustCreateInvestigation(t, repository, create)
	assertInvestigationSnapshot(t, repository, create.Case.ID, want)
}

func TestInvestigationAcceptanceCandidateLimit(t *testing.T) {
	for _, candidateCount := range []int{100, 101} {
		t.Run(fmt.Sprintf("%d_candidates", candidateCount), func(t *testing.T) {
			db, _ := migrateRepositorySchema(t)
			subject, create := seedInvestigationAcceptance(t, db)
			for index := 1; index < candidateCount; index++ {
				insertInvestigationAcceptanceCandidate(t, db, subject, 101+index)
			}
			repository := NewRepository(db)
			candidates, err := repository.FindInvestigationCandidates(context.Background(), create.CandidateQuery)
			if err != nil || len(candidates) != candidateCount {
				t.Fatalf("candidate count = %d, error = %v, want %d", len(candidates), err, candidateCount)
			}
			create.Candidates = candidates[:100]
			err = repository.CreateInvestigationCase(context.Background(), create)
			if candidateCount == 101 {
				if !errors.Is(err, audit.ErrInvestigationScopeTooBroad) {
					t.Fatalf("101st candidate error = %v, want ErrInvestigationScopeTooBroad", err)
				}
				assertInvestigationAbsent(t, db, repository, create)
				return
			}
			if err != nil {
				t.Fatalf("create at 100-candidate boundary: %v", err)
			}
			assertInvestigationSnapshot(t, repository, create.Case.ID, candidates)
			assertInvestigationGrant(t, repository, create.Grant, create.Case.CreatedAt, true)
		})
	}
}

func TestInvestigationAcceptanceEventFailureRollsBack(t *testing.T) {
	for _, operation := range []string{"creation", "grant", "closure"} {
		t.Run(operation, func(t *testing.T) {
			db, _ := migrateRepositorySchema(t)
			_, create := seedInvestigationAcceptance(t, db)
			repository := NewRepository(db)
			var err error
			if operation == "creation" {
				mustExec(t, db, `INSERT INTO security_events (id, event_type, request_id, outcome, detail_code, occurred_at) VALUES ($1, 'synthetic_existing_event', $2, 'success', 'unchanged', $3)`, create.Event.ID, create.Event.RequestID, create.Event.OccurredAt)
				err = repository.CreateInvestigationCase(context.Background(), create)
			} else {
				mustCreateInvestigation(t, repository, create)
				if operation == "grant" {
					grant := create.Grant
					grant.ID = "85000000-0000-0000-0000-000000000104"
					grant.SessionID = "85000000-0000-0000-0000-000000000103"
					insertElevatedAuditSession(t, db, grant.ActorIdentityID, grant.SessionID, grant.IssuedAt)
					err = repository.CreateInvestigationAccessGrant(context.Background(), grant, create.Event)
					assertInvestigationRowCount(t, db, "investigation_access_grants", grant.ID, 0)
					assertInvestigationGrant(t, repository, grant, grant.IssuedAt, false)
				} else {
					closure, event := investigationAcceptanceClosure(create)
					event.ID = create.Event.ID
					err = repository.CloseInvestigationCase(context.Background(), closure, event)
				}
			}
			var postgresError *pgconn.PgError
			if !errors.As(err, &postgresError) || postgresError.Code != "23505" || postgresError.ConstraintName != "security_events_pkey" {
				t.Fatalf("%s error = %v, want security-event primary-key conflict", operation, err)
			}
			if operation == "creation" {
				assertInvestigationAbsent(t, db, repository, create)
				var unchanged bool
				if err := db.QueryRow(`SELECT event_type = 'synthetic_existing_event' AND detail_code = 'unchanged' AND investigation_case_id IS NULL FROM security_events WHERE id = $1`, create.Event.ID).Scan(&unchanged); err != nil || !unchanged {
					t.Fatalf("preexisting event unchanged = %t, error = %v", unchanged, err)
				}
				return
			}
			caseRecord, err := repository.GetInvestigationCase(context.Background(), create.Case.ID)
			if err != nil || caseRecord.Status != audit.InvestigationCaseOpen || caseRecord.ClosedAt != nil || caseRecord.Disposition != "" {
				t.Fatalf("case after rollback = %+v, error = %v", caseRecord, err)
			}
			assertInvestigationGrant(t, repository, create.Grant, create.Grant.IssuedAt.Add(time.Minute), true)
			assertInvestigationSnapshot(t, repository, create.Case.ID, create.Candidates)
			assertInvestigationEventCount(t, db, create.Case.ID, "case_created", 1)
			assertInvestigationEventCount(t, db, create.Case.ID, "case_closed", 0)
		})
	}
}

func TestInvestigationAcceptanceCrossSessionGrantDenial(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	_, create := seedInvestigationAcceptance(t, db)
	repository := NewRepository(db)
	mustCreateInvestigation(t, repository, create)
	otherSession := create.Grant
	otherSession.ID = "85000000-0000-0000-0000-000000000104"
	otherSession.SessionID = "85000000-0000-0000-0000-000000000103"
	insertElevatedAuditSession(t, db, otherSession.ActorIdentityID, otherSession.SessionID, otherSession.IssuedAt)
	otherActor := create.Grant
	otherActor.ActorIdentityID = "82000000-0000-0000-0000-000000000104"
	mustExec(t, db, `INSERT INTO identities (id, email, role, status) VALUES ($1, 'other-investigation-admin@example.internal', 'system_administrator', 'active')`, otherActor.ActorIdentityID)
	assertInvestigationGrant(t, repository, create.Grant, create.Grant.IssuedAt, true)
	assertInvestigationGrant(t, repository, otherSession, create.Grant.IssuedAt, false)
	assertInvestigationGrant(t, repository, otherActor, create.Grant.IssuedAt, false)
	otherActor.SessionID = "85000000-0000-0000-0000-000000000105"
	insertElevatedAuditSession(t, db, otherActor.ActorIdentityID, otherActor.SessionID, otherActor.IssuedAt)
	assertInvestigationGrant(t, repository, otherActor, create.Grant.IssuedAt, false)
	event := create.Event
	event.ID = "86000000-0000-0000-0000-000000000104"
	event.DetailCode = "access_granted"
	if err := repository.CreateInvestigationAccessGrant(context.Background(), otherSession, event); err != nil {
		t.Fatalf("issue explicit grant to second session: %v", err)
	}
	assertInvestigationGrant(t, repository, otherSession, otherSession.IssuedAt, true)
	assertInvestigationGrant(t, repository, create.Grant, create.Grant.IssuedAt, true)
	assertInvestigationGrant(t, repository, otherActor, create.Grant.IssuedAt, false)
}

func TestInvestigationAcceptanceClosureInvalidatesAllGrants(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	subject, create := seedInvestigationAcceptance(t, db)
	repository := NewRepository(db)
	mustCreateInvestigation(t, repository, create)
	second := create.Grant
	second.ID = "85000000-0000-0000-0000-000000000104"
	second.SessionID = "85000000-0000-0000-0000-000000000103"
	insertElevatedAuditSession(t, db, second.ActorIdentityID, second.SessionID, second.IssuedAt)
	event := create.Event
	event.ID = "86000000-0000-0000-0000-000000000104"
	event.DetailCode = "access_granted"
	if err := repository.CreateInvestigationAccessGrant(context.Background(), second, event); err != nil {
		t.Fatalf("issue second session grant: %v", err)
	}
	closure, closedEvent := investigationAcceptanceClosure(create)
	if err := repository.CloseInvestigationCase(context.Background(), closure, closedEvent); err != nil {
		t.Fatalf("close investigation: %v", err)
	}
	closed, err := repository.GetInvestigationCase(context.Background(), create.Case.ID)
	if err != nil || closed.Status != audit.InvestigationCaseClosed || closed.ClosedBy != closure.Actor.IdentityID || closed.ClosedAt == nil || !closed.ClosedAt.Equal(closure.ClosedAt) || closed.Disposition != closure.Disposition || closed.ClosureNote != closure.Note {
		t.Fatalf("closed case = %+v, error = %v", closed, err)
	}
	for _, grant := range []audit.AccessGrant{create.Grant, second} {
		assertInvestigationGrant(t, repository, grant, closure.ClosedAt, false)
		var revokedAt time.Time
		if err := db.QueryRow(`SELECT revoked_at FROM investigation_access_grants WHERE id = $1`, grant.ID).Scan(&revokedAt); err != nil || !revokedAt.Equal(closure.ClosedAt) {
			t.Fatalf("grant revocation time = %v, error = %v", revokedAt, err)
		}
	}
	second.ID = "85000000-0000-0000-0000-000000000106"
	event.ID = "86000000-0000-0000-0000-000000000106"
	if err := repository.CreateInvestigationAccessGrant(context.Background(), second, event); !errors.Is(err, audit.ErrInvestigationClosed) {
		t.Fatalf("grant after closure error = %v, want ErrInvestigationClosed", err)
	}
	assertInvestigationRowCount(t, db, "investigation_access_grants", second.ID, 0)
	if err := repository.CloseInvestigationCase(context.Background(), closure, closedEvent); !errors.Is(err, audit.ErrInvestigationClosed) {
		t.Fatalf("repeated closure error = %v, want ErrInvestigationClosed", err)
	}
	assertInvestigationEventCount(t, db, create.Case.ID, "case_closed", 1)
	assertInvestigationSnapshot(t, repository, create.Case.ID, create.Candidates)
	var identityStatus, keyStatus string
	if err := db.QueryRow(`SELECT identities.status, api_keys.status FROM identities JOIN api_keys ON api_keys.identity_id = identities.id WHERE identities.id = $1 AND api_keys.id = $2`, subject.identityID, subject.keyID).Scan(&identityStatus, &keyStatus); err != nil || identityStatus != "active" || keyStatus != "active" {
		t.Fatalf("closure changed workforce access: identity=%q key=%q error=%v", identityStatus, keyStatus, err)
	}
}

func TestInvestigationAcceptanceImmutableSnapshotAndCleanup(t *testing.T) {
	for _, closeCase := range []bool{false, true} {
		t.Run(fmt.Sprintf("closed_%t", closeCase), func(t *testing.T) {
			db, _ := migrateRepositorySchema(t)
			subject, create := seedInvestigationAcceptance(t, db)
			repository := NewRepository(db)
			mustCreateInvestigation(t, repository, create)
			late := insertInvestigationAcceptanceCandidate(t, db, subject, 102)
			mustExec(t, db, `UPDATE audit_records SET capture_status = 'truncated' WHERE id = $1`, subject.auditID)
			current, err := repository.FindInvestigationCandidates(context.Background(), create.CandidateQuery)
			if err != nil || len(current) != 2 || current[0].CaptureStatus != audit.CaptureStatusTruncated || current[1].AuditID != late.AuditID {
				t.Fatalf("live candidates did not change independently: count=%d error=%v", len(current), err)
			}
			assertInvestigationSnapshot(t, repository, create.Case.ID, create.Candidates)
			stale := create
			stale.Case.ID = "88000000-0000-0000-0000-000000000102"
			stale.Grant.CaseID, stale.Event.InvestigationCaseID = stale.Case.ID, stale.Case.ID
			stale.Grant.ID = "85000000-0000-0000-0000-000000000104"
			stale.Event.ID = "86000000-0000-0000-0000-000000000104"
			if err := repository.CreateInvestigationCase(context.Background(), stale); !errors.Is(err, audit.ErrInvestigationSnapshotChanged) {
				t.Fatalf("stale snapshot error = %v, want ErrInvestigationSnapshotChanged", err)
			}
			assertInvestigationAbsent(t, db, repository, stale)
			closure, event := investigationAcceptanceClosure(create)
			if closeCase {
				if err := repository.CloseInvestigationCase(context.Background(), closure, event); err != nil {
					t.Fatalf("close cleanup fixture case: %v", err)
				}
			}
			expiresAt := create.Candidates[0].ExpiresAt
			if _, err := repository.ReadRawContent(context.Background(), audit.RawContentLookup{AuditID: subject.auditID, ContentKind: audit.ContentKindRequest, VisibleAt: expiresAt}); !errors.Is(err, audit.ErrRawContentUnavailable) {
				t.Fatalf("case extended raw visibility at expiry: %v", err)
			}
			if deleted, err := repository.DeleteExpiredRawContent(context.Background(), expiresAt); err != nil || deleted != 2 {
				t.Fatalf("raw cleanup with case = %d, error = %v, want 2", deleted, err)
			}
			assertRowCount(t, db, "audit_raw_content", subject.auditID, 0)
			assertInvestigationSnapshot(t, repository, create.Case.ID, create.Candidates)
			assertInvestigationRowCount(t, db, "investigation_cases", create.Case.ID, 1)
			if _, err := repository.PurgeExpiredMetadata(context.Background(), subject.now.AddDate(2, 0, 0)); err != nil {
				t.Fatalf("audit metadata cleanup with retained case: %v", err)
			}
			assertRowCount(t, db, "audit_records", subject.auditID, 0)
			assertRowCount(t, db, "audit_records", late.AuditID, 0)
			assertInvestigationSnapshot(t, repository, create.Case.ID, create.Candidates)
			if _, err := repository.PurgeExpiredMetadata(context.Background(), closure.ClosedAt.AddDate(2, 0, 0).Add(time.Second)); err != nil {
				t.Fatalf("case retention cleanup: %v", err)
			}
			assertInvestigationRowCount(t, db, "investigation_cases", create.Case.ID, 1)
			assertInvestigationSnapshot(t, repository, create.Case.ID, create.Candidates)
			assertInvestigationEventCount(t, db, create.Case.ID, "case_created", 1)
		})
	}
}

func TestInvestigationAcceptanceExpiredCaseCleanupPreservesRawContent(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	subject, create := seedInvestigationAcceptance(t, db)
	closure, event := investigationAcceptanceClosure(create)
	purgeAt := closure.ClosedAt.AddDate(2, 0, 0).Add(time.Second)
	mustExec(t, db, `INSERT INTO investigation_cases (id, subject_identity_id, policy_concern, reason, start_at, end_at, status, created_by_identity_id, created_at, closed_by_identity_id, closed_at, disposition, closure_note) VALUES ($1, $2, $3, $4, $5, $6, 'closed', $7, $6, $7, $8, $9, $10)`, create.Case.ID, subject.identityID, create.Case.PolicyConcern, create.Case.Reason, create.Case.StartAt, create.Case.CreatedAt, create.Case.CreatedBy, closure.ClosedAt, closure.Disposition, closure.Note)
	mustExec(t, db, `INSERT INTO investigation_case_audits (case_id, audit_id, ordinal, capture_status, audit_created_at, raw_expires_at) VALUES ($1, $2, 1, 'pending', $3, $4)`, create.Case.ID, subject.auditID, subject.now, create.Candidates[0].ExpiresAt)
	mustExec(t, db, `INSERT INTO investigation_access_grants (id, case_id, actor_identity_id, session_id, issued_at, expires_at, revoked_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`, create.Grant.ID, create.Case.ID, create.Grant.ActorIdentityID, create.Grant.SessionID, create.Grant.IssuedAt, create.Grant.ExpiresAt, closure.ClosedAt)
	mustExec(t, db, `INSERT INTO security_events (id, event_type, actor_identity_id, target_identity_id, investigation_case_id, request_id, outcome, detail_code, occurred_at, retain_until) VALUES ($1, 'investigation_case', $2, $3, $4, $5, 'success', 'case_closed', $6, $7)`, event.ID, event.ActorIdentityID, subject.identityID, create.Case.ID, event.RequestID, closure.ClosedAt, closure.ClosedAt.AddDate(2, 0, 0))
	retained := subject
	retained.now = purgeAt.Add(-time.Hour)
	retainedCandidate := insertInvestigationAcceptanceCandidate(t, db, retained, 102)
	repository := NewRepository(db)
	assertInvestigationSnapshot(t, repository, create.Case.ID, create.Candidates)
	result, err := repository.PurgeExpiredMetadata(context.Background(), purgeAt)
	if err != nil || result.SecurityEventRows != 1 {
		t.Fatalf("expired case cleanup: security events=%d, error=%v, want 1", result.SecurityEventRows, err)
	}
	assertInvestigationAbsent(t, db, repository, create)
	assertRowCount(t, db, "audit_raw_content", subject.auditID, 1)
	assertRowCount(t, db, "audit_records", subject.auditID, 1)
	assertRowCount(t, db, "audit_raw_content", retainedCandidate.AuditID, 1)
	visible, err := repository.ReadRawContent(context.Background(), audit.RawContentLookup{AuditID: retainedCandidate.AuditID, ContentKind: audit.ContentKindRequest, VisibleAt: purgeAt})
	if err != nil || !visible.ExpiresAt.Equal(retainedCandidate.ExpiresAt) {
		t.Fatalf("independent retained raw expiry = %v, error = %v", visible.ExpiresAt, err)
	}
	if deleted, err := repository.DeleteExpiredRawContent(context.Background(), purgeAt); err != nil || deleted != 1 {
		t.Fatalf("independent expired raw cleanup = %d, error = %v, want 1", deleted, err)
	}
	assertRowCount(t, db, "audit_raw_content", retainedCandidate.AuditID, 1)
}

func TestInvestigationAcceptanceMigrationV8UpDownReapply(t *testing.T) {
	databaseURL := testDatabaseURL(t)
	const schemaName = "investigation_acceptance_migration_test"
	adminDB := openTestDatabase(t, databaseURL)
	resetTestSchema(t, adminDB, schemaName)
	db := openTestDatabase(t, databaseURLWithSearchPath(t, databaseURL, schemaName))
	migrator := openTestMigrator(t, db, schemaName, allMigrationFiles)
	migrateCompatibilityStage(t, migrator, 7)
	fixture := insertAuditPolicyFixture(t, db)
	insertRequestRawContent(t, db, fixture)
	const eventID = "86000000-0000-0000-0000-000000000108"
	mustExec(t, db, `INSERT INTO security_events (id, event_type, actor_identity_id, target_audit_id, request_id, outcome, occurred_at) VALUES ($1, 'raw_view', $2, $3, $4, 'denied', $5)`, eventID, fixture.identityID, fixture.auditID, fixture.requestID, fixture.now)
	assertInvestigationMigrationObjects(t, db, schemaName, false)
	migrateCompatibilityStage(t, migrator, 8)
	assertInvestigationMigrationObjects(t, db, schemaName, true)
	const caseID = "88000000-0000-0000-0000-000000000108"
	const sessionID = "85000000-0000-0000-0000-000000000108"
	insertElevatedAuditSession(t, db, fixture.identityID, sessionID, fixture.now)
	mustExec(t, db, `INSERT INTO investigation_cases (id, subject_identity_id, policy_concern, reason, start_at, end_at, created_by_identity_id, created_at) VALUES ($1, $2, 'migration concern', 'migration reason', $3, $4, $2, $4)`, caseID, fixture.identityID, fixture.now.Add(-time.Hour), fixture.now)
	mustExec(t, db, `INSERT INTO investigation_case_audits (case_id, audit_id, ordinal, capture_status, audit_created_at, raw_expires_at) VALUES ($1, $2, 1, 'pending', $3, $4)`, caseID, fixture.auditID, fixture.now, fixture.now.Add(24*time.Hour))
	mustExec(t, db, `INSERT INTO investigation_access_grants (id, case_id, actor_identity_id, session_id, issued_at, expires_at) VALUES ($1, $2, $3, $1, $4, $5)`, sessionID, caseID, fixture.identityID, fixture.now, fixture.now.Add(30*time.Minute))
	mustExec(t, db, `INSERT INTO security_events (id, event_type, investigation_case_id, request_id, outcome, occurred_at) VALUES ($1, 'investigation_case', $2, $3, 'success', $4)`, "86000000-0000-0000-0000-000000000109", caseID, fixture.requestID, fixture.now)
	repository := NewRepository(db)
	assertInvestigationSnapshot(t, repository, caseID, []audit.InvestigationCandidate{{AuditID: fixture.auditID, CaptureStatus: audit.CaptureStatusPending, CreatedAt: fixture.now, ExpiresAt: fixture.now.Add(24 * time.Hour)}})
	if err := migrator.Steps(-1); err != nil {
		t.Fatalf("roll back investigation migration: %v", err)
	}
	assertMigrationVersion(t, migrator, 7)
	assertInvestigationMigrationObjects(t, db, schemaName, false)
	assertRowCount(t, db, "audit_records", fixture.auditID, 1)
	assertRowCount(t, db, "audit_raw_content", fixture.auditID, 1)
	var eventCount int
	if err := db.QueryRow(`SELECT count(*) FROM security_events WHERE id IN ($1, $2)`, eventID, "86000000-0000-0000-0000-000000000109").Scan(&eventCount); err != nil || eventCount != 2 {
		t.Fatalf("security events after v8 rollback = %d, error = %v, want 2", eventCount, err)
	}
	migrateCompatibilityStage(t, migrator, 8)
	assertInvestigationMigrationObjects(t, db, schemaName, true)
	page, err := repository.ListInvestigationCases(context.Background(), audit.InvestigationCaseListFilter{Limit: 100})
	if err != nil || len(page.Cases) != 0 {
		t.Fatalf("cases after reapply = %d, error = %v, want empty", len(page.Cases), err)
	}
	var expiresAt time.Time
	if err := db.QueryRow(`SELECT expires_at FROM audit_raw_content WHERE audit_id = $1 AND content_kind = 'request'`, fixture.auditID).Scan(&expiresAt); err != nil || !expiresAt.Equal(fixture.now.Add(24*time.Hour)) {
		t.Fatalf("raw expiry changed by migration: %v, error = %v", expiresAt, err)
	}
	expectRejected(t, db, `UPDATE security_events SET outcome = 'success' WHERE id = $1`, eventID)
}

func seedInvestigationAcceptance(t *testing.T, db *sql.DB) (auditPolicyFixture, audit.InvestigationCaseCreate) {
	t.Helper()
	fixture := insertAuditPolicyFixture(t, db)
	subject := fixture
	subject.now = time.Date(2022, time.August, 1, 0, 0, 0, 0, time.UTC)
	subject.identityID = "82000000-0000-0000-0000-000000000101"
	subject.keyID = "83000000-0000-0000-0000-000000000101"
	subject.auditID = "84000000-0000-0000-0000-000000000101"
	subject.requestID = "87000000-0000-0000-0000-000000000101"
	insertEmployeeAuditCandidate(t, db, subject, subject.identityID, subject.keyID, subject.auditID, subject.requestID)
	now := subject.now.Add(time.Minute)
	const caseID = "88000000-0000-0000-0000-000000000101"
	const sessionID = "85000000-0000-0000-0000-000000000101"
	insertElevatedAuditSession(t, db, fixture.identityID, sessionID, now)
	return subject, audit.InvestigationCaseCreate{
		Case: audit.InvestigationCase{
			ID: caseID, SubjectIdentityID: subject.identityID, PolicyConcern: "synthetic policy concern", Reason: "synthetic investigation reason",
			StartAt: subject.now.Add(-time.Hour), EndAt: now, Status: audit.InvestigationCaseOpen, CreatedBy: fixture.identityID, CreatedAt: now,
		},
		Candidates: []audit.InvestigationCandidate{{AuditID: subject.auditID, CaptureStatus: audit.CaptureStatusPending, CreatedAt: subject.now, ExpiresAt: subject.now.Add(24 * time.Hour)}},
		Grant:      audit.AccessGrant{ID: "85000000-0000-0000-0000-000000000102", CaseID: caseID, ActorIdentityID: fixture.identityID, SessionID: sessionID, IssuedAt: now, ExpiresAt: now.Add(30 * time.Minute)},
		Event: access.SecurityEvent{
			ID: "86000000-0000-0000-0000-000000000101", EventType: "investigation_case", ActorIdentityID: fixture.identityID,
			TargetIdentityID: subject.identityID, InvestigationCaseID: caseID, RequestID: subject.requestID,
			Outcome: access.SecurityEventSuccess, Reason: "synthetic investigation reason", DetailCode: "case_created", OccurredAt: now,
		},
		CandidateQuery: audit.InvestigationCandidateQuery{SubjectIdentityID: subject.identityID, StartAt: subject.now.Add(-time.Hour), EndAt: now, VisibleAt: now, Limit: 101},
	}
}

func insertInvestigationAcceptanceCandidate(t *testing.T, db *sql.DB, subject auditPolicyFixture, sequence int) audit.InvestigationCandidate {
	t.Helper()
	subject.auditID = fmt.Sprintf("84000000-0000-0000-0000-%012d", sequence)
	subject.requestID = fmt.Sprintf("87000000-0000-0000-0000-%012d", sequence)
	insertPendingAudit(t, db, subject.auditID, subject.requestID, subject, subject.now)
	insertRequestRawContent(t, db, subject)
	return audit.InvestigationCandidate{AuditID: subject.auditID, CaptureStatus: audit.CaptureStatusPending, CreatedAt: subject.now, ExpiresAt: subject.now.Add(24 * time.Hour)}
}

func mustCreateInvestigation(t *testing.T, repository *Repository, create audit.InvestigationCaseCreate) {
	t.Helper()
	if err := repository.CreateInvestigationCase(context.Background(), create); err != nil {
		t.Fatalf("CreateInvestigationCase(): %v", err)
	}
}

func investigationAcceptanceClosure(create audit.InvestigationCaseCreate) (audit.InvestigationCaseClosure, access.SecurityEvent) {
	closure := audit.InvestigationCaseClosure{
		CaseID: create.Case.ID, Actor: access.ActivePortalSession{SessionID: create.Grant.SessionID, IdentityID: create.Grant.ActorIdentityID, Role: access.RoleSystemAdministrator},
		Disposition: audit.InvestigationConfirmedViolation, Note: "synthetic manual finding", ClosedAt: create.Case.CreatedAt.Add(time.Minute), Confirmed: true, RequestID: create.Event.RequestID,
	}
	event := create.Event
	event.ID = "86000000-0000-0000-0000-000000000105"
	event.DetailCode = "case_closed"
	event.OccurredAt = closure.ClosedAt
	return closure, event
}

func assertInvestigationSnapshot(t *testing.T, repository *Repository, caseID string, want []audit.InvestigationCandidate) {
	t.Helper()
	got, err := repository.ListInvestigationCandidates(context.Background(), caseID)
	if err != nil {
		t.Fatalf("ListInvestigationCandidates(): %v", err)
	}
	assertInvestigationCandidatesEqual(t, got, want)
}

func assertInvestigationCandidatesEqual(t *testing.T, got, want []audit.InvestigationCandidate) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("candidate count = %d, want %d", len(got), len(want))
	}
	for index, candidate := range got {
		expected := want[index]
		if candidate.AuditID != expected.AuditID || candidate.CaptureStatus != expected.CaptureStatus || !candidate.CreatedAt.Equal(expected.CreatedAt) || !candidate.ExpiresAt.Equal(expected.ExpiresAt) {
			t.Fatalf("candidate %d metadata = %+v, want %+v", index, candidate, expected)
		}
	}
}

func assertInvestigationGrant(t *testing.T, repository *Repository, want audit.AccessGrant, at time.Time, present bool) {
	t.Helper()
	got, err := repository.FindInvestigationAccessGrant(context.Background(), audit.AccessGrantLookup{CaseID: want.CaseID, ActorIdentityID: want.ActorIdentityID, SessionID: want.SessionID, At: at})
	if !present {
		if !errors.Is(err, audit.ErrInvestigationGrantNotFound) || got.ID != "" {
			t.Fatalf("grant lookup error = %v, want ErrInvestigationGrantNotFound and no grant", err)
		}
		return
	}
	if err != nil || got.ID != want.ID || got.CaseID != want.CaseID || got.ActorIdentityID != want.ActorIdentityID || got.SessionID != want.SessionID || !got.IssuedAt.Equal(want.IssuedAt) || !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("grant metadata = %+v, error = %v, want %+v", got, err, want)
	}
}

func assertInvestigationEventCount(t *testing.T, db *sql.DB, caseID, detailCode string, want int) {
	t.Helper()
	var got int
	if err := db.QueryRow(`SELECT count(*) FROM security_events WHERE investigation_case_id = $1 AND detail_code = $2`, caseID, detailCode).Scan(&got); err != nil || got != want {
		t.Fatalf("%s event count = %d, error = %v, want %d", detailCode, got, err, want)
	}
}

func assertInvestigationAbsent(t *testing.T, db *sql.DB, repository *Repository, create audit.InvestigationCaseCreate) {
	t.Helper()
	assertInvestigationRowCount(t, db, "investigation_cases", create.Case.ID, 0)
	assertInvestigationRowCount(t, db, "investigation_access_grants", create.Grant.ID, 0)
	assertInvestigationSnapshot(t, repository, create.Case.ID, nil)
	var events int
	if err := db.QueryRow(`SELECT count(*) FROM security_events WHERE investigation_case_id = $1`, create.Case.ID).Scan(&events); err != nil || events != 0 {
		t.Fatalf("absent case event count = %d, error = %v, want 0", events, err)
	}
}

func assertInvestigationMigrationObjects(t *testing.T, db *sql.DB, schemaName string, want bool) {
	t.Helper()
	for _, name := range []string{
		"investigation_cases", "investigation_case_audits", "investigation_access_grants",
		"investigation_cases_status_created_idx", "investigation_cases_subject_created_idx",
		"investigation_case_audits_audit_idx", "investigation_access_grants_lookup_idx", "security_events_investigation_case_idx",
	} {
		var present bool
		if err := db.QueryRow(`SELECT to_regclass($1 || '.' || $2) IS NOT NULL`, schemaName, name).Scan(&present); err != nil || present != want {
			t.Fatalf("migration object %s present = %t, error = %v, want %t", name, present, err, want)
		}
	}
	var columnPresent bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = $1 AND table_name = 'security_events' AND column_name = 'investigation_case_id')`, schemaName).Scan(&columnPresent); err != nil || columnPresent != want {
		t.Fatalf("case-attribution column present = %t, error = %v, want %t", columnPresent, err, want)
	}
}
