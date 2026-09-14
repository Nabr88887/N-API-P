//go:build integration

package database

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
)

func TestElevatedAuditRepositorySelectsCrossOwnerFiltersAndStableSnapshot(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	data := insertElevatedQueryData(t, db, fixture, time.Now().UTC().Truncate(time.Microsecond))
	repository := NewRepository(db)
	visibleAt := data.now.Add(10 * time.Minute)
	selection := audit.ElevatedAuditSelection{Limit: 10, VisibleAt: visibleAt, SnapshotAt: visibleAt}
	candidates, err := repository.ListElevatedAuditCandidates(context.Background(), selection)
	if err != nil {
		t.Fatalf("ListElevatedAuditCandidates() error = %v", err)
	}
	assertElevatedCandidateIDs(t, candidates, data.personalAuditID, data.serviceAuditID, data.secondPersonalAuditID)

	identityID := data.employeeTwoID
	selection.IdentityID = &identityID
	candidates, err = repository.ListElevatedAuditCandidates(context.Background(), selection)
	if err != nil {
		t.Fatalf("identity filter error = %v", err)
	}
	assertElevatedCandidateIDs(t, candidates, data.serviceAuditID, data.secondPersonalAuditID)

	selection = audit.ElevatedAuditSelection{Limit: 10, VisibleAt: visibleAt, SnapshotAt: visibleAt}
	serviceAccountID := data.serviceAccountID
	selection.ServiceAccountID = &serviceAccountID
	candidates, err = repository.ListElevatedAuditCandidates(context.Background(), selection)
	if err != nil {
		t.Fatalf("service-account filter error = %v", err)
	}
	assertElevatedCandidateIDs(t, candidates, data.serviceAuditID)

	selection = audit.ElevatedAuditSelection{Limit: 10, VisibleAt: visibleAt, SnapshotAt: visibleAt}
	responsibleIdentityID := data.employeeTwoID
	selection.ResponsibleIdentityID = &responsibleIdentityID
	candidates, err = repository.ListElevatedAuditCandidates(context.Background(), selection)
	if err != nil {
		t.Fatalf("responsible-identity filter error = %v", err)
	}
	assertElevatedCandidateIDs(t, candidates, data.serviceAuditID)

	modelID := "gpt-filtered"
	captureStatus := audit.CaptureStatusComplete
	outcome := audit.AuditOutcomeSuccess
	ownerKind := audit.OwnerKindService
	from := data.now.Add(-time.Minute)
	to := data.now.Add(time.Minute)
	selection = audit.ElevatedAuditSelection{
		Limit: 10, VisibleAt: visibleAt, SnapshotAt: visibleAt, From: &from, To: &to,
		ModelID: &modelID, CaptureStatus: &captureStatus, Outcome: &outcome, OwnerKind: &ownerKind,
	}
	candidates, err = repository.ListElevatedAuditCandidates(context.Background(), selection)
	if err != nil {
		t.Fatalf("optional filter error = %v", err)
	}
	assertElevatedCandidateIDs(t, candidates, data.serviceAuditID)

	selection = audit.ElevatedAuditSelection{Limit: 10, VisibleAt: visibleAt, SnapshotAt: visibleAt, AuditIDs: []string{data.personalAuditID, data.secondPersonalAuditID}}
	candidates, err = repository.ListElevatedAuditCandidates(context.Background(), selection)
	if err != nil {
		t.Fatalf("audit-ID filter error = %v", err)
	}
	assertElevatedCandidateIDs(t, candidates, data.personalAuditID, data.secondPersonalAuditID)

	selection = audit.ElevatedAuditSelection{Limit: 10, VisibleAt: visibleAt, SnapshotAt: visibleAt}
	mustExec(t, db, `INSERT INTO audit_records (id, request_id, key_id, owner_kind, identity_id, team_id, model_id, capture_status, outcome, observed_request_bytes, observed_response_bytes, created_at, updated_at) VALUES ($1, $2, $3, 'personal', $4, $5, 'gpt-new', 'complete', 'success', 1, 1, $6, $6)`, data.afterSnapshotAuditID, data.afterSnapshotRequestID, data.employeeOneKeyID, data.employeeOneID, fixture.teamID, visibleAt.Add(time.Second))
	insertElevatedRawMarker(t, db, data.afterSnapshotAuditID, data.now, visibleAt.Add(time.Hour))
	candidates, err = repository.ListElevatedAuditCandidates(context.Background(), selection)
	if err != nil {
		t.Fatalf("snapshot filter error = %v", err)
	}
	assertElevatedCandidateIDs(t, candidates, data.personalAuditID, data.serviceAuditID, data.secondPersonalAuditID)

	selection = audit.ElevatedAuditSelection{Limit: 2, VisibleAt: visibleAt, SnapshotAt: visibleAt}
	candidates, err = repository.ListElevatedAuditCandidates(context.Background(), selection)
	if err != nil {
		t.Fatalf("first cursor page error = %v", err)
	}
	if len(candidates) != 2 {
		t.Fatalf("first cursor page length = %d, want 2", len(candidates))
	}
	last := candidates[len(candidates)-1].Metadata
	selection.Cursor = &audit.ElevatedAuditPosition{CreatedAt: last.CreatedAt, ID: last.ID}
	candidates, err = repository.ListElevatedAuditCandidates(context.Background(), selection)
	if err != nil {
		t.Fatalf("cursor continuation error = %v", err)
	}
	assertElevatedCandidateIDs(t, candidates, data.secondPersonalAuditID)
}

func TestElevatedAuditQueryServiceUsesPostgresFullTextAndRejectsBoundCursorReplay(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	now := time.Now().UTC().Truncate(time.Microsecond)
	data := insertElevatedQueryData(t, db, fixture, now)
	mustExec(t, db, `DELETE FROM audit_raw_content WHERE audit_id IN ($1, $2)`, data.personalAuditID, data.serviceAuditID)
	insertElevatedEncryptedContent(t, db, data, fixture.teamID)
	insertElevatedEncryptedSecondRecord(t, db, data, fixture.teamID)
	insertElevatedAuditSession(t, db, fixture.identityID, data.sessionID, data.issuedAt)
	repository := NewRepository(db)
	grant := elevatedAuditTestGrant(data.grantID, fixture.identityID, data.sessionID, data.issuedAt, "query integration")
	if err := repository.CreateElevatedAuditGrant(context.Background(), grant, elevatedAuditIssuedEvent(grant, data.grantEventID, data.grantRequestID)); err != nil {
		t.Fatalf("CreateElevatedAuditGrant() error = %v", err)
	}
	envelope, err := audit.NewEnvelopeService(1, map[int][]byte{1: bytes.Repeat([]byte{0x41}, 32)})
	if err != nil {
		t.Fatalf("NewEnvelopeService() error = %v", err)
	}
	service, err := audit.NewElevatedAuditQueryService(repository, envelope)
	if err != nil {
		t.Fatalf("NewElevatedAuditQueryService() error = %v", err)
	}
	sessionExpiry := data.issuedAt.Add(12 * time.Hour)
	reauthenticatedUntil := data.issuedAt.Add(time.Hour)
	session := access.ActivePortalSession{
		SessionID: data.sessionID, IdentityID: fixture.identityID, Role: access.RoleSystemAdministrator,
		IdleExpiresAt: data.issuedAt.Add(time.Hour), AbsoluteExpiresAt: sessionExpiry, ReauthenticatedUntil: &reauthenticatedUntil,
	}

	firstPage, err := service.Query(context.Background(), audit.ElevatedAuditQueryInput{
		Session: session, RequestID: "87000000-0000-0000-0000-000000000061",
		Query: audit.ElevatedAuditQuery{FullText: "needle", Limit: 1},
	})
	if err != nil {
		t.Fatalf("full-text query error = %v", err)
	}
	if len(firstPage.Records) != 1 || firstPage.Records[0].ID != data.personalAuditID || firstPage.NextCursor == "" {
		t.Fatalf("full-text first page = ids=%v cursor=%q", elevatedRecordIDs(firstPage.Records), firstPage.NextCursor)
	}
	if !bytes.Contains(firstPage.Records[0].RequestJSON, []byte("needle")) {
		t.Fatalf("full-text record request does not contain the synthetic match")
	}
	firstPage.Clear()

	secondPage, err := service.Query(context.Background(), audit.ElevatedAuditQueryInput{
		Session: session, RequestID: "87000000-0000-0000-0000-000000000062",
		Query: audit.ElevatedAuditQuery{FullText: "needle", Limit: 1, Cursor: firstPage.NextCursor},
	})
	if err != nil {
		t.Fatalf("cursor continuation error = %v", err)
	}
	if len(secondPage.Records) != 1 || secondPage.Records[0].ID != data.serviceAuditID {
		t.Fatalf("full-text second page = ids=%v", elevatedRecordIDs(secondPage.Records))
	}
	secondPage.Clear()

	tamperedQuery := audit.ElevatedAuditQuery{FullText: "different", Limit: 1, Cursor: firstPage.NextCursor}
	if _, err := service.Query(context.Background(), audit.ElevatedAuditQueryInput{Session: session, RequestID: "87000000-0000-0000-0000-000000000063", Query: tamperedQuery}); !errors.Is(err, audit.ErrInvalidElevatedAuditCursor) {
		t.Fatalf("cross-query cursor error = %v, want ErrInvalidElevatedAuditCursor", err)
	}

	otherSessionID := "85000000-0000-0000-0000-000000000063"
	insertElevatedAuditSession(t, db, fixture.identityID, otherSessionID, data.issuedAt)
	otherGrant := elevatedAuditTestGrant("85000000-0000-0000-0000-000000000064", fixture.identityID, otherSessionID, data.issuedAt, "second query integration")
	if err := repository.CreateElevatedAuditGrant(context.Background(), otherGrant, elevatedAuditIssuedEvent(otherGrant, "86000000-0000-0000-0000-000000000064", "87000000-0000-0000-0000-000000000064")); err != nil {
		t.Fatalf("second CreateElevatedAuditGrant() error = %v", err)
	}
	otherSession := session
	otherSession.SessionID = otherSessionID
	if _, err := service.Query(context.Background(), audit.ElevatedAuditQueryInput{Session: otherSession, RequestID: "87000000-0000-0000-0000-000000000065", Query: audit.ElevatedAuditQuery{FullText: "needle", Limit: 1, Cursor: firstPage.NextCursor}}); !errors.Is(err, audit.ErrInvalidElevatedAuditCursor) {
		t.Fatalf("cross-grant cursor error = %v, want ErrInvalidElevatedAuditCursor", err)
	}
}

type elevatedQueryTestData struct {
	now                     time.Time
	employeeOneID           string
	employeeTwoID           string
	employeeOneKeyID        string
	serviceAccountID        string
	personalAuditID         string
	serviceAuditID          string
	secondPersonalAuditID   string
	afterSnapshotAuditID    string
	afterSnapshotRequestID  string
	personalRequestID       string
	serviceRequestID        string
	secondPersonalRequestID string
	sessionID               string
	grantID                 string
	grantEventID            string
	grantRequestID          string
	issuedAt                time.Time
}

func insertElevatedQueryData(t *testing.T, db *sql.DB, fixture auditPolicyFixture, now time.Time) elevatedQueryTestData {
	t.Helper()
	data := elevatedQueryTestData{
		now: now, employeeOneID: "82000000-0000-0000-0000-000000000010", employeeTwoID: "82000000-0000-0000-0000-000000000011",
		employeeOneKeyID: "83000000-0000-0000-0000-000000000010", serviceAccountID: "88000000-0000-0000-0000-000000000010",
		personalAuditID: "84000000-0000-0000-0000-000000000010", serviceAuditID: "84000000-0000-0000-0000-000000000011", secondPersonalAuditID: "84000000-0000-0000-0000-000000000012",
		afterSnapshotAuditID: "84000000-0000-0000-0000-000000000013", afterSnapshotRequestID: "87000000-0000-0000-0000-000000000013",
		personalRequestID: "87000000-0000-0000-0000-000000000010", serviceRequestID: "87000000-0000-0000-0000-000000000011", secondPersonalRequestID: "87000000-0000-0000-0000-000000000012",
		sessionID: "85000000-0000-0000-0000-000000000060", grantID: "85000000-0000-0000-0000-000000000061",
		grantEventID: "86000000-0000-0000-0000-000000000061", grantRequestID: "87000000-0000-0000-0000-000000000060", issuedAt: now.Add(-time.Minute),
	}
	mustExec(t, db, `INSERT INTO identities (id, email, role, status) VALUES ($1, $2, 'employee', 'active'), ($3, $4, 'employee', 'active')`, data.employeeOneID, "query-one@example.internal", data.employeeTwoID, "query-two@example.internal")
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2), ($3, $2)`, data.employeeOneID, fixture.teamID, data.employeeTwoID)
	mustExec(t, db, `INSERT INTO api_keys (id, identity_id, kind, name, prefix, verification_hash, status, created_at) VALUES ($1, $2, 'personal', 'query-one-key', 'nap_qone', $3, 'active', $4)`, data.employeeOneKeyID, data.employeeOneID, []byte("query-one-key-hash"), now)
	secondKeyID := "83000000-0000-0000-0000-000000000011"
	mustExec(t, db, `INSERT INTO api_keys (id, identity_id, kind, name, prefix, verification_hash, status, created_at) VALUES ($1, $2, 'personal', 'query-two-key', 'nap_qtwo', $3, 'active', $4)`, secondKeyID, data.employeeTwoID, []byte("query-two-key-hash"), now)
	mustExec(t, db, `INSERT INTO service_accounts (id, team_id, responsible_identity_id, name, status, created_at, updated_at) VALUES ($1, $2, $3, 'query-service', 'active', $4, $4)`, data.serviceAccountID, fixture.teamID, data.employeeTwoID, now)
	serviceKeyID := "83000000-0000-0000-0000-000000000012"
	mustExec(t, db, `INSERT INTO api_keys (id, service_account_id, kind, name, prefix, verification_hash, status, created_at) VALUES ($1, $2, 'service', 'query-service-key', 'nap_qsvc', $3, 'active', $4)`, serviceKeyID, data.serviceAccountID, []byte("query-service-key-hash"), now)
	insertElevatedQueryAudit(t, db, data.personalAuditID, data.personalRequestID, data.employeeOneKeyID, data.employeeOneID, fixture.teamID, "gpt-personal", "complete", "success", now)
	insertElevatedQueryAudit(t, db, data.serviceAuditID, data.serviceRequestID, serviceKeyID, data.serviceAccountID, fixture.teamID, "gpt-filtered", "complete", "success", now.Add(-15*time.Second))
	insertElevatedQueryAudit(t, db, data.secondPersonalAuditID, data.secondPersonalRequestID, secondKeyID, data.employeeTwoID, fixture.teamID, "gpt-second", "truncated", "cancelled", now.Add(-30*time.Second))
	insertElevatedRawMarker(t, db, data.personalAuditID, now, now.Add(time.Hour))
	insertElevatedRawMarker(t, db, data.serviceAuditID, now.Add(-15*time.Second), now.Add(time.Hour))
	insertElevatedRawMarker(t, db, data.secondPersonalAuditID, now.Add(-30*time.Second), now.Add(time.Hour))
	insertElevatedRawMarker(t, db, "84000000-0000-0000-0000-000000000099", now.Add(-time.Hour), now.Add(-time.Minute))
	return data
}

func insertElevatedQueryAudit(t *testing.T, db *sql.DB, auditID, requestID, keyID, ownerID, teamID, modelID, captureStatus, outcome string, createdAt time.Time) {
	t.Helper()
	if keyID == "83000000-0000-0000-0000-000000000012" {
		mustExec(t, db, `INSERT INTO audit_records (id, request_id, key_id, owner_kind, service_account_id, responsible_identity_id, team_id, model_id, capture_status, outcome, observed_request_bytes, observed_response_bytes, created_at, updated_at) VALUES ($1, $2, $3, 'service', $4, $5, $6, $7, $8, $9, 32, 32, $10, $10)`, auditID, requestID, keyID, ownerID, "82000000-0000-0000-0000-000000000011", teamID, modelID, captureStatus, outcome, createdAt)
		return
	}
	mustExec(t, db, `INSERT INTO audit_records (id, request_id, key_id, owner_kind, identity_id, team_id, model_id, capture_status, outcome, observed_request_bytes, observed_response_bytes, created_at, updated_at) VALUES ($1, $2, $3, 'personal', $4, $5, $6, $7, $8, 32, 32, $9, $9)`, auditID, requestID, keyID, ownerID, teamID, modelID, captureStatus, outcome, createdAt)
}

func insertElevatedRawMarker(t *testing.T, db *sql.DB, auditID string, createdAt, expiresAt time.Time) {
	t.Helper()
	if auditID == "84000000-0000-0000-0000-000000000099" {
		mustExec(t, db, `INSERT INTO audit_records (id, request_id, key_id, owner_kind, identity_id, team_id, model_id, capture_status, outcome, observed_request_bytes, observed_response_bytes, created_at, updated_at) VALUES ($1, $2, $3, 'personal', $4, $5, 'gpt-expired', 'complete', 'success', 1, 1, $6, $6)`, auditID, "87000000-0000-0000-0000-000000000099", "83000000-0000-0000-0000-000000000010", "82000000-0000-0000-0000-000000000010", "81000000-0000-0000-0000-000000000001", createdAt)
	}
	mustExec(t, db, `INSERT INTO audit_raw_content (audit_id, content_kind, compression, ciphertext, cipher_nonce, wrapped_data_key, wrap_nonce, key_version, created_at, expires_at) VALUES ($1, 'request', 'gzip', $2, $3, $4, $5, 1, $6, $7)`, auditID, []byte("synthetic-encrypted-content-and-tag"), make([]byte, 12), []byte("synthetic-wrapped-data-key-and-tag"), make([]byte, 12), createdAt, expiresAt)
}

func insertElevatedEncryptedContent(t *testing.T, db *sql.DB, data elevatedQueryTestData, teamID string) {
	t.Helper()
	envelope, err := audit.NewEnvelopeService(1, map[int][]byte{1: bytes.Repeat([]byte{0x41}, 32)})
	if err != nil {
		t.Fatalf("NewEnvelopeService() error = %v", err)
	}
	requestContext := audit.EncryptionContext{AuditID: data.personalAuditID, ContentKind: audit.ContentKindRequest, OwnerKind: audit.OwnerKindPersonal, IdentityID: data.employeeOneID, TeamID: teamID, CreatedAt: data.now}
	responseContext := requestContext
	responseContext.ContentKind = audit.ContentKindResponse
	request, err := envelope.Encrypt([]byte(`{"messages":[{"content":"synthetic needle"}]}`), requestContext)
	if err != nil {
		t.Fatalf("encrypt request fixture: %v", err)
	}
	response, err := envelope.Encrypt([]byte(`{"response":"synthetic answer"}`), responseContext)
	if err != nil {
		t.Fatalf("encrypt response fixture: %v", err)
	}
	insertRepositoryRawViewContent(t, db, data.personalAuditID, "request", request, requestContext.CreatedAt, data.now.Add(time.Hour))
	insertRepositoryRawViewContent(t, db, data.personalAuditID, "response", response, responseContext.CreatedAt, data.now.Add(time.Hour))
}

func insertElevatedEncryptedSecondRecord(t *testing.T, db *sql.DB, data elevatedQueryTestData, teamID string) {
	t.Helper()
	envelope, err := audit.NewEnvelopeService(1, map[int][]byte{1: bytes.Repeat([]byte{0x41}, 32)})
	if err != nil {
		t.Fatalf("NewEnvelopeService() error = %v", err)
	}
	createdAt := data.now.Add(-15 * time.Second)
	requestContext := audit.EncryptionContext{AuditID: data.serviceAuditID, ContentKind: audit.ContentKindRequest, OwnerKind: audit.OwnerKindService, ServiceAccountID: data.serviceAccountID, ResponsibleIdentityID: data.employeeTwoID, TeamID: teamID, CreatedAt: createdAt}
	responseContext := requestContext
	responseContext.ContentKind = audit.ContentKindResponse
	request, err := envelope.Encrypt([]byte(`{"messages":[{"content":"synthetic needle for service"}]}`), requestContext)
	if err != nil {
		t.Fatalf("encrypt service request fixture: %v", err)
	}
	response, err := envelope.Encrypt([]byte(`{"response":"service answer"}`), responseContext)
	if err != nil {
		t.Fatalf("encrypt service response fixture: %v", err)
	}
	insertRepositoryRawViewContent(t, db, data.serviceAuditID, "request", request, createdAt, data.now.Add(time.Hour))
	insertRepositoryRawViewContent(t, db, data.serviceAuditID, "response", response, createdAt, data.now.Add(time.Hour))
}

func assertElevatedCandidateIDs(t *testing.T, candidates []audit.ElevatedAuditCandidate, want ...string) {
	t.Helper()
	got := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		got = append(got, candidate.Metadata.ID)
	}
	if len(got) != len(want) {
		t.Fatalf("candidate IDs = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("candidate IDs = %v, want %v", got, want)
		}
	}
}

func elevatedRecordIDs(records []audit.ElevatedAuditRecord) []string {
	ids := make([]string, 0, len(records))
	for _, record := range records {
		ids = append(ids, record.ID)
	}
	return ids
}
