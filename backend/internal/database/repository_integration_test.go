//go:build integration

package database

import (
	"context"
	"database/sql"
	"errors"
	"n-api-p/internal/audit"
	"testing"
	"time"
)

func TestRepositoryListsAuditsWithExplicitColumnsAndStableBoundedPagination(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	insertPendingAudit(t, db, "84000000-0000-0000-0000-000000000002", "87000000-0000-0000-0000-000000000002", fixture, fixture.now)
	insertPendingAudit(t, db, "84000000-0000-0000-0000-000000000003", "87000000-0000-0000-0000-000000000003", fixture, fixture.now)
	mustExec(t, db, `ALTER TABLE audit_records ADD COLUMN repository_test_extra text NOT NULL DEFAULT 'extra'`)

	repository := NewRepository(db)
	identityID := fixture.identityID
	captureStatus := "pending"
	modelID := "gpt-test"

	for _, limit := range []int{0, MaxPageSize + 1} {
		_, err := repository.ListAuditRecords(context.Background(), AuditListFilter{Limit: limit})
		if !errors.Is(err, ErrInvalidPageSize) {
			t.Fatalf("list audit records with limit %d error = %v, want ErrInvalidPageSize", limit, err)
		}
	}

	firstPage, err := repository.ListAuditRecords(context.Background(), AuditListFilter{
		IdentityID:    &identityID,
		CaptureStatus: &captureStatus,
		ModelID:       &modelID,
		Limit:         2,
	})
	if err != nil {
		t.Fatalf("list first audit page: %v", err)
	}
	assertAuditIDs(t, firstPage,
		"84000000-0000-0000-0000-000000000003",
		"84000000-0000-0000-0000-000000000002",
	)

	secondPage, err := repository.ListAuditRecords(context.Background(), AuditListFilter{
		IdentityID:    &identityID,
		CaptureStatus: &captureStatus,
		ModelID:       &modelID,
		Cursor: &AuditCursor{
			CreatedAt: firstPage[1].CreatedAt,
			ID:        firstPage[1].ID,
		},
		Limit: 2,
	})
	if err != nil {
		t.Fatalf("list second audit page: %v", err)
	}
	assertAuditIDs(t, secondPage, "84000000-0000-0000-0000-000000000001")

	injection := "gpt-test' OR '1'='1"
	results, err := repository.ListAuditRecords(context.Background(), AuditListFilter{
		IdentityID: &identityID,
		ModelID:    &injection,
		Limit:      MaxPageSize,
	})
	if err != nil {
		t.Fatalf("list audit records with hostile model filter: %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("hostile model filter returned %d records, want none", len(results))
	}
}

func TestRepositoryListsAndGetsAuditMetadataWithoutRawContent(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	secondAuditID := "84000000-0000-0000-0000-000000000004"
	insertPendingAudit(t, db, secondAuditID, "87000000-0000-0000-0000-000000000004", fixture, fixture.now.Add(time.Minute))

	repository := NewRepository(db)
	page, err := repository.ListAuditMetadata(context.Background(), audit.MetadataFilter{Limit: 1})
	if err != nil {
		t.Fatalf("ListAuditMetadata() error = %v", err)
	}
	if len(page.Records) != 1 || page.Records[0].ID != secondAuditID || page.NextCursor == "" {
		t.Fatalf("first metadata page = %+v", page)
	}
	secondPage, err := repository.ListAuditMetadata(context.Background(), audit.MetadataFilter{Limit: 1, Cursor: page.NextCursor})
	if err != nil {
		t.Fatalf("ListAuditMetadata(second page) error = %v", err)
	}
	if len(secondPage.Records) != 1 || secondPage.Records[0].ID != fixture.auditID || secondPage.NextCursor != "" {
		t.Fatalf("second metadata page = %+v", secondPage)
	}
	record, err := repository.GetAuditMetadata(context.Background(), fixture.auditID)
	if err != nil {
		t.Fatalf("GetAuditMetadata() error = %v", err)
	}
	if record.ID != fixture.auditID || record.ModelID != "gpt-test" || record.ObservedRequestBytes != 128 {
		t.Fatalf("metadata record = %+v", record)
	}
	if _, err := repository.GetAuditMetadata(context.Background(), "84000000-0000-0000-0000-000000000099"); !errors.Is(err, audit.ErrMetadataNotFound) {
		t.Fatalf("GetAuditMetadata(missing) error = %v, want ErrMetadataNotFound", err)
	}
}

func TestRepositoryCreatePendingAuditRollsBackOnRawContentFailure(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)

	auditID := "84000000-0000-0000-0000-000000000010"
	requestID := "87000000-0000-0000-0000-000000000010"
	input := audit.PendingAudit{
		ID:                   auditID,
		RequestID:            requestID,
		KeyID:                fixture.keyID,
		OwnerKind:            audit.OwnerKindPersonal,
		IdentityID:           fixture.identityID,
		TeamID:               fixture.teamID,
		ModelID:              "gpt-test",
		CaptureStatus:        audit.CaptureStatusPending,
		Outcome:              audit.AuditOutcomePending,
		ObservedRequestBytes: 128,
		CreatedAt:            fixture.now,
		ExpiresAt:            fixture.now.Add(24 * time.Hour),
		RequestContent: audit.EncryptedContent{
			Compression:    "gzip",
			Ciphertext:     []byte("too-short"),
			CipherNonce:    make([]byte, 12),
			WrappedDataKey: []byte("wrapped-data-key-and-tag"),
			WrapNonce:      make([]byte, 12),
			KeyVersion:     1,
		},
	}

	if err := repository.CreatePendingAudit(context.Background(), input); err == nil {
		t.Fatal("create pending audit with invalid raw content succeeded")
	}
	assertRowCount(t, db, "audit_records", auditID, 0)
	assertRowCount(t, db, "audit_raw_content", auditID, 0)

	input.RequestContent.Ciphertext = []byte("encrypted-request-payload-and-tag")
	if err := repository.CreatePendingAudit(context.Background(), input); err != nil {
		t.Fatalf("create valid pending audit: %v", err)
	}
	assertRowCount(t, db, "audit_records", auditID, 1)
	assertRowCount(t, db, "audit_raw_content", auditID, 1)
}

func TestRepositoryFinalizeAuditCommitsResponseAndMetadataAtomically(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	insertRequestRawContent(t, db, fixture)
	repository := NewRepository(db)
	completedAt := fixture.now.Add(time.Minute)
	status := 200

	if err := repository.FinalizeAudit(context.Background(), audit.FinalAudit{
		ID: fixture.auditID, RequestID: fixture.requestID, OwnerKind: audit.OwnerKindPersonal,
		IdentityID: fixture.identityID, TeamID: fixture.teamID, ModelID: "gpt-test",
		CaptureStatus: audit.CaptureStatusComplete, Outcome: audit.AuditOutcomeSuccess,
		UpstreamRequestID: "upstream-1", UpstreamHTTPStatus: &status, FinishReason: "stop",
		ObservedResponseBytes: 64, CompletedAt: completedAt,
		ResponseContent: validEncryptedContent(),
	}); err != nil {
		t.Fatalf("FinalizeAudit() error = %v", err)
	}

	var captureStatus, outcome string
	if err := db.QueryRow(`SELECT capture_status, outcome FROM audit_records WHERE id = $1`, fixture.auditID).Scan(&captureStatus, &outcome); err != nil {
		t.Fatalf("read finalized audit metadata: %v", err)
	}
	if captureStatus != "complete" || outcome != "success" {
		t.Fatalf("final metadata = (%q, %q), want (complete, success)", captureStatus, outcome)
	}
	assertContentKindCount(t, db, fixture.auditID, "response", 1)
}

func TestRepositoryFinalizeAuditRejectsNonPendingAndRollsBackResponseFailure(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	insertRequestRawContent(t, db, fixture)
	repository := NewRepository(db)
	invalidContent := validEncryptedContent()
	invalidContent.Ciphertext = []byte("too-short")

	if err := repository.FinalizeAudit(context.Background(), audit.FinalAudit{
		ID: fixture.auditID, RequestID: fixture.requestID, CaptureStatus: audit.CaptureStatusComplete,
		Outcome: audit.AuditOutcomeSuccess, ObservedResponseBytes: 8, CompletedAt: fixture.now.Add(time.Minute),
		ResponseContent: invalidContent,
	}); err == nil {
		t.Fatal("FinalizeAudit() accepted invalid response content")
	}
	var captureStatus, outcome string
	if err := db.QueryRow(`SELECT capture_status, outcome FROM audit_records WHERE id = $1`, fixture.auditID).Scan(&captureStatus, &outcome); err != nil {
		t.Fatalf("read rolled-back audit metadata: %v", err)
	}
	if captureStatus != "pending" || outcome != "pending" {
		t.Fatalf("rolled-back metadata = (%q, %q), want pending/pending", captureStatus, outcome)
	}
	assertContentKindCount(t, db, fixture.auditID, "response", 0)

	if err := repository.FinalizeAudit(context.Background(), audit.FinalAudit{
		ID: fixture.auditID, RequestID: fixture.requestID, CaptureStatus: audit.CaptureStatusIncomplete,
		Outcome: audit.AuditOutcomeCancelled, ObservedResponseBytes: 0, CompletedAt: fixture.now.Add(time.Minute),
	}); err != nil {
		t.Fatalf("FinalizeAudit() cancellation error = %v", err)
	}
	if err := repository.FinalizeAudit(context.Background(), audit.FinalAudit{
		ID: fixture.auditID, RequestID: fixture.requestID, CaptureStatus: audit.CaptureStatusComplete,
		Outcome: audit.AuditOutcomeSuccess, ObservedResponseBytes: 8, CompletedAt: fixture.now.Add(2 * time.Minute),
		ResponseContent: validEncryptedContent(),
	}); !errors.Is(err, audit.ErrAuditNotPending) {
		t.Fatalf("FinalizeAudit() second transition error = %v, want ErrAuditNotPending", err)
	}
}

func insertPendingAudit(t *testing.T, db *sql.DB, auditID, requestID string, fixture auditPolicyFixture, createdAt time.Time) {
	t.Helper()
	mustExec(t, db, `INSERT INTO audit_records (id, request_id, key_id, owner_kind, identity_id, team_id, model_id, capture_status, outcome, observed_request_bytes, observed_response_bytes, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12)`, auditID, requestID, fixture.keyID, "personal", fixture.identityID, fixture.teamID, "gpt-test", "pending", "pending", 128, 0, createdAt)
}

func assertAuditIDs(t *testing.T, records []AuditRecord, want ...string) {
	t.Helper()
	if len(records) != len(want) {
		t.Fatalf("audit record count = %d, want %d", len(records), len(want))
	}
	for i, record := range records {
		if record.ID != want[i] {
			t.Fatalf("audit record %d ID = %s, want %s", i, record.ID, want[i])
		}
	}
}

func assertRowCount(t *testing.T, db *sql.DB, tableName string, value any, want int) {
	t.Helper()

	var got int
	var err error
	switch tableName {
	case "audit_records":
		err = db.QueryRow(`SELECT count(*) FROM audit_records WHERE id = $1`, value).Scan(&got)
	case "audit_raw_content":
		err = db.QueryRow(`SELECT count(*) FROM audit_raw_content WHERE audit_id = $1`, value).Scan(&got)
	default:
		t.Fatalf("unsupported row-count table %q", tableName)
	}
	if err != nil {
		t.Fatalf("count %s rows: %v", tableName, err)
	}
	if got != want {
		t.Fatalf("%s row count = %d, want %d", tableName, got, want)
	}
}

func insertRequestRawContent(t *testing.T, db *sql.DB, fixture auditPolicyFixture) {
	t.Helper()
	mustExec(t, db, `INSERT INTO audit_raw_content (audit_id, content_kind, compression, ciphertext, cipher_nonce, wrapped_data_key, wrap_nonce, key_version, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, fixture.auditID, "request", "gzip", []byte("encrypted-request-payload-and-tag"), make([]byte, 12), []byte("wrapped-data-key-and-tag"), make([]byte, 12), 1, fixture.now, fixture.now.Add(24*time.Hour))
}

func validEncryptedContent() *audit.EncryptedContent {
	return &audit.EncryptedContent{
		Compression: "gzip", Ciphertext: []byte("encrypted-response-payload-and-tag"), CipherNonce: make([]byte, 12),
		WrappedDataKey: []byte("wrapped-response-key-and-tag"), WrapNonce: make([]byte, 12), KeyVersion: 1,
	}
}

func assertContentKindCount(t *testing.T, db *sql.DB, auditID, contentKind string, want int) {
	t.Helper()
	var got int
	if err := db.QueryRow(`SELECT count(*) FROM audit_raw_content WHERE audit_id = $1 AND content_kind = $2`, auditID, contentKind).Scan(&got); err != nil {
		t.Fatalf("count %s raw content: %v", contentKind, err)
	}
	if got != want {
		t.Fatalf("%s raw content count = %d, want %d", contentKind, got, want)
	}
}
