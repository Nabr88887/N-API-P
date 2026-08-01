//go:build integration

package database

import (
	"context"
	"database/sql"
	"errors"
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

func TestRepositoryCreatePendingAuditRollsBackOnRawContentFailure(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)

	auditID := "84000000-0000-0000-0000-000000000010"
	requestID := "87000000-0000-0000-0000-000000000010"
	identityID := fixture.identityID
	input := CreatePendingAuditInput{
		ID:                   auditID,
		RequestID:            requestID,
		KeyID:                fixture.keyID,
		OwnerKind:            "personal",
		IdentityID:           &identityID,
		TeamID:               fixture.teamID,
		ModelID:              "gpt-test",
		ObservedRequestBytes: 128,
		CreatedAt:            fixture.now,
		RequestContent: EncryptedRawContent{
			Compression:    "gzip",
			Ciphertext:     []byte("too-short"),
			CipherNonce:    make([]byte, 12),
			WrappedDataKey: []byte("wrapped-data-key-and-tag"),
			WrapNonce:      make([]byte, 12),
			KeyVersion:     1,
			ExpiresAt:      fixture.now.Add(24 * time.Hour),
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
