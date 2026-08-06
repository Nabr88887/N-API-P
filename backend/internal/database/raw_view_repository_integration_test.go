//go:build integration

package database

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
)

func TestRepositoryRawViewDecryptsBothContentKindsAndAuditsSuccess(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	now := time.Now().UTC().Truncate(time.Microsecond)
	createdAt := now.Add(-time.Minute)
	expiresAt := now.Add(time.Hour)
	key := bytes.Repeat([]byte{0x61}, 32)
	envelope, err := audit.NewEnvelopeService(1, map[int][]byte{1: key})
	if err != nil {
		t.Fatalf("NewEnvelopeService() error = %v", err)
	}
	requestContext := audit.EncryptionContext{
		AuditID: fixture.auditID, ContentKind: audit.ContentKindRequest, OwnerKind: audit.OwnerKindPersonal,
		IdentityID: fixture.identityID, TeamID: fixture.teamID, CreatedAt: createdAt,
	}
	responseContext := requestContext
	responseContext.ContentKind = audit.ContentKindResponse
	requestContent, err := envelope.Encrypt([]byte(`{"request":"synthetic prompt"}`), requestContext)
	if err != nil {
		t.Fatalf("encrypt request content: %v", err)
	}
	responseContent, err := envelope.Encrypt([]byte(`{"response":"synthetic answer"}`), responseContext)
	if err != nil {
		t.Fatalf("encrypt response content: %v", err)
	}
	insertRepositoryRawViewContent(t, db, fixture.auditID, "request", requestContent, createdAt, expiresAt)
	insertRepositoryRawViewContent(t, db, fixture.auditID, "response", responseContent, createdAt, expiresAt)

	grantUntil := now.Add(time.Minute)
	service, err := audit.NewRawViewService(NewRepository(db), envelope)
	if err != nil {
		t.Fatalf("NewRawViewService() error = %v", err)
	}
	view, err := service.Inspect(context.Background(), audit.RawViewInput{
		Session: access.ActivePortalSession{
			SessionID: "session-raw-view", IdentityID: fixture.identityID, Role: access.RoleSystemAdministrator,
			ReauthenticatedUntil: &grantUntil,
		},
		AuditID: fixture.auditID, RequestID: fixture.requestID, Reason: "synthetic investigation",
	})
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if view.AuditID != fixture.auditID || string(view.RequestJSON) != `{"request":"synthetic prompt"}` || string(view.ResponseJSON) != `{"response":"synthetic answer"}` {
		t.Fatalf("raw view = %+v", view)
	}
	if !json.Valid(view.RequestJSON) || !json.Valid(view.ResponseJSON) {
		t.Fatal("raw view content is not valid JSON")
	}

	var event struct {
		ActorID       string
		TargetAuditID string
		RequestID     string
		Outcome       string
		Reason        sql.NullString
		DetailCode    sql.NullString
	}
	if err := db.QueryRow(`SELECT actor_identity_id::text, target_audit_id::text, request_id::text, outcome, reason, detail_code FROM security_events WHERE event_type = $1 AND target_audit_id = $2`, string(access.SensitiveActionRawView), fixture.auditID).Scan(&event.ActorID, &event.TargetAuditID, &event.RequestID, &event.Outcome, &event.Reason, &event.DetailCode); err != nil {
		t.Fatalf("read raw-view security event: %v", err)
	}
	if event.ActorID != fixture.identityID || event.TargetAuditID != fixture.auditID || event.RequestID != fixture.requestID || event.Outcome != string(access.SecurityEventSuccess) || !event.Reason.Valid || event.Reason.String != "synthetic investigation" || !event.DetailCode.Valid || event.DetailCode.String != "raw_viewed" {
		t.Fatalf("raw-view event = %+v", event)
	}
}

func insertRepositoryRawViewContent(t *testing.T, db *sql.DB, auditID, contentKind string, content audit.EncryptedContent, createdAt, expiresAt time.Time) {
	t.Helper()
	mustExec(t, db, `INSERT INTO audit_raw_content (audit_id, content_kind, compression, ciphertext, cipher_nonce, wrapped_data_key, wrap_nonce, key_version, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, auditID, contentKind, content.Compression, content.Ciphertext, content.CipherNonce, content.WrappedDataKey, content.WrapNonce, content.KeyVersion, createdAt, expiresAt)
}
