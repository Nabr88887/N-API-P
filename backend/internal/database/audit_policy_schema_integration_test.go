//go:build integration

package database

import (
	"database/sql"
	"testing"
	"time"
)

func TestAuditPolicySchemaContract(t *testing.T) {
	db, schemaName := migrateAuditPolicySchema(t)

	expected := map[string][]string{
		"model_allowlist":   {"model_id", "status", "input_unit_price", "output_unit_price", "price_version", "created_at", "updated_at", "updated_by_identity_id"},
		"audit_records":     {"id", "request_id", "key_id", "owner_kind", "identity_id", "service_account_id", "responsible_identity_id", "team_id", "model_id", "capture_status", "outcome", "upstream_request_id", "upstream_http_status", "error_code", "finish_reason", "observed_request_bytes", "observed_response_bytes", "created_at", "updated_at", "completed_at"},
		"audit_raw_content": {"audit_id", "content_kind", "compression", "ciphertext", "cipher_nonce", "wrapped_data_key", "wrap_nonce", "key_version", "created_at", "expires_at"},
		"usage_records":     {"id", "audit_id", "request_id", "key_id", "owner_kind", "identity_id", "service_account_id", "responsible_identity_id", "team_id", "model_id", "upstream_request_id", "outcome", "usage_reported", "input_tokens", "output_tokens", "total_tokens", "price_version", "input_unit_price", "output_unit_price", "calculated_amount", "created_at"},
		"security_events":   {"id", "event_type", "actor_identity_id", "target_identity_id", "target_service_account_id", "target_key_id", "target_audit_id", "investigation_case_id", "request_id", "outcome", "reason", "detail_code", "occurred_at", "retain_until"},
		"operational_state": {"id", "raw_retention_days", "audit_gate_state", "audit_gate_reason_code", "gate_changed_at", "last_persistence_probe_at", "last_cleanup_at", "deletion_overdue_since", "updated_at"},
	}

	for table, columns := range expected {
		assertTableColumns(t, db, schemaName, table, columns)
	}
	assertColumnsAbsent(t, db, schemaName, "audit_records", []string{"request_body", "response_body", "ciphertext", "wrapped_data_key"})
	assertColumnsAbsent(t, db, schemaName, "audit_raw_content", []string{"plaintext", "content", "request_body", "response_body", "data_key", "master_key"})
	for _, table := range []string{"budgets", "budget_policies", "training_datasets", "totp_factors", "team_model_policies"} {
		assertTableAbsent(t, db, schemaName, table)
	}
}

func TestAuditPolicySchemaRejectsUnsafeState(t *testing.T) {
	db, _ := migrateAuditPolicySchema(t)
	fixture := insertAuditPolicyFixture(t, db)

	expectRejected(t, db, `INSERT INTO audit_raw_content (audit_id, content_kind, compression, ciphertext, cipher_nonce, wrapped_data_key, wrap_nonce, key_version, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, fixture.auditID, "request", "gzip", []byte("encrypted-payload-and-tag"), make([]byte, 12), []byte("wrapped-data-key-and-tag"), make([]byte, 12), 1, fixture.now, fixture.now)
	expectRejected(t, db, `INSERT INTO usage_records (id, audit_id, request_id, key_id, owner_kind, identity_id, service_account_id, team_id, model_id, outcome, usage_reported, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`, "85000000-0000-0000-0000-000000000001", fixture.auditID, fixture.requestID, fixture.keyID, "personal", fixture.identityID, "83000000-0000-0000-0000-000000000099", fixture.teamID, "gpt-test", "success", false, fixture.now)
	expectRejected(t, db, `INSERT INTO usage_records (id, audit_id, request_id, key_id, owner_kind, identity_id, team_id, model_id, outcome, usage_reported, input_tokens, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`, "85000000-0000-0000-0000-000000000004", fixture.auditID, fixture.requestID, fixture.keyID, "personal", fixture.identityID, fixture.teamID, "gpt-test", "success", true, 10, fixture.now)
	expectRejected(t, db, `UPDATE model_allowlist SET price_version = $1, input_unit_price = $2 WHERE model_id = $3`, "v1", "0.001", "gpt-test")
	expectRejected(t, db, `INSERT INTO usage_records (id, audit_id, request_id, key_id, owner_kind, identity_id, team_id, model_id, outcome, usage_reported, input_tokens, output_tokens, total_tokens, price_version, input_unit_price, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`, "85000000-0000-0000-0000-000000000002", fixture.auditID, fixture.requestID, fixture.keyID, "personal", fixture.identityID, fixture.teamID, "gpt-test", "success", true, 10, 20, 30, "v1", "0.001", fixture.now)
	expectRejected(t, db, `UPDATE operational_state SET raw_retention_days = $1 WHERE id = $2`, 31, 1)
	expectRejected(t, db, `UPDATE api_keys SET verification_hash = NULL WHERE id = $1`, fixture.keyID)
	mustExec(t, db, `UPDATE api_keys SET status = 'revoked', revoked_at = $1, verification_hash = NULL WHERE id = $2`, fixture.now.Add(time.Hour), fixture.keyID)
}

func TestSecurityEventsAreAppendOnlyAndStartupFailsClosed(t *testing.T) {
	db, _ := migrateAuditPolicySchema(t)
	fixture := insertAuditPolicyFixture(t, db)

	const eventID = "86000000-0000-0000-0000-000000000001"
	mustExec(t, db, `INSERT INTO security_events (id, event_type, actor_identity_id, target_audit_id, request_id, outcome, detail_code) VALUES ($1, $2, $3, $4, $5, $6, $7)`, eventID, "raw_view", fixture.identityID, fixture.auditID, fixture.requestID, "denied", "reauthentication_required")
	expectRejected(t, db, `UPDATE security_events SET outcome = $1 WHERE id = $2`, "success", eventID)
	expectRejected(t, db, `DELETE FROM security_events WHERE id = $1`, eventID)

	var retentionDays int
	var gateState string
	if err := db.QueryRow(`SELECT raw_retention_days, audit_gate_state FROM operational_state WHERE id = $1`, 1).Scan(&retentionDays, &gateState); err != nil {
		t.Fatalf("read operational state: %v", err)
	}
	if retentionDays != 7 || gateState != "blocked" {
		t.Fatalf("operational startup state = (%d, %q), want (7, %q)", retentionDays, gateState, "blocked")
	}
}

func TestOperationalBlockedGateRequiresReason(t *testing.T) {
	db, _ := migrateAuditPolicySchema(t)
	expectRejected(t, db, `UPDATE operational_state SET audit_gate_reason_code = NULL WHERE id = $1`, 1)
}

func TestUsageAuditRequestCorrelationCannotMismatch(t *testing.T) {
	db, _ := migrateAuditPolicySchema(t)
	fixture := insertAuditPolicyFixture(t, db)

	const (
		secondAuditID   = "84000000-0000-0000-0000-000000000002"
		secondRequestID = "87000000-0000-0000-0000-000000000002"
	)
	mustExec(t, db, `INSERT INTO audit_records (id, request_id, key_id, owner_kind, identity_id, team_id, model_id, capture_status, outcome, observed_request_bytes, observed_response_bytes, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12)`, secondAuditID, secondRequestID, fixture.keyID, "personal", fixture.identityID, fixture.teamID, "gpt-test", "pending", "pending", 64, 0, fixture.now)
	expectRejected(t, db, `INSERT INTO usage_records (id, audit_id, request_id, key_id, owner_kind, identity_id, team_id, model_id, outcome, usage_reported, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, "85000000-0000-0000-0000-000000000005", fixture.auditID, secondRequestID, fixture.keyID, "personal", fixture.identityID, fixture.teamID, "gpt-test", "success", false, fixture.now)
}

type auditPolicyFixture struct {
	now        time.Time
	teamID     string
	identityID string
	keyID      string
	auditID    string
	requestID  string
}

func insertAuditPolicyFixture(t *testing.T, db *sql.DB) auditPolicyFixture {
	t.Helper()

	fixture := auditPolicyFixture{
		now:        time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		teamID:     "81000000-0000-0000-0000-000000000001",
		identityID: "82000000-0000-0000-0000-000000000001",
		keyID:      "83000000-0000-0000-0000-000000000001",
		auditID:    "84000000-0000-0000-0000-000000000001",
		requestID:  "87000000-0000-0000-0000-000000000001",
	}
	mustExec(t, db, `INSERT INTO teams (id, name, status) VALUES ($1, $2, $3)`, fixture.teamID, "Audit", "active")
	mustExec(t, db, `INSERT INTO identities (id, email, role, status) VALUES ($1, $2, $3, $4)`, fixture.identityID, "auditor@example.internal", "system_administrator", "active")
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, fixture.identityID, fixture.teamID)
	mustExec(t, db, `INSERT INTO api_keys (id, identity_id, kind, name, prefix, verification_hash, status, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, fixture.keyID, fixture.identityID, "personal", "audit-test", "nap_audit", []byte("hash-only"), "active", fixture.now)
	mustExec(t, db, `INSERT INTO model_allowlist (model_id, status, updated_by_identity_id) VALUES ($1, $2, $3)`, "gpt-test", "allowed", fixture.identityID)
	mustExec(t, db, `INSERT INTO audit_records (id, request_id, key_id, owner_kind, identity_id, team_id, model_id, capture_status, outcome, observed_request_bytes, observed_response_bytes, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12)`, fixture.auditID, fixture.requestID, fixture.keyID, "personal", fixture.identityID, fixture.teamID, "gpt-test", "pending", "pending", 128, 0, fixture.now)
	return fixture
}

func migrateAuditPolicySchema(t *testing.T) (*sql.DB, string) {
	t.Helper()

	databaseURL := testDatabaseURL(t)
	const schemaName = "audit_policy_schema_test"
	adminDB := openTestDatabase(t, databaseURL)
	resetTestSchema(t, adminDB, schemaName)
	schemaDB := openTestDatabase(t, databaseURLWithSearchPath(t, databaseURL, schemaName))
	migrator := openTestMigrator(t, schemaDB, schemaName, allMigrationFiles)
	if err := migrator.Up(); err != nil {
		t.Fatalf("apply audit and policy migrations: %v", err)
	}
	return schemaDB, schemaName
}

func assertColumnsAbsent(t *testing.T, db *sql.DB, schemaName, tableName string, columns []string) {
	t.Helper()

	for _, column := range columns {
		var exists bool
		if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2 AND column_name = $3)`, schemaName, tableName, column).Scan(&exists); err != nil {
			t.Fatalf("query forbidden column %s.%s: %v", tableName, column, err)
		}
		if exists {
			t.Fatalf("forbidden column %s.%s exists", tableName, column)
		}
	}
}
