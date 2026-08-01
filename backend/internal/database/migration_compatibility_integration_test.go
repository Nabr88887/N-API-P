//go:build integration

package database

import (
	"bytes"
	"database/sql"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
)

func TestPriorImageContractsRemainCompatibleAcrossAdditiveMigrations(t *testing.T) {
	db, migrator := openCompatibilitySchema(t)

	migrateCompatibilityStage(t, migrator, 2)
	workforce := seedPriorImageV2Workforce(t, db)
	probePriorImageV2Workforce(t, db, workforce)

	migrateCompatibilityStage(t, migrator, 3)
	probePriorImageV2Workforce(t, db, workforce)
	audit := seedPriorImageV3Audit(t, db, workforce)
	probePriorImageV3Audit(t, db, audit)

	migrateCompatibilityStage(t, migrator, 4)
	probePriorImageV2Workforce(t, db, workforce)
	probePriorImageV3Audit(t, db, audit)
}

type priorImageV2WorkforceFixture struct {
	now        time.Time
	teamID     string
	identityID string
	keyID      string
}

type priorImageV3AuditFixture struct {
	now        time.Time
	auditID    string
	requestID  string
	usageID    string
	eventID    string
	keyID      string
	identityID string
	teamID     string
}

func openCompatibilitySchema(t *testing.T) (*sql.DB, *migrate.Migrate) {
	t.Helper()

	databaseURL := testDatabaseURL(t)
	const schemaName = "migration_compatibility_test"
	adminDB := openTestDatabase(t, databaseURL)
	resetTestSchema(t, adminDB, schemaName)
	schemaDB := openTestDatabase(t, databaseURLWithSearchPath(t, databaseURL, schemaName))
	return schemaDB, openTestMigrator(t, schemaDB, schemaName, allMigrationFiles)
}

func migrateCompatibilityStage(t *testing.T, migrator *migrate.Migrate, version uint) {
	t.Helper()

	if err := migrator.Migrate(version); err != nil {
		t.Fatalf("migrate compatibility schema to version %d: %v", version, err)
	}
	assertMigrationVersion(t, migrator, version)
}

func seedPriorImageV2Workforce(t *testing.T, db *sql.DB) priorImageV2WorkforceFixture {
	t.Helper()

	fixture := priorImageV2WorkforceFixture{
		now:        time.Date(2026, 8, 1, 1, 0, 0, 0, time.UTC),
		teamID:     "91000000-0000-0000-0000-000000000001",
		identityID: "92000000-0000-0000-0000-000000000001",
		keyID:      "93000000-0000-0000-0000-000000000001",
	}
	mustExec(t, db, `INSERT INTO teams (id, name, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $4)`, fixture.teamID, "Compatibility", "active", fixture.now)
	mustExec(t, db, `INSERT INTO identities (id, email, role, status, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $5)`, fixture.identityID, "compatibility@example.internal", "employee", "active", fixture.now)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id, created_at) VALUES ($1, $2, $3)`, fixture.identityID, fixture.teamID, fixture.now)
	mustExec(t, db, `INSERT INTO api_keys (id, identity_id, kind, name, prefix, verification_hash, status, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, fixture.keyID, fixture.identityID, "personal", "compatibility-key", "nap_cmp_01", []byte("compatibility-hash-only"), "active", fixture.now)
	return fixture
}

// These queries are frozen at their migration version so later code cannot
// silently broaden what the compatibility probe accepts.
const priorImageV2WorkforceUpdateSQL = `
UPDATE identities
SET updated_at = $1
WHERE id = $2 AND status = $3`

const priorImageV2WorkforceQuerySQL = `
SELECT
    i.id::text,
    i.email,
    i.role,
    i.status,
    m.team_id::text,
    t.name,
    t.status,
    k.id::text,
    k.kind,
    k.name,
    k.prefix,
    k.status
FROM identities AS i
JOIN memberships AS m ON m.identity_id = i.id
JOIN teams AS t ON t.id = m.team_id
JOIN api_keys AS k ON k.identity_id = i.id
WHERE i.id = $1 AND i.status = $2
ORDER BY k.created_at DESC, k.id DESC
LIMIT $3`

func probePriorImageV2Workforce(t *testing.T, db *sql.DB, fixture priorImageV2WorkforceFixture) {
	t.Helper()

	updatedAt := fixture.now.Add(time.Minute)
	result, err := db.Exec(priorImageV2WorkforceUpdateSQL, updatedAt, fixture.identityID, "active")
	if err != nil {
		t.Fatalf("prior image v2 workforce update: %v", err)
	}
	if affected, err := result.RowsAffected(); err != nil {
		t.Fatalf("read prior image v2 update count: %v", err)
	} else if affected != 1 {
		t.Fatalf("prior image v2 update count = %d, want 1", affected)
	}

	var identityID, email, role, identityStatus string
	var teamID, teamName, teamStatus string
	var keyID, keyKind, keyName, keyPrefix, keyStatus string
	if err := db.QueryRow(
		priorImageV2WorkforceQuerySQL,
		fixture.identityID,
		"active",
		1,
	).Scan(
		&identityID,
		&email,
		&role,
		&identityStatus,
		&teamID,
		&teamName,
		&teamStatus,
		&keyID,
		&keyKind,
		&keyName,
		&keyPrefix,
		&keyStatus,
	); err != nil {
		t.Fatalf("prior image v2 workforce query: %v", err)
	}
	if identityID != fixture.identityID || email != "compatibility@example.internal" || role != "employee" || identityStatus != "active" {
		t.Fatalf("prior image v2 identity = (%q, %q, %q, %q), want frozen fixture", identityID, email, role, identityStatus)
	}
	if teamID != fixture.teamID || teamName != "Compatibility" || teamStatus != "active" {
		t.Fatalf("prior image v2 team = (%q, %q, %q), want frozen fixture", teamID, teamName, teamStatus)
	}
	if keyID != fixture.keyID || keyKind != "personal" || keyName != "compatibility-key" || keyPrefix != "nap_cmp_01" || keyStatus != "active" {
		t.Fatalf("prior image v2 key = (%q, %q, %q, %q, %q), want frozen fixture", keyID, keyKind, keyName, keyPrefix, keyStatus)
	}
}

func seedPriorImageV3Audit(t *testing.T, db *sql.DB, workforce priorImageV2WorkforceFixture) priorImageV3AuditFixture {
	t.Helper()

	fixture := priorImageV3AuditFixture{
		now:        workforce.now.Add(time.Hour),
		auditID:    "94000000-0000-0000-0000-000000000001",
		requestID:  "95000000-0000-0000-0000-000000000001",
		usageID:    "96000000-0000-0000-0000-000000000001",
		eventID:    "97000000-0000-0000-0000-000000000001",
		keyID:      workforce.keyID,
		identityID: workforce.identityID,
		teamID:     workforce.teamID,
	}
	mustExec(t, db, `INSERT INTO model_allowlist (model_id, status, updated_by_identity_id, created_at, updated_at) VALUES ($1, $2, $3, $4, $4)`, "gpt-compatibility", "allowed", workforce.identityID, fixture.now)
	mustExec(t, db, `INSERT INTO audit_records (id, request_id, key_id, owner_kind, identity_id, team_id, model_id, capture_status, outcome, observed_request_bytes, observed_response_bytes, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12)`, fixture.auditID, fixture.requestID, workforce.keyID, "personal", workforce.identityID, workforce.teamID, "gpt-compatibility", "pending", "pending", 256, 0, fixture.now)
	mustExec(t, db, `INSERT INTO audit_raw_content (audit_id, content_kind, compression, ciphertext, cipher_nonce, wrapped_data_key, wrap_nonce, key_version, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, fixture.auditID, "request", "gzip", []byte("encrypted-compatibility-payload-and-tag"), make([]byte, 12), []byte("wrapped-compatibility-key-and-tag"), make([]byte, 12), 1, fixture.now, fixture.now.Add(24*time.Hour))
	mustExec(t, db, `INSERT INTO usage_records (id, audit_id, request_id, key_id, owner_kind, identity_id, team_id, model_id, outcome, usage_reported, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, fixture.usageID, fixture.auditID, fixture.requestID, workforce.keyID, "personal", workforce.identityID, workforce.teamID, "gpt-compatibility", "success", false, fixture.now)
	mustExec(t, db, `INSERT INTO security_events (id, event_type, actor_identity_id, target_audit_id, request_id, outcome, detail_code, occurred_at, retain_until) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, fixture.eventID, "compatibility_probe", workforce.identityID, fixture.auditID, fixture.requestID, "success", "prior_image_v3", fixture.now, fixture.now.AddDate(2, 0, 0))
	return fixture
}

const priorImageV3AuditUpdateSQL = `
UPDATE audit_records
SET updated_at = $1
WHERE id = $2 AND capture_status = $3`

const priorImageV3AuditQuerySQL = `
SELECT
    id::text,
    request_id::text,
    key_id::text,
    owner_kind,
    identity_id::text,
    team_id::text,
    model_id,
    capture_status,
    outcome,
    observed_request_bytes,
    observed_response_bytes
FROM audit_records
WHERE id = $1
LIMIT $2`

const priorImageV3RawContentQuerySQL = `
SELECT
    content_kind,
    compression,
    ciphertext,
    cipher_nonce,
    wrapped_data_key,
    wrap_nonce,
    key_version,
    expires_at
FROM audit_raw_content
WHERE audit_id = $1 AND content_kind = $2 AND expires_at > $3
LIMIT $4`

const priorImageV3UsageQuerySQL = `
SELECT
    id::text,
    request_id::text,
    key_id::text,
    owner_kind,
    identity_id::text,
    team_id::text,
    model_id,
    outcome,
    usage_reported
FROM usage_records
WHERE audit_id = $1
LIMIT $2`

const priorImageV3EventQuerySQL = `
SELECT
    id::text,
    event_type,
    actor_identity_id::text,
    target_audit_id::text,
    request_id::text,
    outcome,
    detail_code
FROM security_events
WHERE request_id = $1
ORDER BY occurred_at DESC, id DESC
LIMIT $2`

func probePriorImageV3Audit(t *testing.T, db *sql.DB, fixture priorImageV3AuditFixture) {
	t.Helper()

	updatedAt := fixture.now.Add(time.Minute)
	result, err := db.Exec(priorImageV3AuditUpdateSQL, updatedAt, fixture.auditID, "pending")
	if err != nil {
		t.Fatalf("prior image v3 audit update: %v", err)
	}
	if affected, err := result.RowsAffected(); err != nil {
		t.Fatalf("read prior image v3 update count: %v", err)
	} else if affected != 1 {
		t.Fatalf("prior image v3 update count = %d, want 1", affected)
	}

	var auditID, requestID, keyID, ownerKind, identityID, teamID string
	var modelID, captureStatus, outcome string
	var requestBytes, responseBytes int64
	if err := db.QueryRow(priorImageV3AuditQuerySQL, fixture.auditID, 1).Scan(
		&auditID,
		&requestID,
		&keyID,
		&ownerKind,
		&identityID,
		&teamID,
		&modelID,
		&captureStatus,
		&outcome,
		&requestBytes,
		&responseBytes,
	); err != nil {
		t.Fatalf("prior image v3 audit query: %v", err)
	}
	if auditID != fixture.auditID || requestID != fixture.requestID || keyID != fixture.keyID || ownerKind != "personal" || identityID != fixture.identityID || teamID != fixture.teamID || modelID != "gpt-compatibility" || captureStatus != "pending" || outcome != "pending" || requestBytes != 256 || responseBytes != 0 {
		t.Fatalf("prior image v3 audit row no longer matches frozen contract")
	}

	var contentKind, compression string
	var ciphertext, cipherNonce, wrappedDataKey, wrapNonce []byte
	var keyVersion int
	var expiresAt time.Time
	if err := db.QueryRow(priorImageV3RawContentQuerySQL, fixture.auditID, "request", fixture.now, 1).Scan(
		&contentKind,
		&compression,
		&ciphertext,
		&cipherNonce,
		&wrappedDataKey,
		&wrapNonce,
		&keyVersion,
		&expiresAt,
	); err != nil {
		t.Fatalf("prior image v3 raw-content query: %v", err)
	}
	if contentKind != "request" || compression != "gzip" || !bytes.Equal(ciphertext, []byte("encrypted-compatibility-payload-and-tag")) || len(cipherNonce) != 12 || len(wrappedDataKey) <= 16 || len(wrapNonce) != 12 || keyVersion != 1 || !expiresAt.Equal(fixture.now.Add(24*time.Hour)) {
		t.Fatal("prior image v3 raw-content row no longer matches frozen contract")
	}

	var usageID, usageRequestID, usageKeyID, usageOwnerKind, usageIdentityID, usageTeamID string
	var usageModelID, usageOutcome string
	var usageReported bool
	if err := db.QueryRow(priorImageV3UsageQuerySQL, fixture.auditID, 1).Scan(
		&usageID,
		&usageRequestID,
		&usageKeyID,
		&usageOwnerKind,
		&usageIdentityID,
		&usageTeamID,
		&usageModelID,
		&usageOutcome,
		&usageReported,
	); err != nil {
		t.Fatalf("prior image v3 usage query: %v", err)
	}
	if usageID != fixture.usageID || usageRequestID != fixture.requestID || usageKeyID != fixture.keyID || usageOwnerKind != "personal" || usageIdentityID != fixture.identityID || usageTeamID != fixture.teamID || usageModelID != "gpt-compatibility" || usageOutcome != "success" || usageReported {
		t.Fatal("prior image v3 usage row no longer matches frozen contract")
	}

	var eventID, eventType, actorID, targetAuditID, eventRequestID, eventOutcome, detailCode string
	if err := db.QueryRow(priorImageV3EventQuerySQL, fixture.requestID, 1).Scan(
		&eventID,
		&eventType,
		&actorID,
		&targetAuditID,
		&eventRequestID,
		&eventOutcome,
		&detailCode,
	); err != nil {
		t.Fatalf("prior image v3 security-event query: %v", err)
	}
	if eventID != fixture.eventID || eventType != "compatibility_probe" || actorID != fixture.identityID || targetAuditID != fixture.auditID || eventRequestID != fixture.requestID || eventOutcome != "success" || detailCode != "prior_image_v3" {
		t.Fatal("prior image v3 security-event row no longer matches frozen contract")
	}

	var retentionDays int
	var gateState, gateReason string
	if err := db.QueryRow(`SELECT raw_retention_days, audit_gate_state, audit_gate_reason_code FROM operational_state WHERE id = $1`, 1).Scan(&retentionDays, &gateState, &gateReason); err != nil {
		t.Fatalf("prior image v3 operational-state query: %v", err)
	}
	if retentionDays != 7 || gateState != "blocked" || gateReason != "startup_probe_required" {
		t.Fatalf("prior image v3 operational state = (%d, %q, %q), want startup defaults", retentionDays, gateState, gateReason)
	}
}
