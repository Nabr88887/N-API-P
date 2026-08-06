//go:build integration

package database

import (
	"context"
	"database/sql"
	"errors"
	"n-api-p/internal/access"
	"testing"
	"time"
)

func TestRepositoryRetentionPolicyUsesAsymmetricChangeSemantics(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)
	changeAt := fixture.now.Add(time.Hour)

	insertRawRetentionAudit(t, db, "84000000-0000-0000-0000-000000000002", "87000000-0000-0000-0000-000000000002", fixture, fixture.now.Add(-2*24*time.Hour), fixture.now.Add(5*24*time.Hour))
	insertRawRetentionAudit(t, db, "84000000-0000-0000-0000-000000000003", "87000000-0000-0000-0000-000000000003", fixture, fixture.now.Add(-24*time.Hour), fixture.now.Add(6*24*time.Hour))
	insertRawRetentionAudit(t, db, "84000000-0000-0000-0000-000000000004", "87000000-0000-0000-0000-000000000004", fixture, fixture.now.Add(-4*24*time.Hour), fixture.now.Add(-time.Hour))
	insertRawRetentionContent(t, db, fixture.auditID, fixture.now.Add(-2*24*time.Hour), fixture.now.Add(5*24*time.Hour))

	lengthened, err := repository.ChangeRetentionPolicy(context.Background(), access.RetentionPolicyChange{
		Days: 10, MaximumDays: 30, ChangedAt: changeAt,
		Event: retentionPolicyEvent("86000000-0000-0000-0000-000000000001", fixture.identityID, "88000000-0000-0000-0000-000000000001", changeAt),
	})
	if err != nil {
		t.Fatalf("lengthen retention policy: %v", err)
	}
	if lengthened.Days != 10 {
		t.Fatalf("lengthened days = %d, want 10", lengthened.Days)
	}
	assertRawExpiry(t, db, fixture.auditID, "request", fixture.now.Add(5*24*time.Hour))
	assertRawExpiry(t, db, "84000000-0000-0000-0000-000000000002", "request", fixture.now.Add(5*24*time.Hour))
	assertRawExpiry(t, db, "84000000-0000-0000-0000-000000000003", "request", fixture.now.Add(6*24*time.Hour))
	assertRawExpiry(t, db, "84000000-0000-0000-0000-000000000004", "request", fixture.now.Add(-time.Hour))

	current, err := repository.ReadRetentionPolicy(context.Background())
	if err != nil {
		t.Fatalf("read lengthened policy: %v", err)
	}
	newRecordExpiry := changeAt.Add(time.Duration(current.Days) * 24 * time.Hour)
	insertRawRetentionAudit(t, db, "84000000-0000-0000-0000-000000000005", "87000000-0000-0000-0000-000000000005", fixture, changeAt, newRecordExpiry)
	assertRawExpiry(t, db, "84000000-0000-0000-0000-000000000005", "request", newRecordExpiry)

	shortenAt := fixture.now.Add(2 * time.Hour)
	shortened, err := repository.ChangeRetentionPolicy(context.Background(), access.RetentionPolicyChange{
		Days: 3, MaximumDays: 30, ChangedAt: shortenAt,
		Event: retentionPolicyEvent("86000000-0000-0000-0000-000000000002", fixture.identityID, "88000000-0000-0000-0000-000000000002", shortenAt),
	})
	if err != nil {
		t.Fatalf("shorten retention policy: %v", err)
	}
	if shortened.Days != 3 {
		t.Fatalf("shortened days = %d, want 3", shortened.Days)
	}
	assertRawExpiry(t, db, fixture.auditID, "request", fixture.now.Add(24*time.Hour))
	assertRawExpiry(t, db, "84000000-0000-0000-0000-000000000002", "request", fixture.now.Add(24*time.Hour))
	assertRawExpiry(t, db, "84000000-0000-0000-0000-000000000003", "request", fixture.now.Add(48*time.Hour))
	assertRawExpiry(t, db, "84000000-0000-0000-0000-000000000004", "request", fixture.now.Add(-time.Hour))
	assertRawExpiry(t, db, "84000000-0000-0000-0000-000000000005", "request", changeAt.Add(3*24*time.Hour))

	rows, err := db.Query(`SELECT detail_code FROM security_events WHERE event_type = $1 ORDER BY occurred_at`, string(access.SensitiveActionRetentionPolicy))
	if err != nil {
		t.Fatalf("query retention events: %v", err)
	}
	defer rows.Close()
	var details []string
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatalf("scan retention event: %v", err)
		}
		details = append(details, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate retention events: %v", err)
	}
	if len(details) != 2 || details[0] != "lengthened_7_to_10_days" || details[1] != "shortened_10_to_3_days" {
		t.Fatalf("retention event details = %v, want lengthened then shortened", details)
	}
}

func TestRepositoryRetentionPolicyRequiresActiveSystemAdministrator(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)
	mustExec(t, db, `UPDATE identities SET role = 'team_administrator' WHERE id = $1`, fixture.identityID)

	_, err := repository.ChangeRetentionPolicy(context.Background(), access.RetentionPolicyChange{
		Days: 3, MaximumDays: 30, ChangedAt: fixture.now.Add(time.Hour),
		Event: retentionPolicyEvent("86000000-0000-0000-0000-000000000004", fixture.identityID, "88000000-0000-0000-0000-000000000004", fixture.now.Add(time.Hour)),
	})
	if !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("ChangeRetentionPolicy() error = %v, want ErrForbidden", err)
	}
	var days int
	if err := db.QueryRow(`SELECT raw_retention_days FROM operational_state WHERE id = 1`).Scan(&days); err != nil {
		t.Fatalf("read retention policy: %v", err)
	}
	if days != 7 {
		t.Fatalf("retention days = %d after unauthorized change, want 7", days)
	}
}

func TestRepositoryRetentionPolicyRollsBackExpiryAndStateWhenAuditInsertFails(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)
	originalExpiry := fixture.now.Add(5 * 24 * time.Hour)
	insertRawRetentionContent(t, db, fixture.auditID, fixture.now.Add(-2*24*time.Hour), originalExpiry)
	mustExec(t, db, `CREATE FUNCTION reject_retention_policy_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic retention audit failure'; END $$`)
	mustExec(t, db, `CREATE TRIGGER reject_retention_policy_event BEFORE INSERT ON security_events FOR EACH ROW EXECUTE FUNCTION reject_retention_policy_event()`)

	_, err := repository.ChangeRetentionPolicy(context.Background(), access.RetentionPolicyChange{
		Days: 3, MaximumDays: 30, ChangedAt: fixture.now.Add(time.Hour),
		Event: retentionPolicyEvent("86000000-0000-0000-0000-000000000003", fixture.identityID, "88000000-0000-0000-0000-000000000003", fixture.now.Add(time.Hour)),
	})
	if err == nil {
		t.Fatal("ChangeRetentionPolicy() succeeded despite audit insert failure")
	}
	if errors.Is(err, access.ErrInvalidRetentionPolicy) {
		t.Fatalf("ChangeRetentionPolicy() misclassified audit failure: %v", err)
	}

	var days int
	if err := db.QueryRow(`SELECT raw_retention_days FROM operational_state WHERE id = 1`).Scan(&days); err != nil {
		t.Fatalf("read rolled-back retention policy: %v", err)
	}
	if days != 7 {
		t.Fatalf("rolled-back retention days = %d, want 7", days)
	}
	assertRawExpiry(t, db, fixture.auditID, "request", originalExpiry)
}

func insertRawRetentionAudit(t *testing.T, db *sql.DB, auditID, requestID string, fixture auditPolicyFixture, createdAt, expiresAt time.Time) {
	t.Helper()
	mustExec(t, db, `INSERT INTO audit_records (id, request_id, key_id, owner_kind, identity_id, team_id, model_id, capture_status, outcome, observed_request_bytes, observed_response_bytes, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $12)`, auditID, requestID, fixture.keyID, "personal", fixture.identityID, fixture.teamID, "gpt-test", "pending", "pending", 1, 0, createdAt)
	insertRawRetentionContent(t, db, auditID, createdAt, expiresAt)
}

func insertRawRetentionContent(t *testing.T, db *sql.DB, auditID string, createdAt, expiresAt time.Time) {
	t.Helper()
	mustExec(t, db, `INSERT INTO audit_raw_content (audit_id, content_kind, compression, ciphertext, cipher_nonce, wrapped_data_key, wrap_nonce, key_version, created_at, expires_at) VALUES ($1, 'request', 'gzip', $2, $3, $4, $5, 1, $6, $7)`, auditID, []byte("encrypted-retention-payload-and-tag"), make([]byte, 12), []byte("wrapped-retention-key-and-tag"), make([]byte, 12), createdAt, expiresAt)
}

func assertRawExpiry(t *testing.T, db *sql.DB, auditID, contentKind string, want time.Time) {
	t.Helper()
	var got time.Time
	if err := db.QueryRow(`SELECT expires_at FROM audit_raw_content WHERE audit_id = $1 AND content_kind = $2`, auditID, contentKind).Scan(&got); err != nil {
		t.Fatalf("read expiry for %s/%s: %v", auditID, contentKind, err)
	}
	if !got.Equal(want) {
		t.Fatalf("expiry for %s/%s = %s, want %s", auditID, contentKind, got.UTC().Format(time.RFC3339), want.UTC().Format(time.RFC3339))
	}
}

func retentionPolicyEvent(id, actorID, requestID string, occurredAt time.Time) access.SecurityEvent {
	return access.SecurityEvent{
		ID: id, EventType: string(access.SensitiveActionRetentionPolicy), ActorIdentityID: actorID,
		RequestID: requestID, Outcome: access.SecurityEventSuccess, OccurredAt: occurredAt,
	}
}
