//go:build integration

package database

import (
	"testing"
	"time"
)

func TestMetadataRetentionMigrationBackfillsOperationalEventsAndProtectsRetainedEvidence(t *testing.T) {
	db, migrator := openCompatibilitySchema(t)
	migrateCompatibilityStage(t, migrator, 6)
	occurredAt := time.Now().UTC().Add(-40 * 24 * time.Hour).Truncate(time.Second)
	const expiredID = "86000000-0000-0000-0000-000000000071"
	const retainedID = "86000000-0000-0000-0000-000000000072"
	const legacyExpiredID = "86000000-0000-0000-0000-000000000073"
	mustExec(t, db, `INSERT INTO security_events (id, event_type, request_id, outcome, occurred_at) VALUES ($1, 'operational_fault', $2, 'failure', $3), ($4, 'retained_security', $5, 'success', CURRENT_TIMESTAMP), ($6, 'operational_fault', $7, 'failure', $3)`, expiredID, "87000000-0000-0000-0000-000000000071", occurredAt, retainedID, "87000000-0000-0000-0000-000000000072", legacyExpiredID, "87000000-0000-0000-0000-000000000073")

	migrateCompatibilityStage(t, migrator, 7)

	var retainUntil time.Time
	if err := db.QueryRow(`SELECT retain_until FROM security_events WHERE id = $1`, expiredID).Scan(&retainUntil); err != nil {
		t.Fatalf("read operational retention backfill: %v", err)
	}
	if want := occurredAt.Add(30 * 24 * time.Hour); !retainUntil.Equal(want) {
		t.Fatalf("operational retain_until = %v, want %v", retainUntil, want)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SELECT set_config('n_api_p.retention_maintenance', 'on', true)`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`DELETE FROM security_events WHERE id = $1`, retainedID); err == nil {
		t.Fatal("retained event was deleted after setting the legacy maintenance GUC")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `DELETE FROM security_events WHERE id = $1`, legacyExpiredID)
	var purged int64
	if err := db.QueryRow(`SELECT n_api_p_purge_security_events($1, 'operational', 1000)`, time.Now().UTC()).Scan(&purged); err != nil {
		t.Fatalf("controlled security-event purge: %v", err)
	}
	if purged != 1 {
		t.Fatalf("controlled operational rows purged = %d, want 1", purged)
	}
	if err := db.QueryRow(`SELECT n_api_p_purge_security_events($1, 'security', 1001)`, time.Now().UTC()).Scan(&purged); err == nil {
		t.Fatal("controlled purge accepted a batch above its maximum")
	}
}

func TestMetadataRetentionMigrationAddsOwnershipPurgeIndexes(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	for _, indexName := range []string{
		"sessions_identity_retention_idx",
		"one_time_codes_identity_retention_idx",
		"one_time_codes_issuer_retention_idx",
		"model_allowlist_updater_retention_idx",
		"audit_records_key_retention_idx",
		"audit_records_service_retention_idx",
		"audit_records_responsible_retention_idx",
		"usage_records_key_retention_idx",
		"usage_records_service_retention_idx",
		"usage_records_responsible_retention_idx",
		"security_events_target_identity_retention_idx",
		"security_events_target_service_retention_idx",
		"security_events_target_key_retention_idx",
	} {
		var exists bool
		if err := db.QueryRow(`SELECT to_regclass(current_schema() || '.' || $1) IS NOT NULL`, indexName).Scan(&exists); err != nil {
			t.Fatalf("read index %s: %v", indexName, err)
		}
		if !exists {
			t.Fatalf("retention index %s is missing", indexName)
		}
	}
}
