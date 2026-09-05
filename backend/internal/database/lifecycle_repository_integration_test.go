//go:build integration

package database

import (
	"context"
	"database/sql"
	"errors"
	"n-api-p/internal/audit"
	"sync"
	"testing"
	"time"
)

func TestRepositoryRawContentIsInvisibleAtExpiryDuringCleanupRace(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)
	expiresAt := fixture.now.Add(time.Hour)
	insertRawRetentionContent(t, db, fixture.auditID, fixture.now, expiresAt)

	record, err := repository.ReadRawContent(context.Background(), audit.RawContentLookup{
		AuditID: fixture.auditID, ContentKind: audit.ContentKindRequest, VisibleAt: expiresAt.Add(-time.Nanosecond),
	})
	if err != nil {
		t.Fatalf("ReadRawContent() before expiry error = %v", err)
	}
	if !record.ExpiresAt.Equal(expiresAt) || len(record.Content.Ciphertext) == 0 {
		t.Fatalf("visible raw record = %+v", record)
	}

	start := make(chan struct{})
	errorsSeen := make(chan error, 20)
	var readers sync.WaitGroup
	for range 20 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			<-start
			_, err := repository.ReadRawContent(context.Background(), audit.RawContentLookup{
				AuditID: fixture.auditID, ContentKind: audit.ContentKindRequest, VisibleAt: expiresAt,
			})
			errorsSeen <- err
		}()
	}
	close(start)
	if _, err := repository.DeleteExpiredRawContent(context.Background(), expiresAt); err != nil {
		t.Fatalf("DeleteExpiredRawContent() error = %v", err)
	}
	readers.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if !errors.Is(err, audit.ErrRawContentUnavailable) {
			t.Fatalf("read at exact expiry error = %v, want ErrRawContentUnavailable", err)
		}
	}
}

func TestRepositoryLifecycleCleanupPersistsLagAndRetainsMetadata(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)
	cleanupAt := fixture.now.Add(3 * time.Hour)
	expiresAt := cleanupAt.Add(-time.Hour - time.Microsecond)
	insertRawRetentionContent(t, db, fixture.auditID, fixture.now, expiresAt)
	mustExec(t, db, `INSERT INTO usage_records (id, audit_id, request_id, key_id, owner_kind, identity_id, team_id, model_id, outcome, usage_reported, created_at) VALUES ($1, $2, $3, $4, 'personal', $5, $6, 'gpt-test', 'success', false, $7)`, "85000000-0000-0000-0000-000000000020", fixture.auditID, fixture.requestID, fixture.keyID, fixture.identityID, fixture.teamID, fixture.now)
	mustExec(t, db, `INSERT INTO security_events (id, event_type, actor_identity_id, target_audit_id, request_id, outcome, detail_code, occurred_at) VALUES ($1, 'lifecycle_test', $2, $3, $4, 'success', 'metadata_retained', $5)`, "86000000-0000-0000-0000-000000000020", fixture.identityID, fixture.auditID, fixture.requestID, fixture.now)

	lag, err := repository.ObserveDeletionLag(context.Background(), cleanupAt)
	if err != nil {
		t.Fatalf("ObserveDeletionLag() error = %v", err)
	}
	if !lag.Critical || lag.OldestExpiredAt == nil || !lag.OldestExpiredAt.Equal(expiresAt) || lag.OverdueSince == nil || !lag.OverdueSince.Equal(expiresAt.Add(audit.DeletionTarget)) {
		t.Fatalf("deletion lag = %+v, want critical overdue state", lag)
	}
	deleted, err := repository.DeleteExpiredRawContent(context.Background(), cleanupAt)
	if err != nil {
		t.Fatalf("DeleteExpiredRawContent() error = %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted rows = %d, want 1", deleted)
	}
	assertLifecycleRowCount(t, db, "audit_raw_content", "audit_id", fixture.auditID, 0)
	assertLifecycleRowCount(t, db, "audit_records", "id", fixture.auditID, 1)
	assertLifecycleRowCount(t, db, "usage_records", "audit_id", fixture.auditID, 1)
	assertLifecycleRowCount(t, db, "security_events", "target_audit_id", fixture.auditID, 1)

	var lastCleanup time.Time
	var overdue sql.NullTime
	if err := db.QueryRow(`SELECT last_cleanup_at, deletion_overdue_since FROM operational_state WHERE id = 1`).Scan(&lastCleanup, &overdue); err != nil {
		t.Fatalf("read cleanup state: %v", err)
	}
	if !lastCleanup.Equal(cleanupAt) || overdue.Valid {
		t.Fatalf("cleanup state = (%v, %v), want completion and no overdue state", lastCleanup, overdue)
	}
	rows, err := db.Query(`SELECT outcome, detail_code FROM security_events WHERE event_type = 'operational_fault' ORDER BY occurred_at, outcome`)
	if err != nil {
		t.Fatalf("query deletion operational events: %v", err)
	}
	defer rows.Close()
	var events [][2]string
	for rows.Next() {
		var outcome, detail string
		if err := rows.Scan(&outcome, &detail); err != nil {
			t.Fatalf("scan deletion operational event: %v", err)
		}
		events = append(events, [2]string{outcome, detail})
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate deletion operational events: %v", err)
	}
	if len(events) != 2 || events[0] != [2]string{"failure", "raw_deletion_overdue"} || events[1] != [2]string{"success", "raw_deletion_overdue"} {
		t.Fatalf("deletion operational events = %#v", events)
	}
}

func TestRepositoryDeletionLagBecomesCriticalOnlyAfterOneHour(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)
	cleanupAt := fixture.now.Add(3 * time.Hour)
	expiresAt := cleanupAt.Add(-audit.DeletionTarget)
	insertRawRetentionContent(t, db, fixture.auditID, fixture.now, expiresAt)

	lag, err := repository.ObserveDeletionLag(context.Background(), cleanupAt)
	if err != nil {
		t.Fatalf("ObserveDeletionLag() error = %v", err)
	}
	if lag.Critical || lag.OverdueSince != nil {
		t.Fatalf("deletion lag at exact one-hour boundary = %+v, want non-critical", lag)
	}
}

func TestRepositoryDeletionFailurePreservesCriticalLagState(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)
	cleanupAt := fixture.now.Add(3 * time.Hour)
	insertRawRetentionContent(t, db, fixture.auditID, fixture.now, cleanupAt.Add(-2*time.Hour))
	if _, err := repository.ObserveDeletionLag(context.Background(), cleanupAt); err != nil {
		t.Fatalf("ObserveDeletionLag() error = %v", err)
	}
	mustExec(t, db, `CREATE FUNCTION reject_raw_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic cleanup failure'; END $$`)
	mustExec(t, db, `CREATE TRIGGER reject_raw_cleanup BEFORE DELETE ON audit_raw_content FOR EACH ROW EXECUTE FUNCTION reject_raw_cleanup()`)

	if _, err := repository.DeleteExpiredRawContent(context.Background(), cleanupAt); err == nil {
		t.Fatal("DeleteExpiredRawContent() succeeded despite failure trigger")
	}
	var overdue sql.NullTime
	if err := db.QueryRow(`SELECT deletion_overdue_since FROM operational_state WHERE id = 1`).Scan(&overdue); err != nil {
		t.Fatalf("read preserved lag state: %v", err)
	}
	if !overdue.Valid {
		t.Fatal("critical deletion lag state was cleared after failed deletion")
	}
	assertLifecycleRowCount(t, db, "audit_raw_content", "audit_id", fixture.auditID, 1)
}

func TestRepositoryPurgesOnlyRevokedVerificationHashes(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)
	purgeAt := fixture.now.Add(time.Hour)
	const activeKeyID = "83000000-0000-0000-0000-000000000030"
	mustExec(t, db, `INSERT INTO api_keys (id, identity_id, kind, name, prefix, verification_hash, status, created_at) VALUES ($1, $2, 'personal', 'active-sibling', 'nap_active', $3, 'active', $4)`, activeKeyID, fixture.identityID, []byte("active-sibling-hash"), fixture.now)
	mustExec(t, db, `UPDATE api_keys SET status = 'revoked', revoked_at = $1 WHERE id = $2`, purgeAt.Add(-time.Minute), fixture.keyID)

	purged, err := repository.PurgeRevokedVerificationHashes(context.Background(), purgeAt)
	if err != nil {
		t.Fatalf("PurgeRevokedVerificationHashes() error = %v", err)
	}
	if purged != 1 {
		t.Fatalf("purged hashes = %d, want 1", purged)
	}
	var revokedHash, activeHash []byte
	var revokedID, prefix, ownerID, status string
	if err := db.QueryRow(`SELECT id::text, prefix, identity_id::text, status, verification_hash FROM api_keys WHERE id = $1`, fixture.keyID).Scan(&revokedID, &prefix, &ownerID, &status, &revokedHash); err != nil {
		t.Fatalf("read purged key metadata: %v", err)
	}
	if revokedID != fixture.keyID || prefix != "nap_audit" || ownerID != fixture.identityID || status != "revoked" || revokedHash != nil {
		t.Fatalf("purged key = (%q, %q, %q, %q, %v)", revokedID, prefix, ownerID, status, revokedHash)
	}
	if err := db.QueryRow(`SELECT verification_hash FROM api_keys WHERE id = $1`, activeKeyID).Scan(&activeHash); err != nil {
		t.Fatalf("read active key hash: %v", err)
	}
	if string(activeHash) != "active-sibling-hash" {
		t.Fatalf("active key hash = %q, want unchanged", activeHash)
	}
	expectRejected(t, db, `UPDATE api_keys SET verification_hash = NULL WHERE id = $1`, activeKeyID)
}

func TestRepositoryMetadataRetentionUsesCalendarYearCutoffs(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)
	purgeAt := time.Date(2024, time.March, 1, 12, 0, 0, 0, time.UTC)
	mustExec(t, db, `INSERT INTO usage_records (id, audit_id, request_id, key_id, owner_kind, identity_id, team_id, model_id, outcome, usage_reported, created_at) VALUES ($1, $2, $3, $4, 'personal', $5, $6, 'gpt-test', 'success', false, $7)`, "85000000-0000-0000-0000-000000000031", fixture.auditID, fixture.requestID, fixture.keyID, fixture.identityID, fixture.teamID, time.Date(2023, time.March, 2, 0, 0, 0, 0, time.UTC))

	result, err := repository.PurgeExpiredMetadata(context.Background(), purgeAt)
	if err != nil {
		t.Fatalf("PurgeExpiredMetadata() error = %v", err)
	}
	if result.UsageRows != 0 {
		t.Fatalf("usage rows purged across leap-year boundary = %d, want 0", result.UsageRows)
	}
	assertLifecycleRowCount(t, db, "usage_records", "audit_id", fixture.auditID, 1)
}

func TestRepositoryMetadataRetentionRemovesExpiredIdentityDependencies(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	repository := NewRepository(db)
	const identityID = "82000000-0000-0000-0000-000000000071"
	disabledAt := time.Date(2022, time.March, 1, 0, 0, 0, 0, time.UTC)
	purgeAt := time.Date(2024, time.March, 1, 12, 0, 0, 0, time.UTC)
	mustExec(t, db, `INSERT INTO teams (id, name, status, created_at, updated_at) VALUES ($1, 'expired-owner-team', 'active', $2, $2)`, "81000000-0000-0000-0000-000000000071", disabledAt)
	mustExec(t, db, `INSERT INTO identities (id, email, role, status, created_at, updated_at, disabled_at) VALUES ($1, 'expired-owner@example.internal', 'employee', 'disabled', $2, $2, $2)`, identityID, disabledAt)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id, created_at) VALUES ($1, $2, $3)`, identityID, "81000000-0000-0000-0000-000000000071", disabledAt)
	mustExec(t, db, `INSERT INTO sessions (id, identity_id, token_hash, csrf_token_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at, revoked_at) VALUES ($1, $2, $3, $4, $5, $5, $5::timestamptz + interval '30 minutes', $5::timestamptz + interval '12 hours', $5::timestamptz + interval '1 hour')`, "81000000-0000-0000-0000-000000000071", identityID, []byte("expired-session-hash"), []byte("expired-csrf-hash"), disabledAt)
	mustExec(t, db, `INSERT INTO one_time_codes (id, identity_id, email, purpose, code_hash, expires_at, created_at, revoked_at, issued_by_identity_id) VALUES ($1, $2, 'expired-owner@example.internal', 'password_reset', $3, $4::timestamptz + interval '30 minutes', $4, $4::timestamptz + interval '1 minute', $2)`, "81000000-0000-0000-0000-000000000072", identityID, []byte("expired-code-hash"), disabledAt)
	mustExec(t, db, `INSERT INTO model_allowlist (model_id, status, updated_by_identity_id, created_at, updated_at) VALUES ('expired-owner-model', 'disabled', $1, $2, $2)`, identityID, disabledAt)

	result, err := repository.PurgeExpiredMetadata(context.Background(), purgeAt)
	if err != nil {
		t.Fatalf("PurgeExpiredMetadata() error = %v", err)
	}
	if result.OwnershipRows != 1 {
		t.Fatalf("ownership rows purged = %d, want 1", result.OwnershipRows)
	}
	for table, query := range map[string]string{
		"identity":      `SELECT count(*) FROM identities WHERE id = $1`,
		"membership":    `SELECT count(*) FROM memberships WHERE identity_id = $1`,
		"session":       `SELECT count(*) FROM sessions WHERE identity_id = $1`,
		"one-time code": `SELECT count(*) FROM one_time_codes WHERE identity_id = $1 OR issued_by_identity_id = $1`,
	} {
		var count int
		if err := db.QueryRow(query, identityID).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("%s rows = %d, want 0", table, count)
		}
	}
	var updater sql.NullString
	if err := db.QueryRow(`SELECT updated_by_identity_id::text FROM model_allowlist WHERE model_id = 'expired-owner-model'`).Scan(&updater); err != nil {
		t.Fatalf("read retained model policy: %v", err)
	}
	if updater.Valid {
		t.Fatalf("retained model policy updater = %q, want NULL", updater.String)
	}
	models, err := repository.ReadModelAllowlist(context.Background())
	if err != nil {
		t.Fatalf("ReadModelAllowlist() after updater expiry error = %v", err)
	}
	if len(models) != 1 || models[0].ModelID != "expired-owner-model" || models[0].UpdatedByIdentityID != "" {
		t.Fatalf("retained model policy = %+v", models)
	}
}

func TestRepositoryMetadataRetentionRemovesExpiredInvestigationCasesBeforeIdentityOwnership(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	repository := NewRepository(db)
	const (
		identityID = "82000000-0000-0000-0000-000000000081"
		activeID   = "82000000-0000-0000-0000-000000000082"
		caseID     = "88000000-0000-0000-0000-000000000081"
		openCaseID = "88000000-0000-0000-0000-000000000082"
		eventID    = "86000000-0000-0000-0000-000000000081"
		requestID  = "87000000-0000-0000-0000-000000000081"
	)
	disabledAt := time.Date(2022, time.March, 1, 0, 0, 0, 0, time.UTC)
	purgeAt := time.Date(2024, time.March, 1, 12, 0, 0, 0, time.UTC)
	mustExec(t, db, `INSERT INTO identities (id, email, role, status, created_at, updated_at, disabled_at) VALUES ($1, 'expired-investigation-owner@example.internal', 'employee', 'disabled', $2, $2, $2)`, identityID, disabledAt)
	mustExec(t, db, `INSERT INTO identities (id, email, role, status, created_at, updated_at) VALUES ($1, 'active-investigation-owner@example.internal', 'employee', 'active', $2, $2)`, activeID, disabledAt)
	mustExec(t, db, `INSERT INTO investigation_cases (id, subject_identity_id, policy_concern, reason, start_at, end_at, status, created_by_identity_id, created_at, closed_by_identity_id, closed_at, disposition) VALUES ($1, $2, 'expired concern', 'expired reason', $3, $4, 'closed', $2, $5, $2, $5, 'inconclusive')`, caseID, identityID, disabledAt.Add(-time.Hour), disabledAt, disabledAt)
	mustExec(t, db, `INSERT INTO investigation_cases (id, subject_identity_id, policy_concern, reason, start_at, end_at, status, created_by_identity_id, created_at) VALUES ($1, $2, 'open concern', 'open reason', $3, $4, 'open', $2, $4)`, openCaseID, activeID, disabledAt.Add(-time.Hour), disabledAt)
	mustExec(t, db, `INSERT INTO security_events (id, event_type, actor_identity_id, investigation_case_id, request_id, outcome, detail_code, occurred_at, retain_until) VALUES ($1, 'investigation_case', $2, $3, $4, 'success', 'case_created', $5, $6)`, eventID, identityID, caseID, requestID, disabledAt, disabledAt.AddDate(2, 0, 0))

	if _, err := repository.PurgeExpiredMetadata(context.Background(), purgeAt); err != nil {
		t.Fatalf("PurgeExpiredMetadata() error = %v", err)
	}
	for table, query := range map[string]string{
		"identity":  `SELECT count(*) FROM identities WHERE id = $1`,
		"case":      `SELECT count(*) FROM investigation_cases WHERE id = $1`,
		"open case": `SELECT count(*) FROM investigation_cases WHERE id = $1`,
		"event":     `SELECT count(*) FROM security_events WHERE id = $1`,
	} {
		var count int
		value := identityID
		if table == "case" {
			value = caseID
		} else if table == "event" {
			value = eventID
		} else if table == "open case" {
			value = openCaseID
		}
		if err := db.QueryRow(query, value).Scan(&count); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if table == "open case" {
			if count != 1 {
				t.Fatalf("%s rows = %d, want 1", table, count)
			}
		} else if count != 0 {
			t.Fatalf("%s rows = %d, want 0", table, count)
		}
	}
}

func TestRepositoryMetadataFailureDoesNotRollbackSuccessfulClasses(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)
	purgeAt := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)
	mustExec(t, db, `INSERT INTO usage_records (id, audit_id, request_id, key_id, owner_kind, identity_id, team_id, model_id, outcome, usage_reported, created_at) VALUES ($1, $2, $3, $4, 'personal', $5, $6, 'gpt-test', 'success', false, $7)`, "85000000-0000-0000-0000-000000000032", fixture.auditID, fixture.requestID, fixture.keyID, fixture.identityID, fixture.teamID, purgeAt.AddDate(-1, 0, -1))
	mustExec(t, db, `INSERT INTO security_events (id, event_type, request_id, outcome, occurred_at, retain_until) VALUES ($1, 'operational_fault', $2, 'failure', $3, $4)`, "86000000-0000-0000-0000-000000000032", "87000000-0000-0000-0000-000000000032", purgeAt.AddDate(0, -2, 0), purgeAt.AddDate(0, -1, 0))
	mustExec(t, db, `CREATE FUNCTION reject_synthetic_operational_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic metadata failure'; END $$`)
	mustExec(t, db, `CREATE TRIGGER reject_synthetic_operational_cleanup BEFORE DELETE ON security_events FOR EACH ROW WHEN (OLD.event_type = 'operational_fault') EXECUTE FUNCTION reject_synthetic_operational_cleanup()`)

	result, err := repository.PurgeExpiredMetadata(context.Background(), purgeAt)
	if err == nil {
		t.Fatal("PurgeExpiredMetadata() succeeded despite the synthetic operational failure")
	}
	if result.UsageRows != 1 {
		t.Fatalf("usage rows purged = %d, want 1 despite independent operational failure", result.UsageRows)
	}
	assertLifecycleRowCount(t, db, "usage_records", "audit_id", fixture.auditID, 0)
}

func assertLifecycleRowCount(t *testing.T, db *sql.DB, tableName, columnName string, value any, want int) {
	t.Helper()
	queries := map[string]string{
		"audit_raw_content.audit_id":      `SELECT count(*) FROM audit_raw_content WHERE audit_id = $1`,
		"audit_records.id":                `SELECT count(*) FROM audit_records WHERE id = $1`,
		"usage_records.audit_id":          `SELECT count(*) FROM usage_records WHERE audit_id = $1`,
		"security_events.target_audit_id": `SELECT count(*) FROM security_events WHERE target_audit_id = $1`,
	}
	query, ok := queries[tableName+"."+columnName]
	if !ok {
		t.Fatalf("unsupported count target %s.%s", tableName, columnName)
	}
	var got int
	if err := db.QueryRow(query, value).Scan(&got); err != nil {
		t.Fatalf("count %s rows: %v", tableName, err)
	}
	if got != want {
		t.Fatalf("%s row count = %d, want %d", tableName, got, want)
	}
}
