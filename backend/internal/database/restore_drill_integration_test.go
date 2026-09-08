//go:build integration

package database_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base64"
	"errors"
	"io/fs"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
	"n-api-p/internal/database"
	"n-api-p/internal/httpapi"
	"n-api-p/internal/observability"
	"n-api-p/internal/operations"
)

//go:embed migrations/*.up.sql
var task105MigrationFiles embed.FS

const (
	task105AdminID       = "95000000-0000-0000-0000-000000000001"
	task105EmployeeID    = "95000000-0000-0000-0000-000000000002"
	task105TeamID        = "95000000-0000-0000-0000-000000000003"
	task105ServiceID     = "95000000-0000-0000-0000-000000000004"
	task105PersonalKeyID = "95000000-0000-0000-0000-000000000005"
	task105ServiceKeyID  = "95000000-0000-0000-0000-000000000006"
	task105SessionID     = "95000000-0000-0000-0000-000000000007"
	task105ActivationID  = "95000000-0000-0000-0000-000000000008"
	task105AuditID       = "95000000-0000-0000-0000-000000000009"
	task105RequestID     = "95000000-0000-0000-0000-000000000010"
	task105UsageID       = "95000000-0000-0000-0000-000000000011"
	task105EventID       = "95000000-0000-0000-0000-000000000012"
	task105CaseID        = "95000000-0000-0000-0000-000000000013"
	task105GrantID       = "95000000-0000-0000-0000-000000000014"
	task105RawMarker     = "synthetic-raw-content-must-not-restore"
	task105SessionToken  = "synthetic-task105-session-token"
	task105CSRFToken     = "synthetic-task105-csrf-token"
)

func TestTask105PrepareSource(t *testing.T) {
	if task105Phase() != "prepare-source" {
		t.Skip("task 10.5 phase is not prepare-source")
	}
	db := task105OpenDatabase(t)
	task105ApplyMigrations(t, db)
	now := time.Now().UTC().Truncate(time.Second).Add(-time.Hour)
	personal := task105Credential(1)
	service := task105Credential(2)
	task105Exec(t, db, `INSERT INTO teams (id, name, status, created_at, updated_at) VALUES ($1, 'task105-team', 'active', $2, $2)`, task105TeamID, now)
	task105Exec(t, db, `INSERT INTO identities (id, email, role, status, created_at, updated_at) VALUES ($1, 'task105-admin@example.internal', 'system_administrator', 'active', $2, $2), ($3, 'task105-employee@example.internal', 'employee', 'active', $2, $2)`, task105AdminID, now, task105EmployeeID)
	task105Exec(t, db, `INSERT INTO memberships (identity_id, team_id, created_at) VALUES ($1, $2, $3), ($4, $2, $3)`, task105AdminID, task105TeamID, now, task105EmployeeID)
	task105Exec(t, db, `INSERT INTO service_accounts (id, team_id, responsible_identity_id, name, status, created_at, updated_at) VALUES ($1, $2, $3, 'task105-service', 'active', $4, $4)`, task105ServiceID, task105TeamID, task105EmployeeID, now)
	task105Exec(t, db, `INSERT INTO api_keys (id, identity_id, kind, name, prefix, verification_hash, status, created_at) VALUES ($1, $2, 'personal', 'task105-personal', $3, $4, 'active', $5)`, task105PersonalKeyID, task105EmployeeID, personal[:12], task105Hash(personal), now)
	task105Exec(t, db, `INSERT INTO api_keys (id, service_account_id, kind, name, prefix, verification_hash, status, created_at) VALUES ($1, $2, 'service', 'task105-service-key', $3, $4, 'active', $5)`, task105ServiceKeyID, task105ServiceID, service[:12], task105Hash(service), now)
	task105Exec(t, db, `INSERT INTO sessions (id, identity_id, token_hash, csrf_token_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at, reauthenticated_until) VALUES ($1, $2, $3, $4, $5::timestamptz, $5::timestamptz, $5::timestamptz + interval '2 hours', $5::timestamptz + interval '12 hours', $5::timestamptz + interval '2 hours')`, task105SessionID, task105EmployeeID, task105Hash(task105SessionToken), task105Hash(task105CSRFToken), now)
	task105Exec(t, db, `INSERT INTO one_time_codes (id, identity_id, email, purpose, code_hash, expires_at, created_at, issued_by_identity_id) VALUES ($1, $2, 'task105-employee@example.internal', 'activation', decode('7461736b3130352d636f64652d68617368', 'hex'), $3::timestamptz + interval '1 hour', $3::timestamptz, $4)`, task105ActivationID, task105EmployeeID, now, task105AdminID)
	task105Exec(t, db, `INSERT INTO model_allowlist (model_id, status, updated_by_identity_id, created_at, updated_at) VALUES ('task105-model', 'allowed', $1, $2, $2)`, task105AdminID, now)
	task105Exec(t, db, `UPDATE operational_state SET audit_gate_state = 'open', audit_gate_reason_code = NULL, gate_changed_at = $1, last_persistence_probe_at = $1, updated_at = $1 WHERE id = 1`, now)
	task105Exec(t, db, `INSERT INTO audit_records (id, request_id, key_id, owner_kind, identity_id, team_id, model_id, capture_status, outcome, upstream_request_id, upstream_http_status, finish_reason, observed_request_bytes, observed_response_bytes, created_at, updated_at, completed_at) VALUES ($1, $2, $3, 'personal', $4, $5, 'task105-model', 'complete', 'success', 'task105-upstream', 200, 'stop', 64, 96, $6::timestamptz, $6::timestamptz, $6::timestamptz)`, task105AuditID, task105RequestID, task105PersonalKeyID, task105EmployeeID, task105TeamID, now)
	task105Exec(t, db, `INSERT INTO investigation_cases (id, subject_identity_id, policy_concern, reason, start_at, end_at, status, created_by_identity_id, created_at) VALUES ($1, $2, 'task105-policy-concern', 'task105-investigation-reason', $3, $4, 'open', $5, $6)`, task105CaseID, task105EmployeeID, now.Add(-2*time.Hour), now.Add(-time.Hour), task105AdminID, now)
	task105Exec(t, db, `INSERT INTO investigation_case_audits (case_id, audit_id, ordinal, capture_status, audit_created_at, raw_expires_at, created_at) VALUES ($1, $2, 1, 'complete', $3, $3::timestamptz + interval '7 days', $3)`, task105CaseID, task105AuditID, now)
	task105Exec(t, db, `INSERT INTO investigation_access_grants (id, case_id, actor_identity_id, session_id, issued_at, expires_at) VALUES ($1, $2, $3, $4, $5, $5::timestamptz + interval '15 minutes')`, task105GrantID, task105CaseID, task105EmployeeID, task105SessionID, now)
	task105Exec(t, db, `INSERT INTO audit_raw_content (audit_id, content_kind, compression, ciphertext, cipher_nonce, wrapped_data_key, wrap_nonce, key_version, created_at, expires_at) VALUES ($1, 'request', 'gzip', $2, decode(repeat('61', 12), 'hex'), decode(repeat('62', 32), 'hex'), decode(repeat('63', 12), 'hex'), 1, $3::timestamptz, $3::timestamptz + interval '7 days')`, task105AuditID, []byte(task105RawMarker+"-ciphertext"), now)
	task105Exec(t, db, `INSERT INTO usage_records (id, audit_id, request_id, key_id, owner_kind, identity_id, team_id, model_id, upstream_request_id, outcome, usage_reported, input_tokens, output_tokens, total_tokens, created_at) VALUES ($1, $2, $3, $4, 'personal', $5, $6, 'task105-model', 'task105-upstream', 'success', true, 3, 4, 7, $7)`, task105UsageID, task105AuditID, task105RequestID, task105PersonalKeyID, task105EmployeeID, task105TeamID, now)
	task105Exec(t, db, `INSERT INTO security_events (id, event_type, request_id, outcome, reason, detail_code, occurred_at, retain_until) VALUES ($1, 'operational_fault', $2, 'failure', $3, 'task105_recovery_point', $4::timestamptz, $4::timestamptz + interval '30 days')`, task105EventID, task105RequestID, now.Format(time.RFC3339), now)
	task105AssertCount(t, db, "audit_raw_content", 1)
}

func TestTask105VerifyRestoredBeforeInvalidation(t *testing.T) {
	if task105Phase() != "verify-restored" {
		t.Skip("task 10.5 phase is not verify-restored")
	}
	db := task105OpenDatabase(t)
	task105AssertMigrationVersion(t, db)
	for table, want := range map[string]int{
		"identities": 2, "teams": 1, "memberships": 2, "service_accounts": 1,
		"sessions": 1, "one_time_codes": 1, "api_keys": 2, "model_allowlist": 1,
		"audit_records": 1, "usage_records": 1, "security_events": 1,
		"investigation_cases": 1, "investigation_case_audits": 1, "investigation_access_grants": 1,
		"operational_state": 1, "audit_raw_content": 0,
	} {
		task105AssertCount(t, db, table, want)
	}
	task105AssertInvestigationMetadata(t, db)

	repository := database.NewRepository(db)
	session, err := access.NewSessionService(repository).Authenticate(context.Background(), task105SessionToken, task105CSRFToken, true)
	if err != nil || session.SessionID != task105SessionID || session.IdentityID != task105EmployeeID {
		t.Fatalf("restored session = %+v, err=%v", session, err)
	}
	personal, err := access.NewPersonalKeyService(repository).Authenticate(context.Background(), task105Credential(1))
	if err != nil || personal.KeyID != task105PersonalKeyID || personal.IdentityID != task105EmployeeID {
		t.Fatalf("restored personal key = %+v, err=%v", personal, err)
	}
	service, err := access.NewServiceAccountService(repository).Authenticate(context.Background(), task105Credential(2))
	if err != nil || service.KeyID != task105ServiceKeyID || service.ServiceAccountID != task105ServiceID {
		t.Fatalf("restored service key = %+v, err=%v", service, err)
	}
}

func TestTask105PrepareTarget(t *testing.T) {
	if task105Phase() != "prepare-target" {
		t.Skip("task 10.5 phase is not prepare-target")
	}
	db := task105OpenDatabase(t)
	task105ApplyMigrations(t, db)
	var retention int
	var state, reason string
	if err := db.QueryRow(`SELECT raw_retention_days, audit_gate_state, audit_gate_reason_code FROM operational_state WHERE id = 1`).Scan(&retention, &state, &reason); err != nil {
		t.Fatal(err)
	}
	if retention != 7 || state != string(audit.AuditGateStateBlocked) || reason != audit.GateReasonStartupProbe {
		t.Fatalf("migration seed = (%d, %s, %s), want (7, blocked, startup_probe_required)", retention, state, reason)
	}
	result, err := db.Exec(`DELETE FROM operational_state WHERE id = 1`)
	if err != nil {
		t.Fatal(err)
	}
	if rows, _ := result.RowsAffected(); rows != 1 {
		t.Fatalf("deleted migration seed rows = %d, want 1", rows)
	}
}

func TestTask105InvalidateRestoredCredentials(t *testing.T) {
	if task105Phase() != "invalidate" {
		t.Skip("task 10.5 phase is not invalidate")
	}
	db := task105OpenDatabase(t)
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	rollback := true
	defer func() {
		if rollback {
			_ = tx.Rollback()
		}
	}()
	for _, statement := range []string{
		`UPDATE sessions SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP), reauthenticated_until = NULL`,
		`UPDATE one_time_codes SET used_at = COALESCE(used_at, CURRENT_TIMESTAMP), revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP) WHERE used_at IS NULL AND revoked_at IS NULL`,
		`UPDATE api_keys SET status = 'revoked', revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP), verification_hash = NULL`,
		`UPDATE investigation_access_grants SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP) WHERE revoked_at IS NULL`,
		`UPDATE operational_state SET audit_gate_state = 'blocked', audit_gate_reason_code = 'restore_requires_probe', gate_changed_at = CURRENT_TIMESTAMP, last_persistence_probe_at = NULL, last_cleanup_at = NULL, deletion_overdue_since = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = 1`,
	} {
		if _, err := tx.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec(`INSERT INTO security_events (id, event_type, request_id, outcome, reason, detail_code, occurred_at, retain_until) VALUES (gen_random_uuid(), 'operational_fault', gen_random_uuid(), 'failure', 'restore_raw_window_not_recovered', 'database_unavailable', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + interval '30 days')`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	rollback = false
}

func TestTask105VerifyRestored(t *testing.T) {
	if task105Phase() != "verify" {
		t.Skip("task 10.5 phase is not verify")
	}
	db := task105OpenDatabase(t)
	var rawRows, activeSessions, activeKeys, usableCodes int
	if err := db.QueryRow(`SELECT count(*) FROM audit_raw_content`).Scan(&rawRows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM sessions WHERE revoked_at IS NULL`).Scan(&activeSessions); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM api_keys WHERE status = 'active' OR verification_hash IS NOT NULL`).Scan(&activeKeys); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM one_time_codes WHERE used_at IS NULL AND revoked_at IS NULL`).Scan(&usableCodes); err != nil {
		t.Fatal(err)
	}
	if rawRows != 0 || activeSessions != 0 || activeKeys != 0 || usableCodes != 0 {
		t.Fatalf("restore safety counts raw=%d sessions=%d keys=%d codes=%d", rawRows, activeSessions, activeKeys, usableCodes)
	}
	task105AssertInvestigationMetadata(t, db)
	var activeInvestigationGrants int
	if err := db.QueryRow(`SELECT count(*) FROM investigation_access_grants WHERE revoked_at IS NULL`).Scan(&activeInvestigationGrants); err != nil {
		t.Fatal(err)
	}
	if activeInvestigationGrants != 0 {
		t.Fatalf("active restored investigation grants = %d, want 0", activeInvestigationGrants)
	}
	var state, reason string
	if err := db.QueryRow(`SELECT audit_gate_state, audit_gate_reason_code FROM operational_state WHERE id = 1`).Scan(&state, &reason); err != nil {
		t.Fatal(err)
	}
	if state != string(audit.AuditGateStateBlocked) || reason != "restore_requires_probe" {
		t.Fatalf("gate = (%s, %s), want blocked/restore_requires_probe", state, reason)
	}
	var eventCount int
	if err := db.QueryRow(`SELECT count(*) FROM security_events WHERE reason = 'restore_raw_window_not_recovered' AND detail_code = 'database_unavailable'`).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 {
		t.Fatalf("restore event count = %d, want 1", eventCount)
	}
	repository := database.NewRepository(db)
	if _, err := access.NewSessionService(repository).Authenticate(context.Background(), task105SessionToken, task105CSRFToken, true); !errors.Is(err, access.ErrSessionInvalid) {
		t.Fatalf("old session error = %v, want ErrSessionInvalid", err)
	}
	if _, err := access.NewPersonalKeyService(repository).Authenticate(context.Background(), task105Credential(1)); !errors.Is(err, access.ErrInvalidAPIKey) {
		t.Fatalf("old personal key error = %v", err)
	}
	if _, err := access.NewServiceAccountService(repository).Authenticate(context.Background(), task105Credential(2)); !errors.Is(err, access.ErrInvalidAPIKey) {
		t.Fatalf("old service key error = %v", err)
	}
	gate, err := audit.NewDegradedStateMachine(repository)
	if err != nil {
		t.Fatal(err)
	}
	metrics := observability.NewMetrics()
	gate.SetMetrics(metrics)
	blocked := gate.Status()
	if blocked.State != audit.AuditGateStateBlocked {
		t.Fatalf("new gate state = %s, want blocked", blocked.State)
	}
	task105AssertGateMetric(t, metrics, "blocked")
	task105AssertFaults(t, repository, true, true)
	checker := httpapi.NewOperatorHealthChecker(httpapi.OperatorHealthDependencies{
		Configuration:      func(context.Context) error { return nil },
		Database:           func(ctx context.Context) error { return db.PingContext(ctx) },
		ActiveAuditKey:     func(context.Context) error { return nil },
		ReadAuditGate:      repository.ReadAuditGate,
		ObserveDeletionLag: repository.ObserveDeletionLag,
		Now:                func() time.Time { return time.Date(2026, 8, 19, 1, 0, 0, 0, time.UTC) },
	})
	if ready := checker.Readiness(context.Background()); ready.State != httpapi.HealthStateUnhealthy {
		t.Fatalf("readiness before probe = %s, want unhealthy", ready.State)
	}
	if err := gate.Recover(context.Background(), time.Date(2026, 8, 18, 23, 0, 0, 0, time.UTC), time.Date(2026, 8, 19, 1, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if ready := checker.Readiness(context.Background()); ready.State != httpapi.HealthStateHealthy {
		t.Fatalf("readiness after probe = %s, want healthy", ready.State)
	}
	operationsService, err := operations.NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	if err := operationsService.RecordFault(context.Background(), operations.FaultDatabaseUnavailable, false, time.Now().UTC()); err != nil {
		t.Fatalf("record database recovery = %v", err)
	}
	if snapshot, err := repository.ReadAuditGate(context.Background()); err != nil || snapshot.State != audit.AuditGateStateOpen {
		t.Fatalf("durable gate after probe = %+v, err=%v", snapshot, err)
	}
	task105AssertGateMetric(t, metrics, "open")
	task105AssertFaults(t, repository, false, false)
	replacement, err := access.NewPersonalKeyService(repository).Create(context.Background(), access.CreatePersonalKeyInput{IdentityID: task105EmployeeID, Name: "replacement"})
	if err != nil {
		t.Fatalf("replacement key issuance = %v", err)
	}
	replacementCredential, ok := replacement.Credential.Reveal()
	if !ok {
		t.Fatal("replacement key was not revealed exactly once")
	}
	if _, err := access.NewPersonalKeyService(repository).Authenticate(context.Background(), replacementCredential); err != nil {
		t.Fatalf("replacement key authentication = %v", err)
	}
	var latestReason string
	if err := db.QueryRow(`SELECT reason FROM security_events WHERE detail_code = 'task105_recovery_point' LIMIT 1`).Scan(&latestReason); err != nil {
		t.Fatal(err)
	}
	recoveryPoint, err := time.Parse(time.RFC3339, latestReason)
	if err != nil {
		t.Fatalf("parse recovery point %q: %v", latestReason, err)
	}
	if loss := time.Since(recoveryPoint); loss < 0 || loss > 24*time.Hour {
		t.Fatalf("synthetic recovery-point age = %s, want within 24h", loss)
	}
	recoveryStartedAtMillis, err := strconv.ParseInt(strings.TrimSpace(os.Getenv("TASK105_RECOVERY_STARTED_AT_MS")), 10, 64)
	if err != nil || recoveryStartedAtMillis <= 0 {
		t.Fatalf("TASK105_RECOVERY_STARTED_AT_MS is invalid: %v", err)
	}
	if elapsed := time.Since(time.UnixMilli(recoveryStartedAtMillis)); elapsed < 0 || elapsed > 2*time.Hour {
		t.Fatalf("synthetic recovery elapsed = %s, want within 2h", elapsed)
	}
	var disasterReason, disasterDetail string
	if err := db.QueryRow(`SELECT reason, detail_code FROM security_events WHERE reason = 'restore_raw_window_not_recovered' LIMIT 1`).Scan(&disasterReason, &disasterDetail); err != nil {
		t.Fatal(err)
	}
	contentFree := strings.ToLower(disasterReason + " " + disasterDetail)
	for _, forbidden := range []string{task105RawMarker, task105SessionToken, task105CSRFToken, task105Credential(1), task105Credential(2), "postgres://", "password", "select ", "update "} {
		if strings.Contains(contentFree, strings.ToLower(forbidden)) {
			t.Fatalf("disaster event contains forbidden value %q", forbidden)
		}
	}
}

func task105AssertMigrationVersion(t *testing.T, db *sql.DB) {
	t.Helper()
	entries, err := fs.ReadDir(task105MigrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	var migrations []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".up.sql") {
			migrations = append(migrations, entry.Name())
		}
	}
	wantMigrations := []string{
		"000001_empty_baseline.up.sql",
		"000002_workforce_access.up.sql",
		"000003_audit_policy_operations.up.sql",
		"000004_repository_indexes.up.sql",
		"000005_lifecycle_maintenance.up.sql",
		"000006_metadata_retention.up.sql",
		"000007_metadata_retention_hardening.up.sql",
		"000008_governed_investigations.up.sql",
	}
	if strings.Join(migrations, "\n") != strings.Join(wantMigrations, "\n") {
		t.Fatalf("migration inventory = %v, want %v", migrations, wantMigrations)
	}

	rows, err := db.Query(`SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'public' ORDER BY tablename`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			t.Fatal(err)
		}
		if table != "spatial_ref_sys" {
			tables = append(tables, table)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	wantTables := []string{
		"api_keys", "audit_raw_content", "audit_records", "identities", "memberships",
		"model_allowlist", "one_time_codes", "operational_state", "security_events",
		"service_accounts", "sessions", "teams", "usage_records", "investigation_cases",
		"investigation_case_audits", "investigation_access_grants",
	}
	sort.Strings(wantTables)
	if strings.Join(tables, "\n") != strings.Join(wantTables, "\n") {
		t.Fatalf("application tables = %v, want %v", tables, wantTables)
	}
	var hashNullable string
	if err := db.QueryRow(`SELECT is_nullable FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'api_keys' AND column_name = 'verification_hash'`).Scan(&hashNullable); err != nil {
		t.Fatal(err)
	}
	if hashNullable != "YES" {
		t.Fatalf("api_keys.verification_hash nullable = %s, want YES for migration 000005", hashNullable)
	}
	var lifecycleIndexExists bool
	if err := db.QueryRow(`SELECT pg_catalog.to_regclass('public.api_keys_revoked_idx') IS NOT NULL`).Scan(&lifecycleIndexExists); err != nil {
		t.Fatal(err)
	}
	if !lifecycleIndexExists {
		t.Fatal("migration 000004 index api_keys_revoked_idx is missing")
	}
	var retentionFunctionExists bool
	if err := db.QueryRow(`SELECT to_regprocedure(current_schema() || '.n_api_p_purge_security_events(timestamptz,text,integer)') IS NOT NULL`).Scan(&retentionFunctionExists); err != nil {
		t.Fatal(err)
	}
	if !retentionFunctionExists {
		t.Fatal("migration 000007 controlled security-event purge function is missing")
	}
}

func task105AssertGateMetric(t *testing.T, metrics *observability.Metrics, state string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
	body := recorder.Body.String()
	for _, candidate := range []string{"open", "blocked", "unknown"} {
		want := "0"
		if candidate == state {
			want = "1"
		}
		metric := `n_api_p_audit_gate_state{state="` + candidate + `"} ` + want
		if !strings.Contains(body, metric) {
			t.Fatalf("metrics missing %q", metric)
		}
	}
}

func task105AssertFaults(t *testing.T, repository *database.Repository, auditActive, databaseActive bool) {
	t.Helper()
	service, err := operations.NewService(repository)
	if err != nil {
		t.Fatal(err)
	}
	health, err := service.Health(context.Background(), operations.HealthInput{Session: access.ActivePortalSession{
		IdentityID: task105AdminID,
		Role:       access.RoleSystemAdministrator,
	}})
	if err != nil {
		t.Fatal(err)
	}
	states := make(map[operations.FaultCode]bool, len(health.Faults))
	for _, fault := range health.Faults {
		states[fault.Code] = fault.Active
	}
	if len(states) != 4 || states[operations.FaultAuditUnavailable] != auditActive || states[operations.FaultDatabaseUnavailable] != databaseActive || states[operations.FaultRawDeletionOverdue] || states[operations.FaultRequiredKeyFailure] {
		t.Fatalf("fault states = %v, want audit=%t database=%t and all others inactive", states, auditActive, databaseActive)
	}
}

func task105Phase() string { return strings.TrimSpace(os.Getenv("TASK105_PHASE")) }

func task105OpenDatabase(t *testing.T) *sql.DB {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("N_API_P_TEST_DATABASE_URL"))
	if dsn == "" {
		t.Fatal("N_API_P_TEST_DATABASE_URL is required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}
	return db
}

func task105ApplyMigrations(t *testing.T, db *sql.DB) {
	t.Helper()
	entries, err := fs.ReadDir(task105MigrationFiles, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		migration, err := task105MigrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(string(migration)); err != nil {
			t.Fatalf("apply %s: %v", entry.Name(), err)
		}
	}
}

func task105Exec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatal(err)
	}
}

func task105AssertCount(t *testing.T, db *sql.DB, table string, want int) {
	t.Helper()
	var got int
	if err := db.QueryRow(`SELECT count(*) FROM ` + table).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s rows = %d, want %d", table, got, want)
	}
}

func task105AssertInvestigationMetadata(t *testing.T, db *sql.DB) {
	t.Helper()
	var subjectID, creatorID, auditID, captureStatus, actorID, sessionID string
	var ordinal int
	if err := db.QueryRow(`
		SELECT cases.subject_identity_id, cases.created_by_identity_id,
		       case_audits.audit_id, case_audits.ordinal, case_audits.capture_status,
		       grants.actor_identity_id, grants.session_id
		FROM investigation_cases AS cases
		JOIN investigation_case_audits AS case_audits ON case_audits.case_id = cases.id
		JOIN investigation_access_grants AS grants ON grants.case_id = cases.id
		WHERE cases.id = $1 AND grants.id = $2`, task105CaseID, task105GrantID).Scan(
		&subjectID, &creatorID, &auditID, &ordinal, &captureStatus, &actorID, &sessionID,
	); err != nil {
		t.Fatal(err)
	}
	if subjectID != task105EmployeeID || creatorID != task105AdminID ||
		auditID != task105AuditID || ordinal != 1 || captureStatus != "complete" ||
		actorID != task105EmployeeID || sessionID != task105SessionID {
		t.Fatalf("restored investigation metadata = (%s, %s, %s, %d, %s, %s, %s), want seeded v8 metadata",
			subjectID, creatorID, auditID, ordinal, captureStatus, actorID, sessionID)
	}
}

func task105Credential(value byte) string {
	return "nap_" + base64.RawURLEncoding.EncodeToString([]byte{value, value, value, value, value, value, value, value, value, value, value, value, value, value, value, value, value, value, value, value, value, value, value, value, value, value, value, value, value, value, value, value})
}

func task105Hash(credential string) []byte {
	hash := sha256.Sum256([]byte(credential))
	return hash[:]
}
