//go:build integration

package database

import (
	"database/sql"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

func TestWorkforceAccessSchemaContract(t *testing.T) {
	db, schemaName := migrateWorkforceSchema(t)

	expected := map[string][]string{
		"identities":       {"id", "email", "password_hash", "role", "status", "failed_login_attempts", "failed_login_window_started_at", "locked_until", "created_at", "updated_at", "disabled_at"},
		"teams":            {"id", "name", "status", "created_at", "updated_at", "disabled_at"},
		"memberships":      {"identity_id", "team_id", "created_at"},
		"service_accounts": {"id", "team_id", "responsible_identity_id", "name", "status", "created_at", "updated_at", "disabled_at"},
		"sessions":         {"id", "identity_id", "token_hash", "csrf_token_hash", "created_at", "last_seen_at", "idle_expires_at", "absolute_expires_at", "reauthenticated_until", "revoked_at"},
		"one_time_codes":   {"id", "identity_id", "email", "purpose", "code_hash", "expires_at", "created_at", "used_at", "revoked_at", "issued_by_identity_id", "revoke_personal_keys_on_use"},
		"api_keys":         {"id", "identity_id", "service_account_id", "kind", "name", "prefix", "verification_hash", "status", "created_at", "last_used_at", "revoked_at"},
	}

	for table, columns := range expected {
		assertTableColumns(t, db, schemaName, table, columns)
	}
	assertNoSensitivePlaintextColumns(t, db, schemaName)

	for _, forbiddenTable := range []string{"totp_factors", "budgets", "training_datasets", "team_model_policies"} {
		assertTableAbsent(t, db, schemaName, forbiddenTable)
	}
}

func TestWorkforceAccessSchemaRejectsInvalidOwnership(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)

	const (
		teamID        = "10000000-0000-0000-0000-000000000001"
		employeeID    = "20000000-0000-0000-0000-000000000001"
		adminID       = "20000000-0000-0000-0000-000000000002"
		serviceID     = "30000000-0000-0000-0000-000000000001"
		personalKeyID = "40000000-0000-0000-0000-000000000001"
	)

	mustExec(t, db, `INSERT INTO teams (id, name, status) VALUES ($1, $2, $3)`, teamID, "Platform", "active")
	mustExec(t, db, `INSERT INTO identities (id, email, role, status) VALUES ($1, $2, $3, $4)`, employeeID, "employee@example.internal", "employee", "active")
	mustExec(t, db, `INSERT INTO identities (id, email, role, status) VALUES ($1, $2, $3, $4)`, adminID, "admin@example.internal", "system_administrator", "active")
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, employeeID, teamID)
	mustExec(t, db, `INSERT INTO service_accounts (id, team_id, responsible_identity_id, name, status) VALUES ($1, $2, $3, $4, $5)`, serviceID, teamID, employeeID, "build-agent", "active")
	mustExec(t, db, `INSERT INTO api_keys (id, identity_id, kind, name, prefix, verification_hash, status) VALUES ($1, $2, $3, $4, $5, $6, $7)`, personalKeyID, employeeID, "personal", "IDE", "nap_live_01", []byte("hash-only"), "active")

	expectRejected(t, db, `INSERT INTO identities (id, email, role, status) VALUES ($1, $2, $3, $4)`, "20000000-0000-0000-0000-000000000003", "employee@example.internal", "employee", "active")
	expectRejected(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, employeeID, teamID)
	expectRejected(t, db, `INSERT INTO service_accounts (id, team_id, responsible_identity_id, name, status) VALUES ($1, $2, $3, $4, $5)`, "30000000-0000-0000-0000-000000000002", teamID, "20000000-0000-0000-0000-000000000099", "invalid-owner", "active")
	expectRejected(t, db, `INSERT INTO service_accounts (id, team_id, responsible_identity_id, name, status) VALUES ($1, $2, $3, $4, $5)`, "30000000-0000-0000-0000-000000000003", teamID, adminID, "cross-team-owner", "active")
	expectRejected(t, db, `INSERT INTO api_keys (id, identity_id, service_account_id, kind, name, prefix, verification_hash, status) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, "40000000-0000-0000-0000-000000000002", employeeID, serviceID, "personal", "invalid", "nap_bad_01", []byte("hash-only"), "active")
	expectRejected(t, db, `INSERT INTO api_keys (id, kind, name, prefix, verification_hash, status) VALUES ($1, $2, $3, $4, $5, $6)`, "40000000-0000-0000-0000-000000000003", "service", "invalid", "nap_bad_02", []byte("hash-only"), "active")
}

func migrateWorkforceSchema(t *testing.T) (*sql.DB, string) {
	t.Helper()

	databaseURL := testDatabaseURL(t)
	const schemaName = "workforce_schema_test"
	adminDB := openTestDatabase(t, databaseURL)
	resetTestSchema(t, adminDB, schemaName)
	schemaDB := openTestDatabase(t, databaseURLWithSearchPath(t, databaseURL, schemaName))
	migrator := openTestMigrator(t, schemaDB, schemaName, allMigrationFiles)
	if err := migrator.Up(); err != nil {
		t.Fatalf("apply workforce migrations: %v", err)
	}
	return schemaDB, schemaName
}

func testDatabaseURL(t *testing.T) string {
	t.Helper()

	value := strings.TrimSpace(os.Getenv("N_API_P_TEST_DATABASE_URL"))
	if value == "" {
		t.Fatal("N_API_P_TEST_DATABASE_URL is required for integration tests")
	}
	return value
}

func assertTableColumns(t *testing.T, db *sql.DB, schemaName, tableName string, want []string) {
	t.Helper()

	rows, err := db.Query(`SELECT column_name FROM information_schema.columns WHERE table_schema = $1 AND table_name = $2 ORDER BY column_name`, schemaName, tableName)
	if err != nil {
		t.Fatalf("query %s columns: %v", tableName, err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			t.Fatalf("scan %s column: %v", tableName, err)
		}
		got = append(got, column)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate %s columns: %v", tableName, err)
	}
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("%s columns = %v, want %v", tableName, got, want)
	}
}

func assertNoSensitivePlaintextColumns(t *testing.T, db *sql.DB, schemaName string) {
	t.Helper()

	rows, err := db.Query(`SELECT table_name, column_name FROM information_schema.columns WHERE table_schema = $1 AND column_name IN ('password', 'token', 'code', 'api_key', 'key_value') ORDER BY table_name, column_name`, schemaName)
	if err != nil {
		t.Fatalf("query sensitive plaintext columns: %v", err)
	}
	defer rows.Close()
	if rows.Next() {
		var tableName, columnName string
		if err := rows.Scan(&tableName, &columnName); err != nil {
			t.Fatalf("scan sensitive plaintext column: %v", err)
		}
		t.Fatalf("sensitive plaintext column exists: %s.%s", tableName, columnName)
	}
}

func assertTableAbsent(t *testing.T, db *sql.DB, schemaName, tableName string) {
	t.Helper()

	var exists bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = $1 AND table_name = $2)`, schemaName, tableName).Scan(&exists); err != nil {
		t.Fatalf("query forbidden table %s: %v", tableName, err)
	}
	if exists {
		t.Fatalf("forbidden table %s exists", tableName)
	}
}

func mustExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("execute schema fixture: %v", err)
	}
}

func expectRejected(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err == nil {
		t.Fatal("invalid schema fixture was accepted")
	}
}
