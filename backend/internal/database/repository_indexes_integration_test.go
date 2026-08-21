//go:build integration

package database

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"testing"
)

func TestRepositoryLookupIndexes(t *testing.T) {
	db, schemaName := migrateRepositorySchema(t)

	contracts := map[string][]string{
		"identities_status_created_idx":                 {"ON " + schemaName + ".identities", "(status, created_at DESC, id DESC)"},
		"teams_status_created_idx":                      {"ON " + schemaName + ".teams", "(status, created_at DESC, id DESC)"},
		"memberships_team_identity_idx":                 {"ON " + schemaName + ".memberships", "(team_id, identity_id)"},
		"service_accounts_team_status_idx":              {"ON " + schemaName + ".service_accounts", "(team_id, status, created_at DESC, id DESC)"},
		"service_accounts_responsible_status_idx":       {"ON " + schemaName + ".service_accounts", "(responsible_identity_id, status, created_at DESC, id DESC)"},
		"sessions_identity_active_idx":                  {"ON " + schemaName + ".sessions", "(identity_id, idle_expires_at, absolute_expires_at)", "WHERE (revoked_at IS NULL)"},
		"sessions_idle_expiry_idx":                      {"ON " + schemaName + ".sessions", "(idle_expires_at)", "WHERE (revoked_at IS NULL)"},
		"sessions_absolute_expiry_idx":                  {"ON " + schemaName + ".sessions", "(absolute_expires_at)", "WHERE (revoked_at IS NULL)"},
		"sessions_identity_retention_idx":               {"ON " + schemaName + ".sessions", "(identity_id, id)"},
		"one_time_codes_identity_purpose_expiry_idx":    {"ON " + schemaName + ".one_time_codes", "(identity_id, purpose, expires_at DESC)", "WHERE ((used_at IS NULL) AND (revoked_at IS NULL))"},
		"one_time_codes_expiry_idx":                     {"ON " + schemaName + ".one_time_codes", "(expires_at)", "WHERE ((used_at IS NULL) AND (revoked_at IS NULL))"},
		"one_time_codes_identity_retention_idx":         {"ON " + schemaName + ".one_time_codes", "(identity_id, id)"},
		"one_time_codes_issuer_retention_idx":           {"ON " + schemaName + ".one_time_codes", "(issued_by_identity_id, id)"},
		"api_keys_identity_status_created_idx":          {"ON " + schemaName + ".api_keys", "(identity_id, status, created_at DESC, id DESC)", "WHERE (identity_id IS NOT NULL)"},
		"api_keys_service_status_created_idx":           {"ON " + schemaName + ".api_keys", "(service_account_id, status, created_at DESC, id DESC)", "WHERE (service_account_id IS NOT NULL)"},
		"api_keys_revoked_idx":                          {"ON " + schemaName + ".api_keys", "(revoked_at, id)", "WHERE (revoked_at IS NOT NULL)"},
		"model_allowlist_status_model_idx":              {"ON " + schemaName + ".model_allowlist", "(status, model_id)"},
		"model_allowlist_updater_retention_idx":         {"ON " + schemaName + ".model_allowlist", "(updated_by_identity_id, model_id)", "WHERE (updated_by_identity_id IS NOT NULL)"},
		"audit_records_created_idx":                     {"ON " + schemaName + ".audit_records", "(created_at DESC, id DESC)"},
		"audit_records_key_retention_idx":               {"ON " + schemaName + ".audit_records", "(key_id, id)"},
		"audit_records_service_retention_idx":           {"ON " + schemaName + ".audit_records", "(service_account_id, id)", "WHERE (service_account_id IS NOT NULL)"},
		"audit_records_responsible_retention_idx":       {"ON " + schemaName + ".audit_records", "(responsible_identity_id, id)", "WHERE (responsible_identity_id IS NOT NULL)"},
		"audit_records_identity_created_idx":            {"ON " + schemaName + ".audit_records", "(identity_id, created_at DESC, id DESC)", "WHERE (identity_id IS NOT NULL)"},
		"audit_records_team_created_idx":                {"ON " + schemaName + ".audit_records", "(team_id, created_at DESC, id DESC)"},
		"audit_records_capture_status_updated_idx":      {"ON " + schemaName + ".audit_records", "(capture_status, updated_at, id)"},
		"audit_records_upstream_request_idx":            {"ON " + schemaName + ".audit_records", "(upstream_request_id)", "WHERE (upstream_request_id IS NOT NULL)"},
		"audit_raw_content_expiry_idx":                  {"ON " + schemaName + ".audit_raw_content", "(expires_at, audit_id, content_kind)"},
		"usage_records_identity_created_idx":            {"ON " + schemaName + ".usage_records", "(identity_id, created_at DESC, id DESC)", "WHERE (identity_id IS NOT NULL)"},
		"usage_records_team_created_idx":                {"ON " + schemaName + ".usage_records", "(team_id, created_at DESC, id DESC)"},
		"usage_records_created_idx":                     {"ON " + schemaName + ".usage_records", "(created_at DESC, id DESC)"},
		"usage_records_key_retention_idx":               {"ON " + schemaName + ".usage_records", "(key_id, id)"},
		"usage_records_service_retention_idx":           {"ON " + schemaName + ".usage_records", "(service_account_id, id)", "WHERE (service_account_id IS NOT NULL)"},
		"usage_records_responsible_retention_idx":       {"ON " + schemaName + ".usage_records", "(responsible_identity_id, id)", "WHERE (responsible_identity_id IS NOT NULL)"},
		"security_events_occurred_idx":                  {"ON " + schemaName + ".security_events", "(occurred_at DESC, id DESC)"},
		"security_events_retention_idx":                 {"ON " + schemaName + ".security_events", "(retain_until, id)"},
		"security_events_request_idx":                   {"ON " + schemaName + ".security_events", "(request_id, occurred_at DESC, id DESC)"},
		"security_events_target_audit_idx":              {"ON " + schemaName + ".security_events", "(target_audit_id, occurred_at DESC, id DESC)", "WHERE (target_audit_id IS NOT NULL)"},
		"security_events_actor_occurred_idx":            {"ON " + schemaName + ".security_events", "(actor_identity_id, occurred_at DESC, id DESC)", "WHERE (actor_identity_id IS NOT NULL)"},
		"security_events_target_identity_retention_idx": {"ON " + schemaName + ".security_events", "(target_identity_id, id)", "WHERE (target_identity_id IS NOT NULL)"},
		"security_events_target_service_retention_idx":  {"ON " + schemaName + ".security_events", "(target_service_account_id, id)", "WHERE (target_service_account_id IS NOT NULL)"},
		"security_events_target_key_retention_idx":      {"ON " + schemaName + ".security_events", "(target_key_id, id)", "WHERE (target_key_id IS NOT NULL)"},
	}

	indexNames := make([]string, 0, len(contracts))
	for indexName := range contracts {
		indexNames = append(indexNames, indexName)
	}
	sort.Strings(indexNames)
	for _, indexName := range indexNames {
		fragments := contracts[indexName]
		assertIndexDefinition(t, db, schemaName, indexName, fragments)
	}
}

func migrateRepositorySchema(t *testing.T) (*sql.DB, string) {
	t.Helper()

	databaseURL := testDatabaseURL(t)
	const schemaName = "repository_schema_test"
	adminDB := openTestDatabase(t, databaseURL)
	resetTestSchema(t, adminDB, schemaName)
	schemaDB := openTestDatabase(t, databaseURLWithSearchPath(t, databaseURL, schemaName))
	migrator := openTestMigrator(t, schemaDB, schemaName, allMigrationFiles)
	if err := migrator.Up(); err != nil {
		t.Fatalf("apply repository migrations: %v", err)
	}
	return schemaDB, schemaName
}

func assertIndexDefinition(t *testing.T, db *sql.DB, schemaName, indexName string, fragments []string) {
	t.Helper()

	qualifiedName := fmt.Sprintf("%s.%s", schemaName, indexName)
	var definition sql.NullString
	if err := db.QueryRow(`SELECT pg_get_indexdef(to_regclass($1))`, qualifiedName).Scan(&definition); err != nil {
		t.Fatalf("query index %s: %v", indexName, err)
	}
	if !definition.Valid {
		t.Fatalf("index %s does not exist", indexName)
	}
	for _, fragment := range fragments {
		if !strings.Contains(definition.String, fragment) {
			t.Fatalf("index %s definition %q does not contain %q", indexName, definition.String, fragment)
		}
	}
}
