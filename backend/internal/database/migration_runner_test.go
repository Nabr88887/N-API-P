package database

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
)

var requiredRecoveryTables = []string{
	"public.identities",
	"public.teams",
	"public.memberships",
	"public.service_accounts",
	"public.sessions",
	"public.one_time_codes",
	"public.api_keys",
	"public.model_allowlist",
	"public.audit_records",
	"public.usage_records",
	"public.security_events",
	"public.operational_state",
	"public.investigation_cases",
	"public.investigation_case_audits",
	"public.investigation_access_grants",
}

func TestLoadMigrationRequestAcceptsVerifiedCurrentRecoveryManifest(t *testing.T) {
	now := time.Date(2026, 8, 22, 8, 0, 0, 0, time.UTC)
	path := writeRecoveryManifest(t, validRecoveryManifest(now.Add(-time.Hour), 6))
	values := map[string]string{
		"N_API_P_DATABASE_URL":                      "postgres://migration-user:secret@database.internal/n_api_p",
		"N_API_P_MIGRATION_EXPECTED_SOURCE_VERSION": "6",
		"N_API_P_MIGRATION_RECOVERY_MANIFEST_PATH":  path,
	}

	request, err := loadMigrationRequest(mapLookup(values), now)
	if err != nil {
		t.Fatalf("load migration request: %v", err)
	}
	if request.expectedSourceVersion != 6 || request.databaseURL != values["N_API_P_DATABASE_URL"] {
		t.Fatalf("migration request = %+v", request)
	}
}

func TestLoadMigrationRequestAcceptsVerifiedEmptySourceRecoveryPoint(t *testing.T) {
	now := time.Date(2026, 8, 22, 8, 0, 0, 0, time.UTC)
	manifest := validRecoveryManifest(now.Add(-time.Hour), 0)
	manifest["included_tables"] = []string{}
	path := writeRecoveryManifest(t, manifest)
	values := map[string]string{
		"N_API_P_DATABASE_URL":                      "postgres://migration-user:secret@database.internal/n_api_p",
		"N_API_P_MIGRATION_EXPECTED_SOURCE_VERSION": "0",
		"N_API_P_MIGRATION_RECOVERY_MANIFEST_PATH":  path,
	}

	request, err := loadMigrationRequest(mapLookup(values), now)
	if err != nil {
		t.Fatalf("load empty-source migration request: %v", err)
	}
	if request.expectedSourceVersion != 0 {
		t.Fatalf("expected source version = %d, want 0", request.expectedSourceVersion)
	}
}

func TestLoadMigrationRequestRejectsInvalidBoundaryInputsWithoutLeakingValues(t *testing.T) {
	now := time.Date(2026, 8, 22, 8, 0, 0, 0, time.UTC)
	validPath := writeRecoveryManifest(t, validRecoveryManifest(now.Add(-time.Hour), 6))
	tests := []struct {
		name   string
		values map[string]string
		secret string
	}{
		{
			name: "invalid database URL",
			values: map[string]string{
				"N_API_P_DATABASE_URL":                      "not-a-postgres-url-with-supersecret",
				"N_API_P_MIGRATION_EXPECTED_SOURCE_VERSION": "6",
				"N_API_P_MIGRATION_RECOVERY_MANIFEST_PATH":  validPath,
			},
			secret: "supersecret",
		},
		{
			name: "source version beyond image target",
			values: map[string]string{
				"N_API_P_DATABASE_URL":                      "postgres://database.internal/n_api_p",
				"N_API_P_MIGRATION_EXPECTED_SOURCE_VERSION": "9",
				"N_API_P_MIGRATION_RECOVERY_MANIFEST_PATH":  validPath,
			},
		},
		{
			name: "relative manifest path",
			values: map[string]string{
				"N_API_P_DATABASE_URL":                      "postgres://database.internal/n_api_p",
				"N_API_P_MIGRATION_EXPECTED_SOURCE_VERSION": "6",
				"N_API_P_MIGRATION_RECOVERY_MANIFEST_PATH":  "private/recovery-manifest.json",
			},
			secret: "private/recovery-manifest.json",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadMigrationRequest(mapLookup(test.values), now)
			if migrationErrorCode(err) != migrationCodeConfigurationRejected {
				t.Fatalf("error = %v, code = %q, want %q", err, migrationErrorCode(err), migrationCodeConfigurationRejected)
			}
			if test.secret != "" && strings.Contains(err.Error(), test.secret) {
				t.Fatalf("error %q leaked sensitive input", err)
			}
		})
	}
}

func TestBoundedMigrationDatabaseURLOverridesConnectionAndLockTimeouts(t *testing.T) {
	got, err := boundedMigrationDatabaseURL("postgresql://operator:secret@database.internal/n_api_p?sslmode=verify-full&lock_timeout=1h&search_path=unsafe")
	if err != nil {
		t.Fatalf("bound migration database URL: %v", err)
	}
	if !strings.Contains(got, "connect_timeout=10") || !strings.Contains(got, "lock_timeout=15s") || !strings.Contains(got, "search_path=public") || !strings.Contains(got, "sslmode=verify-full") {
		t.Fatalf("bounded database URL = %q", got)
	}
}

func TestBoundedMigrationDatabaseURLRejectsStartupOptions(t *testing.T) {
	_, err := boundedMigrationDatabaseURL("postgresql://operator:secret@database.internal/n_api_p?options=-csearch_path%3Dunsafe")
	if migrationErrorCode(err) != migrationCodeConfigurationRejected {
		t.Fatalf("error = %v, code = %q, want %q", err, migrationErrorCode(err), migrationCodeConfigurationRejected)
	}
}

func TestLoadMigrationRequestRejectsUnsafeOrInvalidRecoveryManifest(t *testing.T) {
	now := time.Date(2026, 8, 22, 8, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(map[string]any)
		mode   fs.FileMode
	}{
		{name: "unverified", mutate: func(manifest map[string]any) { manifest["verification_result"] = "pending" }},
		{name: "stale", mutate: func(manifest map[string]any) {
			manifest["created_at"] = now.Add(-24*time.Hour - time.Second).Format(time.RFC3339)
		}},
		{name: "future", mutate: func(manifest map[string]any) { manifest["created_at"] = now.Add(time.Second).Format(time.RFC3339) }},
		{name: "non UTC", mutate: func(manifest map[string]any) { manifest["created_at"] = "2026-08-22T15:00:00+08:00" }},
		{name: "wrong source version", mutate: func(manifest map[string]any) { manifest["migration_version"] = 5 }},
		{name: "raw table not excluded", mutate: func(manifest map[string]any) { manifest["excluded_tables"] = []string{} }},
		{name: "metadata allowlist drift", mutate: func(manifest map[string]any) { manifest["included_tables"] = requiredRecoveryTables[:11] }},
		{name: "unknown field", mutate: func(manifest map[string]any) { manifest["database_url"] = "postgres://leak.invalid/db" }},
		{name: "writable by owner", mode: 0o600},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := validRecoveryManifest(now.Add(-time.Hour), 6)
			if test.mutate != nil {
				test.mutate(manifest)
			}
			mode := test.mode
			if mode == 0 {
				mode = 0o400
			}
			path := writeRecoveryManifestMode(t, manifest, mode)
			values := map[string]string{
				"N_API_P_DATABASE_URL":                      "postgres://database.internal/n_api_p",
				"N_API_P_MIGRATION_EXPECTED_SOURCE_VERSION": "6",
				"N_API_P_MIGRATION_RECOVERY_MANIFEST_PATH":  path,
			}

			_, err := loadMigrationRequest(mapLookup(values), now)
			if migrationErrorCode(err) != migrationCodeRecoveryPointRejected {
				t.Fatalf("error = %v, code = %q, want %q", err, migrationErrorCode(err), migrationCodeRecoveryPointRejected)
			}
			if strings.Contains(err.Error(), path) || strings.Contains(err.Error(), "leak.invalid") {
				t.Fatalf("error %q leaked manifest content or path", err)
			}
		})
	}
}

func TestLoadMigrationRequestRejectsDuplicateRecoveryManifestField(t *testing.T) {
	now := time.Date(2026, 8, 22, 8, 0, 0, 0, time.UTC)
	content, err := json.Marshal(validRecoveryManifest(now.Add(-time.Hour), 6))
	if err != nil {
		t.Fatalf("marshal recovery manifest: %v", err)
	}
	content = append([]byte(`{"backup_id":"duplicate",`), content[1:]...)
	path := filepath.Join(t.TempDir(), "duplicate-recovery-manifest.json")
	if err := os.WriteFile(path, content, 0o400); err != nil {
		t.Fatalf("write duplicate recovery manifest: %v", err)
	}
	values := map[string]string{
		"N_API_P_DATABASE_URL":                      "postgres://database.internal/n_api_p",
		"N_API_P_MIGRATION_EXPECTED_SOURCE_VERSION": "6",
		"N_API_P_MIGRATION_RECOVERY_MANIFEST_PATH":  path,
	}

	_, err = loadMigrationRequest(mapLookup(values), now)
	if migrationErrorCode(err) != migrationCodeRecoveryPointRejected {
		t.Fatalf("error = %v, code = %q, want %q", err, migrationErrorCode(err), migrationCodeRecoveryPointRejected)
	}
}

func TestEmbeddedProductionMigrationsContainOnlyReviewedForwardFiles(t *testing.T) {
	matches, err := fs.Glob(embeddedForwardMigrations, "migrations/*")
	if err != nil {
		t.Fatalf("glob embedded migrations: %v", err)
	}
	if len(matches) != int(productionMigrationTargetVersion) {
		t.Fatalf("embedded migrations = %v, want %d files", matches, productionMigrationTargetVersion)
	}
	for _, match := range matches {
		if !strings.HasSuffix(match, ".up.sql") || strings.HasSuffix(match, ".down.sql") {
			t.Fatalf("embedded production migration %q is not forward-only", match)
		}
	}
}

func TestInvestigationMigrationUsesSingleCharacterLikeEscape(t *testing.T) {
	content, err := fs.ReadFile(embeddedForwardMigrations, "migrations/000008_governed_investigations.up.sql")
	if err != nil {
		t.Fatalf("read investigation migration: %v", err)
	}
	if !strings.Contains(string(content), `LIKE 'investigation\_%' ESCAPE '\'`) {
		t.Fatal("investigation case constraint must use a single-character LIKE escape")
	}
}

func TestInvestigationCandidatesKeepAuditUUIDSnapshotsIndependentOfAuditRows(t *testing.T) {
	content, err := fs.ReadFile(embeddedForwardMigrations, "migrations/000008_governed_investigations.up.sql")
	if err != nil {
		t.Fatalf("read investigation migration: %v", err)
	}
	source := string(content)
	if !strings.Contains(source, "audit_id uuid NOT NULL") {
		t.Fatal("investigation candidate snapshot must retain a non-null audit UUID")
	}
	if strings.Contains(source, "audit_id uuid NOT NULL REFERENCES audit_records") {
		t.Fatal("investigation candidate snapshot must not cascade or restrict audit metadata cleanup")
	}
}

func TestValidateProductionSchemaInventoryUsesVersionedExactAllowlist(t *testing.T) {
	tests := []struct {
		name    string
		version uint
		tables  []string
	}{
		{name: "empty source", version: 0, tables: nil},
		{name: "empty baseline", version: 1, tables: []string{"schema_migrations"}},
		{name: "target", version: 8, tables: append([]string{"schema_migrations", "audit_raw_content"}, unqualifiedTableNames(requiredRecoveryTables)...)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateProductionSchemaInventory(test.version, test.tables); err != nil {
				t.Fatalf("validate schema inventory: %v", err)
			}
			drifted := append(slices.Clone(test.tables), "unexpected_table")
			if err := validateProductionSchemaInventory(test.version, drifted); err == nil {
				t.Fatal("schema drift error = nil, want rejection")
			}
		})
	}
}

func TestRunForwardMigrationMovesExpectedCleanSourceToTarget(t *testing.T) {
	engine := &fakeMigrationEngine{versions: []migrationVersion{
		{version: 6},
		{version: productionMigrationTargetVersion},
	}}

	if err := runForwardMigration(engine, 6); err != nil {
		t.Fatalf("run forward migration: %v", err)
	}
	if engine.upCalls != 1 {
		t.Fatalf("up calls = %d, want 1", engine.upCalls)
	}
}

func TestRunForwardMigrationAtTargetDoesNotInvokeMigration(t *testing.T) {
	engine := &fakeMigrationEngine{versions: []migrationVersion{{version: productionMigrationTargetVersion}}}

	if err := runForwardMigration(engine, productionMigrationTargetVersion); err != nil {
		t.Fatalf("verify target migration: %v", err)
	}
	if engine.upCalls != 0 {
		t.Fatalf("up calls = %d, want 0", engine.upCalls)
	}
}

func TestRunForwardMigrationRejectsDirtyUnexpectedOrUnversionedSources(t *testing.T) {
	tests := []struct {
		name     string
		engine   *fakeMigrationEngine
		expected uint
	}{
		{name: "dirty", engine: &fakeMigrationEngine{versions: []migrationVersion{{version: 6, dirty: true}}}, expected: 6},
		{name: "unexpected", engine: &fakeMigrationEngine{versions: []migrationVersion{{version: 5}}}, expected: 6},
		{name: "unversioned mismatch", engine: &fakeMigrationEngine{versions: []migrationVersion{{err: migrate.ErrNilVersion}}}, expected: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := runForwardMigration(test.engine, test.expected)
			if migrationErrorCode(err) != migrationCodeSourceRejected {
				t.Fatalf("error = %v, code = %q, want %q", err, migrationErrorCode(err), migrationCodeSourceRejected)
			}
			if test.engine.upCalls != 0 {
				t.Fatalf("up calls = %d, want 0", test.engine.upCalls)
			}
		})
	}
}

func TestRunForwardMigrationAcceptsExpectedUnversionedSource(t *testing.T) {
	engine := &fakeMigrationEngine{versions: []migrationVersion{
		{err: migrate.ErrNilVersion},
		{version: productionMigrationTargetVersion},
	}}
	if err := runForwardMigration(engine, 0); err != nil {
		t.Fatalf("migrate unversioned source: %v", err)
	}
	if engine.upCalls != 1 {
		t.Fatalf("up calls = %d, want 1", engine.upCalls)
	}
}

func TestRunForwardMigrationReportsApplyAndVerificationFailures(t *testing.T) {
	tests := []struct {
		name     string
		engine   *fakeMigrationEngine
		wantCode string
	}{
		{
			name:     "apply failure",
			engine:   &fakeMigrationEngine{versions: []migrationVersion{{version: 6}}, upErr: errors.New("driver included secret material")},
			wantCode: migrationCodeApplyFailed,
		},
		{
			name: "final version mismatch",
			engine: &fakeMigrationEngine{versions: []migrationVersion{
				{version: 6},
				{version: 6},
			}},
			wantCode: migrationCodeVerificationFailed,
		},
		{
			name: "final dirty version",
			engine: &fakeMigrationEngine{versions: []migrationVersion{
				{version: 6},
				{version: productionMigrationTargetVersion, dirty: true},
			}},
			wantCode: migrationCodeVerificationFailed,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := runForwardMigration(test.engine, 6)
			if migrationErrorCode(err) != test.wantCode {
				t.Fatalf("error = %v, code = %q, want %q", err, migrationErrorCode(err), test.wantCode)
			}
			if strings.Contains(err.Error(), "secret material") {
				t.Fatalf("error %q leaked driver detail", err)
			}
		})
	}
}

type migrationVersion struct {
	version uint
	dirty   bool
	err     error
}

type fakeMigrationEngine struct {
	versions []migrationVersion
	upCalls  int
	upErr    error
}

func (engine *fakeMigrationEngine) Version() (uint, bool, error) {
	if len(engine.versions) == 0 {
		return 0, false, errors.New("unexpected version read")
	}
	version := engine.versions[0]
	engine.versions = engine.versions[1:]
	return version.version, version.dirty, version.err
}

func (engine *fakeMigrationEngine) Up() error {
	engine.upCalls++
	return engine.upErr
}

func mapLookup(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}

func validRecoveryManifest(createdAt time.Time, migrationVersion uint) map[string]any {
	return map[string]any{
		"backup_id":              "backup-20260822-070000",
		"created_at":             createdAt.Format(time.RFC3339),
		"migration_version":      migrationVersion,
		"included_tables":        slices.Clone(requiredRecoveryTables),
		"excluded_tables":        []string{"public.audit_raw_content"},
		"encryption_key_version": "backup-key-v1",
		"byte_size":              4096,
		"checksum":               "sha256:" + strings.Repeat("a", 64),
		"verification_result":    "verified",
	}
}

func writeRecoveryManifest(t *testing.T, manifest map[string]any) string {
	t.Helper()
	return writeRecoveryManifestMode(t, manifest, 0o400)
}

func writeRecoveryManifestMode(t *testing.T, manifest map[string]any, mode fs.FileMode) string {
	t.Helper()
	content, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal recovery manifest: %v", err)
	}
	path := filepath.Join(t.TempDir(), "recovery-manifest.json")
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatalf("write recovery manifest: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("set recovery manifest mode: %v", err)
	}
	return path
}
