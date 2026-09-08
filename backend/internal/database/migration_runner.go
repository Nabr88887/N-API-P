package database

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratepgx "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	productionMigrationTargetVersion uint = 8
	maximumRecoveryManifestBytes          = 16 * 1024
	maximumRecoveryPointAge               = 24 * time.Hour
	migrationStatementTimeout             = 5 * time.Minute
	migrationDatabaseProbeTimeout         = 10 * time.Second

	migrationCodeConfigurationRejected = "migration_configuration_rejected"
	migrationCodeRecoveryPointRejected = "migration_recovery_point_rejected"
	migrationCodeSourceRejected        = "migration_source_rejected"
	migrationCodeConnectionFailed      = "migration_connection_failed"
	migrationCodeApplyFailed           = "migration_apply_failed"
	migrationCodeVerificationFailed    = "migration_verification_failed"
	migrationCodeInternalFailure       = "migration_internal_failure"
)

var (
	//go:embed migrations/*.up.sql
	embeddedForwardMigrations embed.FS

	workforceRecoveryTables = []string{
		"public.identities",
		"public.teams",
		"public.memberships",
		"public.service_accounts",
		"public.sessions",
		"public.one_time_codes",
		"public.api_keys",
	}
	metadataRecoveryTables = []string{
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
	}
	investigationRecoveryTables = []string{
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
)

type MigrationRequest struct {
	databaseURL           string
	expectedSourceVersion uint
}

type recoveryManifest struct {
	BackupID             string   `json:"backup_id"`
	CreatedAt            string   `json:"created_at"`
	MigrationVersion     uint     `json:"migration_version"`
	IncludedTables       []string `json:"included_tables"`
	ExcludedTables       []string `json:"excluded_tables"`
	EncryptionKeyVersion string   `json:"encryption_key_version"`
	ByteSize             int64    `json:"byte_size"`
	Checksum             string   `json:"checksum"`
	VerificationResult   string   `json:"verification_result"`
}

type migrationFailure struct {
	code string
}

func (failure migrationFailure) Error() string {
	return failure.code
}

func MigrationFailureCode(err error) string {
	return migrationErrorCode(err)
}

func migrationErrorCode(err error) string {
	var failure migrationFailure
	if errors.As(err, &failure) {
		return failure.code
	}
	return migrationCodeInternalFailure
}

func LoadProductionMigrationRequest(lookup func(string) (string, bool), now time.Time) (MigrationRequest, error) {
	return loadMigrationRequest(lookup, now)
}

func loadMigrationRequest(lookup func(string) (string, bool), now time.Time) (MigrationRequest, error) {
	if lookup == nil || now.IsZero() {
		return MigrationRequest{}, migrationFailure{code: migrationCodeConfigurationRejected}
	}
	databaseURL, ok := requiredMigrationValue(lookup, "N_API_P_DATABASE_URL")
	if !ok || !validMigrationDatabaseURL(databaseURL) {
		return MigrationRequest{}, migrationFailure{code: migrationCodeConfigurationRejected}
	}
	versionValue, ok := requiredMigrationValue(lookup, "N_API_P_MIGRATION_EXPECTED_SOURCE_VERSION")
	if !ok {
		return MigrationRequest{}, migrationFailure{code: migrationCodeConfigurationRejected}
	}
	version, err := strconv.ParseUint(versionValue, 10, 32)
	if err != nil || version > uint64(productionMigrationTargetVersion) {
		return MigrationRequest{}, migrationFailure{code: migrationCodeConfigurationRejected}
	}
	manifestPath, ok := requiredMigrationValue(lookup, "N_API_P_MIGRATION_RECOVERY_MANIFEST_PATH")
	if !ok || !filepath.IsAbs(manifestPath) {
		return MigrationRequest{}, migrationFailure{code: migrationCodeConfigurationRejected}
	}
	if err := validateRecoveryManifest(manifestPath, uint(version), now.UTC()); err != nil {
		return MigrationRequest{}, migrationFailure{code: migrationCodeRecoveryPointRejected}
	}
	return MigrationRequest{databaseURL: databaseURL, expectedSourceVersion: uint(version)}, nil
}

func requiredMigrationValue(lookup func(string) (string, bool), key string) (string, bool) {
	value, ok := lookup(key)
	if !ok || value == "" || value != strings.TrimSpace(value) {
		return "", false
	}
	return value, true
}

func validMigrationDatabaseURL(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && (parsed.Scheme == "postgres" || parsed.Scheme == "postgresql") &&
		parsed.Host != "" && parsed.Path != "" && parsed.Path != "/" && parsed.Fragment == "" && parsed.Opaque == ""
}

func boundedMigrationDatabaseURL(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || !validMigrationDatabaseURL(value) {
		return "", migrationFailure{code: migrationCodeConfigurationRejected}
	}
	query := parsed.Query()
	if query.Has("options") {
		return "", migrationFailure{code: migrationCodeConfigurationRejected}
	}
	query.Set("connect_timeout", "10")
	query.Set("lock_timeout", "15s")
	query.Set("search_path", "public")
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func validateRecoveryManifest(path string, expectedSourceVersion uint, now time.Time) error {
	content, err := readRootOwnedRecoveryManifest(path, maximumRecoveryManifestBytes)
	if err != nil || rejectDuplicateMigrationJSONFields(content) != nil {
		return migrationFailure{code: migrationCodeRecoveryPointRejected}
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var manifest recoveryManifest
	if err := decoder.Decode(&manifest); err != nil {
		return migrationFailure{code: migrationCodeRecoveryPointRejected}
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return migrationFailure{code: migrationCodeRecoveryPointRejected}
	}
	createdAt, err := time.Parse(time.RFC3339, manifest.CreatedAt)
	if err != nil || !strings.HasSuffix(manifest.CreatedAt, "Z") || createdAt.Format(time.RFC3339) != manifest.CreatedAt {
		return migrationFailure{code: migrationCodeRecoveryPointRejected}
	}
	age := now.Sub(createdAt)
	if age < 0 || age > maximumRecoveryPointAge || manifest.MigrationVersion != expectedSourceVersion ||
		manifest.VerificationResult != "verified" || manifest.ByteSize <= 0 ||
		!validMigrationToken(manifest.BackupID, 128) || !validMigrationToken(manifest.EncryptionKeyVersion, 128) ||
		!validSHA256Checksum(manifest.Checksum) ||
		!equalStringSet(manifest.IncludedTables, recoveryTablesForVersion(expectedSourceVersion)) ||
		!equalStringSet(manifest.ExcludedTables, []string{"public.audit_raw_content"}) {
		return migrationFailure{code: migrationCodeRecoveryPointRejected}
	}
	return nil
}

func recoveryTablesForVersion(version uint) []string {
	switch {
	case version <= 1:
		return nil
	case version == 2:
		return workforceRecoveryTables
	case version <= 7:
		return metadataRecoveryTables
	default:
		return investigationRecoveryTables
	}
}

func validMigrationToken(value string, maximum int) bool {
	if value == "" || len(value) > maximum || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '.' || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}

func validSHA256Checksum(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func equalStringSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	gotCopy := slices.Clone(got)
	wantCopy := slices.Clone(want)
	slices.Sort(gotCopy)
	slices.Sort(wantCopy)
	return slices.Equal(gotCopy, wantCopy) && !hasDuplicateStrings(gotCopy)
}

func hasDuplicateStrings(values []string) bool {
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return true
		}
	}
	return false
}

func rejectDuplicateMigrationJSONFields(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("invalid JSON object")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		fieldToken, err := decoder.Token()
		if err != nil {
			return err
		}
		field, ok := fieldToken.(string)
		if !ok {
			return errors.New("invalid JSON field")
		}
		if _, exists := seen[field]; exists {
			return errors.New("duplicate JSON field")
		}
		seen[field] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return errors.New("invalid JSON object")
	}
	return nil
}

type migrationEngine interface {
	Version() (uint, bool, error)
	Up() error
}

func runForwardMigration(engine migrationEngine, expectedSourceVersion uint) error {
	if engine == nil {
		return migrationFailure{code: migrationCodeInternalFailure}
	}
	version, dirty, err := engine.Version()
	unversioned := errors.Is(err, migrate.ErrNilVersion)
	if err != nil && !unversioned {
		return migrationFailure{code: migrationCodeSourceRejected}
	}
	if dirty || (unversioned && expectedSourceVersion != 0) || (!unversioned && (version == 0 || version != expectedSourceVersion)) {
		return migrationFailure{code: migrationCodeSourceRejected}
	}
	if expectedSourceVersion == productionMigrationTargetVersion {
		return nil
	}
	if err := engine.Up(); err != nil {
		return migrationFailure{code: migrationCodeApplyFailed}
	}
	version, dirty, err = engine.Version()
	if err != nil || dirty || version != productionMigrationTargetVersion {
		return migrationFailure{code: migrationCodeVerificationFailed}
	}
	return nil
}

func ApplyProductionMigrations(ctx context.Context, request MigrationRequest) (resultErr error) {
	if ctx == nil || !validMigrationDatabaseURL(request.databaseURL) || request.expectedSourceVersion > productionMigrationTargetVersion {
		return migrationFailure{code: migrationCodeConfigurationRejected}
	}
	databaseURL, err := boundedMigrationDatabaseURL(request.databaseURL)
	if err != nil {
		return err
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return migrationFailure{code: migrationCodeConnectionFailed}
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(2)
	migratorOwnsDatabase := false
	defer func() {
		if migratorOwnsDatabase {
			return
		}
		if closeErr := db.Close(); closeErr != nil && resultErr == nil {
			resultErr = migrationFailure{code: migrationCodeVerificationFailed}
		}
	}()

	probeCtx, cancel := context.WithTimeout(ctx, migrationDatabaseProbeTimeout)
	err = db.PingContext(probeCtx)
	cancel()
	if err != nil {
		return migrationFailure{code: migrationCodeConnectionFailed}
	}
	sourceVersion, sourceDirty, err := readProductionMigrationVersion(ctx, db)
	if err != nil || sourceDirty || sourceVersion != request.expectedSourceVersion {
		return migrationFailure{code: migrationCodeSourceRejected}
	}
	tables, err := listProductionTables(ctx, db)
	if err != nil || validateProductionSchemaInventory(sourceVersion, tables) != nil {
		return migrationFailure{code: migrationCodeSourceRejected}
	}
	sourceDriver, err := iofs.New(embeddedForwardMigrations, "migrations")
	if err != nil {
		return migrationFailure{code: migrationCodeInternalFailure}
	}
	databaseDriver, err := migratepgx.WithInstance(db, &migratepgx.Config{
		SchemaName:       "public",
		StatementTimeout: migrationStatementTimeout,
	})
	if err != nil {
		_ = sourceDriver.Close()
		return migrationFailure{code: migrationCodeConnectionFailed}
	}
	migrator, err := migrate.NewWithInstance("iofs", sourceDriver, "pgx5", databaseDriver)
	if err != nil {
		_ = sourceDriver.Close()
		_ = databaseDriver.Close()
		return migrationFailure{code: migrationCodeInternalFailure}
	}
	migratorOwnsDatabase = true
	defer func() {
		sourceErr, databaseErr := migrator.Close()
		if resultErr == nil && (sourceErr != nil || databaseErr != nil) {
			resultErr = migrationFailure{code: migrationCodeVerificationFailed}
		}
	}()

	stopBridgeDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			migrator.GracefulStop <- true
		case <-stopBridgeDone:
		}
	}()
	defer close(stopBridgeDone)
	if err := runForwardMigration(migrator, request.expectedSourceVersion); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return migrationFailure{code: migrationCodeApplyFailed}
	}
	tables, err = listProductionTables(ctx, db)
	if err != nil || validateProductionSchemaInventory(productionMigrationTargetVersion, tables) != nil {
		return migrationFailure{code: migrationCodeVerificationFailed}
	}
	return nil
}

func readProductionMigrationVersion(ctx context.Context, db *sql.DB) (uint, bool, error) {
	queryCtx, cancel := context.WithTimeout(ctx, migrationDatabaseProbeTimeout)
	defer cancel()
	var version uint
	var dirty bool
	err := db.QueryRowContext(queryCtx, "SELECT version, dirty FROM public.schema_migrations LIMIT 1").Scan(&version, &dirty)
	if errors.Is(err, sql.ErrNoRows) || isUndefinedTableError(err) {
		return 0, false, nil
	}
	if err != nil || version == 0 || version > productionMigrationTargetVersion {
		return 0, false, migrationFailure{code: migrationCodeSourceRejected}
	}
	return version, dirty, nil
}

func isUndefinedTableError(err error) bool {
	type sqlStateError interface {
		SQLState() string
	}
	var stateError sqlStateError
	return errors.As(err, &stateError) && stateError.SQLState() == "42P01"
}

func listProductionTables(ctx context.Context, db *sql.DB) ([]string, error) {
	queryCtx, cancel := context.WithTimeout(ctx, migrationDatabaseProbeTimeout)
	defer cancel()
	rows, err := db.QueryContext(queryCtx, `
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
		ORDER BY table_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			return nil, err
		}
		tables = append(tables, table)
	}
	return tables, rows.Err()
}

func validateProductionSchemaInventory(version uint, tables []string) error {
	if version > productionMigrationTargetVersion {
		return migrationFailure{code: migrationCodeVerificationFailed}
	}
	var want []string
	switch {
	case version == 0:
		want = nil
	case version == 1:
		want = []string{"schema_migrations"}
	case version == 2:
		want = append([]string{"schema_migrations"}, unqualifiedTableNames(workforceRecoveryTables)...)
	case version <= 7:
		want = append([]string{"schema_migrations", "audit_raw_content"}, unqualifiedTableNames(metadataRecoveryTables)...)
	default:
		want = append([]string{"schema_migrations", "audit_raw_content"}, unqualifiedTableNames(investigationRecoveryTables)...)
	}
	if !equalStringSet(tables, want) {
		return migrationFailure{code: migrationCodeVerificationFailed}
	}
	return nil
}

func unqualifiedTableNames(tables []string) []string {
	result := make([]string, 0, len(tables))
	for _, table := range tables {
		result = append(result, strings.TrimPrefix(table, "public."))
	}
	return result
}
