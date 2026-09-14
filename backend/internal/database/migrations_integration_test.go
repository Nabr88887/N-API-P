//go:build integration

package database

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"io/fs"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratepgx "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations/000001_empty_baseline.up.sql migrations/000001_empty_baseline.down.sql
var baselineMigrationFiles embed.FS

//go:embed migrations/*.sql
var allMigrationFiles embed.FS

func TestEmptyMigrationBaselineIsReversible(t *testing.T) {
	databaseURL := os.Getenv("N_API_P_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("N_API_P_TEST_DATABASE_URL is required for integration tests")
	}

	const schemaName = "migration_baseline_test"
	adminDB := openTestDatabase(t, databaseURL)
	resetTestSchema(t, adminDB, schemaName)

	schemaURL := databaseURLWithSearchPath(t, databaseURL, schemaName)
	schemaDB := openTestDatabase(t, schemaURL)
	migrator := openTestMigrator(t, schemaDB, schemaName, baselineMigrationFiles)

	if err := migrator.Up(); err != nil {
		t.Fatalf("apply empty baseline migration: %v", err)
	}
	assertMigrationVersion(t, migrator, 1)
	assertNoProductTables(t, schemaDB, schemaName)

	if err := migrator.Down(); err != nil {
		t.Fatalf("roll back empty baseline migration: %v", err)
	}
	assertNoMigrationVersion(t, migrator)
	assertNoProductTables(t, schemaDB, schemaName)

	if err := migrator.Up(); err != nil {
		t.Fatalf("reapply empty baseline migration: %v", err)
	}
	assertMigrationVersion(t, migrator, 1)
	assertNoProductTables(t, schemaDB, schemaName)
}

func TestElevatedAuditMigrationRollsBackAndReapplies(t *testing.T) {
	databaseURL := os.Getenv("N_API_P_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Fatal("N_API_P_TEST_DATABASE_URL is required for integration tests")
	}

	const schemaName = "elevated_audit_migration_test"
	adminDB := openTestDatabase(t, databaseURL)
	resetTestSchema(t, adminDB, schemaName)
	schemaDB := openTestDatabase(t, databaseURLWithSearchPath(t, databaseURL, schemaName))
	migrator := openTestMigrator(t, schemaDB, schemaName, allMigrationFiles)

	if err := migrator.Up(); err != nil {
		t.Fatalf("apply elevated audit migrations: %v", err)
	}
	assertMigrationVersion(t, migrator, 9)
	assertElevatedAuditMigrationObjects(t, schemaDB, schemaName, true)

	if err := migrator.Steps(-1); err != nil {
		t.Fatalf("roll back elevated audit migration: %v", err)
	}
	assertMigrationVersion(t, migrator, 8)
	assertElevatedAuditMigrationObjects(t, schemaDB, schemaName, false)

	if err := migrator.Up(); err != nil {
		t.Fatalf("reapply elevated audit migration: %v", err)
	}
	assertMigrationVersion(t, migrator, 9)
	assertElevatedAuditMigrationObjects(t, schemaDB, schemaName, true)
}

func assertElevatedAuditMigrationObjects(t *testing.T, db *sql.DB, schemaName string, wantPresent bool) {
	t.Helper()
	var tablePresent bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = $1 AND table_name = 'elevated_audit_grants')`, schemaName).Scan(&tablePresent); err != nil {
		t.Fatalf("query elevated audit grant table: %v", err)
	}
	if tablePresent != wantPresent {
		t.Fatalf("elevated_audit_grants present = %t, want %t", tablePresent, wantPresent)
	}
	for _, column := range []string{"session_id", "grant_id", "query_metadata", "result_count"} {
		var columnPresent bool
		if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = $1 AND table_name = 'security_events' AND column_name = $2)`, schemaName, column).Scan(&columnPresent); err != nil {
			t.Fatalf("query security event column %s: %v", column, err)
		}
		if columnPresent != wantPresent {
			t.Fatalf("security_events.%s present = %t, want %t", column, columnPresent, wantPresent)
		}
	}
}

func openTestDatabase(t *testing.T, databaseURL string) *sql.DB {
	t.Helper()

	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close test database: %v", err)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping test database: %v", err)
	}

	return db
}

func resetTestSchema(t *testing.T, db *sql.DB, schemaName string) {
	t.Helper()

	identifier := pgx.Identifier{schemaName}.Sanitize()
	if _, err := db.Exec("DROP SCHEMA IF EXISTS " + identifier + " CASCADE"); err != nil {
		t.Fatalf("drop stale test schema: %v", err)
	}
	if _, err := db.Exec("CREATE SCHEMA " + identifier); err != nil {
		t.Fatalf("create test schema: %v", err)
	}
	t.Cleanup(func() {
		if _, err := db.Exec("DROP SCHEMA IF EXISTS " + identifier + " CASCADE"); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
	})
}

func databaseURLWithSearchPath(t *testing.T, databaseURL, schemaName string) string {
	t.Helper()

	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse test database URL: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schemaName)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func openTestMigrator(t *testing.T, db *sql.DB, schemaName string, files fs.FS) *migrate.Migrate {
	t.Helper()

	sourceDriver, err := iofs.New(files, "migrations")
	if err != nil {
		t.Fatalf("open embedded migrations: %v", err)
	}
	databaseDriver, err := migratepgx.WithInstance(db, &migratepgx.Config{
		SchemaName: schemaName,
	})
	if err != nil {
		t.Fatalf("open migration database driver: %v", err)
	}
	migrator, err := migrate.NewWithInstance("iofs", sourceDriver, "pgx5", databaseDriver)
	if err != nil {
		t.Fatalf("open migrator: %v", err)
	}
	t.Cleanup(func() {
		sourceErr, databaseErr := migrator.Close()
		if sourceErr != nil || databaseErr != nil {
			t.Errorf("close migrator: %v", errors.Join(sourceErr, databaseErr))
		}
	})

	return migrator
}

func assertMigrationVersion(t *testing.T, migrator *migrate.Migrate, want uint) {
	t.Helper()

	got, dirty, err := migrator.Version()
	if err != nil {
		t.Fatalf("read migration version: %v", err)
	}
	if got != want || dirty {
		t.Fatalf("migration version = (%d, dirty=%t), want (%d, dirty=false)", got, dirty, want)
	}
}

func assertNoMigrationVersion(t *testing.T, migrator *migrate.Migrate) {
	t.Helper()

	version, dirty, err := migrator.Version()
	if !errors.Is(err, migrate.ErrNilVersion) {
		t.Fatalf("migration version after rollback = (%d, dirty=%t, err=%v), want nil version", version, dirty, err)
	}
}

func assertNoProductTables(t *testing.T, db *sql.DB, schemaName string) {
	t.Helper()

	rows, err := db.Query(`
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = $1
		  AND table_name <> 'schema_migrations'
		ORDER BY table_name`, schemaName)
	if err != nil {
		t.Fatalf("query product tables: %v", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			t.Errorf("close product table rows: %v", err)
		}
	}()

	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			t.Fatalf("scan product table: %v", err)
		}
		tables = append(tables, table)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate product tables: %v", err)
	}
	if len(tables) != 0 {
		t.Fatalf("product tables after empty baseline = %v, want none", tables)
	}
}
