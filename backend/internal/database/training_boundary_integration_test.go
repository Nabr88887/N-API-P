//go:build integration

package database

import (
	"database/sql"
	"testing"
)

func TestFirstReleaseHasNoTrainingTablesOrRoles(t *testing.T) {
	db, schemaName := migrateAuditPolicySchema(t)
	assertNoTablesWithPrefix(t, db, schemaName, "training")

	expectRejected(t, db, `INSERT INTO identities (id, email, role, status) VALUES ($1, $2, $3, $4)`,
		"82000000-0000-0000-0000-000000000059", "training-reviewer@example.internal", "training_reviewer", "active")
}

func assertNoTablesWithPrefix(t *testing.T, db *sql.DB, schemaName, prefix string) {
	t.Helper()

	rows, err := db.Query(`
		SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = $1 AND table_name LIKE $2
		ORDER BY table_name`, schemaName, prefix+"%")
	if err != nil {
		t.Fatalf("query forbidden table prefix %q: %v", prefix, err)
	}
	defer rows.Close()

	var found string
	if rows.Next() {
		if err := rows.Scan(&found); err != nil {
			t.Fatalf("scan forbidden table prefix %q: %v", prefix, err)
		}
		t.Fatalf("forbidden table with prefix %q exists: %s", prefix, found)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate forbidden table prefix %q: %v", prefix, err)
	}
}
