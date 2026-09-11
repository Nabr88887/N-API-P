package database

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestElevatedAuditMigrationHasMetadataOnlyRollback(t *testing.T) {
	contentsBytes, err := os.ReadFile(filepath.Join("migrations", "000009_elevated_audit_access.down.sql"))
	if err != nil {
		t.Fatalf("read rollback migration: %v", err)
	}
	contents := string(contentsBytes)
	for _, fragment := range []string{
		"DROP COLUMN IF EXISTS grant_id",
		"DROP COLUMN IF EXISTS session_id",
		"DROP TABLE IF EXISTS elevated_audit_grants",
	} {
		if !strings.Contains(contents, fragment) {
			t.Fatalf("rollback migration missing %q: %s", fragment, contents)
		}
	}
	for _, forbidden := range []string{"audit_raw_content", "INSERT", "UPDATE", "plaintext", "ciphertext"} {
		if strings.Contains(strings.ToLower(contents), strings.ToLower(forbidden)) {
			t.Fatalf("rollback migration contains forbidden raw-content operation %q: %s", forbidden, contents)
		}
	}
}
