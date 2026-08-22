//go:build linux

package database

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadMigrationRequestRejectsSymlinkRecoveryManifest(t *testing.T) {
	now := time.Date(2026, 8, 22, 8, 0, 0, 0, time.UTC)
	target := writeRecoveryManifest(t, validRecoveryManifest(now.Add(-time.Hour), 6))
	link := filepath.Join(t.TempDir(), "recovery-manifest-link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("create recovery manifest symlink: %v", err)
	}
	assertRecoveryManifestPathRejected(t, link, now)
}

func TestLoadMigrationRequestRejectsNonRootRecoveryManifest(t *testing.T) {
	now := time.Date(2026, 8, 22, 8, 0, 0, 0, time.UTC)
	path := writeRecoveryManifest(t, validRecoveryManifest(now.Add(-time.Hour), 6))
	if err := os.Chown(path, 1, 1); err != nil {
		t.Fatalf("change recovery manifest ownership: %v", err)
	}
	assertRecoveryManifestPathRejected(t, path, now)
}

func assertRecoveryManifestPathRejected(t *testing.T, path string, now time.Time) {
	t.Helper()
	values := map[string]string{
		"N_API_P_DATABASE_URL":                      "postgres://database.internal/n_api_p",
		"N_API_P_MIGRATION_EXPECTED_SOURCE_VERSION": "6",
		"N_API_P_MIGRATION_RECOVERY_MANIFEST_PATH":  path,
	}
	_, err := loadMigrationRequest(mapLookup(values), now)
	if migrationErrorCode(err) != migrationCodeRecoveryPointRejected {
		t.Fatalf("error = %v, code = %q, want %q", err, migrationErrorCode(err), migrationCodeRecoveryPointRejected)
	}
}
