//go:build integration

package database

import (
	"context"
	"errors"
	"testing"

	"n-api-p/internal/access"
)

func TestBootstrapCreatesOneAdministratorAndRejectsRepeat(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	repository := NewRepository(db)
	const password = "synthetic-password-123"
	if err := repository.BootstrapAdministrator(context.Background(), " Admin@Example.Invalid ", password); err != nil {
		t.Fatal(err)
	}
	var role, status, hash string
	if err := db.QueryRow(`SELECT role, status, password_hash FROM identities WHERE email = 'admin@example.invalid'`).Scan(&role, &status, &hash); err != nil {
		t.Fatal(err)
	}
	if role != "system_administrator" || status != "active" {
		t.Fatal("bootstrap did not create an active administrator")
	}
	if valid, err := access.NewArgon2idPasswordHasher().Verify(password, hash); err != nil || !valid {
		t.Fatal("bootstrap password cannot authenticate")
	}
	if err := repository.BootstrapAdministrator(context.Background(), "admin@example.invalid", "different-password-123"); !errors.Is(err, ErrBootstrapNotEmpty) {
		t.Fatalf("repeat error = %v", err)
	}
	var after string
	if err := db.QueryRow(`SELECT password_hash FROM identities WHERE email = 'admin@example.invalid'`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if hash != after {
		t.Fatal("repeat bootstrap changed the password")
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM security_events WHERE event_type = 'administrator_bootstrapped' AND outcome = 'success' AND actor_identity_id IS NULL AND target_identity_id IS NOT NULL AND reason IS NULL AND detail_code = 'operator_empty_identity_database'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("bootstrap audit count = %d, error = %v", count, err)
	}
}

func TestBootstrapRejectsAnyExistingIdentity(t *testing.T) {
	for _, status := range []string{"pending", "active", "disabled"} {
		t.Run(status, func(t *testing.T) {
			db, _ := migrateWorkforceSchema(t)
			mustExec(t, db, `INSERT INTO identities (id, email, role, status, disabled_at) VALUES ('21000000-0000-0000-0000-000000000001', 'existing@example.invalid', 'employee', $1, CASE WHEN $1 = 'disabled' THEN CURRENT_TIMESTAMP END)`, status)
			err := NewRepository(db).BootstrapAdministrator(context.Background(), "admin@example.invalid", "synthetic-password-123")
			if !errors.Is(err, ErrBootstrapNotEmpty) {
				t.Fatalf("nonempty bootstrap error = %v", err)
			}
			assertCountWhere(t, db, "identities", "email", "admin@example.invalid", 0)
		})
	}
}

func TestBootstrapSerializesConcurrentInitializations(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	errs := runConcurrent(2, func(index int) error {
		emails := []string{"first@example.invalid", "second@example.invalid"}
		return NewRepository(db).BootstrapAdministrator(context.Background(), emails[index], "synthetic-password-123")
	})
	assertOneSuccessOneError(t, errs, ErrBootstrapNotEmpty)
}

func TestBootstrapRollsBackIdentityWhenAuditFails(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	mustExec(t, db, `CREATE FUNCTION reject_bootstrap_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic audit failure'; END $$`)
	mustExec(t, db, `CREATE TRIGGER reject_bootstrap_event BEFORE INSERT ON security_events FOR EACH ROW EXECUTE FUNCTION reject_bootstrap_event()`)
	if err := NewRepository(db).BootstrapAdministrator(context.Background(), "admin@example.invalid", "synthetic-password-123"); err == nil {
		t.Fatal("bootstrap accepted failed audit persistence")
	}
	assertCountWhere(t, db, "identities", "email", "admin@example.invalid", 0)
}

func TestBootstrapRejectsDirtyOrIncompatibleSchema(t *testing.T) {
	for _, state := range []struct {
		version int
		dirty   bool
	}{{9, true}, {8, false}, {10, false}} {
		db, _ := migrateWorkforceSchema(t)
		mustExec(t, db, `UPDATE schema_migrations SET version = $1, dirty = $2`, state.version, state.dirty)
		if err := NewRepository(db).BootstrapAdministrator(context.Background(), "admin@example.invalid", "synthetic-password-123"); !errors.Is(err, ErrBootstrapSchema) {
			t.Fatalf("incompatible schema error = %v", err)
		}
		assertCountWhere(t, db, "identities", "email", "admin@example.invalid", 0)
	}
}
