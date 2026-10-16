package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"n-api-p/internal/access"
)

var (
	ErrInvalidBootstrapInput = errors.New("invalid administrator bootstrap input")
	ErrBootstrapNotEmpty     = errors.New("administrator bootstrap requires an empty identity database")
	ErrBootstrapSchema       = errors.New("administrator bootstrap requires the current clean schema")
)

// BootstrapAdministrator is an operator-only entry point, never an HTTP handler
// or a password reset. It atomically seeds the first identity and its audit event.
func (r *Repository) BootstrapAdministrator(ctx context.Context, email, password string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	address, err := mail.ParseAddress(email)
	if err != nil || address.Address != email || len(email) > 254 {
		return ErrInvalidBootstrapInput
	}
	passwordHash, err := access.NewArgon2idPasswordHasher().Initialize(password)
	if err != nil {
		return fmt.Errorf("initialize administrator password: %w", err)
	}
	return r.withTransaction(ctx, "bootstrap administrator", func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `LOCK TABLE schema_migrations IN SHARE MODE`); err != nil {
			return fmt.Errorf("lock bootstrap schema version: %w", err)
		}
		var version int
		var dirty bool
		if err := tx.QueryRowContext(ctx, `SELECT version, dirty FROM schema_migrations`).Scan(&version, &dirty); err != nil {
			return fmt.Errorf("read bootstrap schema version: %w", err)
		}
		if version != int(productionMigrationTargetVersion) || dirty {
			return ErrBootstrapSchema
		}
		// A table lock also excludes ordinary identity inserts; an advisory lock
		// alone would only serialize callers of this command.
		if _, err := tx.ExecContext(ctx, `LOCK TABLE identities IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			return fmt.Errorf("lock bootstrap identities: %w", err)
		}
		var populated bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM identities)`).Scan(&populated); err != nil {
			return fmt.Errorf("check bootstrap identity state: %w", err)
		}
		if populated {
			return ErrBootstrapNotEmpty
		}
		now := time.Now().UTC()
		var identityID, eventID string
		if err := tx.QueryRowContext(ctx, `SELECT gen_random_uuid(), gen_random_uuid()`).Scan(&identityID, &eventID); err != nil {
			return fmt.Errorf("generate bootstrap identifiers: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO identities (id, email, password_hash, role, status, created_at, updated_at)
VALUES ($1, $2, $3, 'system_administrator', 'active', $4, $4)`, identityID, email, passwordHash, now); err != nil {
			return fmt.Errorf("insert bootstrap administrator: %w", err)
		}
		return appendSecurityEventTx(ctx, tx, access.SecurityEvent{
			ID: eventID, EventType: "administrator_bootstrapped",
			TargetIdentityID: identityID, RequestID: eventID,
			Outcome: access.SecurityEventSuccess, DetailCode: "operator_empty_identity_database", OccurredAt: now,
		})
	})
}
