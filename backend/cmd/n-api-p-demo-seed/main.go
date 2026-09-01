// Command n-api-p-demo-seed initializes synthetic local-demo data only.
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"n-api-p/internal/access"
)

const (
	demoEmail = "demo-admin@example.invalid"
	demoModel = "demo-model"
	demoTeam  = "Local Demo Team"
)

func main() {
	if err := run(context.Background(), os.LookupEnv, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "demo seed failed")
		os.Exit(1)
	}
}

func run(ctx context.Context, lookup func(string) (string, bool), output io.Writer) error {
	databaseURL, ok := lookup("N_API_P_DATABASE_URL")
	if !ok || strings.TrimSpace(databaseURL) == "" {
		return errors.New("database URL is required")
	}
	if !validateDemoDatabaseURL(databaseURL) {
		return errors.New("database URL is not an approved local demo database")
	}
	credentialsPath, ok := lookup("N_API_P_DEMO_CREDENTIALS_FILE")
	if !ok || !filepath.IsAbs(credentialsPath) {
		return errors.New("credentials file path is required")
	}
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer db.Close()
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(probeCtx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	hasher := access.NewArgon2idPasswordHasher()
	password, err := newDemoPassword()
	if err != nil {
		return fmt.Errorf("generate demo password: %w", err)
	}
	hash, err := hasher.Initialize(password)
	if err != nil {
		return fmt.Errorf("hash demo password: %w", err)
	}
	identityID, err := newUUID()
	if err != nil {
		return fmt.Errorf("generate demo identity id: %w", err)
	}
	teamID, err := newUUID()
	if err != nil {
		return fmt.Errorf("generate demo team id: %w", err)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin seed transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
INSERT INTO identities (id, email, password_hash, role, status)
VALUES ($1, $2, $3, 'system_administrator', 'active')
ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash, role = EXCLUDED.role, status = EXCLUDED.status, disabled_at = NULL, updated_at = CURRENT_TIMESTAMP`, identityID, demoEmail, hash); err != nil {
		return fmt.Errorf("seed demo administrator: %w", err)
	}
	if err := tx.QueryRowContext(ctx, `
INSERT INTO teams (id, name, status)
VALUES ($1, $2, 'active')
ON CONFLICT (name) DO UPDATE SET status = 'active', disabled_at = NULL, updated_at = CURRENT_TIMESTAMP
RETURNING id::text`, teamID, demoTeam).Scan(&teamID); err != nil {
		return fmt.Errorf("seed demo team: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO memberships (identity_id, team_id)
VALUES ((SELECT id FROM identities WHERE email = $1), $2)
ON CONFLICT (identity_id, team_id) DO NOTHING`, demoEmail, teamID); err != nil {
		return fmt.Errorf("seed demo membership: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO model_allowlist (model_id, status, updated_by_identity_id)
VALUES ($1, 'allowed', (SELECT id FROM identities WHERE email = $2))
ON CONFLICT (model_id) DO UPDATE SET status = 'allowed', updated_by_identity_id = EXCLUDED.updated_by_identity_id, updated_at = CURRENT_TIMESTAMP`, demoModel, demoEmail); err != nil {
		return fmt.Errorf("seed demo model: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit demo seed: %w", err)
	}
	if err := writeCredentials(credentialsPath, password); err != nil {
		return err
	}
	_, _ = io.WriteString(output, "demo credentials written to the configured local runtime file\n")
	return nil
}

func validateDemoDatabaseURL(raw string) bool {
	if strings.TrimSpace(raw) != raw || raw == "" {
		return false
	}
	databaseURL, err := url.Parse(raw)
	if err != nil || databaseURL.Scheme != "postgres" || databaseURL.Opaque != "" ||
		databaseURL.Hostname() != "db" || databaseURL.Port() != "5432" ||
		databaseURL.EscapedPath() != "/n_api_p_demo" || databaseURL.RawPath != "" ||
		databaseURL.Fragment != "" {
		return false
	}
	if databaseURL.User == nil || databaseURL.User.Username() != "n_api_p_demo" {
		return false
	}
	password, hasPassword := databaseURL.User.Password()
	if !hasPassword || password == "" {
		return false
	}
	query := databaseURL.Query()
	return len(query) == 1 && len(query["sslmode"]) == 1 && query.Get("sslmode") == "disable"
}

func writeCredentials(path, password string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create credentials directory: %w", err)
	}
	temporaryID, err := newUUID()
	if err != nil {
		return fmt.Errorf("generate credentials temporary id: %w", err)
	}
	temporary := path + ".tmp-" + temporaryID
	content := fmt.Sprintf("email=%s\npassword=%s\n", demoEmail, password)
	if err := os.WriteFile(temporary, []byte(content), 0o600); err != nil {
		return fmt.Errorf("write credentials file: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("replace credentials file: %w", err)
	}
	return nil
}

func newDemoPassword() (string, error) {
	value := make([]byte, 18)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return "LocalDemo-" + base64.RawURLEncoding.EncodeToString(value), nil
}

func newUUID() (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value)
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}
