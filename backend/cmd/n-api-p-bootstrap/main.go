// Command n-api-p-bootstrap creates the first administrator in an empty identity
// database. Credentials arrive on stdin, never through arguments or output.
package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"n-api-p/internal/access"
	"n-api-p/internal/database"
)

const confirmation = "--confirm-empty-database-bootstrap"

func main() {
	if len(os.Args) != 2 || os.Args[1] != confirmation {
		fmt.Fprintln(os.Stderr, "requires --confirm-empty-database-bootstrap and credentials on stdin")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := run(ctx, os.Stdin, os.Stdout, bootstrap); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func bootstrap(ctx context.Context, email, password string) (err error) {
	dsn := os.Getenv("N_API_P_DATABASE_URL")
	if strings.TrimSpace(dsn) == "" {
		return errors.New("database configuration missing")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	return database.NewRepository(db).BootstrapAdministrator(ctx, email, password)
}

func run(ctx context.Context, input io.Reader, output io.Writer, initialize func(context.Context, string, string) error) error {
	payload, err := io.ReadAll(io.LimitReader(input, 2049))
	if err != nil || len(payload) > 2048 {
		return errors.New("bootstrap input rejected")
	}
	defer clear(payload)
	var credentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credentials); err != nil || credentials.Email == "" || credentials.Password == "" {
		return errors.New("bootstrap input rejected")
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("bootstrap input rejected")
	}
	err = initialize(ctx, credentials.Email, credentials.Password)
	credentials.Password = ""
	switch {
	case errors.Is(err, database.ErrBootstrapNotEmpty):
		return errors.New("bootstrap refused: identities already exist; no credentials changed")
	case errors.Is(err, database.ErrBootstrapSchema):
		return errors.New("bootstrap refused: schema is not current and clean")
	case errors.Is(err, database.ErrInvalidBootstrapInput), errors.Is(err, access.ErrPasswordRejected):
		return errors.New("bootstrap input rejected: use an email address and a 12-128 character password")
	case err != nil:
		// Database errors can contain connection information or user input.
		return errors.New("administrator bootstrap failed; inspect database state before retrying")
	}
	if _, err := io.WriteString(output, "first administrator created; sign in through the private HTTPS portal\n"); err != nil {
		return errors.New("bootstrap output failed; inspect database state before retrying")
	}
	return nil
}
