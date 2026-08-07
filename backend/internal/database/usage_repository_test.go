package database

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIsUsageRecordConflictMatchesOnlyAppendOnlyConstraints(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "audit ID", err: &pgconn.PgError{Code: postgresUniqueViolation, ConstraintName: "usage_records_audit_id_key"}, want: true},
		{name: "request ID wrapped", err: fmt.Errorf("wrapped: %w", &pgconn.PgError{Code: postgresUniqueViolation, ConstraintName: "usage_records_request_id_key"}), want: true},
		{name: "record primary key", err: &pgconn.PgError{Code: postgresUniqueViolation, ConstraintName: "usage_records_pkey"}},
		{name: "unrelated unique constraint", err: &pgconn.PgError{Code: postgresUniqueViolation, ConstraintName: "other_key"}},
		{name: "different PostgreSQL code", err: &pgconn.PgError{Code: "23503", ConstraintName: "usage_records_audit_id_key"}},
		{name: "non PostgreSQL error", err: errors.New("insert failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := isUsageRecordConflict(test.err); got != test.want {
				t.Fatalf("isUsageRecordConflict() = %t, want %t", got, test.want)
			}
		})
	}
}
