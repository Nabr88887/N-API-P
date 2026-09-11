package database

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"n-api-p/internal/audit"
)

var _ audit.ElevatedAuditQueryRepository = (*Repository)(nil)

func TestElevatedAuditSelectionIsParameterizedRetainedAndCredentialFree(t *testing.T) {
	for _, fragment := range []string{
		"raw.expires_at > $11",
		"($1::uuid IS NULL OR records.identity_id = $1 OR records.responsible_identity_id = $1)",
		"($2::uuid IS NULL OR records.service_account_id = $2)",
		"($3::uuid IS NULL OR records.responsible_identity_id = $3)",
		"ORDER BY records.created_at DESC, records.id DESC",
		"LIMIT $14",
		"records.created_at <= $15",
	} {
		if !strings.Contains(listElevatedAuditCandidatesSQL, fragment) {
			t.Fatalf("elevated audit selection missing %q: %s", fragment, listElevatedAuditCandidatesSQL)
		}
	}
	for _, forbidden := range []string{"verification_hash", "password_hash", "ciphertext", "wrapped_data_key", "key_id::text"} {
		if strings.Contains(listElevatedAuditCandidatesSQL, forbidden) {
			t.Fatalf("elevated audit selection exposes forbidden field %q", forbidden)
		}
	}
}

func TestOptionalElevatedAuditIDsUsesPgxUUIDArrayEncoding(t *testing.T) {
	value, err := optionalElevatedAuditIDs([]string{"00000000-0000-0000-0000-000000000001"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := value.(pgtype.FlatArray[pgtype.UUID]); !ok {
		t.Fatalf("optional UUID array type = %T, want pgtype.FlatArray[pgtype.UUID]", value)
	}
	for _, format := range []int16{pgtype.TextFormatCode, pgtype.BinaryFormatCode} {
		if _, err := pgtype.NewMap().Encode(pgtype.UUIDArrayOID, format, value, nil); err != nil {
			t.Fatalf("UUID array encoding format=%d: %v", format, err)
		}
	}
}
