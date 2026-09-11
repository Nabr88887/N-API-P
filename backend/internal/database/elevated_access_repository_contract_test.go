package database

import (
	"strings"
	"testing"

	"n-api-p/internal/audit"
)

var _ audit.ElevatedAuditGrantRepository = (*Repository)(nil)

func TestElevatedAuditGrantQueriesVerifyActiveSessionAndIdentity(t *testing.T) {
	for _, fragment := range []string{
		"JOIN sessions",
		"JOIN identities",
		"sessions.revoked_at IS NULL",
		"identities.status = 'active'",
		"identities.role = 'system_administrator'",
		"expires_at > $",
		"revoked_at IS NULL",
	} {
		if !strings.Contains(findElevatedAuditGrantSQL, fragment) {
			t.Fatalf("grant lookup query missing %q: %s", fragment, findElevatedAuditGrantSQL)
		}
	}
}

func TestElevatedAuditGrantIssuanceSerializesAndSupersedesOldAuthority(t *testing.T) {
	if !strings.Contains(verifyElevatedAuditGrantSessionSQL, "FOR UPDATE") {
		t.Fatal("grant issuance must serialize on the session before replacing authority")
	}
	for _, fragment := range []string{"UPDATE elevated_audit_grants", "revoked_at = $3", "actor_identity_id = $1 AND session_id = $2", "INSERT INTO security_events", "audit_grant_revoked", "superseded"} {
		if !strings.Contains(supersedeElevatedAuditGrantsSQL, fragment) {
			t.Fatalf("supersession lacks %q", fragment)
		}
	}
}
