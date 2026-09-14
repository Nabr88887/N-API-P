package database

import (
	"strings"
	"testing"
	"time"

	"n-api-p/internal/audit"
)

func TestInvestigationGrantSessionVerificationRequiresRecentReauthentication(t *testing.T) {
	if !strings.Contains(verifyInvestigationGrantSessionSQL, "reauthenticated_until > $3") {
		t.Fatalf("grant session verification does not require reauthentication at issuance: %s", verifyInvestigationGrantSessionSQL)
	}
}

func TestInvestigationClosureUsesTheSameSessionVerification(t *testing.T) {
	if !strings.Contains(verifyInvestigationGrantSessionSQL, "reauthenticated_until > $3") || !strings.Contains(verifyInvestigationGrantSessionSQL, "sessions.idle_expires_at > $3") {
		t.Fatalf("closure session verification does not require active recent session: %s", verifyInvestigationGrantSessionSQL)
	}
}

func TestInvestigationCursorRoundTripsNanosecondTimestamp(t *testing.T) {
	at := time.Date(2026, 9, 4, 8, 0, 0, 123456789, time.UTC)
	id := "83000000-0000-0000-0000-000000000001"
	cursor := encodeInvestigationCursor(at, id)
	gotAt, gotID, err := decodeInvestigationCursor(cursor)
	if err != nil {
		t.Fatalf("decode cursor: %v", err)
	}
	if !gotAt.Equal(at) || gotID != id {
		t.Fatalf("decoded cursor = (%v, %q), want (%v, %q)", gotAt, gotID, at, id)
	}
	if strings.Count(cursor, ".") < 2 {
		t.Fatalf("cursor %q does not exercise fractional timestamp parsing", cursor)
	}
}

func TestSameInvestigationCandidatesComparesInstantsAndFields(t *testing.T) {
	utc := time.Date(2026, 9, 14, 8, 0, 0, 123456789, time.UTC)
	local := utc.In(time.FixedZone("synthetic", 9*60*60))
	left := []audit.InvestigationCandidate{{AuditID: "83000000-0000-0000-0000-000000000001", CaptureStatus: audit.CaptureStatusPending, CreatedAt: utc, ExpiresAt: utc.Add(time.Hour)}}
	right := []audit.InvestigationCandidate{{AuditID: "83000000-0000-0000-0000-000000000001", CaptureStatus: audit.CaptureStatusPending, CreatedAt: local, ExpiresAt: local.Add(time.Hour)}}
	if !sameInvestigationCandidates(left, right) {
		t.Fatal("candidates with equal instants but different locations were rejected")
	}
	right[0].CaptureStatus = audit.CaptureStatusComplete
	if sameInvestigationCandidates(left, right) {
		t.Fatal("candidates with changed capture status were accepted")
	}
}
