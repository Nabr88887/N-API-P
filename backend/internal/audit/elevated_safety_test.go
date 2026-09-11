package audit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"n-api-p/internal/access"
)

func TestElevatedAuditQueryRejectsTamperedVisibilityBeforeDecrypting(t *testing.T) {
	now := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	session := elevatedAuditTestSession(now, now.Add(time.Hour))
	repository := &elevatedAuditQueryRepositoryFake{grant: ElevatedAuditGrant{ID: "grant-1", ActorIdentityID: session.IdentityID, SessionID: session.SessionID, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}}
	service := newTestElevatedAuditQueryService(t, repository, now)
	normalized, _, err := normalizeElevatedAuditQuery(ElevatedAuditQuery{Limit: 1}, now)
	if err != nil {
		t.Fatal(err)
	}
	cursor := service.encodeCursor(repository.grant.ID, hashElevatedAuditQuery(normalized), now, ElevatedAuditPosition{ID: elevatedAuditUUID(1), CreatedAt: now.Add(-time.Hour)})
	parts := strings.Split(cursor, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var decoded elevatedAuditCursorPayload
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded.VisibleAt = now.Add(-time.Hour)
	payload, err = json.Marshal(decoded)
	if err != nil {
		t.Fatal(err)
	}
	tampered := base64.RawURLEncoding.EncodeToString(payload) + "." + parts[1]
	if _, err := service.Query(context.Background(), ElevatedAuditQueryInput{Session: session, RequestID: elevatedAuditUUID(21), Query: ElevatedAuditQuery{Limit: 1, Cursor: tampered}}); !errors.Is(err, ErrInvalidElevatedAuditCursor) {
		t.Fatalf("tampered visibility error = %v", err)
	}
	if len(repository.events) != 0 {
		t.Fatal("tampered cursor reached operation start")
	}
}

func TestElevatedAuditQueryRechecksRevocationBeforeContentRead(t *testing.T) {
	now := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	session := elevatedAuditTestSession(now, now.Add(time.Hour))
	fake := &elevatedAuditQueryRepositoryFake{
		grant:      ElevatedAuditGrant{ID: "grant-1", ActorIdentityID: session.IdentityID, SessionID: session.SessionID, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)},
		candidates: []ElevatedAuditCandidate{{Metadata: elevatedAuditMetadata("audit-1", "employee-1", "")}},
		raw:        map[string][]byte{"audit-1/request": []byte(`{"prompt":"synthetic"}`)},
	}
	repository := &revokingElevatedQueryRepository{elevatedAuditQueryRepositoryFake: fake, now: now}
	service := newTestElevatedAuditQueryService(t, fake, now)
	service.repository = repository
	page, err := service.Query(context.Background(), ElevatedAuditQueryInput{Session: session, RequestID: elevatedAuditUUID(22), Query: ElevatedAuditQuery{Limit: 1}})
	if !errors.Is(err, ErrElevatedAuditGrantRevoked) || len(page.Records) != 0 || repository.reads != 0 {
		t.Fatalf("revoked query error=%v, records=%d, content reads=%d", err, len(page.Records), repository.reads)
	}
}

func TestElevatedAuditQueryReturnsBoundedPartialCaptureInsteadOfJSONFailure(t *testing.T) {
	repository, exporter, input := elevatedExportSafetyFixture(t)
	repository.candidates = repository.candidates[:1]
	repository.candidates[0].Metadata.CaptureStatus = CaptureStatusTruncated
	repository.raw["audit-1/request"] = []byte(`{"prompt":"partial`)
	page, err := exporter.query.Query(context.Background(), ElevatedAuditQueryInput{Session: input.Session, RequestID: input.RequestID, Query: input.Query})
	if err != nil || len(page.Records) != 1 {
		t.Fatalf("partial query records=%d, error=%v", len(page.Records), err)
	}
	defer page.Clear()
	payload, err := json.Marshal(page.Records[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"request_fragment":`) || strings.Contains(string(payload), `"request":`) {
		t.Fatalf("partial capture is not a fragment: %s", payload)
	}
}

func TestElevatedAuditQueryBoundsPlaintextPageBytesWithoutSkipping(t *testing.T) {
	repository, exporter, input := elevatedExportSafetyFixture(t)
	for _, id := range []string{"audit-1", "audit-2"} {
		repository.raw[id+"/request"] = []byte(`{"prompt":"` + strings.Repeat("synthetic ", 600000) + `"}`)
	}
	page, err := exporter.query.Query(context.Background(), ElevatedAuditQueryInput{Session: input.Session, RequestID: input.RequestID, Query: input.Query})
	if err != nil {
		t.Fatal(err)
	}
	defer page.Clear()
	if len(page.Records) != 1 || page.NextCursor == "" {
		t.Fatalf("bounded page records=%d, cursor=%t", len(page.Records), page.NextCursor != "")
	}
	input.Query.Cursor = page.NextCursor
	next, err := exporter.query.Query(context.Background(), ElevatedAuditQueryInput{Session: input.Session, RequestID: input.RequestID, Query: input.Query})
	if err != nil {
		t.Fatal(err)
	}
	defer next.Clear()
	if len(next.Records) != 1 || next.Records[0].ID != "audit-2" {
		t.Fatal("byte limit skipped the next record")
	}
}

func TestElevatedAuditQueryValidatesFilterIDsBeforeAuditing(t *testing.T) {
	repository, service, input := elevatedExportSafetyFixture(t)
	invalid := "untrusted filter content"
	input.Query.IdentityID = &invalid
	_, err := service.query.Query(context.Background(), ElevatedAuditQueryInput{Session: input.Session, RequestID: input.RequestID, Query: input.Query})
	if !errors.Is(err, ErrInvalidElevatedAuditQuery) || len(repository.events) != 0 {
		t.Fatalf("invalid filter error=%v, events=%d", err, len(repository.events))
	}
}

func TestElevatedAuditQueryRecordsKnownPageCount(t *testing.T) {
	repository, service, input := elevatedExportSafetyFixture(t)
	page, err := service.query.Query(context.Background(), ElevatedAuditQueryInput{Session: input.Session, RequestID: input.RequestID, Query: input.Query})
	if err != nil {
		t.Fatal(err)
	}
	defer page.Clear()
	terminal := repository.events[len(repository.events)-1]
	if terminal.ResultCount == nil || *terminal.ResultCount != 2 || terminal.DetailCode != "query_completed" {
		t.Fatal("query completion count is missing")
	}
}

func TestElevatedAuditQueryRejectsLowRoles(t *testing.T) {
	for _, role := range []access.Role{access.RoleEmployee, access.RoleTeamAdministrator, ""} {
		t.Run(string(role), func(t *testing.T) {
			repository, service, input := elevatedExportSafetyFixture(t)
			input.Session.Role = role
			_, err := service.query.Query(context.Background(), ElevatedAuditQueryInput{Session: input.Session, RequestID: input.RequestID, Query: input.Query})
			if !errors.Is(err, access.ErrForbidden) || len(repository.events) != 0 {
				t.Fatalf("role denied=%v, events=%d", err, len(repository.events))
			}
		})
	}
}

func TestElevatedAuditQueryRejectsCrossGrantCursor(t *testing.T) {
	repository, service, input := elevatedExportSafetyFixture(t)
	input.Query.Limit = 1
	first, err := service.query.Query(context.Background(), ElevatedAuditQueryInput{Session: input.Session, RequestID: input.RequestID, Query: input.Query})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Clear()
	repository.grant.ID = "replacement-grant"
	input.Query.Cursor = first.NextCursor
	if _, err := service.query.Query(context.Background(), ElevatedAuditQueryInput{Session: input.Session, RequestID: input.RequestID, Query: input.Query}); !errors.Is(err, ErrInvalidElevatedAuditCursor) {
		t.Fatalf("cross-grant cursor=%v", err)
	}
}

func TestElevatedAuditQueryUsesStoredContentEncryptionContext(t *testing.T) {
	repository, service, input := elevatedExportSafetyFixture(t)
	repository.candidates = repository.candidates[:1]
	metadata := repository.candidates[0].Metadata
	envelope, err := NewEnvelopeService(1, map[int][]byte{1: bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	stored := RawContentRecord{AuditID: metadata.ID, ContentKind: ContentKindResponse, OwnerKind: metadata.OwnerKind, IdentityID: metadata.IdentityID, TeamID: metadata.TeamID, CreatedAt: metadata.CreatedAt, ExpiresAt: service.now().Add(time.Hour)}
	stored.Content, err = envelope.Encrypt([]byte(`{"answer":"synthetic encrypted response"}`), rawViewEncryptionContext(stored))
	if err != nil {
		t.Fatal(err)
	}
	service.query.repository = &storedElevatedQueryRepository{elevatedAuditQueryRepositoryFake: repository, stored: stored}
	service.query.decryptor = envelope
	page, err := service.query.Query(context.Background(), ElevatedAuditQueryInput{Session: input.Session, RequestID: input.RequestID, Query: input.Query})
	if err != nil {
		t.Fatal(err)
	}
	defer page.Clear()
	if len(page.Records) != 1 || !bytes.Contains(page.Records[0].ResponseJSON, []byte("synthetic encrypted response")) {
		t.Fatal("stored encrypted response was not returned")
	}
}

func TestElevatedAuditQueryMarksUndecryptableContentUnavailable(t *testing.T) {
	repository, service, input := elevatedExportSafetyFixture(t)
	repository.candidates = repository.candidates[:1]
	repository.raw["audit-1/request"] = []byte("synthetic corrupt content")
	page, err := service.query.Query(context.Background(), ElevatedAuditQueryInput{Session: input.Session, RequestID: input.RequestID, Query: input.Query})
	if err != nil {
		t.Fatal(err)
	}
	defer page.Clear()
	if len(page.Records) != 1 || page.Records[0].RequestCaptureStatus != ElevatedAuditCaptureStatusUnavailable || len(page.Records[0].RequestJSON) != 0 {
		t.Fatal("corrupt content was not marked unavailable")
	}
}

type storedElevatedQueryRepository struct {
	*elevatedAuditQueryRepositoryFake
	stored RawContentRecord
}

func (repository *storedElevatedQueryRepository) ReadRawContent(_ context.Context, lookup RawContentLookup) (RawContentRecord, error) {
	if lookup.ContentKind != repository.stored.ContentKind {
		return RawContentRecord{}, ErrRawContentUnavailable
	}
	return repository.stored, nil
}

type revokingElevatedQueryRepository struct {
	*elevatedAuditQueryRepositoryFake
	now   time.Time
	reads int
}

func (repository *revokingElevatedQueryRepository) ListElevatedAuditCandidates(ctx context.Context, selection ElevatedAuditSelection) ([]ElevatedAuditCandidate, error) {
	repository.grant.RevokedAt = &repository.now
	return repository.elevatedAuditQueryRepositoryFake.ListElevatedAuditCandidates(ctx, selection)
}

func (repository *revokingElevatedQueryRepository) ReadRawContent(ctx context.Context, lookup RawContentLookup) (RawContentRecord, error) {
	repository.reads++
	return repository.elevatedAuditQueryRepositoryFake.ReadRawContent(ctx, lookup)
}
