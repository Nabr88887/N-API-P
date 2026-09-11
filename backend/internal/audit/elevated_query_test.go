package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"n-api-p/internal/access"
)

func TestElevatedAuditQueryReturnsCrossEmployeeRecordsWithAllowlistedUsage(t *testing.T) {
	now := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	session := elevatedAuditTestSession(now, now.Add(time.Hour))
	repository := &elevatedAuditQueryRepositoryFake{
		grant: ElevatedAuditGrant{ID: "grant-1", ActorIdentityID: session.IdentityID, SessionID: session.SessionID, Purpose: "review", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)},
		candidates: []ElevatedAuditCandidate{
			{Metadata: elevatedAuditMetadata("audit-1", "employee-1", ""), Usage: &AuditUsage{InputTokens: 2, OutputTokens: 3, TotalTokens: 5}},
			{Metadata: elevatedAuditMetadata("audit-2", "", "service-1"), Usage: &AuditUsage{InputTokens: 7, OutputTokens: 11, TotalTokens: 18}},
		},
		raw: map[string][]byte{"audit-1/request": []byte(`{"prompt":"first"}`), "audit-1/response": []byte(`{"answer":"one"}`), "audit-2/request": []byte(`{"prompt":"second"}`), "audit-2/response": []byte(`{"answer":"two"}`)},
	}
	service := newTestElevatedAuditQueryService(t, repository, now)

	page, err := service.Query(context.Background(), ElevatedAuditQueryInput{Session: session, RequestID: elevatedAuditUUID(11), Query: ElevatedAuditQuery{Limit: 10}})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(page.Records) != 2 || page.Records[0].IdentityID != "employee-1" || page.Records[1].ServiceAccountID != "service-1" {
		t.Fatalf("records = %+v, want cross-employee/service results", page.Records)
	}
	if page.Records[0].Usage == nil || page.Records[0].Usage.TotalTokens != 5 || string(page.Records[0].RequestJSON) != `{"prompt":"first"}` {
		t.Fatalf("first record = %+v, want raw content and allowlisted usage", page.Records[0])
	}
	payload, err := json.Marshal(page.Records)
	if err != nil {
		t.Fatalf("marshal records: %v", err)
	}
	for _, forbidden := range []string{"key_id", "ciphertext", "verification_hash", "api_key", "upstream_token", "password", "session_cookie"} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("result contains forbidden field %q: %s", forbidden, payload)
		}
	}
}

func TestElevatedAuditQueryFullTextFiltersInMemoryWithoutEventContent(t *testing.T) {
	now := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	session := elevatedAuditTestSession(now, now.Add(time.Hour))
	repository := &elevatedAuditQueryRepositoryFake{
		grant:      ElevatedAuditGrant{ID: "grant-1", ActorIdentityID: session.IdentityID, SessionID: session.SessionID, Purpose: "review", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)},
		candidates: []ElevatedAuditCandidate{{Metadata: elevatedAuditMetadata("audit-1", "employee-1", "")}, {Metadata: elevatedAuditMetadata("audit-2", "employee-2", "")}},
		raw:        map[string][]byte{"audit-1/request": []byte(`{"prompt":"contains alpha"}`), "audit-1/response": []byte(`{"answer":"one"}`), "audit-2/request": []byte(`{"prompt":"other"}`), "audit-2/response": []byte(`{"answer":"two"}`)},
	}
	service := newTestElevatedAuditQueryService(t, repository, now)

	page, err := service.Query(context.Background(), ElevatedAuditQueryInput{Session: session, RequestID: elevatedAuditUUID(12), Query: ElevatedAuditQuery{FullText: " alpha ", Limit: 10}})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(page.Records) != 1 || page.Records[0].ID != "audit-1" {
		t.Fatalf("filtered records = %+v, want audit-1 only", page.Records)
	}
	if len(repository.events) != 2 || strings.Contains(repository.events[0].DetailCode, "alpha") || strings.Contains(repository.events[0].Reason, "alpha") {
		t.Fatalf("query event = %+v, must not contain full-text content", repository.events)
	}
}

func TestElevatedAuditQueryRejectsTamperedOrCrossQueryCursor(t *testing.T) {
	now := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	session := elevatedAuditTestSession(now, now.Add(time.Hour))
	repository := &elevatedAuditQueryRepositoryFake{
		grant:      ElevatedAuditGrant{ID: "grant-1", ActorIdentityID: session.IdentityID, SessionID: session.SessionID, Purpose: "review", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)},
		candidates: []ElevatedAuditCandidate{{Metadata: elevatedAuditMetadata("audit-1", "employee-1", "")}, {Metadata: elevatedAuditMetadata("audit-2", "employee-2", "")}},
		raw:        map[string][]byte{"audit-1/request": []byte(`{"prompt":"one"}`), "audit-1/response": []byte(`{"answer":"one"}`), "audit-2/request": []byte(`{"prompt":"two"}`), "audit-2/response": []byte(`{"answer":"two"}`)},
	}
	service := newTestElevatedAuditQueryService(t, repository, now)
	first, err := service.Query(context.Background(), ElevatedAuditQueryInput{Session: session, RequestID: elevatedAuditUUID(13), Query: ElevatedAuditQuery{Limit: 1}})
	if err != nil || first.NextCursor == "" {
		t.Fatalf("first query = %+v, %v; want cursor", first, err)
	}
	if _, err := service.Query(context.Background(), ElevatedAuditQueryInput{Session: session, RequestID: elevatedAuditUUID(14), Query: ElevatedAuditQuery{Limit: 1, Cursor: first.NextCursor + "tampered"}}); !errors.Is(err, ErrInvalidElevatedAuditCursor) {
		t.Fatalf("tampered cursor error = %v, want invalid cursor", err)
	}
	if _, err := service.Query(context.Background(), ElevatedAuditQueryInput{Session: session, RequestID: elevatedAuditUUID(15), Query: ElevatedAuditQuery{Limit: 1, FullText: "different", Cursor: first.NextCursor}}); !errors.Is(err, ErrInvalidElevatedAuditCursor) {
		t.Fatalf("cross-query cursor error = %v, want invalid cursor", err)
	}
}

func TestElevatedAuditQueryContinuesSignedSnapshotAfterClockAdvances(t *testing.T) {
	firstNow := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	secondNow := firstNow.Add(time.Minute)
	session := elevatedAuditTestSession(firstNow, firstNow.Add(time.Hour))
	repository := &elevatedAuditQueryRepositoryFake{
		grant:      ElevatedAuditGrant{ID: "grant-1", ActorIdentityID: session.IdentityID, SessionID: session.SessionID, Purpose: "review", IssuedAt: firstNow.Add(-time.Minute), ExpiresAt: firstNow.Add(time.Hour)},
		candidates: []ElevatedAuditCandidate{{Metadata: elevatedAuditMetadata("audit-1", "employee-1", "")}, {Metadata: elevatedAuditMetadata("audit-2", "employee-2", "")}},
		raw:        map[string][]byte{"audit-1/request": []byte(`{"prompt":"one"}`), "audit-1/response": []byte(`{"answer":"one"}`), "audit-2/request": []byte(`{"prompt":"two"}`), "audit-2/response": []byte(`{"answer":"two"}`)},
	}
	service := newTestElevatedAuditQueryService(t, repository, firstNow)
	first, err := service.Query(context.Background(), ElevatedAuditQueryInput{Session: session, RequestID: elevatedAuditUUID(19), Query: ElevatedAuditQuery{Limit: 1}})
	if err != nil || first.NextCursor == "" {
		t.Fatalf("first query = %+v, %v; want cursor", first, err)
	}
	service.now = func() time.Time { return secondNow }
	second, err := service.Query(context.Background(), ElevatedAuditQueryInput{Session: session, RequestID: elevatedAuditUUID(20), Query: ElevatedAuditQuery{Limit: 1, Cursor: first.NextCursor}})
	if err != nil || len(second.Records) != 1 || second.Records[0].ID != "audit-2" {
		t.Fatalf("continued snapshot = %+v, %v; want next retained record", second, err)
	}
}

func TestElevatedAuditExportStreamsJSONLAndRecordsLifecycleEvents(t *testing.T) {
	now := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	session := elevatedAuditTestSession(now, now.Add(time.Hour))
	repository := &elevatedAuditQueryRepositoryFake{
		grant:      ElevatedAuditGrant{ID: "grant-1", ActorIdentityID: session.IdentityID, SessionID: session.SessionID, Purpose: "review", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)},
		candidates: []ElevatedAuditCandidate{{Metadata: elevatedAuditMetadata("audit-1", "employee-1", "")}},
		raw:        map[string][]byte{"audit-1/request": []byte(`{"prompt":"one"}`), "audit-1/response": []byte(`{"answer":"one"}`)},
	}
	queryService := newTestElevatedAuditQueryService(t, repository, now)
	exportService, err := NewElevatedAuditExportService(queryService)
	if err != nil {
		t.Fatalf("NewElevatedAuditExportService() error = %v", err)
	}
	exportService.now = func() time.Time { return now }
	exportService.newID = func() (string, error) { return elevatedAuditUUID(98), nil }
	var output bytes.Buffer
	err = exportService.Export(context.Background(), ElevatedAuditExportInput{Session: session, RequestID: elevatedAuditUUID(16), Query: ElevatedAuditQuery{Limit: 10}}, &output)
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	if !strings.HasSuffix(output.String(), "\n") || !strings.Contains(output.String(), `"id":"audit-1"`) {
		t.Fatalf("export output = %q, want JSONL audit record", output.String())
	}
	for _, event := range repository.events {
		if event.EventType == "audit_export_start" || event.EventType == "audit_export_terminal" {
			if strings.Contains(event.Reason, "one") || strings.Contains(event.DetailCode, "one") {
				t.Fatalf("export event contains raw content: %+v", event)
			}
		}
	}
	if !hasEventType(repository.events, "audit_export_start") || !hasEventType(repository.events, "audit_export_terminal") {
		t.Fatalf("export lifecycle events = %+v", repository.events)
	}
}

func TestElevatedAuditExportReportsIncompleteOnCancellationOrWriteFailure(t *testing.T) {
	now := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	session := elevatedAuditTestSession(now, now.Add(time.Hour))
	repository := &elevatedAuditQueryRepositoryFake{
		grant:      ElevatedAuditGrant{ID: "grant-1", ActorIdentityID: session.IdentityID, SessionID: session.SessionID, Purpose: "review", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute)},
		candidates: []ElevatedAuditCandidate{{Metadata: elevatedAuditMetadata("audit-1", "employee-1", "")}},
		raw:        map[string][]byte{"audit-1/request": []byte(`{"prompt":"one"}`), "audit-1/response": []byte(`{"answer":"one"}`)},
	}
	queryService := newTestElevatedAuditQueryService(t, repository, now)
	exportService, err := NewElevatedAuditExportService(queryService)
	if err != nil {
		t.Fatalf("NewElevatedAuditExportService() error = %v", err)
	}
	exportService.now = func() time.Time { return now }
	exportService.newID = func() (string, error) { return elevatedAuditUUID(97), nil }
	ctx, cancel := context.WithCancel(context.Background())
	if err := exportService.Export(ctx, ElevatedAuditExportInput{Session: session, RequestID: elevatedAuditUUID(17), Query: ElevatedAuditQuery{Limit: 10}}, cancelingWriter{cancel: cancel}); !errors.Is(err, ErrElevatedAuditExportIncomplete) {
		t.Fatalf("cancelled Export() error = %v, want incomplete", err)
	}
	if !hasEventDetail(repository.events, "export_incomplete") {
		t.Fatalf("cancelled export events = %+v", repository.events)
	}
	terminalEvents := 0
	for _, event := range repository.events {
		if event.EventType == "audit_export_terminal" {
			terminalEvents++
		}
	}
	if terminalEvents != 1 {
		t.Fatalf("terminal event count = %d, want exactly one: %+v", terminalEvents, repository.events)
	}
}

func TestElevatedAuditQueryUsesBoundedContextForRepositoryWork(t *testing.T) {
	now := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	session := elevatedAuditTestSession(now, now.Add(time.Hour))
	repository := &blockingElevatedAuditQueryRepository{}
	service := newTestElevatedAuditQueryService(t, &elevatedAuditQueryRepositoryFake{}, now)
	service.repository = repository
	service.queryTimeout = time.Millisecond

	_, err := service.Query(context.Background(), ElevatedAuditQueryInput{Session: session, RequestID: elevatedAuditUUID(18), Query: ElevatedAuditQuery{Limit: 1}})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Query() error = %v, want bounded deadline", err)
	}
}

type cancelingWriter struct {
	cancel context.CancelFunc
}

func (writer cancelingWriter) Write(value []byte) (int, error) {
	writer.cancel()
	return len(value), nil
}

func hasEventType(events []access.SecurityEvent, eventType string) bool {
	for _, event := range events {
		if event.EventType == eventType {
			return true
		}
	}
	return false
}

func hasEventDetail(events []access.SecurityEvent, detail string) bool {
	for _, event := range events {
		if strings.Contains(event.DetailCode, detail) {
			return true
		}
	}
	return false
}

func newTestElevatedAuditQueryService(t *testing.T, repository *elevatedAuditQueryRepositoryFake, now time.Time) *ElevatedAuditQueryService {
	t.Helper()
	service, err := NewElevatedAuditQueryService(repository, &elevatedAuditQueryDecryptor{repository: repository})
	if err != nil {
		t.Fatalf("NewElevatedAuditQueryService() error = %v", err)
	}
	service.now = func() time.Time { return now }
	service.newID = func() (string, error) { return elevatedAuditUUID(99), nil }
	service.cursorKey = []byte("synthetic elevated audit cursor key")
	return service
}

func elevatedAuditMetadata(id, identityID, serviceAccountID string) Metadata {
	return Metadata{ID: id, RequestID: elevatedAuditUUID(200), KeyID: "must-not-leak", OwnerKind: OwnerKindPersonal, IdentityID: identityID, ServiceAccountID: serviceAccountID, TeamID: "team-1", ModelID: "model-1", CaptureStatus: CaptureStatusComplete, Outcome: AuditOutcomeSuccess, CreatedAt: time.Date(2026, 9, 11, 8, 0, 0, 0, time.UTC), UpdatedAt: time.Date(2026, 9, 11, 8, 0, 0, 0, time.UTC)}
}

type elevatedAuditQueryRepositoryFake struct {
	grant      ElevatedAuditGrant
	candidates []ElevatedAuditCandidate
	raw        map[string][]byte
	events     []access.SecurityEvent
}

type blockingElevatedAuditQueryRepository struct{}

func (*blockingElevatedAuditQueryRepository) FindElevatedAuditGrant(ctx context.Context, _ ElevatedAuditGrantLookup) (ElevatedAuditGrant, error) {
	<-ctx.Done()
	return ElevatedAuditGrant{}, ctx.Err()
}

func (*blockingElevatedAuditQueryRepository) ListElevatedAuditCandidates(context.Context, ElevatedAuditSelection) ([]ElevatedAuditCandidate, error) {
	return nil, nil
}

func (*blockingElevatedAuditQueryRepository) ReadRawContent(context.Context, RawContentLookup) (RawContentRecord, error) {
	return RawContentRecord{}, ErrRawContentUnavailable
}

func (*blockingElevatedAuditQueryRepository) AppendSecurityEvent(context.Context, access.SecurityEvent) error {
	return nil
}

func (repository *elevatedAuditQueryRepositoryFake) FindElevatedAuditGrant(context.Context, ElevatedAuditGrantLookup) (ElevatedAuditGrant, error) {
	return repository.grant, nil
}

func (repository *elevatedAuditQueryRepositoryFake) ListElevatedAuditCandidates(_ context.Context, selection ElevatedAuditSelection) ([]ElevatedAuditCandidate, error) {
	start := 0
	if selection.Cursor != nil {
		for index, candidate := range repository.candidates {
			if candidate.Metadata.ID == selection.Cursor.ID {
				start = index + 1
				break
			}
		}
	}
	end := start + selection.Limit
	if end > len(repository.candidates) {
		end = len(repository.candidates)
	}
	return repository.candidates[start:end], nil
}

func (repository *elevatedAuditQueryRepositoryFake) ReadRawContent(_ context.Context, lookup RawContentLookup) (RawContentRecord, error) {
	value, ok := repository.raw[lookup.AuditID+"/"+string(lookup.ContentKind)]
	if !ok {
		return RawContentRecord{}, ErrRawContentUnavailable
	}
	return RawContentRecord{AuditID: lookup.AuditID, ContentKind: lookup.ContentKind, Content: EncryptedContent{Ciphertext: append([]byte(nil), value...)}, OwnerKind: OwnerKindPersonal, IdentityID: "employee-1", TeamID: "team-1", CreatedAt: lookup.VisibleAt.Add(-time.Minute), ExpiresAt: lookup.VisibleAt.Add(time.Hour)}, nil
}

func (repository *elevatedAuditQueryRepositoryFake) AppendSecurityEvent(_ context.Context, event access.SecurityEvent) error {
	repository.events = append(repository.events, event)
	return nil
}

type elevatedAuditQueryDecryptor struct {
	repository *elevatedAuditQueryRepositoryFake
}

func (decryptor *elevatedAuditQueryDecryptor) Decrypt(content EncryptedContent, _ EncryptionContext) ([]byte, error) {
	if len(content.Ciphertext) == 0 {
		return nil, errors.New("missing synthetic content")
	}
	return append([]byte(nil), content.Ciphertext...), nil
}

func (repository *elevatedAuditQueryRepositoryFake) RevokeElevatedAuditGrant(context.Context, string, string, string, time.Time, access.SecurityEvent) error {
	return nil
}
