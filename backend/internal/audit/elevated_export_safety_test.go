package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"n-api-p/internal/access"
)

func TestElevatedAuditExportWritesBeforeDecryptingNextRecord(t *testing.T) {
	repository, service, input := elevatedExportSafetyFixture(t)
	repository.raw["audit-2/request"] = []byte("invalid synthetic JSON")
	var output bytes.Buffer
	err := service.Export(context.Background(), input, &output)
	if !errors.Is(err, ErrElevatedAuditExportIncomplete) || !strings.Contains(output.String(), `"id":"audit-1"`) {
		t.Fatalf("stream error=%v, bytes=%d; want first record before next decryption failure", err, output.Len())
	}
}

func TestElevatedAuditExportRejectsShortWrites(t *testing.T) {
	_, service, input := elevatedExportSafetyFixture(t)
	err := service.Export(context.Background(), input, elevatedWriterFunc(func(value []byte) (int, error) { return len(value) - 1, nil }))
	if !errors.Is(err, ErrElevatedAuditExportIncomplete) || !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("short write error=%v", err)
	}
}

func TestElevatedAuditExportStopsAtRevocationAndKeepsTerminalEvidence(t *testing.T) {
	fake, service, input := elevatedExportSafetyFixture(t)
	service.query.repository = &inactiveElevatedQueryRepository{elevatedAuditQueryRepositoryFake: fake}
	writes := 0
	err := service.Export(context.Background(), input, elevatedWriterFunc(func(value []byte) (int, error) {
		writes++
		now := service.now()
		fake.grant.RevokedAt = &now
		return len(value), nil
	}))
	if !errors.Is(err, ErrElevatedAuditExportIncomplete) || writes != 1 {
		t.Fatalf("revoked export error=%v, writes=%d", err, writes)
	}
	terminal := 0
	for _, event := range fake.events {
		if event.EventType == "audit_export_terminal" {
			terminal++
			if event.Outcome != access.SecurityEventFailure || event.GrantID != fake.grant.ID {
				t.Fatal("invalid revoked export terminal evidence")
			}
		}
	}
	if terminal != 1 {
		t.Fatalf("terminal events=%d, want one", terminal)
	}
}

func TestElevatedAuditExportPersistsCountAndContentFreeQueryMetadata(t *testing.T) {
	repository, service, input := elevatedExportSafetyFixture(t)
	input.Query.FullText = "one"
	if err := service.Export(context.Background(), input, io.Discard); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(repository.events[len(repository.events)-1])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"ResultCount":1`) || !strings.Contains(string(payload), `"full_text":true`) {
		t.Fatalf("terminal event lacks count/query metadata: %s", payload)
	}
	if strings.Contains(string(payload), `"one"`) {
		t.Fatal("terminal event contains search content")
	}
}

func TestElevatedAuditExportTerminalFailureMarksHealthAndNeverCompletes(t *testing.T) {
	fake, service, input := elevatedExportSafetyFixture(t)
	service.query.repository = &terminalFailureRepository{elevatedAuditQueryRepositoryFake: fake}
	gate := &elevatedFailureGate{}
	if setter, ok := any(service).(interface{ SetFailureGate(FailureGate) }); ok {
		setter.SetFailureGate(gate)
	}
	err := service.Export(context.Background(), input, io.Discard)
	if !errors.Is(err, ErrElevatedAuditExportIncomplete) || !gate.blocked {
		t.Fatalf("terminal failure=%v, health blocked=%t", err, gate.blocked)
	}
}

func TestElevatedAuditExportExceedsTenThousandRecordsWithoutBusinessCap(t *testing.T) {
	repository, service, input := elevatedExportSafetyFixture(t)
	repository.candidates = make([]ElevatedAuditCandidate, 10001)
	repository.raw = make(map[string][]byte, len(repository.candidates))
	for index := range repository.candidates {
		id := elevatedAuditUUID(index + 1000)
		repository.candidates[index] = ElevatedAuditCandidate{Metadata: elevatedAuditMetadata(id, "employee-1", "")}
		repository.raw[id+"/request"] = []byte(`{"prompt":"synthetic"}`)
	}
	input.Query.Limit = 500
	count := 0
	err := service.Export(context.Background(), input, elevatedWriterFunc(func(value []byte) (int, error) { count++; return len(value), nil }))
	if err != nil || count != 10001 {
		t.Fatalf("export count=%d, error=%v", count, err)
	}
	if len(service.slots) != 0 {
		t.Fatal("completed export leaked a slot")
	}
}

func TestElevatedAuditExportBoundsSlotWaitAndReleasesAfterFailure(t *testing.T) {
	_, service, input := elevatedExportSafetyFixture(t)
	service.queryTimeout = time.Millisecond
	service.slots <- struct{}{}
	service.slots <- struct{}{}
	if err := service.Export(context.Background(), input, io.Discard); !errors.Is(err, ErrElevatedAuditExportIncomplete) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("saturated export wait=%v", err)
	}
	<-service.slots
	<-service.slots
	service.queryTimeout = time.Second
	if err := service.Export(context.Background(), input, elevatedWriterFunc(func([]byte) (int, error) { return 0, io.ErrClosedPipe })); !errors.Is(err, ErrElevatedAuditExportIncomplete) {
		t.Fatalf("writer failure=%v", err)
	}
	if len(service.slots) != 0 {
		t.Fatal("failed export leaked a slot")
	}
}

type terminalFailureRepository struct {
	*elevatedAuditQueryRepositoryFake
}

func (repository *terminalFailureRepository) AppendSecurityEvent(ctx context.Context, event access.SecurityEvent) error {
	if event.EventType == "audit_export_terminal" {
		return access.ErrSecurityAuditUnavailable
	}
	return repository.elevatedAuditQueryRepositoryFake.AppendSecurityEvent(ctx, event)
}

type elevatedFailureGate struct{ blocked bool }

func (gate *elevatedFailureGate) Block(context.Context, string) error {
	gate.blocked = true
	return nil
}
func (*elevatedFailureGate) MarkFinalizationFailure(context.Context, string, string, time.Time) error {
	return nil
}

func elevatedExportSafetyFixture(t *testing.T) (*elevatedAuditQueryRepositoryFake, *ElevatedAuditExportService, ElevatedAuditExportInput) {
	t.Helper()
	now := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	session := elevatedAuditTestSession(now, now.Add(time.Hour))
	repository := &elevatedAuditQueryRepositoryFake{
		grant:      ElevatedAuditGrant{ID: "grant-1", ActorIdentityID: session.IdentityID, SessionID: session.SessionID, Purpose: "synthetic review", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)},
		candidates: []ElevatedAuditCandidate{{Metadata: elevatedAuditMetadata("audit-1", "employee-1", "")}, {Metadata: elevatedAuditMetadata("audit-2", "employee-2", "")}},
		raw:        map[string][]byte{"audit-1/request": []byte(`{"prompt":"one"}`), "audit-2/request": []byte(`{"prompt":"two"}`)},
	}
	service, err := NewElevatedAuditExportService(newTestElevatedAuditQueryService(t, repository, now))
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	return repository, service, ElevatedAuditExportInput{Session: session, RequestID: elevatedAuditUUID(23), Query: ElevatedAuditQuery{Limit: 10}}
}

type elevatedWriterFunc func([]byte) (int, error)

func (writer elevatedWriterFunc) Write(value []byte) (int, error) { return writer(value) }

type inactiveElevatedQueryRepository struct {
	*elevatedAuditQueryRepositoryFake
}

func (repository *inactiveElevatedQueryRepository) FindElevatedAuditGrant(context.Context, ElevatedAuditGrantLookup) (ElevatedAuditGrant, error) {
	if repository.grant.RevokedAt != nil {
		return ElevatedAuditGrant{}, ErrElevatedAuditGrantRevoked
	}
	return repository.grant, nil
}
