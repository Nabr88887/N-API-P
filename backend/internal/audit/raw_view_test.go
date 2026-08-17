package audit

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"n-api-p/internal/access"
)

var rawViewTestTime = time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)

func TestRawViewReturnsOneDecryptedAuditOnlyAfterSuccessEvent(t *testing.T) {
	repository, envelope := rawViewFixture(t)
	service, err := NewRawViewService(repository, envelope)
	if err != nil {
		t.Fatalf("NewRawViewService() error = %v", err)
	}
	service.now = func() time.Time { return rawViewTestTime }
	service.newRequestID = func() (string, error) { return "87000000-0000-0000-0000-000000000058", nil }

	view, err := service.Inspect(context.Background(), RawViewInput{
		Session: rawViewAdminSession(rawViewTestTime.Add(time.Minute)),
		AuditID: "audit-1", Reason: "  incident investigation  ",
	})
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if view.AuditID != "audit-1" || string(view.RequestJSON) != `{"request":"secret prompt"}` || string(view.ResponseJSON) != `{"response":"secret answer"}` {
		t.Fatalf("raw view = %+v", view)
	}
	if len(repository.lookups) != 2 || repository.lookups[0].ContentKind != ContentKindRequest || repository.lookups[1].ContentKind != ContentKindResponse {
		t.Fatalf("lookups = %+v, want one request and one response", repository.lookups)
	}
	for _, lookup := range repository.lookups {
		if lookup.AuditID != "audit-1" || !lookup.VisibleAt.Equal(rawViewTestTime) {
			t.Fatalf("lookup = %+v", lookup)
		}
	}
	if len(repository.events) != 1 {
		t.Fatalf("events = %d, want 1", len(repository.events))
	}
	event := repository.events[0]
	if event.EventType != string(access.SensitiveActionRawView) || event.ActorIdentityID != "admin-1" || event.TargetAuditID != "audit-1" || event.RequestID != "87000000-0000-0000-0000-000000000058" || event.Outcome != access.SecurityEventSuccess || event.Reason != "incident investigation" || event.DetailCode != "raw_viewed" {
		t.Fatalf("success event = %+v", event)
	}
	for _, forbidden := range []string{"secret prompt", "secret answer", "ciphertext", "wrapped_data_key", "nonce"} {
		if strings.Contains(event.Reason+event.DetailCode, forbidden) {
			t.Fatalf("security event contains forbidden value %q: %+v", forbidden, event)
		}
	}
}

func TestRawViewDeniesEmployeesTeamsStaleGrantsAndBlankReasonsBeforeLookup(t *testing.T) {
	tests := map[string]struct {
		session access.ActivePortalSession
		reason  string
		wantErr error
		detail  string
	}{
		"employee":               {session: access.ActivePortalSession{IdentityID: "employee-1", Role: access.RoleEmployee}, reason: "investigate", wantErr: access.ErrSensitiveActionForbidden, detail: "forbidden"},
		"team administrator":     {session: access.ActivePortalSession{IdentityID: "team-admin-1", Role: access.RoleTeamAdministrator}, reason: "investigate", wantErr: access.ErrSensitiveActionForbidden, detail: "forbidden"},
		"stale reauthentication": {session: rawViewAdminSession(rawViewTestTime), reason: "investigate", wantErr: access.ErrReauthenticationRequired, detail: "reauthentication_required"},
		"missing reason":         {session: rawViewAdminSession(rawViewTestTime.Add(time.Minute)), reason: " \t\r\n ", wantErr: ErrRawViewReasonRequired, detail: "reason_required"},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			repository, envelope := rawViewFixture(t)
			service, err := NewRawViewService(repository, envelope)
			if err != nil {
				t.Fatalf("NewRawViewService() error = %v", err)
			}
			service.now = func() time.Time { return rawViewTestTime }
			_, err = service.Inspect(context.Background(), RawViewInput{
				Session: test.session, AuditID: "audit-1", RequestID: "request-1", Reason: test.reason,
			})
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Inspect() error = %v, want %v", err, test.wantErr)
			}
			if len(repository.lookups) != 0 {
				t.Fatalf("denied request performed raw lookups: %+v", repository.lookups)
			}
			if len(repository.events) != 1 || repository.events[0].Outcome != access.SecurityEventDenied || repository.events[0].DetailCode != test.detail || repository.events[0].TargetAuditID != "audit-1" {
				t.Fatalf("denied events = %+v", repository.events)
			}
		})
	}
}

func TestRawViewReturnsNoPlaintextForMissingOrExpiredContent(t *testing.T) {
	tests := map[string]ContentKind{
		"missing request":  ContentKindRequest,
		"missing response": ContentKindResponse,
	}
	for name, missingKind := range tests {
		t.Run(name, func(t *testing.T) {
			repository, envelope := rawViewFixture(t)
			repository.readErrors[missingKind] = ErrRawContentUnavailable
			service, err := NewRawViewService(repository, envelope)
			if err != nil {
				t.Fatalf("NewRawViewService() error = %v", err)
			}
			service.now = func() time.Time { return rawViewTestTime }
			view, err := service.Inspect(context.Background(), RawViewInput{
				Session: rawViewAdminSession(rawViewTestTime.Add(time.Minute)), AuditID: "audit-1", RequestID: "request-1", Reason: "investigate",
			})
			if !errors.Is(err, ErrRawViewNotFound) || len(view.RequestJSON) != 0 || len(view.ResponseJSON) != 0 {
				t.Fatalf("Inspect() = (%+v, %v), want empty ErrRawViewNotFound", view, err)
			}
			if len(repository.events) != 1 || repository.events[0].Outcome != access.SecurityEventFailure || repository.events[0].DetailCode != "raw_content_unavailable" {
				t.Fatalf("failure events = %+v", repository.events)
			}
			if missingKind == ContentKindRequest && repository.events[0].TargetAuditID != "" {
				t.Fatalf("missing audit event exposed an unverified target: %+v", repository.events[0])
			}
			if missingKind == ContentKindResponse && repository.events[0].TargetAuditID != "audit-1" {
				t.Fatalf("known audit target missing from event: %+v", repository.events[0])
			}
		})
	}
}

func TestRawViewReturnsNoPlaintextForCiphertextContextAndKeyFailures(t *testing.T) {
	tests := map[string]func(*rawViewRepositoryFake){
		"tampered ciphertext": func(repository *rawViewRepositoryFake) {
			record := repository.records[ContentKindRequest]
			record.Content.Ciphertext[0] ^= 1
			repository.records[ContentKindRequest] = record
		},
		"moved encryption context": func(repository *rawViewRepositoryFake) {
			record := repository.records[ContentKindRequest]
			record.IdentityID = "employee-other"
			repository.records[ContentKindRequest] = record
		},
		"unknown key version": func(repository *rawViewRepositoryFake) {
			record := repository.records[ContentKindRequest]
			record.Content.KeyVersion = 99
			repository.records[ContentKindRequest] = record
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			repository, envelope := rawViewFixture(t)
			mutate(repository)
			service, err := NewRawViewService(repository, envelope)
			if err != nil {
				t.Fatalf("NewRawViewService() error = %v", err)
			}
			service.now = func() time.Time { return rawViewTestTime }
			view, err := service.Inspect(context.Background(), RawViewInput{
				Session: rawViewAdminSession(rawViewTestTime.Add(time.Minute)), AuditID: "audit-1", RequestID: "request-1", Reason: "investigate",
			})
			if !errors.Is(err, ErrRawViewDecryptionFailed) || len(view.RequestJSON) != 0 || len(view.ResponseJSON) != 0 {
				t.Fatalf("Inspect() = (%+v, %v), want empty decryption failure", view, err)
			}
			if len(repository.events) != 1 || repository.events[0].Outcome != access.SecurityEventFailure || repository.events[0].DetailCode != "decryption_failed" || repository.events[0].TargetAuditID != "audit-1" {
				t.Fatalf("failure events = %+v", repository.events)
			}
		})
	}
}

func TestRawViewEventWriteFailureReturnsNoPlaintext(t *testing.T) {
	repository, envelope := rawViewFixture(t)
	repository.appendErr = errors.New("event store unavailable")
	service, err := NewRawViewService(repository, envelope)
	if err != nil {
		t.Fatalf("NewRawViewService() error = %v", err)
	}
	service.now = func() time.Time { return rawViewTestTime }
	view, err := service.Inspect(context.Background(), RawViewInput{
		Session: rawViewAdminSession(rawViewTestTime.Add(time.Minute)), AuditID: "audit-1", RequestID: "request-1", Reason: "investigate",
	})
	if !errors.Is(err, access.ErrSecurityAuditUnavailable) || len(view.RequestJSON) != 0 || len(view.ResponseJSON) != 0 {
		t.Fatalf("Inspect() = (%+v, %v), want empty audit failure", view, err)
	}
}

func rawViewFixture(t *testing.T) (*rawViewRepositoryFake, *EnvelopeService) {
	t.Helper()
	key := bytes.Repeat([]byte{0x58}, 32)
	envelope := newDeterministicEnvelopeService(t, 1, map[int][]byte{1: key}, sequentialBytes(112))
	requestContext := EncryptionContext{
		AuditID: "audit-1", ContentKind: ContentKindRequest, OwnerKind: OwnerKindPersonal,
		IdentityID: "employee-1", TeamID: "team-1", CreatedAt: rawViewTestTime.Add(-time.Hour),
	}
	responseContext := requestContext
	responseContext.ContentKind = ContentKindResponse
	requestContent, err := envelope.Encrypt([]byte(`{"request":"secret prompt"}`), requestContext)
	if err != nil {
		t.Fatalf("encrypt request fixture: %v", err)
	}
	responseContent, err := envelope.Encrypt([]byte(`{"response":"secret answer"}`), responseContext)
	if err != nil {
		t.Fatalf("encrypt response fixture: %v", err)
	}
	record := func(kind ContentKind, content EncryptedContent) RawContentRecord {
		return RawContentRecord{
			AuditID: "audit-1", ContentKind: kind, Content: content,
			OwnerKind: OwnerKindPersonal, IdentityID: "employee-1", TeamID: "team-1",
			CreatedAt: requestContext.CreatedAt, ExpiresAt: rawViewTestTime.Add(time.Hour),
		}
	}
	return &rawViewRepositoryFake{
		records: map[ContentKind]RawContentRecord{
			ContentKindRequest:  record(ContentKindRequest, requestContent),
			ContentKindResponse: record(ContentKindResponse, responseContent),
		},
		readErrors: make(map[ContentKind]error),
	}, envelope
}

func rawViewAdminSession(grantUntil time.Time) access.ActivePortalSession {
	return access.ActivePortalSession{
		SessionID: "session-1", IdentityID: "admin-1", Role: access.RoleSystemAdministrator,
		ReauthenticatedUntil: &grantUntil,
	}
}

type rawViewRepositoryFake struct {
	records    map[ContentKind]RawContentRecord
	readErrors map[ContentKind]error
	lookups    []RawContentLookup
	events     []access.SecurityEvent
	appendErr  error
}

func (repository *rawViewRepositoryFake) ReadRawContent(_ context.Context, lookup RawContentLookup) (RawContentRecord, error) {
	repository.lookups = append(repository.lookups, lookup)
	if err := repository.readErrors[lookup.ContentKind]; err != nil {
		return RawContentRecord{}, err
	}
	return repository.records[lookup.ContentKind], nil
}

func (repository *rawViewRepositoryFake) AppendSecurityEvent(_ context.Context, event access.SecurityEvent) error {
	if repository.appendErr != nil {
		return repository.appendErr
	}
	repository.events = append(repository.events, event)
	return nil
}
