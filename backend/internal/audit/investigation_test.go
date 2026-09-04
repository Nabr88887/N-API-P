package audit

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"n-api-p/internal/access"
)

func TestInvestigationServiceCreatesBoundedCaseAndInitialGrant(t *testing.T) {
	now := time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC)
	repository := &investigationRepositoryFake{
		candidates: []InvestigationCandidate{
			{AuditID: "84000000-0000-0000-0000-000000000001", CaptureStatus: CaptureStatusComplete, CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour)},
		},
	}
	service := newTestInvestigationService(repository, now)
	grantUntil := now.Add(time.Minute)
	result, err := service.Create(context.Background(), CreateInvestigationCaseInput{
		Session: access.ActivePortalSession{SessionID: "session-1", IdentityID: "admin-1", Role: access.RoleSystemAdministrator, AbsoluteExpiresAt: now.Add(time.Hour), ReauthenticatedUntil: &grantUntil},
		SubjectIdentityID: "82000000-0000-0000-0000-000000000001",
		PolicyConcern:     "unexpected token usage",
		Reason:            "review synthetic policy alert",
		StartAt:           now.Add(-2 * time.Hour), EndAt: now,
		Confirmed:         true, RequestID: "87000000-0000-0000-0000-000000000001",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if result.Case.Status != InvestigationCaseOpen || result.Case.SubjectIdentityID == "" {
		t.Fatalf("case = %+v, want open case with subject", result.Case)
	}
	if !result.Grant.ExpiresAt.Equal(now.Add(30 * time.Minute)) {
		t.Fatalf("grant expiry = %v, want 30 minutes", result.Grant.ExpiresAt)
	}
	if len(repository.created.Candidates) != 1 || repository.created.Grant.SessionID != "session-1" {
		t.Fatalf("created record = %+v", repository.created)
	}
	if len(repository.events) != 1 || repository.events[0].DetailCode != "case_created" {
		t.Fatalf("events = %+v, want case-created event", repository.events)
	}
}

func TestInvestigationServiceRejectsBroadScopeAndDoesNotCreatePartialCase(t *testing.T) {
	now := time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC)
	candidates := make([]InvestigationCandidate, maxInvestigationCandidates+1)
	for index := range candidates {
		candidates[index] = InvestigationCandidate{AuditID: uuidForInvestigationTest(index + 1), CreatedAt: now.Add(-time.Duration(index+1) * time.Minute), ExpiresAt: now.Add(time.Hour), CaptureStatus: CaptureStatusComplete}
	}
	repository := &investigationRepositoryFake{candidates: candidates}
	service := newTestInvestigationService(repository, now)
	grantUntil := now.Add(time.Minute)
	_, err := service.Create(context.Background(), CreateInvestigationCaseInput{
		Session: access.ActivePortalSession{SessionID: "session-1", IdentityID: "admin-1", Role: access.RoleSystemAdministrator, AbsoluteExpiresAt: now.Add(time.Hour), ReauthenticatedUntil: &grantUntil},
		SubjectIdentityID: "82000000-0000-0000-0000-000000000001", PolicyConcern: "scope", Reason: "reason",
		StartAt: now.Add(-24 * time.Hour), EndAt: now, Confirmed: true, RequestID: "87000000-0000-0000-0000-000000000002",
	})
	if !errors.Is(err, ErrInvestigationScopeTooBroad) {
		t.Fatalf("Create() error = %v, want ErrInvestigationScopeTooBroad", err)
	}
	if repository.created.Case.ID != "" || repository.created.Grant.ID != "" {
		t.Fatalf("partial create = %+v, want none", repository.created)
	}
}

func TestInvestigationServiceUsesCaseGrantForOneRecordAndLabelsPartialResponse(t *testing.T) {
	now := time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC)
	caseID := "83000000-0000-0000-0000-000000000001"
	auditID := "84000000-0000-0000-0000-000000000001"
	repository := &investigationRepositoryFake{
		caseRecord: InvestigationCase{ID: caseID, SubjectIdentityID: "82000000-0000-0000-0000-000000000001", Status: InvestigationCaseOpen},
		candidates: []InvestigationCandidate{{AuditID: auditID, CaptureStatus: CaptureStatusTruncated, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}},
		grant: AccessGrant{ID: "85000000-0000-0000-0000-000000000001", CaseID: caseID, ActorIdentityID: "admin-1", SessionID: "session-1", ExpiresAt: now.Add(20 * time.Minute)},
		content: map[RawContentLookup]RawContentRecord{},
	}
	service := newTestInvestigationService(repository, now)
	requestContent := encryptedFixtureRecord(auditID, ContentKindRequest, now, now.Add(time.Hour))
	responseContent := encryptedFixtureRecord(auditID, ContentKindResponse, now, now.Add(time.Hour))
	repository.content[RawContentLookup{AuditID: auditID, ContentKind: ContentKindRequest, VisibleAt: now}] = requestContent
	repository.content[RawContentLookup{AuditID: auditID, ContentKind: ContentKindResponse, VisibleAt: now}] = responseContent
	service.decryptor = investigationDecryptorFake{values: map[string][]byte{
		string(ContentKindRequest):  []byte(`{"messages":[{"role":"user","content":"prompt"}]}`),
		string(ContentKindResponse): []byte(`{"choices":[`),
	}}

	view, err := service.Inspect(context.Background(), CaseRawViewInput{
		Session: access.ActivePortalSession{SessionID: "session-1", IdentityID: "admin-1", Role: access.RoleSystemAdministrator},
		CaseID: caseID, AuditID: auditID, RequestID: "87000000-0000-0000-0000-000000000003",
	})
	if err != nil {
		t.Fatalf("Inspect() error = %v", err)
	}
	if view.Request.Status != ContentViewComplete || view.Response.Status != ContentViewTruncated {
		t.Fatalf("view statuses = (%s, %s), want complete/truncated", view.Request.Status, view.Response.Status)
	}
	if view.Response.JSON != nil || view.Response.Fragment != `{"choices":[` {
		t.Fatalf("response partial = %+v", view.Response)
	}
	if len(repository.events) != 1 || repository.events[0].InvestigationCaseID != caseID {
		t.Fatalf("view event = %+v", repository.events)
	}
}

func TestInvestigationServiceDeniesClosedCaseAndCrossSessionGrant(t *testing.T) {
	now := time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC)
	repository := &investigationRepositoryFake{
		caseRecord: InvestigationCase{ID: "83000000-0000-0000-0000-000000000001", Status: InvestigationCaseClosed},
		grant: AccessGrant{CaseID: "83000000-0000-0000-0000-000000000001", ActorIdentityID: "admin-1", SessionID: "other-session", ExpiresAt: now.Add(time.Minute)},
	}
	service := newTestInvestigationService(repository, now)
	_, err := service.Inspect(context.Background(), CaseRawViewInput{
		Session: access.ActivePortalSession{SessionID: "session-1", IdentityID: "admin-1", Role: access.RoleSystemAdministrator},
		CaseID: repository.caseRecord.ID, AuditID: "84000000-0000-0000-0000-000000000001", RequestID: "87000000-0000-0000-0000-000000000004",
	})
	if !errors.Is(err, ErrInvestigationForbidden) {
		t.Fatalf("Inspect() error = %v, want forbidden", err)
	}
}

func newTestInvestigationService(repository *investigationRepositoryFake, now time.Time) *InvestigationService {
	service, err := NewInvestigationService(repository, investigationDecryptorFake{values: map[string][]byte{}})
	if err != nil {
		panic(err)
	}
	service.now = func() time.Time { return now }
	service.newID = func() (string, error) { return uuidForInvestigationTest(999), nil }
	return service
}

func uuidForInvestigationTest(value int) string {
	return "84000000-0000-0000-0000-" + fiveDigitUUIDSuffix(value)
}

func fiveDigitUUIDSuffix(value int) string {
	return fmt.Sprintf("%012d", value)
}

func encryptedFixtureRecord(auditID string, kind ContentKind, createdAt, expiresAt time.Time) RawContentRecord {
	return RawContentRecord{AuditID: auditID, ContentKind: kind, CreatedAt: createdAt, ExpiresAt: expiresAt, Content: EncryptedContent{Ciphertext: []byte("ciphertext")}}
}

type investigationRepositoryFake struct {
	candidates []InvestigationCandidate
	created    InvestigationCaseCreate
	caseRecord InvestigationCase
	grant      AccessGrant
	content    map[RawContentLookup]RawContentRecord
	events     []access.SecurityEvent
}

func (r *investigationRepositoryFake) FindInvestigationCandidates(context.Context, InvestigationCandidateQuery) ([]InvestigationCandidate, error) {
	return append([]InvestigationCandidate(nil), r.candidates...), nil
}
func (r *investigationRepositoryFake) CreateInvestigationCase(_ context.Context, create InvestigationCaseCreate) error {
	r.created = create
	r.caseRecord = create.Case
	r.grant = create.Grant
	if create.Event.ID != "" { r.events = append(r.events, create.Event) }
	return nil
}
func (r *investigationRepositoryFake) GetInvestigationCase(context.Context, string) (InvestigationCase, error) {
	if r.caseRecord.ID == "" { return InvestigationCase{}, ErrInvestigationNotFound }
	return r.caseRecord, nil
}
func (r *investigationRepositoryFake) ListInvestigationCandidates(context.Context, string) ([]InvestigationCandidate, error) { return r.candidates, nil }
func (r *investigationRepositoryFake) FindInvestigationAccessGrant(context.Context, AccessGrantLookup) (AccessGrant, error) {
	if r.grant.ID == "" { return AccessGrant{}, ErrInvestigationGrantNotFound }
	return r.grant, nil
}
func (r *investigationRepositoryFake) CloseInvestigationCase(_ context.Context, closure InvestigationCaseClosure, events ...access.SecurityEvent) error {
	r.caseRecord.Status = InvestigationCaseClosed
	r.caseRecord.ClosedBy = closure.Actor.IdentityID
	r.caseRecord.ClosedAt = &closure.ClosedAt
	r.caseRecord.Disposition = closure.Disposition
	r.caseRecord.ClosureNote = closure.Note
	for _, event := range events {
		r.events = append(r.events, event)
	}
	return nil
}
func (r *investigationRepositoryFake) ReadRawContent(_ context.Context, lookup RawContentLookup) (RawContentRecord, error) {
	for candidate, record := range r.content {
		if candidate.AuditID == lookup.AuditID && candidate.ContentKind == lookup.ContentKind { return record, nil }
	}
	return RawContentRecord{}, ErrRawContentUnavailable
}
func (r *investigationRepositoryFake) AppendSecurityEvent(_ context.Context, event access.SecurityEvent) error { r.events = append(r.events, event); return nil }

type investigationDecryptorFake struct{ values map[string][]byte }
func (d investigationDecryptorFake) Decrypt(_ EncryptedContent, context EncryptionContext) ([]byte, error) {
	value, ok := d.values[string(context.ContentKind)]
	if !ok { return nil, ErrRawViewDecryptionFailed }
	return append([]byte(nil), value...), nil
}
