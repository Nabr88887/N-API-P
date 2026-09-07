package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
		Session:           access.ActivePortalSession{SessionID: "session-1", IdentityID: "admin-1", Role: access.RoleSystemAdministrator, IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(time.Hour), ReauthenticatedUntil: &grantUntil},
		SubjectIdentityID: "82000000-0000-0000-0000-000000000001",
		PolicyConcern:     "unexpected token usage",
		Reason:            "review synthetic policy alert",
		StartAt:           now.Add(-2 * time.Hour), EndAt: now,
		Confirmed: true, RequestID: "87000000-0000-0000-0000-000000000001",
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
		Session:           access.ActivePortalSession{SessionID: "session-1", IdentityID: "admin-1", Role: access.RoleSystemAdministrator, IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(time.Hour), ReauthenticatedUntil: &grantUntil},
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
		grant:      AccessGrant{ID: "85000000-0000-0000-0000-000000000001", CaseID: caseID, ActorIdentityID: "admin-1", SessionID: "session-1", ExpiresAt: now.Add(20 * time.Minute)},
		content:    map[RawContentLookup]RawContentRecord{},
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
		Session: access.ActivePortalSession{SessionID: "session-1", IdentityID: "admin-1", Role: access.RoleSystemAdministrator, IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(time.Hour)},
		CaseID:  caseID, AuditID: auditID, RequestID: "87000000-0000-0000-0000-000000000003",
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
		grant:      AccessGrant{CaseID: "83000000-0000-0000-0000-000000000001", ActorIdentityID: "admin-1", SessionID: "other-session", ExpiresAt: now.Add(time.Minute)},
	}
	service := newTestInvestigationService(repository, now)
	_, err := service.Inspect(context.Background(), CaseRawViewInput{
		Session: access.ActivePortalSession{SessionID: "session-1", IdentityID: "admin-1", Role: access.RoleSystemAdministrator, IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(time.Hour)},
		CaseID:  repository.caseRecord.ID, AuditID: "84000000-0000-0000-0000-000000000001", RequestID: "87000000-0000-0000-0000-000000000004",
	})
	if !errors.Is(err, ErrInvestigationClosed) {
		t.Fatalf("Inspect() error = %v, want closed", err)
	}
}

func TestInvestigationServiceRejectsExpiredIdleSessionForGrant(t *testing.T) {
	now := time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC)
	repository := &investigationRepositoryFake{caseRecord: InvestigationCase{ID: "83000000-0000-0000-0000-000000000001", Status: InvestigationCaseOpen}}
	service := newTestInvestigationService(repository, now)
	grantUntil := now.Add(time.Minute)
	_, err := service.IssueGrant(context.Background(), IssueInvestigationGrantInput{
		Session: access.ActivePortalSession{
			SessionID: "85000000-0000-0000-0000-000000000001", IdentityID: "82000000-0000-0000-0000-000000000001",
			Role: access.RoleSystemAdministrator, IdleExpiresAt: now, AbsoluteExpiresAt: now.Add(time.Hour), ReauthenticatedUntil: &grantUntil,
		},
		CaseID: repository.caseRecord.ID, Confirmed: true, RequestID: "87000000-0000-0000-0000-000000000005",
	})
	if !errors.Is(err, ErrInvestigationForbidden) {
		t.Fatalf("IssueGrant() error = %v, want forbidden for expired idle session", err)
	}
}

func TestInvestigationServiceRejectsExpiredIdleSessionForClosure(t *testing.T) {
	now := time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC)
	repository := &investigationRepositoryFake{caseRecord: InvestigationCase{ID: "83000000-0000-0000-0000-000000000001", Status: InvestigationCaseOpen}}
	service := newTestInvestigationService(repository, now)
	grantUntil := now.Add(time.Minute)
	err := service.Close(context.Background(), InvestigationCaseClosure{
		CaseID: "83000000-0000-0000-0000-000000000001",
		Actor: access.ActivePortalSession{
			SessionID: "85000000-0000-0000-0000-000000000001", IdentityID: "82000000-0000-0000-0000-000000000001",
			Role: access.RoleSystemAdministrator, IdleExpiresAt: now, AbsoluteExpiresAt: now.Add(time.Hour), ReauthenticatedUntil: &grantUntil,
		},
		Disposition: InvestigationInconclusive, Confirmed: true, ClosedAt: now, RequestID: "87000000-0000-0000-0000-000000000007",
	})
	if !errors.Is(err, ErrInvestigationForbidden) {
		t.Fatalf("Close() error = %v, want forbidden for expired idle session", err)
	}
}

func TestInvestigationServiceCarriesCreationVisibilityInstantIntoSnapshotQuery(t *testing.T) {
	now := time.Date(2026, 9, 4, 8, 0, 0, 123456789, time.UTC)
	repository := &investigationRepositoryFake{candidates: []InvestigationCandidate{{AuditID: "84000000-0000-0000-0000-000000000001", CaptureStatus: CaptureStatusComplete, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}}}
	service := newTestInvestigationService(repository, now)
	grantUntil := now.Add(time.Minute)
	result, err := service.Create(context.Background(), CreateInvestigationCaseInput{
		Session:           access.ActivePortalSession{SessionID: "85000000-0000-0000-0000-000000000001", IdentityID: "82000000-0000-0000-0000-000000000001", Role: access.RoleSystemAdministrator, IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour), ReauthenticatedUntil: &grantUntil},
		SubjectIdentityID: "82000000-0000-0000-0000-000000000002", PolicyConcern: "scope", Reason: "reason", StartAt: now.Add(-time.Hour), EndAt: now, Confirmed: true, RequestID: "87000000-0000-0000-0000-000000000006",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !result.CandidateQuery.VisibleAt.Equal(now) {
		t.Fatalf("candidate visibility = %v, want creation instant %v", result.CandidateQuery.VisibleAt, now)
	}
}

func TestInvestigationServiceRejectsExpiredSessionsForMetadataReads(t *testing.T) {
	now := time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC)
	repository := &investigationRepositoryFake{caseRecord: InvestigationCase{ID: "83000000-0000-0000-0000-000000000001", Status: InvestigationCaseOpen}}
	service := newTestInvestigationService(repository, now)
	session := access.ActivePortalSession{
		SessionID: "85000000-0000-0000-0000-000000000001", IdentityID: "82000000-0000-0000-0000-000000000001", Role: access.RoleSystemAdministrator,
		IdleExpiresAt: now, AbsoluteExpiresAt: now.Add(time.Hour),
	}
	if _, err := service.List(context.Background(), session, InvestigationCaseListFilter{Limit: 20}); !errors.Is(err, ErrInvestigationForbidden) {
		t.Fatalf("List() error = %v, want forbidden for expired session", err)
	}
	if _, err := service.Candidates(context.Background(), session, repository.caseRecord.ID); !errors.Is(err, ErrInvestigationForbidden) {
		t.Fatalf("Candidates() error = %v, want forbidden for expired session", err)
	}
}

func TestInvestigationServiceReturnsNotFoundForUnknownCandidateCase(t *testing.T) {
	now := time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC)
	repository := &investigationRepositoryFake{}
	service := newTestInvestigationService(repository, now)
	session := access.ActivePortalSession{
		SessionID: "85000000-0000-0000-0000-000000000001", IdentityID: "82000000-0000-0000-0000-000000000001", Role: access.RoleSystemAdministrator,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	}
	_, err := service.Candidates(context.Background(), session, "83000000-0000-0000-0000-000000000001")
	if !errors.Is(err, ErrInvestigationNotFound) {
		t.Fatalf("Candidates() error = %v, want ErrInvestigationNotFound", err)
	}
}

func TestInvestigationServiceAuditsRepositoryFailuresAsFailures(t *testing.T) {
	now := time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC)
	caseID := "83000000-0000-0000-0000-000000000001"
	auditID := "84000000-0000-0000-0000-000000000001"
	session := access.ActivePortalSession{
		SessionID: "85000000-0000-0000-0000-000000000001", IdentityID: "82000000-0000-0000-0000-000000000001",
		Role: access.RoleSystemAdministrator, IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(time.Hour),
	}
	for _, test := range []struct {
		name       string
		configure  func(*investigationRepositoryFake)
		wantDetail string
		wantError  string
	}{
		{name: "case lookup", configure: func(repository *investigationRepositoryFake) {
			repository.caseErr = errors.New("case storage unavailable")
		}, wantDetail: "case_lookup_failed", wantError: "case storage unavailable"},
		{name: "grant lookup", configure: func(repository *investigationRepositoryFake) {
			repository.caseRecord = InvestigationCase{ID: caseID, Status: InvestigationCaseOpen}
			repository.grantErr = errors.New("grant storage unavailable")
		}, wantDetail: "grant_lookup_failed", wantError: "grant storage unavailable"},
		{name: "candidate lookup", configure: func(repository *investigationRepositoryFake) {
			repository.caseRecord = InvestigationCase{ID: caseID, Status: InvestigationCaseOpen}
			repository.grant = AccessGrant{ID: "86000000-0000-0000-0000-000000000001", CaseID: caseID, ActorIdentityID: session.IdentityID, SessionID: session.SessionID, ExpiresAt: now.Add(time.Minute)}
			repository.candidatesErr = errors.New("candidate storage unavailable")
		}, wantDetail: "candidate_lookup_failed", wantError: "candidate storage unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &investigationRepositoryFake{}
			test.configure(repository)
			service := newTestInvestigationService(repository, now)
			_, err := service.Inspect(context.Background(), CaseRawViewInput{Session: session, CaseID: caseID, AuditID: auditID, RequestID: "87000000-0000-0000-0000-000000000008"})
			if err == nil || !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Inspect() error = %v, want %q", err, test.wantError)
			}
			if len(repository.events) != 1 || repository.events[0].Outcome != access.SecurityEventFailure || repository.events[0].DetailCode != test.wantDetail {
				t.Fatalf("failure event = %+v, want failure/%s", repository.events, test.wantDetail)
			}
		})
	}
}

func TestInvestigationServiceAuditsRawRepositoryFailureAsFailure(t *testing.T) {
	now := time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC)
	caseID := "83000000-0000-0000-0000-000000000001"
	auditID := "84000000-0000-0000-0000-000000000001"
	repository := &investigationRepositoryFake{
		caseRecord: InvestigationCase{ID: caseID, SubjectIdentityID: "82000000-0000-0000-0000-000000000002", Status: InvestigationCaseOpen},
		grant:      AccessGrant{ID: "86000000-0000-0000-0000-000000000001", CaseID: caseID, ActorIdentityID: "82000000-0000-0000-0000-000000000001", SessionID: "85000000-0000-0000-0000-000000000001", ExpiresAt: now.Add(time.Minute)},
		candidates: []InvestigationCandidate{{AuditID: auditID, CaptureStatus: CaptureStatusComplete, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Hour)}},
		contentErr: errors.New("raw storage unavailable"),
	}
	service := newTestInvestigationService(repository, now)
	_, err := service.Inspect(context.Background(), CaseRawViewInput{
		Session: access.ActivePortalSession{SessionID: repository.grant.SessionID, IdentityID: repository.grant.ActorIdentityID, Role: access.RoleSystemAdministrator, IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(time.Hour)},
		CaseID:  caseID, AuditID: auditID, RequestID: "87000000-0000-0000-0000-000000000009",
	})
	if err == nil || !strings.Contains(err.Error(), "raw storage unavailable") {
		t.Fatalf("Inspect() error = %v, want raw storage failure", err)
	}
	if len(repository.events) != 1 || repository.events[0].Outcome != access.SecurityEventFailure || repository.events[0].DetailCode != "raw_repository_unavailable" {
		t.Fatalf("raw failure event = %+v, want failure/raw_repository_unavailable", repository.events)
	}
}

func TestInvestigationServiceRejectsUnknownCaseListStatus(t *testing.T) {
	now := time.Date(2026, 9, 4, 8, 0, 0, 0, time.UTC)
	repository := &investigationRepositoryFake{}
	service := newTestInvestigationService(repository, now)
	session := access.ActivePortalSession{
		SessionID: "85000000-0000-0000-0000-000000000001", IdentityID: "82000000-0000-0000-0000-000000000001", Role: access.RoleSystemAdministrator,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	}
	if _, err := service.List(context.Background(), session, InvestigationCaseListFilter{Status: InvestigationCaseStatus("unexpected"), Limit: 20}); !errors.Is(err, ErrInvalidInvestigation) {
		t.Fatalf("List() error = %v, want invalid investigation status", err)
	}
}

func TestClearCaseRawViewClearsPlaintextBuffers(t *testing.T) {
	requestBytes := []byte(`{"prompt":"synthetic"}`)
	view := CaseRawView{
		Request:  CaseContentView{Status: ContentViewComplete, JSON: json.RawMessage(requestBytes)},
		Response: CaseContentView{Status: ContentViewTruncated, Fragment: `{"answer":"synthetic"}`},
	}

	clearCaseRawView(&view)

	if view.Request.JSON != nil || view.Response.JSON != nil || view.Request.Fragment != "" || view.Response.Fragment != "" {
		t.Fatalf("case raw view still retains plaintext: %+v", view)
	}
	for index, value := range requestBytes {
		if value != 0 {
			t.Fatalf("request plaintext byte %d = %d, want zeroed", index, value)
		}
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
	candidates    []InvestigationCandidate
	created       InvestigationCaseCreate
	caseRecord    InvestigationCase
	caseErr       error
	grant         AccessGrant
	grantErr      error
	candidatesErr error
	contentErr    error
	content       map[RawContentLookup]RawContentRecord
	events        []access.SecurityEvent
}

func (r *investigationRepositoryFake) FindInvestigationCandidates(context.Context, InvestigationCandidateQuery) ([]InvestigationCandidate, error) {
	return append([]InvestigationCandidate(nil), r.candidates...), nil
}
func (r *investigationRepositoryFake) CreateInvestigationCase(_ context.Context, create InvestigationCaseCreate) error {
	r.created = create
	r.caseRecord = create.Case
	r.grant = create.Grant
	if create.Event.ID != "" {
		r.events = append(r.events, create.Event)
	}
	return nil
}
func (r *investigationRepositoryFake) GetInvestigationCase(context.Context, string) (InvestigationCase, error) {
	if r.caseErr != nil {
		return InvestigationCase{}, r.caseErr
	}
	if r.caseRecord.ID == "" {
		return InvestigationCase{}, ErrInvestigationNotFound
	}
	return r.caseRecord, nil
}
func (r *investigationRepositoryFake) ListInvestigationCandidates(context.Context, string) ([]InvestigationCandidate, error) {
	if r.candidatesErr != nil {
		return nil, r.candidatesErr
	}
	return r.candidates, nil
}
func (r *investigationRepositoryFake) FindInvestigationAccessGrant(context.Context, AccessGrantLookup) (AccessGrant, error) {
	if r.grantErr != nil {
		return AccessGrant{}, r.grantErr
	}
	if r.grant.ID == "" {
		return AccessGrant{}, ErrInvestigationGrantNotFound
	}
	return r.grant, nil
}
func (r *investigationRepositoryFake) CreateInvestigationAccessGrant(_ context.Context, grant AccessGrant, event access.SecurityEvent) error {
	r.grant = grant
	r.events = append(r.events, event)
	return nil
}
func (r *investigationRepositoryFake) ListInvestigationCases(context.Context, InvestigationCaseListFilter) (InvestigationCasePage, error) {
	if r.caseRecord.ID == "" {
		return InvestigationCasePage{}, nil
	}
	return InvestigationCasePage{Cases: []InvestigationCase{r.caseRecord}}, nil
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
	if r.contentErr != nil {
		return RawContentRecord{}, r.contentErr
	}
	for candidate, record := range r.content {
		if candidate.AuditID == lookup.AuditID && candidate.ContentKind == lookup.ContentKind {
			return record, nil
		}
	}
	return RawContentRecord{}, ErrRawContentUnavailable
}
func (r *investigationRepositoryFake) AppendSecurityEvent(_ context.Context, event access.SecurityEvent) error {
	r.events = append(r.events, event)
	return nil
}

type investigationDecryptorFake struct{ values map[string][]byte }

func (d investigationDecryptorFake) Decrypt(_ EncryptedContent, context EncryptionContext) ([]byte, error) {
	value, ok := d.values[string(context.ContentKind)]
	if !ok {
		return nil, ErrRawViewDecryptionFailed
	}
	return append([]byte(nil), value...), nil
}
