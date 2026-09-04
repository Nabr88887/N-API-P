package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"n-api-p/internal/access"
)

const (
	maxInvestigationCandidates = 100
	maxInvestigationDuration   = 30 * 24 * time.Hour
	investigationGrantLife     = 30 * time.Minute
	maxInvestigationText       = 500
	maxInvestigationFragment   = 64 << 10
)

var (
	ErrInvalidInvestigation       = errors.New("invalid investigation request")
	ErrInvestigationForbidden     = errors.New("investigation access forbidden")
	ErrInvestigationNotFound      = errors.New("investigation case not found")
	ErrInvestigationGrantNotFound = errors.New("investigation grant not found")
	ErrInvestigationScopeTooBroad = errors.New("investigation scope too broad")
	ErrInvestigationNoCandidates  = errors.New("investigation has no candidates")
	ErrInvestigationClosed        = errors.New("investigation case is closed")
)

type InvestigationCaseStatus string

const (
	InvestigationCaseOpen   InvestigationCaseStatus = "open"
	InvestigationCaseClosed InvestigationCaseStatus = "closed"
)

type InvestigationDisposition string

const (
	InvestigationConfirmedViolation InvestigationDisposition = "confirmed_violation"
	InvestigationNoViolation        InvestigationDisposition = "no_violation"
	InvestigationInconclusive       InvestigationDisposition = "inconclusive"
)

type InvestigationCase struct {
	ID                string
	SubjectIdentityID string
	PolicyConcern     string
	Reason            string
	StartAt           time.Time
	EndAt             time.Time
	Status            InvestigationCaseStatus
	CreatedBy         string
	CreatedAt         time.Time
	ClosedBy          string
	ClosedAt          *time.Time
	Disposition       InvestigationDisposition
	ClosureNote       string
}

type InvestigationCandidate struct {
	AuditID       string
	CaptureStatus CaptureStatus
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

type AccessGrant struct {
	ID              string
	CaseID          string
	ActorIdentityID string
	SessionID       string
	IssuedAt        time.Time
	ExpiresAt       time.Time
}

type InvestigationCandidateQuery struct {
	SubjectIdentityID string
	StartAt           time.Time
	EndAt             time.Time
	Limit             int
}

type InvestigationCaseCreate struct {
	Case       InvestigationCase
	Candidates []InvestigationCandidate
	Grant      AccessGrant
	Event      access.SecurityEvent
	// CandidateQuery lets a transactional repository re-select and validate the
	// immutable snapshot instead of trusting a stale preflight result.
	CandidateQuery InvestigationCandidateQuery
}

type CreateInvestigationCaseInput struct {
	Session           access.ActivePortalSession
	SubjectIdentityID string
	PolicyConcern     string
	Reason            string
	StartAt           time.Time
	EndAt             time.Time
	Confirmed         bool
	RequestID         string
}

type AccessGrantLookup struct {
	CaseID          string
	ActorIdentityID string
	SessionID       string
	At              time.Time
}

type CaseRawViewInput struct {
	Session   access.ActivePortalSession
	CaseID    string
	AuditID   string
	RequestID string
}

type ContentViewStatus string

const (
	ContentViewComplete    ContentViewStatus = "complete"
	ContentViewTruncated   ContentViewStatus = "truncated"
	ContentViewIncomplete  ContentViewStatus = "incomplete"
	ContentViewUnavailable ContentViewStatus = "unavailable"
)

type CaseContentView struct {
	Status   ContentViewStatus `json:"status"`
	JSON     json.RawMessage   `json:"json,omitempty"`
	Fragment string            `json:"fragment,omitempty"`
}

type CaseRawView struct {
	AuditID  string          `json:"audit_id"`
	Request  CaseContentView `json:"request"`
	Response CaseContentView `json:"response"`
}

type InvestigationCaseClosure struct {
	CaseID      string
	Actor       access.ActivePortalSession
	Disposition InvestigationDisposition
	Note        string
	ClosedAt    time.Time
	Confirmed   bool
	RequestID   string
}

type InvestigationCaseListFilter struct {
	Status InvestigationCaseStatus
	Limit  int
	Cursor string
}

type InvestigationCasePage struct {
	Cases      []InvestigationCase
	NextCursor string
}

type IssueInvestigationGrantInput struct {
	Session   access.ActivePortalSession
	CaseID    string
	Confirmed bool
	RequestID string
}

type InvestigationRepository interface {
	FindInvestigationCandidates(context.Context, InvestigationCandidateQuery) ([]InvestigationCandidate, error)
	CreateInvestigationCase(context.Context, InvestigationCaseCreate) error
	ListInvestigationCases(context.Context, InvestigationCaseListFilter) (InvestigationCasePage, error)
	GetInvestigationCase(context.Context, string) (InvestigationCase, error)
	ListInvestigationCandidates(context.Context, string) ([]InvestigationCandidate, error)
	CreateInvestigationAccessGrant(context.Context, AccessGrant, access.SecurityEvent) error
	FindInvestigationAccessGrant(context.Context, AccessGrantLookup) (AccessGrant, error)
	// The event is part of the same transaction as closure and grant
	// invalidation. The variadic form keeps simple fakes/source compatibility.
	CloseInvestigationCase(context.Context, InvestigationCaseClosure, ...access.SecurityEvent) error
	ReadRawContent(context.Context, RawContentLookup) (RawContentRecord, error)
	AppendSecurityEvent(context.Context, access.SecurityEvent) error
}

type InvestigationDecryptor interface {
	Decrypt(EncryptedContent, EncryptionContext) ([]byte, error)
}

type InvestigationService struct {
	repository InvestigationRepository
	decryptor  InvestigationDecryptor
	now        func() time.Time
	newID      func() (string, error)
}

func NewInvestigationService(repository InvestigationRepository, decryptor InvestigationDecryptor) (*InvestigationService, error) {
	if repository == nil || decryptor == nil {
		return nil, ErrInvalidInvestigation
	}
	return &InvestigationService{repository: repository, decryptor: decryptor, now: time.Now, newID: investigationID}, nil
}

func (service *InvestigationService) Create(ctx context.Context, input CreateInvestigationCaseInput) (InvestigationCaseCreate, error) {
	if service == nil || service.repository == nil || service.newID == nil || strings.TrimSpace(input.RequestID) == "" {
		return InvestigationCaseCreate{}, ErrInvalidInvestigation
	}
	now := service.now().UTC()
	if input.Session.IdentityID == "" || input.Session.SessionID == "" || input.Session.Role != access.RoleSystemAdministrator {
		return service.rejectCreate(ctx, input, ErrInvestigationForbidden, now)
	}
	if input.Session.AbsoluteExpiresAt.IsZero() || !input.Session.AbsoluteExpiresAt.After(now) {
		return service.rejectCreate(ctx, input, ErrInvestigationForbidden, now)
	}
	if input.Session.ReauthenticatedUntil == nil || !input.Session.ReauthenticatedUntil.After(now) {
		return service.rejectCreate(ctx, input, access.ErrReauthenticationRequired, now)
	}
	if !input.Confirmed || !validInvestigationText(input.PolicyConcern) || !validInvestigationText(input.Reason) ||
		!validInvestigationID(input.SubjectIdentityID) || input.StartAt.IsZero() || input.EndAt.IsZero() ||
		!input.StartAt.Before(input.EndAt) || input.EndAt.After(now) || input.EndAt.Sub(input.StartAt) > maxInvestigationDuration {
		return service.rejectCreate(ctx, input, ErrInvalidInvestigation, now)
	}
	query := InvestigationCandidateQuery{SubjectIdentityID: input.SubjectIdentityID, StartAt: input.StartAt.UTC(), EndAt: input.EndAt.UTC(), Limit: maxInvestigationCandidates + 1}
	candidates, err := service.repository.FindInvestigationCandidates(ctx, query)
	if err != nil {
		return InvestigationCaseCreate{}, fmt.Errorf("find investigation candidates: %w", err)
	}
	if len(candidates) > maxInvestigationCandidates {
		return InvestigationCaseCreate{}, ErrInvestigationScopeTooBroad
	}
	if len(candidates) == 0 {
		return InvestigationCaseCreate{}, ErrInvestigationNoCandidates
	}
	caseID, err := service.newID()
	if err != nil {
		return InvestigationCaseCreate{}, ErrInvalidInvestigation
	}
	grantID, err := service.newID()
	if err != nil {
		return InvestigationCaseCreate{}, ErrInvalidInvestigation
	}
	grantExpiry := now.Add(investigationGrantLife)
	if grantExpiry.After(input.Session.AbsoluteExpiresAt) {
		grantExpiry = input.Session.AbsoluteExpiresAt
	}
	result := InvestigationCaseCreate{
		Case: InvestigationCase{ID: caseID, SubjectIdentityID: input.SubjectIdentityID, PolicyConcern: strings.TrimSpace(input.PolicyConcern), Reason: strings.TrimSpace(input.Reason), StartAt: input.StartAt.UTC(), EndAt: input.EndAt.UTC(), Status: InvestigationCaseOpen, CreatedBy: input.Session.IdentityID, CreatedAt: now},
		Candidates: append([]InvestigationCandidate(nil), candidates...),
		Grant: AccessGrant{ID: grantID, CaseID: caseID, ActorIdentityID: input.Session.IdentityID, SessionID: input.Session.SessionID, IssuedAt: now, ExpiresAt: grantExpiry},
		CandidateQuery: query,
	}
	eventID, err := service.newID()
	if err != nil {
		return InvestigationCaseCreate{}, ErrInvalidInvestigation
	}
	result.Event = access.SecurityEvent{ID: eventID, EventType: "investigation_case", ActorIdentityID: input.Session.IdentityID, TargetIdentityID: input.SubjectIdentityID, InvestigationCaseID: caseID, RequestID: input.RequestID, Outcome: access.SecurityEventSuccess, Reason: result.Case.Reason, DetailCode: "case_created", OccurredAt: now}
	if err := service.repository.CreateInvestigationCase(ctx, result); err != nil {
		return InvestigationCaseCreate{}, err
	}
	return result, nil
}

func (service *InvestigationService) rejectCreate(ctx context.Context, input CreateInvestigationCaseInput, result error, now time.Time) (InvestigationCaseCreate, error) {
	if input.Session.IdentityID == "" || strings.TrimSpace(input.RequestID) == "" || service == nil || service.repository == nil || service.newID == nil {
		return InvestigationCaseCreate{}, result
	}
	eventID, idErr := service.newID()
	if idErr != nil {
		return InvestigationCaseCreate{}, access.ErrSecurityAuditUnavailable
	}
	event := access.SecurityEvent{ID: eventID, EventType: "investigation_case", ActorIdentityID: input.Session.IdentityID, RequestID: input.RequestID, Outcome: access.SecurityEventDenied, DetailCode: investigationCreateDetail(result), OccurredAt: now}
	if err := service.repository.AppendSecurityEvent(ctx, event); err != nil {
		return InvestigationCaseCreate{}, access.ErrSecurityAuditUnavailable
	}
	return InvestigationCaseCreate{}, result
}

func investigationCreateDetail(err error) string {
	switch {
	case errors.Is(err, access.ErrReauthenticationRequired):
		return "reauthentication_required"
	case errors.Is(err, ErrInvestigationForbidden):
		return "forbidden"
	default:
		return "invalid_request"
	}
}

func (service *InvestigationService) Inspect(ctx context.Context, input CaseRawViewInput) (CaseRawView, error) {
	if service == nil || service.repository == nil || service.decryptor == nil || service.newID == nil || strings.TrimSpace(input.CaseID) == "" || strings.TrimSpace(input.AuditID) == "" || strings.TrimSpace(input.RequestID) == "" {
		return CaseRawView{}, ErrInvalidInvestigation
	}
	now := service.now().UTC()
	if input.Session.IdentityID == "" || input.Session.SessionID == "" || input.Session.Role != access.RoleSystemAdministrator {
		return service.rejectView(ctx, input, "forbidden", ErrInvestigationForbidden, now)
	}
	caseRecord, err := service.repository.GetInvestigationCase(ctx, input.CaseID)
	if err != nil {
		return service.rejectView(ctx, input, "case_not_found", err, now)
	}
	if caseRecord.Status != InvestigationCaseOpen {
		return service.rejectView(ctx, input, "case_closed", ErrInvestigationClosed, now)
	}
	grant, err := service.repository.FindInvestigationAccessGrant(ctx, AccessGrantLookup{CaseID: input.CaseID, ActorIdentityID: input.Session.IdentityID, SessionID: input.Session.SessionID, At: now})
	if err != nil || grant.ExpiresAt.IsZero() || !grant.ExpiresAt.After(now) || grant.ActorIdentityID != input.Session.IdentityID || grant.SessionID != input.Session.SessionID {
		return service.rejectView(ctx, input, "grant_invalid", ErrInvestigationForbidden, now)
	}
	candidates, err := service.repository.ListInvestigationCandidates(ctx, input.CaseID)
	if err != nil {
		return service.rejectView(ctx, input, "candidate_lookup_failed", ErrInvestigationNotFound, now)
	}
	var candidate *InvestigationCandidate
	for index := range candidates {
		if candidates[index].AuditID == input.AuditID {
			candidate = &candidates[index]
			break
		}
	}
	if candidate == nil {
		return service.rejectView(ctx, input, "audit_outside_case", ErrInvestigationForbidden, now)
	}
	view := CaseRawView{AuditID: input.AuditID, Request: CaseContentView{Status: ContentViewUnavailable}, Response: CaseContentView{Status: ContentViewUnavailable}}
	requestView, requestDetail, requestFatal := service.readCaseContent(ctx, input.AuditID, ContentKindRequest, CaptureStatusComplete, now)
	responseView, responseDetail, responseFatal := service.readCaseContent(ctx, input.AuditID, ContentKindResponse, candidate.CaptureStatus, now)
	view.Request, view.Response = requestView, responseView
	detail := "case_raw_viewed"
	outcome := access.SecurityEventSuccess
	if requestDetail != "" {
		detail, outcome = requestDetail, access.SecurityEventFailure
	}
	if responseDetail != "" {
		detail, outcome = responseDetail, access.SecurityEventFailure
	}
	if requestFatal || responseFatal {
		view = CaseRawView{}
	}
	if err := service.appendViewEvent(ctx, input, caseRecord, outcome, detail, now); err != nil {
		return CaseRawView{}, err
	}
	if requestFatal || responseFatal {
		return CaseRawView{}, ErrInvestigationForbidden
	}
	return view, nil
}

func (service *InvestigationService) rejectView(ctx context.Context, input CaseRawViewInput, detail string, result error, now time.Time) (CaseRawView, error) {
	if input.Session.IdentityID == "" || strings.TrimSpace(input.RequestID) == "" {
		return CaseRawView{}, result
	}
	eventID, err := service.newID()
	if err != nil {
		return CaseRawView{}, access.ErrSecurityAuditUnavailable
	}
	event := access.SecurityEvent{ID: eventID, EventType: "investigation_case_raw_view", ActorIdentityID: input.Session.IdentityID, TargetAuditID: input.AuditID, InvestigationCaseID: input.CaseID, RequestID: input.RequestID, Outcome: access.SecurityEventDenied, DetailCode: detail, OccurredAt: now}
	if err := service.repository.AppendSecurityEvent(ctx, event); err != nil {
		return CaseRawView{}, access.ErrSecurityAuditUnavailable
	}
	return CaseRawView{}, result
}

func (service *InvestigationService) appendViewEvent(ctx context.Context, input CaseRawViewInput, caseRecord InvestigationCase, outcome access.SecurityEventOutcome, detail string, now time.Time) error {
	eventID, err := service.newID()
	if err != nil {
		return access.ErrSecurityAuditUnavailable
	}
	event := access.SecurityEvent{ID: eventID, EventType: "investigation_case_raw_view", ActorIdentityID: input.Session.IdentityID, TargetIdentityID: caseRecord.SubjectIdentityID, TargetAuditID: input.AuditID, InvestigationCaseID: input.CaseID, RequestID: input.RequestID, Outcome: outcome, DetailCode: detail, OccurredAt: now}
	if err := service.repository.AppendSecurityEvent(ctx, event); err != nil {
		return access.ErrSecurityAuditUnavailable
	}
	return nil
}

func (service *InvestigationService) List(ctx context.Context, session access.ActivePortalSession, filter InvestigationCaseListFilter) (InvestigationCasePage, error) {
	if service == nil || service.repository == nil || session.IdentityID == "" || session.Role != access.RoleSystemAdministrator || filter.Limit < 1 || filter.Limit > maxInvestigationCandidates {
		return InvestigationCasePage{}, ErrInvestigationForbidden
	}
	return service.repository.ListInvestigationCases(ctx, filter)
}

func (service *InvestigationService) Candidates(ctx context.Context, session access.ActivePortalSession, caseID string) ([]InvestigationCandidate, error) {
	if service == nil || service.repository == nil || session.IdentityID == "" || session.Role != access.RoleSystemAdministrator || !validInvestigationID(caseID) {
		return nil, ErrInvestigationForbidden
	}
	candidates, err := service.repository.ListInvestigationCandidates(ctx, caseID)
	if err != nil {
		return nil, err
	}
	if len(candidates) > maxInvestigationCandidates {
		return nil, ErrInvestigationScopeTooBroad
	}
	return candidates, nil
}

func (service *InvestigationService) IssueGrant(ctx context.Context, input IssueInvestigationGrantInput) (AccessGrant, error) {
	if service == nil || service.repository == nil || service.newID == nil || strings.TrimSpace(input.RequestID) == "" || !input.Confirmed || !validInvestigationID(input.CaseID) {
		return AccessGrant{}, ErrInvalidInvestigation
	}
	now := service.now().UTC()
	if input.Session.IdentityID == "" || input.Session.SessionID == "" || input.Session.Role != access.RoleSystemAdministrator {
		return AccessGrant{}, ErrInvestigationForbidden
	}
	if input.Session.AbsoluteExpiresAt.IsZero() || !input.Session.AbsoluteExpiresAt.After(now) {
		return AccessGrant{}, ErrInvestigationForbidden
	}
	if input.Session.ReauthenticatedUntil == nil || !input.Session.ReauthenticatedUntil.After(now) {
		return AccessGrant{}, access.ErrReauthenticationRequired
	}
	caseRecord, err := service.repository.GetInvestigationCase(ctx, input.CaseID)
	if err != nil {
		return AccessGrant{}, err
	}
	if caseRecord.Status != InvestigationCaseOpen {
		return AccessGrant{}, ErrInvestigationClosed
	}
	grantID, err := service.newID()
	if err != nil {
		return AccessGrant{}, access.ErrSecurityAuditUnavailable
	}
	expiresAt := now.Add(investigationGrantLife)
	if expiresAt.After(input.Session.AbsoluteExpiresAt) {
		expiresAt = input.Session.AbsoluteExpiresAt
	}
	grant := AccessGrant{ID: grantID, CaseID: input.CaseID, ActorIdentityID: input.Session.IdentityID, SessionID: input.Session.SessionID, IssuedAt: now, ExpiresAt: expiresAt}
	eventID, err := service.newID()
	if err != nil {
		return AccessGrant{}, access.ErrSecurityAuditUnavailable
	}
	event := access.SecurityEvent{ID: eventID, EventType: "investigation_access_grant", ActorIdentityID: input.Session.IdentityID, TargetIdentityID: caseRecord.SubjectIdentityID, InvestigationCaseID: input.CaseID, RequestID: input.RequestID, Outcome: access.SecurityEventSuccess, DetailCode: "grant_issued", OccurredAt: now}
	if err := service.repository.CreateInvestigationAccessGrant(ctx, grant, event); err != nil {
		return AccessGrant{}, err
	}
	return grant, nil
}

func (service *InvestigationService) Close(ctx context.Context, input InvestigationCaseClosure) error {
	if service == nil || service.repository == nil || service.newID == nil || strings.TrimSpace(input.RequestID) == "" || !input.Confirmed || !validInvestigationID(input.CaseID) || input.ClosedAt.IsZero() {
		return ErrInvalidInvestigation
	}
	now := service.now().UTC()
	if input.ClosedAt.After(now) || input.Actor.IdentityID == "" || input.Actor.SessionID == "" || input.Actor.Role != access.RoleSystemAdministrator || input.Actor.AbsoluteExpiresAt.IsZero() || !input.Actor.AbsoluteExpiresAt.After(now) {
		return ErrInvestigationForbidden
	}
	if input.Actor.ReauthenticatedUntil == nil || !input.Actor.ReauthenticatedUntil.After(now) {
		return access.ErrReauthenticationRequired
	}
	if input.Disposition != InvestigationConfirmedViolation && input.Disposition != InvestigationNoViolation && input.Disposition != InvestigationInconclusive {
		return ErrInvalidInvestigation
	}
	if len([]rune(strings.TrimSpace(input.Note))) > maxInvestigationText {
		return ErrInvalidInvestigation
	}
	caseRecord, err := service.repository.GetInvestigationCase(ctx, input.CaseID)
	if err != nil {
		return err
	}
	if caseRecord.Status != InvestigationCaseOpen {
		return ErrInvestigationClosed
	}
	eventID, err := service.newID()
	if err != nil {
		return access.ErrSecurityAuditUnavailable
	}
	closure := input
	closure.Note = strings.TrimSpace(closure.Note)
	event := access.SecurityEvent{ID: eventID, EventType: "investigation_case", ActorIdentityID: input.Actor.IdentityID, TargetIdentityID: caseRecord.SubjectIdentityID, InvestigationCaseID: input.CaseID, RequestID: input.RequestID, Outcome: access.SecurityEventSuccess, DetailCode: "case_closed", OccurredAt: input.ClosedAt.UTC(), Reason: string(input.Disposition)}
	if err := service.repository.CloseInvestigationCase(ctx, closure, event); err != nil {
		return err
	}
	return nil
}

func (service *InvestigationService) readCaseContent(ctx context.Context, auditID string, kind ContentKind, captureStatus CaptureStatus, now time.Time) (CaseContentView, string, bool) {
	record, err := service.repository.ReadRawContent(ctx, RawContentLookup{AuditID: auditID, ContentKind: kind, VisibleAt: now})
	if err != nil || !record.ExpiresAt.After(now) {
		return CaseContentView{Status: ContentViewUnavailable}, "raw_content_unavailable", false
	}
	if record.AuditID != auditID || record.ContentKind != kind {
		return CaseContentView{Status: ContentViewUnavailable}, "integrity_failed", true
	}
	bytes, err := service.decryptor.Decrypt(record.Content, rawViewEncryptionContext(record))
	if err != nil {
		clear(bytes)
		return CaseContentView{Status: ContentViewUnavailable}, "decryption_failed", true
	}
	if captureStatus == CaptureStatusTruncated || captureStatus == CaptureStatusIncomplete {
		return CaseContentView{Status: contentViewStatus(captureStatus), Fragment: boundedUTF8Fragment(bytes)}, "", false
	}
	if !json.Valid(bytes) {
		clear(bytes)
		return CaseContentView{Status: ContentViewUnavailable}, "integrity_failed", true
	}
	return CaseContentView{Status: ContentViewComplete, JSON: json.RawMessage(append([]byte(nil), bytes...))}, "", false
}

func contentViewStatus(status CaptureStatus) ContentViewStatus {
	if status == CaptureStatusTruncated {
		return ContentViewTruncated
	}
	return ContentViewIncomplete
}

func boundedUTF8Fragment(value []byte) string {
	if len(value) > maxInvestigationFragment {
		value = value[:maxInvestigationFragment]
	}
	for len(value) > 0 && !utf8.Valid(value) {
		value = value[:len(value)-1]
	}
	return string(value)
}

func validInvestigationText(value string) bool {
	value = strings.TrimSpace(value)
	return value != "" && len([]rune(value)) <= maxInvestigationText
}

func validInvestigationID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}

func investigationID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	bytes[6] = (bytes[6] & 0x0f) | 0x40
	bytes[8] = (bytes[8] & 0x3f) | 0x80
	encoded := make([]byte, 36)
	hex.Encode(encoded[0:8], bytes[0:4])
	encoded[8] = '-'
	hex.Encode(encoded[9:13], bytes[4:6])
	encoded[13] = '-'
	hex.Encode(encoded[14:18], bytes[6:8])
	encoded[18] = '-'
	hex.Encode(encoded[19:23], bytes[8:10])
	encoded[23] = '-'
	hex.Encode(encoded[24:36], bytes[10:16])
	return string(encoded), nil
}
