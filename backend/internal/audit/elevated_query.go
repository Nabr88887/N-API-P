package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"n-api-p/internal/access"
)

const (
	ElevatedAuditMaxQueryPageSize = 1000
	MaxElevatedAuditBatchIDs      = 1000
	maxElevatedAuditFullText      = 500
	maxElevatedAuditCursorBytes   = 2048
	elevatedAuditQueryTimeout     = 10 * time.Second
	elevatedAuditPageBytes        = 8 << 20
)

var (
	ErrInvalidElevatedAuditQuery  = errors.New("invalid elevated audit query")
	ErrInvalidElevatedAuditCursor = errors.New("invalid elevated audit cursor")
	ErrElevatedAuditQueryFailed   = errors.New("elevated audit query failed")
	ErrElevatedAuditDecryption    = errors.New("elevated audit content decryption failed")
)

type AuditUsage struct {
	InputTokens  int64 `json:"input_tokens"`
	OutputTokens int64 `json:"output_tokens"`
	TotalTokens  int64 `json:"total_tokens"`
}

type ElevatedAuditCaptureStatus string

const (
	ElevatedAuditCaptureStatusPending     ElevatedAuditCaptureStatus = "pending"
	ElevatedAuditCaptureStatusComplete    ElevatedAuditCaptureStatus = "complete"
	ElevatedAuditCaptureStatusTruncated   ElevatedAuditCaptureStatus = "truncated"
	ElevatedAuditCaptureStatusIncomplete  ElevatedAuditCaptureStatus = "incomplete"
	ElevatedAuditCaptureStatusUnavailable ElevatedAuditCaptureStatus = "unavailable"
)

type ElevatedAuditCandidate struct {
	Metadata Metadata
	Usage    *AuditUsage
}

type ElevatedAuditSelection struct {
	IdentityID            *string
	ServiceAccountID      *string
	ResponsibleIdentityID *string
	From                  *time.Time
	To                    *time.Time
	ModelID               *string
	CaptureStatus         *CaptureStatus
	Outcome               *AuditOutcome
	OwnerKind             *OwnerKind
	AuditIDs              []string
	Cursor                *ElevatedAuditPosition
	Limit                 int
	VisibleAt             time.Time
	SnapshotAt            time.Time
}

type ElevatedAuditPosition struct {
	CreatedAt time.Time
	ID        string
}

type ElevatedAuditQuery struct {
	IdentityID            *string        `json:"identity_id,omitempty"`
	ServiceAccountID      *string        `json:"service_account_id,omitempty"`
	ResponsibleIdentityID *string        `json:"responsible_identity_id,omitempty"`
	From                  *time.Time     `json:"from,omitempty"`
	To                    *time.Time     `json:"to,omitempty"`
	ModelID               *string        `json:"model_id,omitempty"`
	CaptureStatus         *CaptureStatus `json:"capture_status,omitempty"`
	Outcome               *AuditOutcome  `json:"outcome,omitempty"`
	OwnerKind             *OwnerKind     `json:"owner_kind,omitempty"`
	FullText              string         `json:"full_text,omitempty"`
	AuditIDs              []string       `json:"audit_ids,omitempty"`
	Cursor                string         `json:"cursor,omitempty"`
	Limit                 int            `json:"limit"`
}

type ElevatedAuditQueryInput struct {
	Session   access.ActivePortalSession
	RequestID string
	Query     ElevatedAuditQuery
	EventType string
}

type ElevatedAuditRecord struct {
	ID                    string                     `json:"id"`
	RequestID             string                     `json:"request_id"`
	OwnerKind             OwnerKind                  `json:"owner_kind"`
	IdentityID            string                     `json:"identity_id,omitempty"`
	ServiceAccountID      string                     `json:"service_account_id,omitempty"`
	ResponsibleIdentityID string                     `json:"responsible_identity_id,omitempty"`
	TeamID                string                     `json:"team_id"`
	ModelID               string                     `json:"model_id"`
	RequestCaptureStatus  ElevatedAuditCaptureStatus `json:"request_capture_status"`
	ResponseCaptureStatus ElevatedAuditCaptureStatus `json:"response_capture_status"`
	Outcome               AuditOutcome               `json:"outcome"`
	CreatedAt             time.Time                  `json:"created_at"`
	UpdatedAt             time.Time                  `json:"updated_at"`
	CompletedAt           *time.Time                 `json:"completed_at,omitempty"`
	RequestJSON           json.RawMessage            `json:"request,omitempty"`
	ResponseJSON          json.RawMessage            `json:"response,omitempty"`
	RequestFragment       string                     `json:"request_fragment,omitempty"`
	ResponseFragment      string                     `json:"response_fragment,omitempty"`
	Usage                 *AuditUsage                `json:"usage,omitempty"`
}

type ElevatedAuditPage struct {
	Records      []ElevatedAuditRecord
	NextCursor   string
	nextPosition *ElevatedAuditPosition
}

func (page *ElevatedAuditPage) Clear() {
	for index := range page.Records {
		clear(page.Records[index].RequestJSON)
		clear(page.Records[index].ResponseJSON)
		page.Records[index].RequestJSON = nil
		page.Records[index].ResponseJSON = nil
		page.Records[index].RequestFragment = ""
		page.Records[index].ResponseFragment = ""
	}
}

type ElevatedAuditQueryRepository interface {
	FindElevatedAuditGrant(context.Context, ElevatedAuditGrantLookup) (ElevatedAuditGrant, error)
	ListElevatedAuditCandidates(context.Context, ElevatedAuditSelection) ([]ElevatedAuditCandidate, error)
	ReadRawContent(context.Context, RawContentLookup) (RawContentRecord, error)
	AppendSecurityEvent(context.Context, access.SecurityEvent) error
}

type ElevatedAuditQueryDecryptor interface {
	Decrypt(EncryptedContent, EncryptionContext) ([]byte, error)
}

type ElevatedAuditQueryService struct {
	repository   ElevatedAuditQueryRepository
	decryptor    ElevatedAuditQueryDecryptor
	now          func() time.Time
	newID        func() (string, error)
	cursorKey    []byte
	queryTimeout time.Duration
}

func NewElevatedAuditQueryService(repository ElevatedAuditQueryRepository, decryptor ElevatedAuditQueryDecryptor) (*ElevatedAuditQueryService, error) {
	if repository == nil || decryptor == nil {
		return nil, ErrInvalidElevatedAuditQuery
	}
	cursorKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, cursorKey); err != nil {
		return nil, ErrInvalidElevatedAuditQuery
	}
	return &ElevatedAuditQueryService{repository: repository, decryptor: decryptor, now: time.Now, newID: newRawViewRequestID, cursorKey: cursorKey, queryTimeout: elevatedAuditQueryTimeout}, nil
}

func (service *ElevatedAuditQueryService) Query(ctx context.Context, input ElevatedAuditQueryInput) (ElevatedAuditPage, error) {
	if service == nil || service.repository == nil || service.decryptor == nil || service.now == nil || service.newID == nil || len(service.cursorKey) == 0 || service.queryTimeout <= 0 {
		return ElevatedAuditPage{}, ErrInvalidElevatedAuditQuery
	}
	queryCtx, cancel := context.WithTimeout(ctx, service.queryTimeout)
	defer cancel()
	now := service.now().UTC()
	if !validElevatedAuditSession(input.Session, now) {
		return ElevatedAuditPage{}, access.ErrForbidden
	}
	requestID := strings.TrimSpace(input.RequestID)
	if !validMetadataID(requestID) {
		return ElevatedAuditPage{}, ErrInvalidElevatedAuditQuery
	}
	normalized, selection, err := normalizeElevatedAuditQuery(input.Query, now)
	if err != nil {
		return ElevatedAuditPage{}, err
	}
	grant, err := service.repository.FindElevatedAuditGrant(queryCtx, ElevatedAuditGrantLookup{ActorIdentityID: input.Session.IdentityID, SessionID: input.Session.SessionID, At: now})
	if errors.Is(err, ErrElevatedAuditGrantNotFound) {
		return ElevatedAuditPage{}, ErrElevatedAuditGrantNotFound
	}
	if err != nil {
		return ElevatedAuditPage{}, err
	}
	if grant.ActorIdentityID != input.Session.IdentityID || grant.SessionID != input.Session.SessionID || grant.RevokedAt != nil || !grant.ExpiresAt.After(now) {
		return ElevatedAuditPage{}, ErrElevatedAuditGrantNotFound
	}
	queryHash := hashElevatedAuditQuery(normalized)
	if input.Query.Cursor != "" {
		cursor, err := service.decodeCursor(input.Query.Cursor, grant.ID, queryHash, now)
		if err != nil {
			return ElevatedAuditPage{}, err
		}
		if cursor.VisibleAt.Before(grant.IssuedAt) {
			return ElevatedAuditPage{}, ErrInvalidElevatedAuditCursor
		}
		selection.Cursor = &cursor.Position
		selection.SnapshotAt = cursor.VisibleAt
	}
	eventType := input.EventType
	if eventType != "audit_batch_view" {
		eventType = "audit_query"
	}
	if err := service.appendQueryEvent(queryCtx, eventType, input.Session, grant, requestID, normalized, nil, access.SecurityEventSuccess, "authorized", now); err != nil {
		return ElevatedAuditPage{}, err
	}

	page, queryErr := service.collect(queryCtx, input.Session, grant, normalized, selection)
	if queryErr == nil {
		queryErr = service.checkGrant(queryCtx, input.Session, grant.ID)
	}
	if queryErr != nil {
		page.Clear()
		eventCtx, cancelEvent := context.WithTimeout(context.WithoutCancel(ctx), service.queryTimeout)
		defer cancelEvent()
		eventErr := service.appendQueryEvent(eventCtx, eventType, input.Session, grant, requestID, normalized, nil, access.SecurityEventFailure, "query_failed", service.now().UTC())
		return ElevatedAuditPage{}, errors.Join(queryErr, eventErr)
	}
	count := int64(len(page.Records))
	if err := service.appendQueryEvent(queryCtx, eventType, input.Session, grant, requestID, normalized, &count, access.SecurityEventSuccess, "query_completed", service.now().UTC()); err != nil {
		page.Clear()
		return ElevatedAuditPage{}, err
	}
	if page.NextCursor != "" && page.nextPosition != nil {
		page.NextCursor = service.encodeCursor(grant.ID, queryHash, selection.SnapshotAt, *page.nextPosition)
	}
	return page, nil
}

func (service *ElevatedAuditQueryService) collect(ctx context.Context, session access.ActivePortalSession, grant ElevatedAuditGrant, query normalizedElevatedAuditQuery, selection ElevatedAuditSelection) (result ElevatedAuditPage, err error) {
	page := ElevatedAuditPage{Records: make([]ElevatedAuditRecord, 0, query.Limit)}
	defer func() {
		if err != nil {
			page.Clear()
		}
	}()
	position := selection.Cursor
	pageBytes := 0
	for {
		if err := ctx.Err(); err != nil {
			return ElevatedAuditPage{}, err
		}
		selection.Cursor = position
		selection.VisibleAt = service.now().UTC()
		candidates, err := service.repository.ListElevatedAuditCandidates(ctx, selection)
		if err != nil {
			return ElevatedAuditPage{}, fmt.Errorf("%w: select candidates: %v", ErrElevatedAuditQueryFailed, err)
		}
		for index, candidate := range candidates {
			if err := service.checkGrant(ctx, session, grant.ID); err != nil {
				return ElevatedAuditPage{}, err
			}
			record, matched, err := service.readCandidate(ctx, candidate, query.FullText, service.now().UTC(), true)
			if err != nil {
				return ElevatedAuditPage{}, err
			}
			previous := position
			position = candidatePosition(candidate)
			if !matched {
				continue
			}
			recordBytes := len(record.RequestJSON) + len(record.ResponseJSON) + len(record.RequestFragment) + len(record.ResponseFragment)
			if pageBytes+recordBytes > elevatedAuditPageBytes && len(page.Records) > 0 {
				clear(record.RequestJSON)
				clear(record.ResponseJSON)
				page.NextCursor = "pending"
				page.nextPosition = previous
				return page, nil
			}
			pageBytes += recordBytes
			page.Records = append(page.Records, record)
			if len(page.Records) == query.Limit {
				if index < len(candidates)-1 || len(candidates) == selection.Limit {
					page.NextCursor = "pending"
					page.nextPosition = position
				}
				return page, nil
			}
		}
		if len(candidates) < selection.Limit {
			return page, nil
		}
		if len(candidates) == 0 {
			return page, nil
		}
	}
}

func (service *ElevatedAuditQueryService) checkGrant(ctx context.Context, session access.ActivePortalSession, grantID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	now := service.now().UTC()
	if !validElevatedAuditSession(session, now) {
		return access.ErrForbidden
	}
	grant, err := service.repository.FindElevatedAuditGrant(ctx, ElevatedAuditGrantLookup{ActorIdentityID: session.IdentityID, SessionID: session.SessionID, At: now})
	if err != nil {
		return err
	}
	if grant.ActorIdentityID != session.IdentityID || grant.SessionID != session.SessionID {
		return access.ErrForbidden
	}
	if grant.ID != grantID || grant.RevokedAt != nil {
		return ErrElevatedAuditGrantRevoked
	}
	if !grant.ExpiresAt.After(now) {
		return ErrElevatedAuditGrantExpired
	}
	return nil
}

func (service *ElevatedAuditQueryService) readCandidate(ctx context.Context, candidate ElevatedAuditCandidate, fullText string, visibleAt time.Time, tolerateUnavailable bool) (ElevatedAuditRecord, bool, error) {
	metadata := candidate.Metadata
	record := ElevatedAuditRecord{
		ID: metadata.ID, RequestID: metadata.RequestID, OwnerKind: metadata.OwnerKind,
		IdentityID: metadata.IdentityID, ServiceAccountID: metadata.ServiceAccountID, ResponsibleIdentityID: metadata.ResponsibleIdentityID,
		TeamID: metadata.TeamID, ModelID: metadata.ModelID, RequestCaptureStatus: ElevatedAuditCaptureStatus(metadata.CaptureStatus),
		ResponseCaptureStatus: ElevatedAuditCaptureStatus(metadata.CaptureStatus), Outcome: metadata.Outcome, CreatedAt: metadata.CreatedAt,
		UpdatedAt: metadata.UpdatedAt, CompletedAt: metadata.CompletedAt, Usage: candidate.Usage,
	}
	requestJSON, requestAvailable, err := service.readCandidateContent(ctx, metadata, ContentKindRequest, visibleAt)
	if tolerateUnavailable && errors.Is(err, ErrElevatedAuditDecryption) {
		err = nil
	}
	if err != nil {
		return ElevatedAuditRecord{}, false, err
	}
	responseJSON, responseAvailable, err := service.readCandidateContent(ctx, metadata, ContentKindResponse, visibleAt)
	if tolerateUnavailable && errors.Is(err, ErrElevatedAuditDecryption) {
		err = nil
	}
	if err != nil {
		clear(requestJSON)
		return ElevatedAuditRecord{}, false, err
	}
	if !requestAvailable {
		record.RequestCaptureStatus = ElevatedAuditCaptureStatusUnavailable
	}
	if !responseAvailable {
		record.ResponseCaptureStatus = ElevatedAuditCaptureStatusUnavailable
	}
	if fullText != "" && !containsElevatedAuditText(requestJSON, responseJSON, fullText) {
		clear(requestJSON)
		clear(responseJSON)
		return ElevatedAuditRecord{}, false, nil
	}
	if metadata.CaptureStatus == CaptureStatusTruncated || metadata.CaptureStatus == CaptureStatusIncomplete {
		record.RequestFragment = boundedUTF8Fragment(requestJSON)
		record.ResponseFragment = boundedUTF8Fragment(responseJSON)
		clear(requestJSON)
		clear(responseJSON)
		return record, true, nil
	}
	record.RequestJSON = requestJSON
	record.ResponseJSON = responseJSON
	return record, true, nil
}

func (service *ElevatedAuditQueryService) readCandidateContent(ctx context.Context, metadata Metadata, kind ContentKind, visibleAt time.Time) (json.RawMessage, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if metadata.CaptureStatus == CaptureStatusPending {
		return nil, false, nil
	}
	content, err := service.repository.ReadRawContent(ctx, RawContentLookup{AuditID: metadata.ID, ContentKind: kind, VisibleAt: visibleAt})
	if errors.Is(err, ErrRawContentUnavailable) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("%w: read %s content: %v", ErrElevatedAuditQueryFailed, kind, err)
	}
	if !content.ExpiresAt.After(service.now().UTC()) {
		clearEncryptedContent(&content.Content)
		return nil, false, nil
	}
	if err := ctx.Err(); err != nil {
		clearEncryptedContent(&content.Content)
		return nil, false, err
	}
	if content.AuditID != metadata.ID || content.ContentKind != kind {
		clearEncryptedContent(&content.Content)
		return nil, false, ErrElevatedAuditDecryption
	}
	decrypted, err := service.decryptor.Decrypt(content.Content, rawViewEncryptionContext(content))
	clearEncryptedContent(&content.Content)
	if err != nil || (metadata.CaptureStatus == CaptureStatusComplete && !json.Valid(decrypted)) {
		clear(decrypted)
		return nil, false, ErrElevatedAuditDecryption
	}
	if !content.ExpiresAt.After(service.now().UTC()) {
		clear(decrypted)
		return nil, false, nil
	}
	return json.RawMessage(decrypted), true, nil
}

func (service *ElevatedAuditQueryService) appendQueryEvent(ctx context.Context, eventType string, session access.ActivePortalSession, grant ElevatedAuditGrant, requestID string, query normalizedElevatedAuditQuery, count *int64, outcome access.SecurityEventOutcome, detail string, occurredAt time.Time) error {
	eventID, err := service.newID()
	if err != nil {
		return access.ErrSecurityAuditUnavailable
	}
	event := access.SecurityEvent{ID: eventID, EventType: eventType, ActorIdentityID: session.IdentityID, SessionID: session.SessionID, GrantID: grant.ID, RequestID: requestID, Outcome: outcome, Reason: grant.Purpose, DetailCode: detail, OccurredAt: occurredAt}
	event.QueryMetadata = query.auditMetadata()
	event.ResultCount = count
	if err := service.repository.AppendSecurityEvent(ctx, event); err != nil {
		return access.ErrSecurityAuditUnavailable
	}
	return nil
}

type normalizedElevatedAuditQuery struct {
	IdentityID            string     `json:"identity_id,omitempty"`
	ServiceAccountID      string     `json:"service_account_id,omitempty"`
	ResponsibleIdentityID string     `json:"responsible_identity_id,omitempty"`
	From                  *time.Time `json:"from,omitempty"`
	To                    *time.Time `json:"to,omitempty"`
	ModelID               string     `json:"model_id,omitempty"`
	CaptureStatus         string     `json:"capture_status,omitempty"`
	Outcome               string     `json:"outcome,omitempty"`
	OwnerKind             string     `json:"owner_kind,omitempty"`
	FullText              string     `json:"full_text,omitempty"`
	AuditIDs              []string   `json:"audit_ids,omitempty"`
	Limit                 int        `json:"-"`
}

func (query normalizedElevatedAuditQuery) auditMetadata() *access.AuditQueryMetadata {
	return &access.AuditQueryMetadata{IdentityID: query.IdentityID, ServiceAccountID: query.ServiceAccountID, ResponsibleIdentityID: query.ResponsibleIdentityID,
		From: query.From, To: query.To, ModelFilter: query.ModelID != "", CaptureStatus: query.CaptureStatus, Outcome: query.Outcome,
		OwnerKind: query.OwnerKind, FullText: query.FullText != "", BatchSize: len(query.AuditIDs)}
}

func normalizeElevatedAuditQuery(input ElevatedAuditQuery, visibleAt time.Time) (normalizedElevatedAuditQuery, ElevatedAuditSelection, error) {
	if input.Limit < 1 || input.Limit > ElevatedAuditMaxQueryPageSize || len([]rune(strings.TrimSpace(input.FullText))) > maxElevatedAuditFullText || len(input.AuditIDs) > MaxElevatedAuditBatchIDs {
		return normalizedElevatedAuditQuery{}, ElevatedAuditSelection{}, ErrInvalidElevatedAuditQuery
	}
	normalized := normalizedElevatedAuditQuery{FullText: strings.ToLower(strings.TrimSpace(input.FullText)), Limit: input.Limit, AuditIDs: append([]string(nil), input.AuditIDs...)}
	sort.Strings(normalized.AuditIDs)
	selection := ElevatedAuditSelection{Limit: input.Limit + 1, VisibleAt: visibleAt, SnapshotAt: visibleAt}
	selection.AuditIDs = normalized.AuditIDs
	for _, field := range []struct {
		value *string
		name  *string
	}{
		{input.IdentityID, &normalized.IdentityID}, {input.ServiceAccountID, &normalized.ServiceAccountID}, {input.ResponsibleIdentityID, &normalized.ResponsibleIdentityID}, {input.ModelID, &normalized.ModelID},
	} {
		if field.value == nil {
			continue
		}
		value := strings.TrimSpace(*field.value)
		if value == "" {
			return normalizedElevatedAuditQuery{}, ElevatedAuditSelection{}, ErrInvalidElevatedAuditQuery
		}
		*field.name = value
	}
	for _, value := range []string{normalized.IdentityID, normalized.ServiceAccountID, normalized.ResponsibleIdentityID} {
		if value != "" && !validMetadataID(value) {
			return normalizedElevatedAuditQuery{}, ElevatedAuditSelection{}, ErrInvalidElevatedAuditQuery
		}
	}
	if len(normalized.ModelID) > 256 {
		return normalizedElevatedAuditQuery{}, ElevatedAuditSelection{}, ErrInvalidElevatedAuditQuery
	}
	for index, auditID := range normalized.AuditIDs {
		if !validMetadataID(strings.TrimSpace(auditID)) {
			return normalizedElevatedAuditQuery{}, ElevatedAuditSelection{}, ErrInvalidElevatedAuditQuery
		}
		normalized.AuditIDs[index] = strings.TrimSpace(auditID)
	}
	sort.Strings(normalized.AuditIDs)
	if normalized.IdentityID != "" {
		selection.IdentityID = &normalized.IdentityID
	}
	if normalized.ServiceAccountID != "" {
		selection.ServiceAccountID = &normalized.ServiceAccountID
	}
	if normalized.ResponsibleIdentityID != "" {
		selection.ResponsibleIdentityID = &normalized.ResponsibleIdentityID
	}
	if normalized.ModelID != "" {
		selection.ModelID = &normalized.ModelID
	}
	if input.From != nil {
		value := input.From.UTC()
		normalized.From = &value
		selection.From = &value
	}
	if input.To != nil {
		value := input.To.UTC()
		normalized.To = &value
		selection.To = &value
	}
	if normalized.From != nil && normalized.To != nil && !normalized.From.Before(*normalized.To) {
		return normalizedElevatedAuditQuery{}, ElevatedAuditSelection{}, ErrInvalidElevatedAuditQuery
	}
	if input.CaptureStatus != nil {
		if !validCaptureStatus(*input.CaptureStatus) {
			return normalizedElevatedAuditQuery{}, ElevatedAuditSelection{}, ErrInvalidElevatedAuditQuery
		}
		normalized.CaptureStatus = string(*input.CaptureStatus)
		selection.CaptureStatus = input.CaptureStatus
	}
	if input.Outcome != nil {
		if !validAuditOutcome(*input.Outcome) {
			return normalizedElevatedAuditQuery{}, ElevatedAuditSelection{}, ErrInvalidElevatedAuditQuery
		}
		normalized.Outcome = string(*input.Outcome)
		selection.Outcome = input.Outcome
	}
	if input.OwnerKind != nil {
		if *input.OwnerKind != OwnerKindPersonal && *input.OwnerKind != OwnerKindService {
			return normalizedElevatedAuditQuery{}, ElevatedAuditSelection{}, ErrInvalidElevatedAuditQuery
		}
		normalized.OwnerKind = string(*input.OwnerKind)
		selection.OwnerKind = input.OwnerKind
	}
	return normalized, selection, nil
}

func validCaptureStatus(status CaptureStatus) bool {
	switch status {
	case CaptureStatusPending, CaptureStatusComplete, CaptureStatusTruncated, CaptureStatusIncomplete:
		return true
	default:
		return false
	}
}

func validAuditOutcome(outcome AuditOutcome) bool {
	switch outcome {
	case AuditOutcomePending, AuditOutcomeSuccess, AuditOutcomeUpstreamError, AuditOutcomeCancelled, AuditOutcomeLocalError:
		return true
	default:
		return false
	}
}

func containsElevatedAuditText(requestJSON, responseJSON json.RawMessage, query string) bool {
	requestText := bytes.ToLower(requestJSON)
	responseText := bytes.ToLower(responseJSON)
	defer clear(requestText)
	defer clear(responseText)
	return bytes.Contains(requestText, []byte(query)) || bytes.Contains(responseText, []byte(query))
}

func candidatePosition(candidate ElevatedAuditCandidate) *ElevatedAuditPosition {
	position := ElevatedAuditPosition{CreatedAt: candidate.Metadata.CreatedAt, ID: candidate.Metadata.ID}
	return &position
}

type elevatedAuditCursorPayload struct {
	GrantID   string                `json:"grant_id"`
	QueryHash string                `json:"query_hash"`
	VisibleAt time.Time             `json:"visible_at"`
	Position  ElevatedAuditPosition `json:"position"`
}

func hashElevatedAuditQuery(query normalizedElevatedAuditQuery) string {
	payload, _ := json.Marshal(query)
	hash := sha256.Sum256(payload)
	return fmt.Sprintf("%x", hash[:])
}

func (service *ElevatedAuditQueryService) encodeCursor(grantID, queryHash string, visibleAt time.Time, position ElevatedAuditPosition) string {
	payload, _ := json.Marshal(elevatedAuditCursorPayload{GrantID: grantID, QueryHash: queryHash, VisibleAt: visibleAt.UTC(), Position: position})
	mac := hmac.New(sha256.New, service.cursorKey)
	_, _ = mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (service *ElevatedAuditQueryService) decodeCursor(value, grantID, queryHash string, now time.Time) (elevatedAuditCursorPayload, error) {
	if len(value) > maxElevatedAuditCursorBytes {
		return elevatedAuditCursorPayload{}, ErrInvalidElevatedAuditCursor
	}
	parts := strings.Split(value, ".")
	if len(parts) != 2 {
		return elevatedAuditCursorPayload{}, ErrInvalidElevatedAuditCursor
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return elevatedAuditCursorPayload{}, ErrInvalidElevatedAuditCursor
	}
	providedMAC, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return elevatedAuditCursorPayload{}, ErrInvalidElevatedAuditCursor
	}
	mac := hmac.New(sha256.New, service.cursorKey)
	_, _ = mac.Write(payload)
	if !hmac.Equal(providedMAC, mac.Sum(nil)) {
		return elevatedAuditCursorPayload{}, ErrInvalidElevatedAuditCursor
	}
	var cursor elevatedAuditCursorPayload
	if err := json.Unmarshal(payload, &cursor); err != nil || cursor.GrantID != grantID || cursor.QueryHash != queryHash || cursor.VisibleAt.IsZero() || cursor.VisibleAt.After(now) || cursor.Position.ID == "" || cursor.Position.CreatedAt.IsZero() {
		return elevatedAuditCursorPayload{}, ErrInvalidElevatedAuditCursor
	}
	return cursor, nil
}

func clearEncryptedContent(content *EncryptedContent) {
	if content == nil {
		return
	}
	clear(content.Ciphertext)
	clear(content.CipherNonce)
	clear(content.WrappedDataKey)
	clear(content.WrapNonce)
}
