package access

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"time"
)

const reauthenticationLifetime = 5 * time.Minute

var (
	ErrReauthenticationRejected    = errors.New("reauthentication rejected")
	ErrReauthenticationRequired    = errors.New("reauthentication required")
	ErrReauthenticationUnavailable = errors.New("reauthentication unavailable")
	ErrSensitiveActionForbidden    = errors.New("sensitive action forbidden")
	ErrSecurityAuditUnavailable    = errors.New("security audit unavailable")
)

type ReauthenticationRepository interface {
	FindReauthenticationCandidate(context.Context, ReauthenticationLookup) (ReauthenticationCandidate, error)
	RotatePortalSession(context.Context, PortalSessionRotation) error
}

type ReauthenticationLookup struct {
	SessionID string
	CheckedAt time.Time
}

type ReauthenticationCandidate struct {
	SessionID         string
	IdentityID        string
	Role              Role
	PasswordHash      string
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time
}

type ReauthenticationInput struct {
	SessionID string
	Password  string
}

type PortalSessionRotation struct {
	ExistingSessionID    string
	IdentityID           string
	ExpectedPasswordHash string
	NewSession           LoginSessionRecord
	ReauthenticatedUntil time.Time
	RotatedAt            time.Time
}

type ReauthenticationService struct {
	repository ReauthenticationRepository
	passwords  PasswordVerifier
	now        func() time.Time
	random     io.Reader
	newID      func() (string, error)
}

func NewReauthenticationService(repository ReauthenticationRepository, passwords PasswordVerifier) *ReauthenticationService {
	return &ReauthenticationService{
		repository: repository,
		passwords:  passwords,
		now:        time.Now,
		random:     rand.Reader,
		newID:      newIdentityID,
	}
}

// Reauthenticate verifies the current password, rotates the opaque session,
// and grants a bounded sensitive-action window without extending absolute
// session lifetime.
func (service *ReauthenticationService) Reauthenticate(ctx context.Context, input ReauthenticationInput) (PortalSession, error) {
	if service.repository == nil || service.passwords == nil || strings.TrimSpace(input.SessionID) == "" || input.Password == "" {
		return PortalSession{}, ErrReauthenticationRejected
	}
	now := service.now().UTC()
	candidate, err := service.repository.FindReauthenticationCandidate(ctx, ReauthenticationLookup{
		SessionID: input.SessionID,
		CheckedAt: now,
	})
	if errors.Is(err, ErrReauthenticationRejected) || errors.Is(err, ErrSessionInvalid) {
		return PortalSession{}, ErrReauthenticationRejected
	}
	if err != nil {
		return PortalSession{}, ErrReauthenticationUnavailable
	}
	if candidate.SessionID == "" || candidate.IdentityID == "" || candidate.PasswordHash == "" || !candidate.AbsoluteExpiresAt.After(now) {
		return PortalSession{}, ErrReauthenticationRejected
	}
	valid, err := service.passwords.Verify(input.Password, candidate.PasswordHash)
	if err != nil {
		return PortalSession{}, ErrReauthenticationUnavailable
	}
	if !valid {
		return PortalSession{}, ErrReauthenticationRejected
	}

	newSession, record, err := service.newSession(candidate, now)
	if err != nil {
		return PortalSession{}, ErrReauthenticationUnavailable
	}
	err = service.repository.RotatePortalSession(ctx, PortalSessionRotation{
		ExistingSessionID:    candidate.SessionID,
		IdentityID:           candidate.IdentityID,
		ExpectedPasswordHash: candidate.PasswordHash,
		NewSession:           record,
		ReauthenticatedUntil: record.ReauthenticatedUntil,
		RotatedAt:            now,
	})
	if errors.Is(err, ErrReauthenticationRejected) || errors.Is(err, ErrSessionInvalid) {
		return PortalSession{}, ErrReauthenticationRejected
	}
	if err != nil {
		return PortalSession{}, ErrReauthenticationUnavailable
	}
	return newSession, nil
}

func (service *ReauthenticationService) newSession(candidate ReauthenticationCandidate, now time.Time) (PortalSession, LoginSessionRecord, error) {
	id, err := service.newID()
	if err != nil {
		return PortalSession{}, LoginSessionRecord{}, err
	}
	token, err := service.randomCredential()
	if err != nil {
		return PortalSession{}, LoginSessionRecord{}, err
	}
	csrfToken, err := service.randomCredential()
	if err != nil {
		return PortalSession{}, LoginSessionRecord{}, err
	}
	absoluteExpiresAt := candidate.AbsoluteExpiresAt
	idleExpiresAt := candidate.IdleExpiresAt
	if idleExpiresAt.IsZero() || idleExpiresAt.After(now.Add(sessionIdleLifetime)) {
		idleExpiresAt = now.Add(sessionIdleLifetime)
	}
	if idleExpiresAt.After(absoluteExpiresAt) {
		idleExpiresAt = absoluteExpiresAt
	}
	reauthenticatedUntil := now.Add(reauthenticationLifetime)
	if reauthenticatedUntil.After(absoluteExpiresAt) {
		reauthenticatedUntil = absoluteExpiresAt
	}
	tokenHash := sha256.Sum256([]byte(token))
	csrfHash := sha256.Sum256([]byte(csrfToken))
	record := LoginSessionRecord{
		ID: id, IdentityID: candidate.IdentityID,
		TokenHash: tokenHash[:], CSRFTokenHash: csrfHash[:],
		CreatedAt: now, LastSeenAt: now,
		IdleExpiresAt: idleExpiresAt, AbsoluteExpiresAt: absoluteExpiresAt,
		ReauthenticatedUntil: reauthenticatedUntil,
	}
	return PortalSession{ID: id, IdentityID: candidate.IdentityID, Token: token, CSRFToken: csrfToken, ExpiresAt: absoluteExpiresAt}, record, nil
}

func (service *ReauthenticationService) randomCredential() (string, error) {
	value := make([]byte, sessionRandomBytes)
	if _, err := io.ReadFull(service.random, value); err != nil {
		return "", err
	}
	return encodeCredential(value), nil
}

type SensitiveAction string

const (
	SensitiveActionRawView                      SensitiveAction = "raw_view"
	SensitiveActionRetentionPolicy              SensitiveAction = "retention_policy_change"
	SensitiveActionCredentialCompromiseRecovery SensitiveAction = "credential_compromise_recovery"
	SensitiveActionModelAllowlist               SensitiveAction = "model_allowlist_change"
)

type SecurityEventOutcome string

const (
	SecurityEventSuccess SecurityEventOutcome = "success"
	SecurityEventDenied  SecurityEventOutcome = "denied"
	SecurityEventFailure SecurityEventOutcome = "failure"
)

type SecurityEvent struct {
	ID                     string
	EventType              string
	ActorIdentityID        string
	TargetIdentityID       string
	TargetServiceAccountID string
	TargetKeyID            string
	TargetAuditID          string
	InvestigationCaseID    string
	SessionID              string
	GrantID                string
	RequestID              string
	Outcome                SecurityEventOutcome
	Reason                 string
	DetailCode             string
	OccurredAt             time.Time
	QueryMetadata          *AuditQueryMetadata
	ResultCount            *int64
}

type AuditQueryMetadata struct {
	IdentityID            string     `json:"identity_id,omitempty"`
	ServiceAccountID      string     `json:"service_account_id,omitempty"`
	ResponsibleIdentityID string     `json:"responsible_identity_id,omitempty"`
	From                  *time.Time `json:"from,omitempty"`
	To                    *time.Time `json:"to,omitempty"`
	ModelFilter           bool       `json:"model_filter"`
	CaptureStatus         string     `json:"capture_status,omitempty"`
	Outcome               string     `json:"outcome,omitempty"`
	OwnerKind             string     `json:"owner_kind,omitempty"`
	FullText              bool       `json:"full_text"`
	BatchSize             int        `json:"batch_size"`
}

type SecurityEventWriter interface {
	AppendSecurityEvent(context.Context, SecurityEvent) error
}

func requireRecentActorReauthentication(ctx context.Context, events SecurityEventWriter, actor Actor, event SecurityEvent, now time.Time) error {
	if hasRecentActorReauthentication(actor, now) {
		return nil
	}
	event.ActorIdentityID = strings.TrimSpace(actor.IdentityID)
	event.Outcome = SecurityEventDenied
	event.DetailCode = "reauthentication_required"
	if events == nil || events.AppendSecurityEvent(ctx, event) != nil {
		return ErrSecurityAuditUnavailable
	}
	return ErrReauthenticationRequired
}

func hasRecentActorReauthentication(actor Actor, now time.Time) bool {
	return actor.ReauthenticatedUntil != nil && actor.ReauthenticatedUntil.After(now)
}

type SensitiveActionRequest struct {
	Session          ActivePortalSession
	Action           SensitiveAction
	TargetIdentityID string
	TargetAuditID    string
	RequestID        string
	Reason           string
}

type SensitiveActionExecution struct {
	TargetAuditID string
	Outcome       SecurityEventOutcome
	DetailCode    string
}

type SensitiveActionGuard struct {
	events SecurityEventWriter
	now    func() time.Time
	newID  func() (string, error)
}

func NewSensitiveActionGuard(events SecurityEventWriter) *SensitiveActionGuard {
	return &SensitiveActionGuard{events: events, now: time.Now, newID: newIdentityID}
}

func (guard *SensitiveActionGuard) Authorize(ctx context.Context, request SensitiveActionRequest) error {
	return guard.AuthorizeAt(ctx, request, guard.now().UTC())
}

func (guard *SensitiveActionGuard) AuthorizeAt(ctx context.Context, request SensitiveActionRequest, now time.Time) error {
	event, result, err := guard.authorizationEvent(request, now)
	if err != nil {
		return err
	}
	if err := guard.events.AppendSecurityEvent(ctx, event); err != nil {
		return ErrSecurityAuditUnavailable
	}
	return result
}

// ExecuteAt authorizes a sensitive action, executes it without an early
// success event, and persists the final outcome before returning success.
func (guard *SensitiveActionGuard) ExecuteAt(
	ctx context.Context,
	request SensitiveActionRequest,
	now time.Time,
	execute func() (SensitiveActionExecution, error),
) error {
	event, authorizationErr, err := guard.authorizationEvent(request, now)
	if err != nil {
		return err
	}
	if authorizationErr != nil {
		if err := guard.events.AppendSecurityEvent(ctx, event); err != nil {
			return ErrSecurityAuditUnavailable
		}
		return authorizationErr
	}
	if execute == nil {
		event.Outcome = SecurityEventFailure
		event.DetailCode = "operation_invalid"
		if err := guard.events.AppendSecurityEvent(ctx, event); err != nil {
			return ErrSecurityAuditUnavailable
		}
		return ErrSensitiveActionForbidden
	}

	execution, executionErr := execute()
	if execution.DetailCode == "" {
		execution.DetailCode = "operation_failed"
	}
	if executionErr == nil {
		if execution.Outcome != SecurityEventSuccess {
			execution.Outcome = SecurityEventFailure
			executionErr = ErrSensitiveActionForbidden
		}
	} else if execution.Outcome != SecurityEventDenied && execution.Outcome != SecurityEventFailure {
		execution.Outcome = SecurityEventFailure
	}
	event.TargetAuditID = execution.TargetAuditID
	event.Outcome = execution.Outcome
	event.DetailCode = execution.DetailCode
	if err := guard.events.AppendSecurityEvent(ctx, event); err != nil {
		return ErrSecurityAuditUnavailable
	}
	return executionErr
}

func (guard *SensitiveActionGuard) authorizationEvent(request SensitiveActionRequest, now time.Time) (SecurityEvent, error, error) {
	if guard.events == nil {
		return SecurityEvent{}, nil, ErrSecurityAuditUnavailable
	}
	newID := guard.newID
	if newID == nil {
		newID = newIdentityID
	}
	eventID, err := newID()
	if err != nil {
		return SecurityEvent{}, nil, ErrSecurityAuditUnavailable
	}
	detailCode := "authorized"
	result := error(nil)
	if !knownSensitiveAction(request.Action) {
		detailCode, result = "invalid_action", ErrSensitiveActionForbidden
	} else if request.Session.IdentityID == "" || request.Session.Role != RoleSystemAdministrator {
		detailCode, result = "forbidden", ErrSensitiveActionForbidden
	} else if request.Session.ReauthenticatedUntil == nil || !request.Session.ReauthenticatedUntil.After(now) {
		detailCode, result = "reauthentication_required", ErrReauthenticationRequired
	}
	outcome := SecurityEventSuccess
	if result != nil {
		outcome = SecurityEventDenied
	}
	event := SecurityEvent{
		ID: eventID, EventType: string(request.Action), ActorIdentityID: request.Session.IdentityID,
		TargetIdentityID: request.TargetIdentityID, TargetAuditID: request.TargetAuditID, RequestID: request.RequestID,
		Outcome: outcome, Reason: request.Reason, DetailCode: detailCode, OccurredAt: now,
	}
	return event, result, nil
}

func knownSensitiveAction(action SensitiveAction) bool {
	switch action {
	case SensitiveActionRawView, SensitiveActionRetentionPolicy, SensitiveActionCredentialCompromiseRecovery, SensitiveActionModelAllowlist:
		return true
	default:
		return false
	}
}

func encodeCredential(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
