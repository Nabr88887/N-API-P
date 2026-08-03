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
)

type SecurityEventOutcome string

const (
	SecurityEventSuccess SecurityEventOutcome = "success"
	SecurityEventDenied  SecurityEventOutcome = "denied"
	SecurityEventFailure SecurityEventOutcome = "failure"
)

type SecurityEvent struct {
	ID               string
	EventType        string
	ActorIdentityID  string
	TargetIdentityID string
	TargetAuditID    string
	RequestID        string
	Outcome          SecurityEventOutcome
	Reason           string
	DetailCode       string
	OccurredAt       time.Time
}

type SecurityEventWriter interface {
	AppendSecurityEvent(context.Context, SecurityEvent) error
}

type SensitiveActionRequest struct {
	Session          ActivePortalSession
	Action           SensitiveAction
	TargetIdentityID string
	TargetAuditID    string
	RequestID        string
	Reason           string
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
	if guard.events == nil {
		return ErrSecurityAuditUnavailable
	}
	newID := guard.newID
	if newID == nil {
		newID = newIdentityID
	}
	eventID, err := newID()
	if err != nil {
		return ErrSecurityAuditUnavailable
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
	if err := guard.events.AppendSecurityEvent(ctx, event); err != nil {
		return ErrSecurityAuditUnavailable
	}
	return result
}

func knownSensitiveAction(action SensitiveAction) bool {
	switch action {
	case SensitiveActionRawView, SensitiveActionRetentionPolicy, SensitiveActionCredentialCompromiseRecovery:
		return true
	default:
		return false
	}
}

func encodeCredential(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}
