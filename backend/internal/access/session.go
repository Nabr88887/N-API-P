package access

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"
)

var (
	ErrSessionInvalid     = errors.New("session invalid")
	ErrSessionUnavailable = errors.New("session unavailable")
)

type PortalSessionRepository interface {
	UsePortalSession(context.Context, PortalSessionUse) (ActivePortalSession, error)
	RevokePortalSession(context.Context, PortalSessionRevocation) error
}

type PortalSessionUse struct {
	TokenHash     []byte
	CSRFTokenHash []byte
	UsedAt        time.Time
	IdleExpiresAt time.Time
}

type PortalSessionRevocation struct {
	SessionID string
	RevokedAt time.Time
}

type ActivePortalSession struct {
	SessionID            string
	IdentityID           string
	Role                 Role
	IdleExpiresAt        time.Time
	AbsoluteExpiresAt    time.Time
	ReauthenticatedUntil *time.Time
}

// PortalIdentity is the minimum server-owned identity projection exposed to
// the browser session. It intentionally contains no password, token, or
// verification material.
type PortalIdentity struct {
	ID      string
	Email   string
	Role    Role
	TeamIDs []string
}

type PortalIdentityReader interface {
	ReadPortalIdentity(context.Context, string) (PortalIdentity, error)
}

type SessionService struct {
	repository PortalSessionRepository
	now        func() time.Time
}

func NewSessionService(repository PortalSessionRepository) *SessionService {
	return &SessionService{repository: repository, now: time.Now}
}

func (service *SessionService) Authenticate(ctx context.Context, token, csrfToken string, requireCSRF bool) (ActivePortalSession, error) {
	if token == "" || (requireCSRF && csrfToken == "") {
		return ActivePortalSession{}, ErrSessionInvalid
	}
	now := service.now().UTC()
	tokenHash := sha256.Sum256([]byte(token))
	use := PortalSessionUse{
		TokenHash: tokenHash[:], UsedAt: now, IdleExpiresAt: now.Add(sessionIdleLifetime),
	}
	if requireCSRF {
		csrfHash := sha256.Sum256([]byte(csrfToken))
		use.CSRFTokenHash = csrfHash[:]
	}
	session, err := service.repository.UsePortalSession(ctx, use)
	if errors.Is(err, ErrSessionInvalid) {
		return ActivePortalSession{}, ErrSessionInvalid
	}
	if err != nil {
		return ActivePortalSession{}, ErrSessionUnavailable
	}
	return session, nil
}

func (service *SessionService) Revoke(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return ErrSessionInvalid
	}
	err := service.repository.RevokePortalSession(ctx, PortalSessionRevocation{
		SessionID: sessionID,
		RevokedAt: service.now().UTC(),
	})
	if errors.Is(err, ErrSessionInvalid) {
		return ErrSessionInvalid
	}
	if err != nil {
		return ErrSessionUnavailable
	}
	return nil
}
