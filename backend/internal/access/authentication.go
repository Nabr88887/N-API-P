package access

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

const (
	loginFailureLimit       = 5
	loginFailureWindow      = 15 * time.Minute
	loginLockDuration       = 15 * time.Minute
	unknownLoginStateLimit  = 4096
	unknownLoginCleanupWait = time.Minute
	sessionRandomBytes      = 32
	sessionIdleLifetime     = 30 * time.Minute
	sessionAbsoluteLifetime = 12 * time.Hour
)

var (
	ErrInvalidCredentials        = errors.New("invalid credentials")
	ErrAuthenticationUnavailable = errors.New("authentication unavailable")
)

// PasswordCodec owns password hashing and verification without exposing the
// encoded password format to the authentication service.
type PasswordCodec interface {
	Initialize(string) (string, error)
	Verify(plaintext, encodedHash string) (bool, error)
}

type AuthenticationRepository interface {
	FindLoginCandidate(context.Context, LoginLookup) (LoginCandidate, error)
	CompleteLogin(context.Context, LoginCompletion) error
}

type LoginInput struct {
	Email    string
	Password string
}

type LoginLookup struct {
	Email     string
	CheckedAt time.Time
}

type LoginCandidate struct {
	Found                  bool
	IdentityID             string
	Email                  string
	Status                 IdentityStatus
	PasswordHash           string
	FailedAttempts         int
	FailureWindowStartedAt *time.Time
	LockedUntil            *time.Time
}

type LoginCompletion struct {
	Candidate            LoginCandidate
	AttemptedAt          time.Time
	PasswordValid        bool
	VerifiedPasswordHash string
	Session              LoginSessionRecord
}

type LoginSessionRecord struct {
	ID                   string
	IdentityID           string
	TokenHash            []byte
	CSRFTokenHash        []byte
	CreatedAt            time.Time
	LastSeenAt           time.Time
	IdleExpiresAt        time.Time
	AbsoluteExpiresAt    time.Time
	ReauthenticatedUntil time.Time
}

type PortalSession struct {
	ID         string
	IdentityID string
	Token      string
	CSRFToken  string
	ExpiresAt  time.Time
}

type unknownLoginLimiter struct {
	mu            sync.Mutex
	states        map[string]unknownLoginState
	nextCleanupAt time.Time
}

type unknownLoginState struct {
	windowStartedAt time.Time
	attempts        int
}

func newUnknownLoginLimiter() *unknownLoginLimiter {
	return &unknownLoginLimiter{states: make(map[string]unknownLoginState)}
}

func (limiter *unknownLoginLimiter) allow(email string, now time.Time) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	state, exists := limiter.states[email]
	if !exists && len(limiter.states) >= unknownLoginStateLimit {
		if limiter.nextCleanupAt.IsZero() || !now.Before(limiter.nextCleanupAt) {
			for key, candidate := range limiter.states {
				if !now.Before(candidate.windowStartedAt.Add(loginFailureWindow)) {
					delete(limiter.states, key)
				}
			}
			limiter.nextCleanupAt = now.Add(unknownLoginCleanupWait)
		}
		if len(limiter.states) >= unknownLoginStateLimit {
			return false
		}
	}
	if state.windowStartedAt.IsZero() || !now.Before(state.windowStartedAt.Add(loginFailureWindow)) {
		state = unknownLoginState{windowStartedAt: now, attempts: 0}
	}
	if state.attempts >= loginFailureLimit {
		limiter.states[email] = state
		return false
	}
	state.attempts++
	limiter.states[email] = state
	return true
}

type AuthenticationService struct {
	repository AuthenticationRepository
	passwords  PasswordCodec
	dummyHash  string
	limiter    *unknownLoginLimiter
	now        func() time.Time
	random     io.Reader
	newID      func() (string, error)
}

func NewAuthenticationService(repository AuthenticationRepository, passwords PasswordCodec) (*AuthenticationService, error) {
	if repository == nil || passwords == nil {
		return nil, errors.New("authentication dependencies are required")
	}
	dummyHash, err := passwords.Initialize("n-api-p-dummy-password")
	if err != nil {
		return nil, fmt.Errorf("initialize authentication dummy hash: %w", err)
	}
	return &AuthenticationService{
		repository: repository,
		passwords:  passwords,
		dummyHash:  dummyHash,
		limiter:    newUnknownLoginLimiter(),
		now:        time.Now,
		random:     rand.Reader,
		newID:      newIdentityID,
	}, nil
}

func (service *AuthenticationService) Login(ctx context.Context, input LoginInput) (PortalSession, error) {
	now := service.now().UTC()
	email := normalizeEmail(input.Email)
	candidate, err := service.repository.FindLoginCandidate(ctx, LoginLookup{Email: email, CheckedAt: now})
	if err != nil {
		return PortalSession{}, ErrAuthenticationUnavailable
	}

	eligible := candidate.Found && candidate.Status == IdentityStatusActive && candidate.PasswordHash != "" &&
		(candidate.LockedUntil == nil || !candidate.LockedUntil.After(now))
	unknownAllowed := true
	if !candidate.Found {
		unknownAllowed = service.limiter.allow(email, now)
	}
	verifyHash := service.dummyHash
	if eligible {
		verifyHash = candidate.PasswordHash
	}
	valid, err := service.passwords.Verify(input.Password, verifyHash)
	if err != nil {
		return PortalSession{}, ErrAuthenticationUnavailable
	}
	if !valid || !eligible || !unknownAllowed {
		if candidate.Found && eligible {
			err = service.repository.CompleteLogin(ctx, LoginCompletion{
				Candidate: candidate, AttemptedAt: now, VerifiedPasswordHash: candidate.PasswordHash,
			})
			if errors.Is(err, ErrInvalidCredentials) {
				return PortalSession{}, ErrInvalidCredentials
			}
			if err != nil {
				return PortalSession{}, ErrAuthenticationUnavailable
			}
		}
		return PortalSession{}, ErrInvalidCredentials
	}

	session, record, err := service.newSession(candidate.IdentityID, now)
	if err != nil {
		return PortalSession{}, ErrAuthenticationUnavailable
	}
	err = service.repository.CompleteLogin(ctx, LoginCompletion{
		Candidate: candidate, AttemptedAt: now, PasswordValid: true,
		VerifiedPasswordHash: candidate.PasswordHash, Session: record,
	})
	if errors.Is(err, ErrInvalidCredentials) {
		return PortalSession{}, ErrInvalidCredentials
	}
	if err != nil {
		return PortalSession{}, ErrAuthenticationUnavailable
	}
	return session, nil
}

// AdvanceLoginFailure applies the access-owned lockout policy to a locked
// identity row. Repositories use it while serializing concurrent attempts.
func AdvanceLoginFailure(attempts int, windowStartedAt *time.Time, attemptedAt time.Time) (int, *time.Time, *time.Time) {
	cutoff := attemptedAt.Add(-loginFailureWindow)
	if windowStartedAt == nil || !windowStartedAt.After(cutoff) {
		attempts = 1
		windowStartedAt = timePointerCopy(attemptedAt)
	} else {
		attempts++
	}
	var lockedUntil *time.Time
	if attempts >= loginFailureLimit {
		lockedUntil = timePointerCopy(attemptedAt.Add(loginLockDuration))
	}
	return attempts, windowStartedAt, lockedUntil
}

func timePointerCopy(value time.Time) *time.Time {
	return &value
}

func (service *AuthenticationService) newSession(identityID string, now time.Time) (PortalSession, LoginSessionRecord, error) {
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
	tokenHash := sha256.Sum256([]byte(token))
	csrfHash := sha256.Sum256([]byte(csrfToken))
	record := LoginSessionRecord{
		ID: id, IdentityID: identityID, TokenHash: tokenHash[:], CSRFTokenHash: csrfHash[:],
		CreatedAt: now, LastSeenAt: now, IdleExpiresAt: now.Add(sessionIdleLifetime), AbsoluteExpiresAt: now.Add(sessionAbsoluteLifetime),
	}
	return PortalSession{ID: id, IdentityID: identityID, Token: token, CSRFToken: csrfToken, ExpiresAt: record.AbsoluteExpiresAt}, record, nil
}

func (service *AuthenticationService) randomCredential() (string, error) {
	value := make([]byte, sessionRandomBytes)
	if _, err := io.ReadFull(service.random, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
