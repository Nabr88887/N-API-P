package access

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	passwordResetLifetime    = 30 * time.Minute
	passwordResetRandomBytes = 32
)

var (
	ErrManualIdentityVerificationRequired = errors.New("manual identity verification required")
	ErrPasswordResetRejected              = errors.New("password reset rejected")
	ErrPasswordResetUnavailable           = errors.New("password reset unavailable")
)

// PasswordResetRepository owns the database transaction boundaries for code
// issuance and completion. Code and password plaintext never cross this API.
type PasswordResetRepository interface {
	IssuePasswordResetCode(context.Context, PasswordResetCodeRecord) error
	PreparePasswordReset(context.Context, PasswordResetLookup) (PasswordResetCandidate, error)
	CompletePasswordReset(context.Context, PasswordResetCompletionRecord) error
}

type PasswordResetIssueInput struct {
	Actor                  ActivePortalSession
	TargetIdentityID       string
	TargetEmail            string
	ManualIdentityVerified bool
	CompromiseResponse     bool
	RequestID              string
}

type PasswordResetCode struct {
	Code      string
	Email     string
	ExpiresAt time.Time
}

type PasswordResetCodeRecord struct {
	CodeID                  string
	TargetIdentityID        string
	Email                   string
	CodeHash                []byte
	ExpiresAt               time.Time
	CreatedAt               time.Time
	IssuedByIdentityID      string
	RevokePersonalKeysOnUse bool
	Event                   SecurityEvent
}

type PasswordResetLookup struct {
	Email     string
	CodeHash  []byte
	CheckedAt time.Time
}

type PasswordResetCandidate struct {
	CodeID                  string
	IdentityID              string
	Email                   string
	RevokePersonalKeysOnUse bool
}

type PasswordResetCompletionInput struct {
	Email       string
	Code        string
	NewPassword string
}

type PasswordResetCompletionRecord struct {
	CodeID                  string
	IdentityID              string
	Email                   string
	CodeHash                []byte
	PasswordHash            string
	ResetAt                 time.Time
	RevokePersonalKeysOnUse bool
	Event                   SecurityEvent
}

type PasswordResetService struct {
	repository       PasswordResetRepository
	passwords        PasswordInitializer
	sensitiveActions *SensitiveActionGuard
	now              func() time.Time
	random           io.Reader
	newID            func() (string, error)
}

func NewPasswordResetService(repository PasswordResetRepository, passwords PasswordInitializer, sensitiveActions *SensitiveActionGuard) *PasswordResetService {
	return &PasswordResetService{
		repository:       repository,
		passwords:        passwords,
		sensitiveActions: sensitiveActions,
		now:              time.Now,
		random:           rand.Reader,
		newID:            newIdentityID,
	}
}

func (service *PasswordResetService) IssueCode(ctx context.Context, input PasswordResetIssueInput) (PasswordResetCode, error) {
	if service.repository == nil || strings.TrimSpace(input.Actor.IdentityID) == "" {
		return PasswordResetCode{}, ErrForbidden
	}
	if !input.ManualIdentityVerified {
		return PasswordResetCode{}, ErrManualIdentityVerificationRequired
	}
	now := service.now().UTC()
	requestID, err := credentialLifecycleRequestID(input.RequestID)
	if err != nil {
		return PasswordResetCode{}, ErrPasswordResetRejected
	}
	if input.CompromiseResponse {
		if service.sensitiveActions == nil {
			return PasswordResetCode{}, ErrPasswordResetUnavailable
		}
		err := service.sensitiveActions.AuthorizeAt(ctx, SensitiveActionRequest{
			Session:          input.Actor,
			Action:           SensitiveActionCredentialCompromiseRecovery,
			TargetIdentityID: strings.TrimSpace(input.TargetIdentityID),
			RequestID:        requestID,
		}, now)
		if errors.Is(err, ErrSensitiveActionForbidden) {
			return PasswordResetCode{}, ErrForbidden
		}
		if errors.Is(err, ErrReauthenticationRequired) {
			return PasswordResetCode{}, ErrReauthenticationRequired
		}
		if err != nil {
			return PasswordResetCode{}, ErrPasswordResetUnavailable
		}
	} else if input.Actor.Role != RoleSystemAdministrator {
		return PasswordResetCode{}, ErrForbidden
	}
	if strings.TrimSpace(input.TargetIdentityID) == "" || normalizeEmail(input.TargetEmail) == "" {
		return PasswordResetCode{}, ErrPasswordResetRejected
	}

	code, codeHash, err := service.newCode()
	if err != nil {
		return PasswordResetCode{}, fmt.Errorf("generate password reset code: %w", err)
	}
	codeID, err := service.newID()
	if err != nil {
		return PasswordResetCode{}, fmt.Errorf("generate password reset code ID: %w", err)
	}
	eventID, err := service.newID()
	if err != nil {
		return PasswordResetCode{}, fmt.Errorf("generate password reset event ID: %w", err)
	}
	email := normalizeEmail(input.TargetEmail)
	expiresAt := now.Add(passwordResetLifetime)
	record := PasswordResetCodeRecord{
		CodeID: codeID, TargetIdentityID: strings.TrimSpace(input.TargetIdentityID), Email: email,
		CodeHash: codeHash, ExpiresAt: expiresAt, CreatedAt: now,
		IssuedByIdentityID:      strings.TrimSpace(input.Actor.IdentityID),
		RevokePersonalKeysOnUse: input.CompromiseResponse,
		Event: SecurityEvent{
			ID: eventID, EventType: "password_reset_issued", ActorIdentityID: strings.TrimSpace(input.Actor.IdentityID),
			TargetIdentityID: strings.TrimSpace(input.TargetIdentityID), RequestID: requestID,
			Outcome: SecurityEventSuccess, DetailCode: passwordResetIssueDetail(input.CompromiseResponse), OccurredAt: now,
		},
	}
	if err := service.repository.IssuePasswordResetCode(ctx, record); err != nil {
		if errors.Is(err, ErrForbidden) || errors.Is(err, ErrPasswordResetRejected) {
			return PasswordResetCode{}, err
		}
		return PasswordResetCode{}, ErrPasswordResetUnavailable
	}
	return PasswordResetCode{Code: code, Email: email, ExpiresAt: expiresAt}, nil
}

func passwordResetIssueDetail(compromise bool) string {
	if compromise {
		return "compromise_response"
	}
	return "routine_recovery"
}

func (service *PasswordResetService) Complete(ctx context.Context, input PasswordResetCompletionInput) error {
	if service.repository == nil || service.passwords == nil || normalizeEmail(input.Email) == "" || input.Code == "" || input.NewPassword == "" {
		return ErrPasswordResetRejected
	}
	now := service.now().UTC()
	codeHash := sha256.Sum256([]byte(input.Code))
	candidate, err := service.repository.PreparePasswordReset(ctx, PasswordResetLookup{
		Email: normalizeEmail(input.Email), CodeHash: codeHash[:], CheckedAt: now,
	})
	if errors.Is(err, ErrPasswordResetRejected) {
		return ErrPasswordResetRejected
	}
	if err != nil {
		return ErrPasswordResetUnavailable
	}
	if candidate.CodeID == "" || candidate.IdentityID == "" || normalizeEmail(candidate.Email) != normalizeEmail(input.Email) {
		return ErrPasswordResetRejected
	}
	passwordHash, err := service.passwords.Initialize(input.NewPassword)
	if errors.Is(err, ErrPasswordRejected) {
		return ErrPasswordRejected
	}
	if err != nil || passwordHash == "" {
		return ErrPasswordInitializationFailed
	}
	eventID, err := service.newID()
	if err != nil {
		return ErrPasswordResetUnavailable
	}
	err = service.repository.CompletePasswordReset(ctx, PasswordResetCompletionRecord{
		CodeID: candidate.CodeID, IdentityID: candidate.IdentityID, Email: candidate.Email,
		CodeHash:     codeHash[:],
		PasswordHash: passwordHash, ResetAt: now,
		RevokePersonalKeysOnUse: candidate.RevokePersonalKeysOnUse,
		Event: SecurityEvent{
			ID: eventID, EventType: "password_reset_completed", TargetIdentityID: candidate.IdentityID,
			RequestID: eventID, Outcome: SecurityEventSuccess,
			DetailCode: passwordResetIssueDetail(candidate.RevokePersonalKeysOnUse), OccurredAt: now,
		},
	})
	if errors.Is(err, ErrPasswordResetRejected) {
		return ErrPasswordResetRejected
	}
	if err != nil {
		return ErrPasswordResetUnavailable
	}
	return nil
}

func (service *PasswordResetService) newCode() (string, []byte, error) {
	randomBytes := make([]byte, passwordResetRandomBytes)
	if _, err := io.ReadFull(service.random, randomBytes); err != nil {
		return "", nil, err
	}
	value := base64.RawURLEncoding.EncodeToString(randomBytes)
	hash := sha256.Sum256([]byte(value))
	return value, hash[:], nil
}
