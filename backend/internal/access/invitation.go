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
	activationLifetime    = 24 * time.Hour
	activationRandomBytes = 32
)

var (
	ErrForbidden                    = errors.New("access forbidden")
	ErrInvalidInvitation            = errors.New("invalid invitation")
	ErrEmailAlreadyExists           = errors.New("email already exists")
	ErrActivationRejected           = errors.New("activation rejected")
	ErrPasswordRejected             = errors.New("password rejected")
	ErrPasswordInitializationFailed = errors.New("password initialization failed")
	ErrInvalidEmailChange           = errors.New("invalid email change")
	ErrIdentityNotFound             = errors.New("identity not found")
)

type Role string

const (
	RoleEmployee            Role = "employee"
	RoleTeamAdministrator   Role = "team_administrator"
	RoleSystemAdministrator Role = "system_administrator"
)

type IdentityStatus string

const (
	IdentityStatusPending IdentityStatus = "pending"
	IdentityStatusActive  IdentityStatus = "active"
)

type Actor struct {
	IdentityID string
	Role       Role
}

type CreateInvitationInput struct {
	Actor  Actor
	Email  string
	TeamID string
}

type Invitation struct {
	IdentityID      string
	Email           string
	ActivationValue string
	ExpiresAt       time.Time
}

type InvitationRecord struct {
	IdentityID         string
	ActivationID       string
	Email              string
	Role               Role
	Status             IdentityStatus
	TeamID             string
	ActivationHash     []byte
	ExpiresAt          time.Time
	IssuedByIdentityID string
	CreatedAt          time.Time
}

// InvitationRepository atomically creates the pending identity, its team
// membership, and the hash-only activation record.
type InvitationRepository interface {
	CreateInvitation(context.Context, InvitationRecord) error
}

type InvitationService struct {
	repository InvitationRepository
	now        func() time.Time
	random     io.Reader
	newID      func() (string, error)
}

func NewInvitationService(repository InvitationRepository) *InvitationService {
	return &InvitationService{
		repository: repository,
		now:        time.Now,
		random:     rand.Reader,
		newID:      newIdentityID,
	}
}

func (service *InvitationService) Create(ctx context.Context, input CreateInvitationInput) (Invitation, error) {
	if input.Actor.Role != RoleSystemAdministrator || strings.TrimSpace(input.Actor.IdentityID) == "" {
		return Invitation{}, ErrForbidden
	}

	email := normalizeEmail(input.Email)
	teamID := strings.TrimSpace(input.TeamID)
	if email == "" || teamID == "" {
		return Invitation{}, ErrInvalidInvitation
	}

	activationValue, activationHash, err := service.newActivationValue()
	if err != nil {
		return Invitation{}, fmt.Errorf("generate activation value: %w", err)
	}
	createdAt := service.now().UTC()
	expiresAt := createdAt.Add(activationLifetime)
	identityID, err := service.newID()
	if err != nil {
		return Invitation{}, fmt.Errorf("generate identity ID: %w", err)
	}
	activationID, err := service.newID()
	if err != nil {
		return Invitation{}, fmt.Errorf("generate activation ID: %w", err)
	}

	err = service.repository.CreateInvitation(ctx, InvitationRecord{
		IdentityID:         identityID,
		ActivationID:       activationID,
		Email:              email,
		Role:               RoleEmployee,
		Status:             IdentityStatusPending,
		TeamID:             teamID,
		ActivationHash:     activationHash,
		ExpiresAt:          expiresAt,
		IssuedByIdentityID: input.Actor.IdentityID,
		CreatedAt:          createdAt,
	})
	if errors.Is(err, ErrEmailAlreadyExists) {
		return Invitation{}, ErrEmailAlreadyExists
	}
	if err != nil {
		return Invitation{}, fmt.Errorf("create invitation: %w", err)
	}

	return Invitation{
		IdentityID:      identityID,
		Email:           email,
		ActivationValue: activationValue,
		ExpiresAt:       expiresAt,
	}, nil
}

func (service *InvitationService) newActivationValue() (string, []byte, error) {
	randomBytes := make([]byte, activationRandomBytes)
	if _, err := io.ReadFull(service.random, randomBytes); err != nil {
		return "", nil, err
	}
	value := base64.RawURLEncoding.EncodeToString(randomBytes)
	hash := sha256.Sum256([]byte(value))
	return value, hash[:], nil
}

func newIdentityID() (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
		return "", err
	}
	randomBytes[6] = (randomBytes[6] & 0x0f) | 0x40
	randomBytes[8] = (randomBytes[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", randomBytes[0:4], randomBytes[4:6], randomBytes[6:8], randomBytes[8:10], randomBytes[10:16]), nil
}

type ActivateInput struct {
	// AttemptSource comes from trusted server-side request metadata, not request input.
	AttemptSource   string
	Email           string
	ActivationValue string
	NewPassword     string
}

type ActivationLookup struct {
	Email          string
	ActivationHash []byte
	CheckedAt      time.Time
}

type ActivationCandidate struct {
	CodeID     string
	IdentityID string
}

type ActivationRecord struct {
	Candidate      ActivationCandidate
	Email          string
	ActivationHash []byte
	PasswordHash   string
	ActivatedAt    time.Time
}

// ActivationRepository cheaply prevalidates an activation value before password
// hashing, then atomically revalidates and consumes it while activating the
// existing identity and revoking unused sibling values. Invalid state returns
// ErrActivationRejected without revealing the failed check.
type ActivationRepository interface {
	PrepareActivation(context.Context, ActivationLookup) (ActivationCandidate, error)
	ActivateIdentity(context.Context, ActivationRecord) error
}

type ActivationAttemptLimiter interface {
	Allow(trustedSource, normalizedEmail string, attemptedAt time.Time) bool
}

// PasswordInitializer is implemented by task 3.2. It owns password policy and
// hash generation so this service never persists or returns plaintext.
type PasswordInitializer interface {
	Initialize(plaintext string) (passwordHash string, err error)
}

type ActivationService struct {
	repository ActivationRepository
	passwords  PasswordInitializer
	limiter    ActivationAttemptLimiter
	now        func() time.Time
}

func NewActivationService(repository ActivationRepository, passwords PasswordInitializer, limiter ActivationAttemptLimiter) *ActivationService {
	return &ActivationService{repository: repository, passwords: passwords, limiter: limiter, now: time.Now}
}

func (service *ActivationService) Activate(ctx context.Context, input ActivateInput) error {
	email := normalizeEmail(input.Email)
	trustedSource := strings.TrimSpace(input.AttemptSource)
	if trustedSource == "" || email == "" || input.ActivationValue == "" {
		return ErrActivationRejected
	}
	attemptedAt := service.now().UTC()
	if service.limiter == nil || !service.limiter.Allow(trustedSource, email, attemptedAt) {
		return ErrActivationRejected
	}

	activationHash := sha256.Sum256([]byte(input.ActivationValue))
	candidate, err := service.repository.PrepareActivation(ctx, ActivationLookup{
		Email: email, ActivationHash: activationHash[:], CheckedAt: attemptedAt,
	})
	if errors.Is(err, ErrActivationRejected) {
		return ErrActivationRejected
	}
	if err != nil {
		return fmt.Errorf("prepare activation: %w", err)
	}

	passwordHash, err := service.passwords.Initialize(input.NewPassword)
	if errors.Is(err, ErrPasswordRejected) {
		return ErrPasswordRejected
	}
	if err != nil || passwordHash == "" {
		return ErrPasswordInitializationFailed
	}

	err = service.repository.ActivateIdentity(ctx, ActivationRecord{
		Candidate:      candidate,
		Email:          email,
		ActivationHash: activationHash[:],
		PasswordHash:   passwordHash,
		ActivatedAt:    attemptedAt,
	})
	if errors.Is(err, ErrActivationRejected) {
		return ErrActivationRejected
	}
	if err != nil {
		return fmt.Errorf("activate identity: %w", err)
	}
	return nil
}

type ChangeEmailInput struct {
	Actor      Actor
	IdentityID string
	Email      string
}

type EmailChangeRecord struct {
	IdentityID          string
	Email               string
	ChangedByIdentityID string
	ChangedAt           time.Time
}

// IdentityRepository updates an identity by immutable ID and atomically
// revokes unused activation values still bound to its previous email.
type IdentityRepository interface {
	ChangeIdentityEmail(context.Context, EmailChangeRecord) error
}

type IdentityService struct {
	repository IdentityRepository
	now        func() time.Time
}

func NewIdentityService(repository IdentityRepository) *IdentityService {
	return &IdentityService{repository: repository, now: time.Now}
}

func (service *IdentityService) ChangeEmail(ctx context.Context, input ChangeEmailInput) error {
	if input.Actor.Role != RoleSystemAdministrator || strings.TrimSpace(input.Actor.IdentityID) == "" {
		return ErrForbidden
	}
	email := normalizeEmail(input.Email)
	if strings.TrimSpace(input.IdentityID) == "" || email == "" {
		return ErrInvalidEmailChange
	}

	err := service.repository.ChangeIdentityEmail(ctx, EmailChangeRecord{
		IdentityID:          input.IdentityID,
		Email:               email,
		ChangedByIdentityID: input.Actor.IdentityID,
		ChangedAt:           service.now().UTC(),
	})
	if errors.Is(err, ErrEmailAlreadyExists) {
		return ErrEmailAlreadyExists
	}
	if errors.Is(err, ErrIdentityNotFound) {
		return ErrIdentityNotFound
	}
	if err != nil {
		return fmt.Errorf("change identity email: %w", err)
	}
	return nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
