package access

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

const MaxActivePersonalKeys = 5

var (
	ErrInvalidPersonalKeyName  = errors.New("invalid personal key name")
	ErrPersonalKeyNameConflict = errors.New("personal key name already exists")
	ErrPersonalKeyLimitReached = errors.New("personal key active limit reached")
	ErrPersonalKeyNotFound     = errors.New("personal key not found")
	ErrInvalidAPIKey           = errors.New("invalid api key")
)

type PersonalKeyStatus string

const (
	PersonalKeyStatusActive  PersonalKeyStatus = "active"
	PersonalKeyStatusRevoked PersonalKeyStatus = "revoked"
)

type PersonalKey struct {
	ID         string
	IdentityID string
	Name       string
	Prefix     string
	Status     PersonalKeyStatus
	CreatedAt  time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

type PersonalKeyIssuance struct {
	Key        PersonalKey
	Credential GeneratedAPIKey
}

type CreatePersonalKeyInput struct {
	IdentityID string
	Name       string
	RequestID  string
}

type RevokePersonalKeyInput struct {
	IdentityID string
	KeyID      string
	RequestID  string
}

// PersonalKeyRecord contains only irreversible verification material and
// metadata. Complete credentials never cross the repository boundary.
type PersonalKeyRecord struct {
	ID               string
	IdentityID       string
	Name             string
	Prefix           string
	VerificationHash []byte `json:"-"`
	CreatedAt        time.Time
	Lifecycle        CredentialLifecycleContext
}

type PersonalKeyRevocation struct {
	IdentityID string
	KeyID      string
	RevokedAt  time.Time
	Lifecycle  CredentialLifecycleContext
}

type PersonalKeyAuthenticationCandidate struct {
	KeyID            string
	IdentityID       string
	VerificationHash []byte `json:"-"`
}

func (record PersonalKeyRecord) String() string {
	return fmt.Sprintf(
		"PersonalKeyRecord{id=%s identity=%s name=%s prefix=%s created_at=%s}",
		record.ID, record.IdentityID, record.Name, record.Prefix, record.CreatedAt.Format(time.RFC3339Nano),
	)
}

func (record PersonalKeyRecord) GoString() string {
	return record.String()
}

func (record PersonalKeyRecord) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", record.ID),
		slog.String("identity_id", record.IdentityID),
		slog.String("name", record.Name),
		slog.String("prefix", record.Prefix),
		slog.Time("created_at", record.CreatedAt),
	)
}

func (candidate PersonalKeyAuthenticationCandidate) String() string {
	return fmt.Sprintf("PersonalKeyAuthenticationCandidate{key_id=%s identity_id=%s}", candidate.KeyID, candidate.IdentityID)
}

func (candidate PersonalKeyAuthenticationCandidate) GoString() string {
	return candidate.String()
}

func (candidate PersonalKeyAuthenticationCandidate) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("key_id", candidate.KeyID),
		slog.String("identity_id", candidate.IdentityID),
	)
}

type PersonalKeyUse struct {
	KeyID  string
	UsedAt time.Time
}

type AuthenticatedPersonalKey struct {
	KeyID      string
	IdentityID string
}

type PersonalKeyRepository interface {
	CreatePersonalKey(context.Context, PersonalKeyRecord) error
	ListPersonalKeys(context.Context, string) ([]PersonalKey, error)
	RevokePersonalKey(context.Context, PersonalKeyRevocation) error
	FindPersonalKeyCandidates(context.Context, string) ([]PersonalKeyAuthenticationCandidate, error)
	RecordPersonalKeyUse(context.Context, PersonalKeyUse) (AuthenticatedPersonalKey, error)
}

type PersonalKeyService struct {
	repository PersonalKeyRepository
	keys       *APIKeyGenerator
	now        func() time.Time
	newID      func() (string, error)
}

func NewPersonalKeyService(repository PersonalKeyRepository) *PersonalKeyService {
	return &PersonalKeyService{
		repository: repository,
		keys:       NewAPIKeyGenerator(),
		now:        time.Now,
		newID:      newIdentityID,
	}
}

func (service *PersonalKeyService) Create(ctx context.Context, input CreatePersonalKeyInput) (PersonalKeyIssuance, error) {
	identityID := strings.TrimSpace(input.IdentityID)
	name := strings.TrimSpace(input.Name)
	if service == nil || service.repository == nil || identityID == "" {
		return PersonalKeyIssuance{}, ErrForbidden
	}
	if name == "" {
		return PersonalKeyIssuance{}, ErrInvalidPersonalKeyName
	}
	createdAt := service.now().UTC()
	lifecycle, err := newCredentialLifecycleContext(
		CredentialLifecyclePersonalKeyCreated, identityID, identityID, "", input.RequestID, createdAt,
	)
	if err != nil {
		return PersonalKeyIssuance{}, err
	}

	id, err := service.newID()
	if err != nil {
		return PersonalKeyIssuance{}, err
	}
	credential, err := service.keys.Generate()
	if err != nil {
		return PersonalKeyIssuance{}, err
	}
	record := PersonalKeyRecord{
		ID:               id,
		IdentityID:       identityID,
		Name:             name,
		Prefix:           credential.Prefix(),
		VerificationHash: credential.VerificationHash(),
		CreatedAt:        createdAt,
		Lifecycle:        lifecycle,
	}
	if err := service.repository.CreatePersonalKey(ctx, record); err != nil {
		credential.Reveal()
		return PersonalKeyIssuance{}, err
	}

	return PersonalKeyIssuance{
		Key: PersonalKey{
			ID: id, IdentityID: identityID, Name: name, Prefix: record.Prefix,
			Status: PersonalKeyStatusActive, CreatedAt: createdAt,
		},
		Credential: *credential,
	}, nil
}

func (service *PersonalKeyService) List(ctx context.Context, identityID string) ([]PersonalKey, error) {
	identityID = strings.TrimSpace(identityID)
	if service == nil || service.repository == nil || identityID == "" {
		return nil, ErrForbidden
	}
	return service.repository.ListPersonalKeys(ctx, identityID)
}

func (service *PersonalKeyService) Revoke(ctx context.Context, input RevokePersonalKeyInput) error {
	identityID := strings.TrimSpace(input.IdentityID)
	keyID := strings.TrimSpace(input.KeyID)
	if service == nil || service.repository == nil || identityID == "" || keyID == "" {
		return ErrPersonalKeyNotFound
	}
	revokedAt := service.now().UTC()
	lifecycle, err := newCredentialLifecycleContext(
		CredentialLifecyclePersonalKeyRevoked, identityID, identityID, "", input.RequestID, revokedAt,
	)
	if err != nil {
		return err
	}
	return service.repository.RevokePersonalKey(ctx, PersonalKeyRevocation{
		IdentityID: identityID,
		KeyID:      keyID,
		RevokedAt:  revokedAt,
		Lifecycle:  lifecycle,
	})
}

func (service *PersonalKeyService) Authenticate(ctx context.Context, credential string) (AuthenticatedPersonalKey, error) {
	encodedLength := base64.RawURLEncoding.EncodedLen(apiKeyRandomBytes)
	if service == nil || service.repository == nil || len(credential) != len(apiKeyPrefix)+encodedLength || !strings.HasPrefix(credential, apiKeyPrefix) {
		return AuthenticatedPersonalKey{}, ErrInvalidAPIKey
	}

	candidates, err := service.repository.FindPersonalKeyCandidates(ctx, credential[:apiKeyPrefixLength])
	if err != nil {
		return AuthenticatedPersonalKey{}, err
	}
	matchedIndex := -1
	for index := range candidates {
		if VerifyAPIKey(credential, candidates[index].VerificationHash) {
			if matchedIndex != -1 {
				return AuthenticatedPersonalKey{}, ErrInvalidAPIKey
			}
			matchedIndex = index
		}
	}
	if matchedIndex == -1 {
		return AuthenticatedPersonalKey{}, ErrInvalidAPIKey
	}

	authenticated, err := service.repository.RecordPersonalKeyUse(ctx, PersonalKeyUse{
		KeyID:  candidates[matchedIndex].KeyID,
		UsedAt: service.now().UTC(),
	})
	if err != nil {
		return AuthenticatedPersonalKey{}, err
	}
	if authenticated.KeyID != candidates[matchedIndex].KeyID || authenticated.IdentityID != candidates[matchedIndex].IdentityID {
		return AuthenticatedPersonalKey{}, ErrInvalidAPIKey
	}
	return authenticated, nil
}
