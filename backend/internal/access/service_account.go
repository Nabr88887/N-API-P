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

const MaxActiveServiceAccountKeys = 3

const ServiceAccountKeyKind = "service"

var (
	ErrInvalidServiceAccount         = errors.New("invalid service account")
	ErrServiceAccountNameConflict    = errors.New("service account name already exists")
	ErrInvalidServiceAccountKey      = errors.New("invalid service account key")
	ErrServiceAccountKeyNameConflict = errors.New("service account key name already exists")
	ErrServiceAccountKeyLimitReached = errors.New("service account key active limit reached")
	ErrServiceAccountKeyNotFound     = errors.New("service account key not found")
)

type ServiceAccountStatus string

const (
	ServiceAccountStatusActive   ServiceAccountStatus = "active"
	ServiceAccountStatusDisabled ServiceAccountStatus = "disabled"
)

type ServiceAccountKeyStatus string

const (
	ServiceAccountKeyStatusActive  ServiceAccountKeyStatus = "active"
	ServiceAccountKeyStatusRevoked ServiceAccountKeyStatus = "revoked"
)

type ServiceAccount struct {
	ID                    string
	TeamID                string
	ResponsibleIdentityID string
	Name                  string
	Status                ServiceAccountStatus
	CreatedAt             time.Time
	UpdatedAt             time.Time
	DisabledAt            *time.Time
}

type CreateServiceAccountInput struct {
	Actor                 Actor
	TeamID                string
	ResponsibleIdentityID string
	Name                  string
	RequestID             string
}

type ServiceAccountRecord struct {
	ID                    string
	TeamID                string
	ResponsibleIdentityID string
	Name                  string
	CreatedByIdentityID   string
	CreatedAt             time.Time
	Event                 SecurityEvent
}

type CreateServiceAccountKeyInput struct {
	Actor            Actor
	ServiceAccountID string
	Name             string
	RequestID        string
}

type ListServiceAccountKeysInput struct {
	Actor            Actor
	ServiceAccountID string
}

type RevokeServiceAccountKeyInput struct {
	Actor            Actor
	ServiceAccountID string
	KeyID            string
	RequestID        string
}

type RotateServiceAccountKeyInput struct {
	Actor            Actor
	ServiceAccountID string
	KeyID            string
	Name             string
	RequestID        string
}

type ServiceAccountKey struct {
	ID                    string
	ServiceAccountID      string
	TeamID                string
	ResponsibleIdentityID string
	Name                  string
	Prefix                string
	Status                ServiceAccountKeyStatus
	CreatedAt             time.Time
	LastUsedAt            *time.Time
	RevokedAt             *time.Time
}

type ServiceAccountKeyIssuance struct {
	Key        ServiceAccountKey
	Credential GeneratedAPIKey
}

type ServiceAccountKeyRecord struct {
	ID                  string
	ServiceAccountID    string
	Kind                string
	Name                string
	Prefix              string
	VerificationHash    []byte `json:"-"`
	CreatedByIdentityID string
	CreatedAt           time.Time
	Lifecycle           CredentialLifecycleContext
}

type ServiceAccountKeyRevocation struct {
	ServiceAccountID string
	KeyID            string
	ActorIdentityID  string
	RevokedAt        time.Time
	Lifecycle        CredentialLifecycleContext
}

type ServiceAccountKeyRotation struct {
	ServiceAccountID string
	OldKeyID         string
	NewKey           ServiceAccountKeyRecord
	RevokedAt        time.Time
	RevokedLifecycle CredentialLifecycleContext
	CreatedLifecycle CredentialLifecycleContext
}

type ServiceAccountKeyAuthenticationCandidate struct {
	KeyID            string
	ServiceAccountID string
	VerificationHash []byte `json:"-"`
}

func (record ServiceAccountKeyRecord) String() string {
	return fmt.Sprintf(
		"ServiceAccountKeyRecord{id=%s service_account=%s kind=%s name=%s prefix=%s created_by=%s created_at=%s}",
		record.ID, record.ServiceAccountID, record.Kind, record.Name, record.Prefix,
		record.CreatedByIdentityID, record.CreatedAt.Format(time.RFC3339Nano),
	)
}

func (record ServiceAccountKeyRecord) GoString() string {
	return record.String()
}

func (record ServiceAccountKeyRecord) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("id", record.ID),
		slog.String("service_account_id", record.ServiceAccountID),
		slog.String("kind", record.Kind),
		slog.String("name", record.Name),
		slog.String("prefix", record.Prefix),
		slog.String("created_by_identity_id", record.CreatedByIdentityID),
		slog.Time("created_at", record.CreatedAt),
	)
}

func (candidate ServiceAccountKeyAuthenticationCandidate) String() string {
	return fmt.Sprintf(
		"ServiceAccountKeyAuthenticationCandidate{key_id=%s service_account_id=%s}",
		candidate.KeyID, candidate.ServiceAccountID,
	)
}

func (candidate ServiceAccountKeyAuthenticationCandidate) GoString() string {
	return candidate.String()
}

func (candidate ServiceAccountKeyAuthenticationCandidate) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("key_id", candidate.KeyID),
		slog.String("service_account_id", candidate.ServiceAccountID),
	)
}

func (rotation ServiceAccountKeyRotation) String() string {
	return fmt.Sprintf(
		"ServiceAccountKeyRotation{service_account=%s old_key=%s new_key=%s revoked_at=%s}",
		rotation.ServiceAccountID, rotation.OldKeyID, rotation.NewKey.String(), rotation.RevokedAt.Format(time.RFC3339Nano),
	)
}

func (rotation ServiceAccountKeyRotation) GoString() string {
	return rotation.String()
}

func (rotation ServiceAccountKeyRotation) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("service_account_id", rotation.ServiceAccountID),
		slog.String("old_key_id", rotation.OldKeyID),
		slog.Any("new_key", rotation.NewKey),
		slog.Time("revoked_at", rotation.RevokedAt),
	)
}

type ServiceAccountKeyUse struct {
	KeyID  string
	UsedAt time.Time
}

type AuthenticatedServiceAccountKey struct {
	KeyID                 string
	ServiceAccountID      string
	TeamID                string
	ResponsibleIdentityID string
}

type ServiceAccountRepository interface {
	CreateServiceAccount(context.Context, ServiceAccountRecord) error
	ListServiceAccounts(context.Context, string) ([]ServiceAccount, error)
	CreateServiceAccountKey(context.Context, ServiceAccountKeyRecord) (ServiceAccountKey, error)
	ListServiceAccountKeys(context.Context, string, string) ([]ServiceAccountKey, error)
	RotateServiceAccountKey(context.Context, ServiceAccountKeyRotation) (ServiceAccountKey, error)
	RevokeServiceAccountKey(context.Context, ServiceAccountKeyRevocation) error
	FindServiceAccountKeyCandidates(context.Context, string) ([]ServiceAccountKeyAuthenticationCandidate, error)
	RecordServiceAccountKeyUse(context.Context, ServiceAccountKeyUse) (AuthenticatedServiceAccountKey, error)
}

type ServiceAccountService struct {
	repository ServiceAccountRepository
	keys       *APIKeyGenerator
	now        func() time.Time
	newID      func() (string, error)
}

func NewServiceAccountService(repository ServiceAccountRepository) *ServiceAccountService {
	return &ServiceAccountService{
		repository: repository,
		keys:       NewAPIKeyGenerator(),
		now:        time.Now,
		newID:      newIdentityID,
	}
}

func (service *ServiceAccountService) Create(ctx context.Context, input CreateServiceAccountInput) (ServiceAccount, error) {
	if !isSystemAdministrator(input.Actor) {
		return ServiceAccount{}, ErrForbidden
	}
	teamID := strings.TrimSpace(input.TeamID)
	responsibleIdentityID := strings.TrimSpace(input.ResponsibleIdentityID)
	name := strings.TrimSpace(input.Name)
	if service == nil || service.repository == nil || teamID == "" || responsibleIdentityID == "" || name == "" {
		return ServiceAccount{}, ErrInvalidServiceAccount
	}
	id, err := service.newID()
	if err != nil {
		return ServiceAccount{}, err
	}
	createdAt := service.now().UTC()
	eventID, err := service.newID()
	if err != nil {
		return ServiceAccount{}, err
	}
	requestID, err := credentialLifecycleRequestID(input.RequestID)
	if err != nil {
		return ServiceAccount{}, ErrInvalidServiceAccount
	}
	if err := service.repository.CreateServiceAccount(ctx, ServiceAccountRecord{
		ID: id, TeamID: teamID, ResponsibleIdentityID: responsibleIdentityID, Name: name,
		CreatedByIdentityID: strings.TrimSpace(input.Actor.IdentityID), CreatedAt: createdAt,
		Event: SecurityEvent{
			ID: eventID, EventType: "service_account_created", ActorIdentityID: strings.TrimSpace(input.Actor.IdentityID),
			TargetServiceAccountID: id, RequestID: requestID, Outcome: SecurityEventSuccess,
			DetailCode: "active", OccurredAt: createdAt,
		},
	}); err != nil {
		return ServiceAccount{}, err
	}
	return ServiceAccount{
		ID: id, TeamID: teamID, ResponsibleIdentityID: responsibleIdentityID, Name: name,
		Status: ServiceAccountStatusActive, CreatedAt: createdAt, UpdatedAt: createdAt,
	}, nil
}

func (service *ServiceAccountService) List(ctx context.Context, actor Actor) ([]ServiceAccount, error) {
	if !isSystemAdministrator(actor) {
		return nil, ErrForbidden
	}
	if service == nil || service.repository == nil {
		return nil, ErrForbidden
	}
	return service.repository.ListServiceAccounts(ctx, strings.TrimSpace(actor.IdentityID))
}

func (service *ServiceAccountService) CreateKey(ctx context.Context, input CreateServiceAccountKeyInput) (ServiceAccountKeyIssuance, error) {
	if !isSystemAdministrator(input.Actor) {
		return ServiceAccountKeyIssuance{}, ErrForbidden
	}
	serviceAccountID := strings.TrimSpace(input.ServiceAccountID)
	name := strings.TrimSpace(input.Name)
	if service == nil || service.repository == nil || serviceAccountID == "" || name == "" {
		return ServiceAccountKeyIssuance{}, ErrInvalidServiceAccountKey
	}
	createdAt := service.now().UTC()
	lifecycle, err := newCredentialLifecycleContext(
		CredentialLifecycleServiceKeyCreated, input.Actor.IdentityID, "", serviceAccountID, input.RequestID, createdAt,
	)
	if err != nil {
		return ServiceAccountKeyIssuance{}, err
	}
	id, err := service.newID()
	if err != nil {
		return ServiceAccountKeyIssuance{}, err
	}
	credential, err := service.keys.Generate()
	if err != nil {
		return ServiceAccountKeyIssuance{}, err
	}
	record := ServiceAccountKeyRecord{
		ID: id, ServiceAccountID: serviceAccountID, Kind: ServiceAccountKeyKind,
		Name: name, Prefix: credential.Prefix(), VerificationHash: credential.VerificationHash(),
		CreatedByIdentityID: strings.TrimSpace(input.Actor.IdentityID), CreatedAt: createdAt,
		Lifecycle: lifecycle,
	}
	key, err := service.repository.CreateServiceAccountKey(ctx, record)
	if err != nil {
		credential.Reveal()
		return ServiceAccountKeyIssuance{}, err
	}
	return ServiceAccountKeyIssuance{Key: key, Credential: *credential}, nil
}

func (service *ServiceAccountService) ListKeys(ctx context.Context, input ListServiceAccountKeysInput) ([]ServiceAccountKey, error) {
	if !isSystemAdministrator(input.Actor) {
		return nil, ErrForbidden
	}
	serviceAccountID := strings.TrimSpace(input.ServiceAccountID)
	if service == nil || service.repository == nil || serviceAccountID == "" {
		return nil, ErrServiceAccountKeyNotFound
	}
	return service.repository.ListServiceAccountKeys(ctx, serviceAccountID, strings.TrimSpace(input.Actor.IdentityID))
}

func (service *ServiceAccountService) RevokeKey(ctx context.Context, input RevokeServiceAccountKeyInput) error {
	if !isSystemAdministrator(input.Actor) {
		return ErrForbidden
	}
	serviceAccountID := strings.TrimSpace(input.ServiceAccountID)
	keyID := strings.TrimSpace(input.KeyID)
	if service == nil || service.repository == nil || serviceAccountID == "" || keyID == "" {
		return ErrServiceAccountKeyNotFound
	}
	revokedAt := service.now().UTC()
	lifecycle, err := newCredentialLifecycleContext(
		CredentialLifecycleServiceKeyRevoked, input.Actor.IdentityID, "", serviceAccountID, input.RequestID, revokedAt,
	)
	if err != nil {
		return err
	}
	return service.repository.RevokeServiceAccountKey(ctx, ServiceAccountKeyRevocation{
		ServiceAccountID: serviceAccountID, KeyID: keyID,
		ActorIdentityID: strings.TrimSpace(input.Actor.IdentityID), RevokedAt: revokedAt, Lifecycle: lifecycle,
	})
}

func (service *ServiceAccountService) RotateKey(ctx context.Context, input RotateServiceAccountKeyInput) (ServiceAccountKeyIssuance, error) {
	if !isSystemAdministrator(input.Actor) {
		return ServiceAccountKeyIssuance{}, ErrForbidden
	}
	serviceAccountID := strings.TrimSpace(input.ServiceAccountID)
	keyID := strings.TrimSpace(input.KeyID)
	name := strings.TrimSpace(input.Name)
	if service == nil || service.repository == nil || serviceAccountID == "" || keyID == "" || name == "" {
		return ServiceAccountKeyIssuance{}, ErrInvalidServiceAccountKey
	}
	rotatedAt := service.now().UTC()
	revokedLifecycle, err := newCredentialLifecycleContext(
		CredentialLifecycleServiceKeyRotationRevoked, input.Actor.IdentityID, "", serviceAccountID, input.RequestID, rotatedAt,
	)
	if err != nil {
		return ServiceAccountKeyIssuance{}, err
	}
	createdLifecycle, err := newCredentialLifecycleContext(
		CredentialLifecycleServiceKeyRotationCreated, input.Actor.IdentityID, "", serviceAccountID, revokedLifecycle.RequestID, rotatedAt,
	)
	if err != nil {
		return ServiceAccountKeyIssuance{}, err
	}
	id, err := service.newID()
	if err != nil {
		return ServiceAccountKeyIssuance{}, err
	}
	credential, err := service.keys.Generate()
	if err != nil {
		return ServiceAccountKeyIssuance{}, err
	}
	newKey := ServiceAccountKeyRecord{
		ID: id, ServiceAccountID: serviceAccountID, Kind: ServiceAccountKeyKind,
		Name: name, Prefix: credential.Prefix(), VerificationHash: credential.VerificationHash(),
		CreatedByIdentityID: strings.TrimSpace(input.Actor.IdentityID), CreatedAt: rotatedAt,
		Lifecycle: createdLifecycle,
	}
	key, err := service.repository.RotateServiceAccountKey(ctx, ServiceAccountKeyRotation{
		ServiceAccountID: serviceAccountID, OldKeyID: keyID, NewKey: newKey,
		RevokedAt: rotatedAt, RevokedLifecycle: revokedLifecycle, CreatedLifecycle: createdLifecycle,
	})
	if err != nil {
		credential.Reveal()
		return ServiceAccountKeyIssuance{}, err
	}
	return ServiceAccountKeyIssuance{Key: key, Credential: *credential}, nil
}

func (service *ServiceAccountService) Authenticate(ctx context.Context, credential string) (AuthenticatedServiceAccountKey, error) {
	encodedLength := base64.RawURLEncoding.EncodedLen(apiKeyRandomBytes)
	if service == nil || service.repository == nil || len(credential) != len(apiKeyPrefix)+encodedLength || !strings.HasPrefix(credential, apiKeyPrefix) {
		return AuthenticatedServiceAccountKey{}, ErrInvalidAPIKey
	}
	candidates, err := service.repository.FindServiceAccountKeyCandidates(ctx, credential[:apiKeyPrefixLength])
	if err != nil {
		return AuthenticatedServiceAccountKey{}, err
	}
	matchedIndex := -1
	for index := range candidates {
		if VerifyAPIKey(credential, candidates[index].VerificationHash) {
			if matchedIndex != -1 {
				return AuthenticatedServiceAccountKey{}, ErrInvalidAPIKey
			}
			matchedIndex = index
		}
	}
	if matchedIndex == -1 || candidates[matchedIndex].ServiceAccountID == "" {
		return AuthenticatedServiceAccountKey{}, ErrInvalidAPIKey
	}
	authenticated, err := service.repository.RecordServiceAccountKeyUse(ctx, ServiceAccountKeyUse{
		KeyID: candidates[matchedIndex].KeyID, UsedAt: service.now().UTC(),
	})
	if err != nil {
		return AuthenticatedServiceAccountKey{}, err
	}
	if authenticated.KeyID != candidates[matchedIndex].KeyID || authenticated.ServiceAccountID != candidates[matchedIndex].ServiceAccountID || authenticated.TeamID == "" || authenticated.ResponsibleIdentityID == "" {
		return AuthenticatedServiceAccountKey{}, ErrInvalidAPIKey
	}
	return authenticated, nil
}

func isSystemAdministrator(actor Actor) bool {
	return actor.Role == RoleSystemAdministrator && strings.TrimSpace(actor.IdentityID) != ""
}
