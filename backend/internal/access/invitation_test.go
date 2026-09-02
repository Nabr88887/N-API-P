package access

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

var fixedNow = time.Date(2026, time.August, 1, 9, 0, 0, 0, time.UTC)

func TestInvitationCreatesPendingEmployeeWithEmailBoundHashedActivation(t *testing.T) {
	repository := newMemoryAccessRepository()
	service := NewInvitationService(repository)
	service.now = func() time.Time { return fixedNow }
	service.random = bytes.NewReader(bytes.Repeat([]byte{0x42}, activationRandomBytes))

	invitation, err := service.Create(context.Background(), CreateInvitationInput{
		Actor:  Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator},
		Email:  "  Employee@Example.Internal ",
		TeamID: "team-1",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if invitation.IdentityID == "" {
		t.Fatal("IdentityID is empty")
	}
	if invitation.Email != "employee@example.internal" {
		t.Fatalf("Email = %q, want normalized email", invitation.Email)
	}
	if invitation.ActivationValue == "" {
		t.Fatal("ActivationValue is empty")
	}
	if !invitation.ExpiresAt.Equal(fixedNow.Add(24 * time.Hour)) {
		t.Fatalf("ExpiresAt = %v, want %v", invitation.ExpiresAt, fixedNow.Add(24*time.Hour))
	}

	identity := repository.identities[invitation.IdentityID]
	if identity.Status != IdentityStatusPending || identity.Role != RoleEmployee {
		t.Fatalf("identity = %+v, want pending employee", identity)
	}
	if identity.Email != invitation.Email {
		t.Fatalf("stored email = %q, want %q", identity.Email, invitation.Email)
	}
	if got := repository.memberships[invitation.IdentityID]; got != "team-1" {
		t.Fatalf("membership team = %q, want team-1", got)
	}

	code := repository.codesByIdentity[invitation.IdentityID][0]
	if string(code.Hash) == invitation.ActivationValue {
		t.Fatal("repository received the complete activation value instead of its hash")
	}
	if code.Email != invitation.Email {
		t.Fatalf("code email = %q, want %q", code.Email, invitation.Email)
	}
	if !code.ExpiresAt.Equal(invitation.ExpiresAt) {
		t.Fatalf("code expiry = %v, want %v", code.ExpiresAt, invitation.ExpiresAt)
	}
}

func TestInvitationRejectsNonSystemAdministratorWithoutMutation(t *testing.T) {
	roles := []Role{"", RoleEmployee, RoleTeamAdministrator}
	for _, role := range roles {
		t.Run(string(role), func(t *testing.T) {
			repository := newMemoryAccessRepository()
			service := NewInvitationService(repository)

			_, err := service.Create(context.Background(), CreateInvitationInput{
				Actor:  Actor{IdentityID: "caller-1", Role: role},
				Email:  "employee@example.internal",
				TeamID: "team-1",
			})

			if !errors.Is(err, ErrForbidden) {
				t.Fatalf("Create() error = %v, want ErrForbidden", err)
			}
			assertRepositoryEmpty(t, repository)
		})
	}
}

func TestInvitationRejectsDuplicateNormalizedEmailWithoutMutation(t *testing.T) {
	repository := newMemoryAccessRepository()
	service := NewInvitationService(repository)
	actor := Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator}

	first, err := service.Create(context.Background(), CreateInvitationInput{
		Actor: actor, Email: "employee@example.internal", TeamID: "team-1",
	})
	if err != nil {
		t.Fatalf("first Create() error = %v", err)
	}

	_, err = service.Create(context.Background(), CreateInvitationInput{
		Actor: actor, Email: "  EMPLOYEE@example.internal ", TeamID: "team-2",
	})
	if !errors.Is(err, ErrEmailAlreadyExists) {
		t.Fatalf("second Create() error = %v, want ErrEmailAlreadyExists", err)
	}
	if len(repository.identities) != 1 || len(repository.memberships) != 1 || len(repository.codesByIdentity) != 1 {
		t.Fatalf("duplicate invitation mutated repository: identities=%d memberships=%d code owners=%d", len(repository.identities), len(repository.memberships), len(repository.codesByIdentity))
	}
	if _, ok := repository.identities[first.IdentityID]; !ok {
		t.Fatal("original identity was replaced")
	}
}

func TestInvitationRepositoryFailureCreatesNoPartialState(t *testing.T) {
	repository := newMemoryAccessRepository()
	repository.createErr = errors.New("synthetic transaction failure")
	service := NewInvitationService(repository)

	_, err := service.Create(context.Background(), CreateInvitationInput{
		Actor:  Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator},
		Email:  "employee@example.internal",
		TeamID: "team-1",
	})
	if err == nil {
		t.Fatal("Create() error = nil, want repository failure")
	}
	assertRepositoryEmpty(t, repository)
}

func TestActivationRejectsAnonymousPublicRegistrationWithoutMutation(t *testing.T) {
	repository := newMemoryAccessRepository()
	service := NewActivationService(repository, staticPasswordInitializer{}, NewActivationLimiter())
	service.now = func() time.Time { return fixedNow }

	err := service.Activate(context.Background(), ActivateInput{
		AttemptSource: "source-a", Email: "unknown@example.internal", ActivationValue: "not-admin-issued", NewPassword: "valid-password-placeholder",
	})

	if err != ErrActivationRejected {
		t.Fatalf("Activate() error = %v, want indistinguishable rejection", err)
	}
	assertRepositoryEmpty(t, repository)
}

func TestActivationRejectsInvalidStatesIndistinguishably(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*memoryAccessRepository, string)
		email  string
	}{
		{name: "wrong email", email: "other@example.internal"},
		{name: "exact expiry boundary", mutate: func(repository *memoryAccessRepository, identityID string) {
			repository.codesByIdentity[identityID][0].ExpiresAt = fixedNow
		}},
		{name: "used", mutate: func(repository *memoryAccessRepository, identityID string) {
			usedAt := fixedNow.Add(-time.Minute)
			repository.codesByIdentity[identityID][0].UsedAt = &usedAt
		}},
		{name: "revoked", mutate: func(repository *memoryAccessRepository, identityID string) {
			revokedAt := fixedNow.Add(-time.Minute)
			repository.codesByIdentity[identityID][0].RevokedAt = &revokedAt
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repository, activation, identityID := createPendingInvitation(t)
			if tt.mutate != nil {
				tt.mutate(repository, identityID)
			}
			email := activation.Email
			if tt.email != "" {
				email = tt.email
			}
			before := repository.identities[identityID]
			service := NewActivationService(repository, staticPasswordInitializer{}, NewActivationLimiter())
			service.now = func() time.Time { return fixedNow }

			err := service.Activate(context.Background(), ActivateInput{
				AttemptSource: "source-a", Email: email, ActivationValue: activation.ActivationValue, NewPassword: "valid-password-placeholder",
			})

			if err != ErrActivationRejected {
				t.Fatalf("Activate() error = %v, want indistinguishable rejection", err)
			}
			after := repository.identities[identityID]
			if after != before {
				t.Fatalf("rejected activation changed identity: before=%+v after=%+v", before, after)
			}
		})
	}
}

func TestActivationConsumesValueOnceAndRevokesSiblingValues(t *testing.T) {
	repository, first, identityID := createPendingInvitation(t)
	second := appendSiblingActivation(t, repository, identityID, first.Email)
	service := NewActivationService(repository, staticPasswordInitializer{}, NewActivationLimiter())
	service.now = func() time.Time { return fixedNow }

	err := service.Activate(context.Background(), ActivateInput{
		AttemptSource: "source-a", Email: first.Email, ActivationValue: first.ActivationValue, NewPassword: "valid-password-placeholder",
	})
	if err != nil {
		t.Fatalf("Activate() error = %v", err)
	}

	identity := repository.identities[identityID]
	if identity.ID != identityID || identity.Status != IdentityStatusActive {
		t.Fatalf("activated identity = %+v, want same ID and active status", identity)
	}
	if identity.PasswordHash != "password-hash" {
		t.Fatalf("PasswordHash = %q, want initialized hash", identity.PasswordHash)
	}
	if identity.PasswordHash == "valid-password-placeholder" {
		t.Fatal("plaintext password was persisted")
	}
	if repository.codesByIdentity[identityID][0].UsedAt == nil {
		t.Fatal("consumed activation value was not marked used")
	}
	if repository.codesByIdentity[identityID][1].RevokedAt == nil {
		t.Fatal("sibling activation value was not revoked")
	}
	if event := repository.activation.Event; event.EventType != "activation_completed" ||
		event.TargetIdentityID != identityID || event.Outcome != SecurityEventSuccess ||
		event.RequestID == "" || !event.OccurredAt.Equal(fixedNow) {
		t.Fatalf("activation completion event = %+v", event)
	}

	for _, attempt := range []Invitation{
		first,
		second,
	} {
		err := service.Activate(context.Background(), ActivateInput{
			AttemptSource: "source-a", Email: attempt.Email, ActivationValue: attempt.ActivationValue, NewPassword: "valid-password-placeholder",
		})
		if err != ErrActivationRejected {
			t.Fatalf("reused/sibling Activate() error = %v, want indistinguishable rejection", err)
		}
	}
}

func TestActivationRejectsInvalidPasswordWithoutConsumingValue(t *testing.T) {
	repository, activation, identityID := createPendingInvitation(t)
	service := NewActivationService(repository, rejectingPasswordInitializer{}, NewActivationLimiter())
	service.now = func() time.Time { return fixedNow }

	err := service.Activate(context.Background(), ActivateInput{
		AttemptSource: "source-a", Email: activation.Email, ActivationValue: activation.ActivationValue, NewPassword: "short",
	})

	if err != ErrPasswordRejected {
		t.Fatalf("Activate() error = %v, want ErrPasswordRejected", err)
	}
	if repository.identities[identityID].Status != IdentityStatusPending {
		t.Fatal("invalid password activated the identity")
	}
	if repository.codesByIdentity[identityID][0].UsedAt != nil {
		t.Fatal("invalid password consumed the activation value")
	}
}

func TestActivationMapsPasswordInitializationFailureWithoutConsumingValue(t *testing.T) {
	repository, activation, identityID := createPendingInvitation(t)
	service := NewActivationService(repository, failingPasswordInitializer{}, NewActivationLimiter())
	service.now = func() time.Time { return fixedNow }

	err := service.Activate(context.Background(), ActivateInput{
		AttemptSource: "source-a", Email: activation.Email, ActivationValue: activation.ActivationValue, NewPassword: "valid-password-placeholder",
	})

	if err != ErrPasswordInitializationFailed {
		t.Fatalf("Activate() error = %v, want ErrPasswordInitializationFailed", err)
	}
	if repository.identities[identityID].Status != IdentityStatusPending {
		t.Fatal("password initialization failure activated the identity")
	}
	if repository.codesByIdentity[identityID][0].UsedAt != nil {
		t.Fatal("password initialization failure consumed the activation value")
	}
}

func TestIdentityEmailChangePreservesImmutableIDAndOwnership(t *testing.T) {
	repository, _, identityID := createPendingInvitation(t)
	identity := repository.identities[identityID]
	identity.Status = IdentityStatusActive
	repository.identities[identityID] = identity
	repository.ownedResources[identityID] = []string{"key-1", "usage-1", "audit-1"}
	service := NewIdentityService(repository)
	service.now = func() time.Time { return fixedNow }

	err := service.ChangeEmail(context.Background(), ChangeEmailInput{
		Actor:      Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator},
		IdentityID: identityID,
		Email:      " New.Address@Example.Internal ",
	})
	if err != nil {
		t.Fatalf("ChangeEmail() error = %v", err)
	}

	identity = repository.identities[identityID]
	if identity.ID != identityID {
		t.Fatalf("identity ID = %q, want immutable %q", identity.ID, identityID)
	}
	if identity.Email != "new.address@example.internal" {
		t.Fatalf("Email = %q, want normalized new address", identity.Email)
	}
	if repository.codesByIdentity[identityID][0].RevokedAt == nil {
		t.Fatal("email change did not revoke activation values bound to the old email")
	}
	resources := repository.ownedResources[identityID]
	if len(resources) != 3 || resources[0] != "key-1" || resources[1] != "usage-1" || resources[2] != "audit-1" {
		t.Fatalf("ownership changed after email update: %v", resources)
	}
}

func TestIdentityEmailChangeRejectsPendingWithoutRevokingActivation(t *testing.T) {
	repository, activation, identityID := createPendingInvitation(t)
	service := NewIdentityService(repository)
	service.now = func() time.Time { return fixedNow }

	err := service.ChangeEmail(context.Background(), ChangeEmailInput{
		Actor:      Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator},
		IdentityID: identityID,
		Email:      "new.address@example.internal",
	})
	if !errors.Is(err, ErrInvalidEmailChange) {
		t.Fatalf("ChangeEmail() error = %v, want ErrInvalidEmailChange", err)
	}
	if got := repository.identities[identityID].Email; got != activation.Email {
		t.Fatalf("pending identity email = %q, want unchanged %q", got, activation.Email)
	}
	if repository.codesByIdentity[identityID][0].RevokedAt != nil {
		t.Fatal("pending identity email change revoked its activation value")
	}
}

type staticPasswordInitializer struct{}

func (staticPasswordInitializer) Initialize(string) (string, error) {
	return "password-hash", nil
}

type rejectingPasswordInitializer struct{}

func (rejectingPasswordInitializer) Initialize(string) (string, error) {
	return "", ErrPasswordRejected
}

type failingPasswordInitializer struct{}

func (failingPasswordInitializer) Initialize(string) (string, error) {
	return "", errors.New("password hashing unavailable")
}

type memoryIdentity struct {
	ID           string
	Email        string
	Role         Role
	Status       IdentityStatus
	PasswordHash string
}

type memoryActivationCode struct {
	ID        string
	Hash      []byte
	Email     string
	ExpiresAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time
}

type memoryAccessRepository struct {
	identities      map[string]memoryIdentity
	memberships     map[string]string
	codesByIdentity map[string][]*memoryActivationCode
	ownedResources  map[string][]string
	activation      ActivationRecord
	createErr       error
}

func newMemoryAccessRepository() *memoryAccessRepository {
	return &memoryAccessRepository{
		identities:      make(map[string]memoryIdentity),
		memberships:     make(map[string]string),
		codesByIdentity: make(map[string][]*memoryActivationCode),
		ownedResources:  make(map[string][]string),
	}
}

func (repository *memoryAccessRepository) CreateInvitation(_ context.Context, record InvitationRecord) error {
	if repository.createErr != nil {
		return repository.createErr
	}
	for _, identity := range repository.identities {
		if identity.Email == record.Email {
			return ErrEmailAlreadyExists
		}
	}
	repository.identities[record.IdentityID] = memoryIdentity{
		ID: record.IdentityID, Email: record.Email, Role: record.Role, Status: record.Status,
	}
	repository.memberships[record.IdentityID] = record.TeamID
	repository.codesByIdentity[record.IdentityID] = append(repository.codesByIdentity[record.IdentityID], &memoryActivationCode{
		ID: record.ActivationID, Hash: append([]byte(nil), record.ActivationHash...), Email: record.Email, ExpiresAt: record.ExpiresAt,
	})
	return nil
}

func (repository *memoryAccessRepository) PrepareActivation(_ context.Context, lookup ActivationLookup) (ActivationCandidate, error) {
	for identityID, codes := range repository.codesByIdentity {
		identity := repository.identities[identityID]
		for _, code := range codes {
			if bytes.Equal(code.Hash, lookup.ActivationHash) && code.Email == lookup.Email && lookup.CheckedAt.Before(code.ExpiresAt) && code.UsedAt == nil && code.RevokedAt == nil && identity.Status == IdentityStatusPending {
				return ActivationCandidate{CodeID: code.ID, IdentityID: identityID}, nil
			}
		}
	}
	return ActivationCandidate{}, ErrActivationRejected
}

func (repository *memoryAccessRepository) ActivateIdentity(_ context.Context, record ActivationRecord) error {
	repository.activation = record
	identity, ok := repository.identities[record.Candidate.IdentityID]
	if !ok || identity.Status != IdentityStatusPending || identity.Email != record.Email {
		return ErrActivationRejected
	}
	codes := repository.codesByIdentity[record.Candidate.IdentityID]
	for _, code := range codes {
		if code.ID != record.Candidate.CodeID {
			continue
		}
		if !bytes.Equal(code.Hash, record.ActivationHash) || code.Email != record.Email || !record.ActivatedAt.Before(code.ExpiresAt) || code.UsedAt != nil || code.RevokedAt != nil {
			return ErrActivationRejected
		}
		code.UsedAt = timePointer(record.ActivatedAt)
		for _, sibling := range codes {
			if sibling != code && sibling.UsedAt == nil && sibling.RevokedAt == nil {
				sibling.RevokedAt = timePointer(record.ActivatedAt)
			}
		}
		identity.Status = IdentityStatusActive
		identity.PasswordHash = record.PasswordHash
		repository.identities[record.Candidate.IdentityID] = identity
		return nil
	}
	return ErrActivationRejected
}

func (repository *memoryAccessRepository) ChangeIdentityEmail(_ context.Context, record EmailChangeRecord) error {
	identity, ok := repository.identities[record.IdentityID]
	if !ok {
		return ErrIdentityNotFound
	}
	if identity.Status != IdentityStatusActive {
		return ErrInvalidEmailChange
	}
	for identityID, existing := range repository.identities {
		if identityID != record.IdentityID && existing.Email == record.Email {
			return ErrEmailAlreadyExists
		}
	}
	identity.Email = record.Email
	repository.identities[record.IdentityID] = identity
	for _, code := range repository.codesByIdentity[record.IdentityID] {
		if code.UsedAt == nil && code.RevokedAt == nil {
			code.RevokedAt = timePointer(record.ChangedAt)
		}
	}
	return nil
}

func createPendingInvitation(t *testing.T) (*memoryAccessRepository, Invitation, string) {
	t.Helper()
	repository := newMemoryAccessRepository()
	service := NewInvitationService(repository)
	service.now = func() time.Time { return fixedNow.Add(-time.Hour) }
	invitation, err := service.Create(context.Background(), CreateInvitationInput{
		Actor: Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator}, Email: "employee@example.internal", TeamID: "team-1",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	return repository, invitation, invitation.IdentityID
}

func appendSiblingActivation(t *testing.T, repository *memoryAccessRepository, identityID, email string) Invitation {
	t.Helper()
	service := NewInvitationService(repository)
	service.now = func() time.Time { return fixedNow.Add(-30 * time.Minute) }
	value, hash, err := service.newActivationValue()
	if err != nil {
		t.Fatalf("newActivationValue() error = %v", err)
	}
	expiresAt := service.now().Add(24 * time.Hour)
	repository.codesByIdentity[identityID] = append(repository.codesByIdentity[identityID], &memoryActivationCode{
		ID: "sibling-code", Hash: hash, Email: email, ExpiresAt: expiresAt,
	})
	return Invitation{Email: email, ActivationValue: value, ExpiresAt: expiresAt}
}

func assertRepositoryEmpty(t *testing.T, repository *memoryAccessRepository) {
	t.Helper()
	if len(repository.identities) != 0 || len(repository.memberships) != 0 || len(repository.codesByIdentity) != 0 {
		t.Fatalf("repository mutated: identities=%d memberships=%d code owners=%d", len(repository.identities), len(repository.memberships), len(repository.codesByIdentity))
	}
}

func timePointer(value time.Time) *time.Time {
	copy := value
	return &copy
}
