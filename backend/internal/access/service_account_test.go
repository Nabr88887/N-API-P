package access

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

var serviceAccountTestTime = time.Date(2026, time.August, 4, 10, 0, 0, 0, time.UTC)

func TestServiceAccountManagementIsSystemAdministratorOnly(t *testing.T) {
	repository := &serviceAccountRepositoryFake{}
	service := NewServiceAccountService(repository)

	for _, actor := range []Actor{
		{IdentityID: "employee-1", Role: RoleEmployee},
		{IdentityID: "team-admin-1", Role: RoleTeamAdministrator},
		{IdentityID: "", Role: RoleSystemAdministrator},
	} {
		input := CreateServiceAccountInput{
			Actor:                 actor,
			TeamID:                "team-1",
			ResponsibleIdentityID: "employee-1",
			Name:                  "build-agent",
		}
		if _, err := service.Create(context.Background(), input); !errors.Is(err, ErrForbidden) {
			t.Fatalf("Create() actor %#v error = %v, want ErrForbidden", actor, err)
		}
		if _, err := service.List(context.Background(), actor); !errors.Is(err, ErrForbidden) {
			t.Fatalf("List() actor %#v error = %v, want ErrForbidden", actor, err)
		}
		if _, err := service.CreateKey(context.Background(), CreateServiceAccountKeyInput{
			Actor: actor, ServiceAccountID: "service-1", Name: "primary",
		}); !errors.Is(err, ErrForbidden) {
			t.Fatalf("CreateKey() actor %#v error = %v, want ErrForbidden", actor, err)
		}
		if _, err := service.ListKeys(context.Background(), ListServiceAccountKeysInput{
			Actor: actor, ServiceAccountID: "service-1",
		}); !errors.Is(err, ErrForbidden) {
			t.Fatalf("ListKeys() actor %#v error = %v, want ErrForbidden", actor, err)
		}
		if err := service.RevokeKey(context.Background(), RevokeServiceAccountKeyInput{
			Actor: actor, ServiceAccountID: "service-1", KeyID: "key-1",
		}); !errors.Is(err, ErrForbidden) {
			t.Fatalf("RevokeKey() actor %#v error = %v, want ErrForbidden", actor, err)
		}
		if _, err := service.RotateKey(context.Background(), RotateServiceAccountKeyInput{
			Actor: actor, ServiceAccountID: "service-1", KeyID: "key-1", Name: "rotated",
		}); !errors.Is(err, ErrForbidden) {
			t.Fatalf("RotateKey() actor %#v error = %v, want ErrForbidden", actor, err)
		}
	}
	if repository.managementCalls() != 0 {
		t.Fatalf("forbidden management reached repository %d times", repository.managementCalls())
	}
}

func TestServiceAccountKeyListingUsesBoundedOpaquePagination(t *testing.T) {
	repository := &serviceAccountRepositoryFake{
		listedServiceKeyPage: ServiceAccountKeyPage{
			Keys:       []ServiceAccountKey{{ID: "key-2", ServiceAccountID: "service-1"}},
			NextCursor: "opaque-next",
		},
	}
	service := NewServiceAccountService(repository)
	page, err := service.ListKeysPage(context.Background(), ListServiceAccountKeysInput{
		Actor: Actor{IdentityID: " admin-1 ", Role: RoleSystemAdministrator}, ServiceAccountID: " service-1 ",
	}, "opaque-current", 25)
	if err != nil {
		t.Fatalf("ListKeysPage() error = %v", err)
	}
	if len(page.Keys) != 1 || page.Keys[0].ID != "key-2" || page.NextCursor != "opaque-next" {
		t.Fatalf("ListKeysPage() = %#v", page)
	}
	if repository.pageServiceAccountID != "service-1" || repository.pageActorIdentityID != "admin-1" || repository.pageCursor != "opaque-current" || repository.pageLimit != 25 {
		t.Fatalf("page repository input = service %q actor %q cursor %q limit %d", repository.pageServiceAccountID, repository.pageActorIdentityID, repository.pageCursor, repository.pageLimit)
	}
	if _, err := service.ListKeysPage(context.Background(), ListServiceAccountKeysInput{
		Actor: Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator}, ServiceAccountID: "service-1",
	}, "", MaxAdministrationPageSize+1); !errors.Is(err, ErrInvalidServiceAccountKey) {
		t.Fatalf("ListKeysPage() oversized limit error = %v, want ErrInvalidServiceAccountKey", err)
	}
}

func TestServiceAccountServiceTrimsAndValidatesOwnerInvariant(t *testing.T) {
	repository := &serviceAccountRepositoryFake{}
	service := NewServiceAccountService(repository)
	service.newID = newTestServiceAccountIDGenerator()

	for _, input := range []CreateServiceAccountInput{
		{Actor: Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator}, TeamID: "", ResponsibleIdentityID: "employee-1", Name: "agent"},
		{Actor: Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator}, TeamID: "team-1", ResponsibleIdentityID: "", Name: "agent"},
		{Actor: Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator}, TeamID: "team-1", ResponsibleIdentityID: "employee-1", Name: " \t "},
	} {
		if _, err := service.Create(context.Background(), input); !errors.Is(err, ErrInvalidServiceAccount) {
			t.Fatalf("invalid service account input %#v error = %v, want ErrInvalidServiceAccount", input, err)
		}
	}

	account, err := service.Create(context.Background(), CreateServiceAccountInput{
		Actor:                 Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator},
		TeamID:                " team-1 ",
		ResponsibleIdentityID: " employee-1 ",
		Name:                  "  build-agent  ",
		RequestID:             "request-service-account-create",
	})
	if err != nil {
		t.Fatalf("valid Create() error = %v", err)
	}
	if account.Name != "build-agent" || account.TeamID != "team-1" || account.ResponsibleIdentityID != "employee-1" {
		t.Fatalf("Create() did not trim service-account owner metadata: %#v", account)
	}
	if repository.createdServiceAccount.Name != "build-agent" || repository.createdServiceAccount.TeamID != "team-1" || repository.createdServiceAccount.ResponsibleIdentityID != "employee-1" {
		t.Fatalf("repository received invalid service-account record: %#v", repository.createdServiceAccount)
	}
	if event := repository.createdServiceAccount.Event; event.EventType != "service_account_created" ||
		event.ActorIdentityID != "admin-1" || event.TargetServiceAccountID != account.ID ||
		event.RequestID != "request-service-account-create" || event.Outcome != SecurityEventSuccess {
		t.Fatalf("service-account creation event = %+v", event)
	}
}

func TestServiceAccountKeyIssuanceIsHashOnlyOneTimeAndAttributed(t *testing.T) {
	repository := &serviceAccountRepositoryFake{}
	service := NewServiceAccountService(repository)
	service.now = func() time.Time { return serviceAccountTestTime }
	service.newID = newTestServiceAccountIDGenerator()
	service.keys.random = bytes.NewReader(bytes.Repeat([]byte{0x73}, apiKeyRandomBytes))

	issuance, err := service.CreateKey(context.Background(), CreateServiceAccountKeyInput{
		Actor:            Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator},
		ServiceAccountID: "service-1",
		Name:             "  deploy  ",
		RequestID:        "request-service-create",
	})
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	if issuance.Key.ServiceAccountID != "service-1" || issuance.Key.TeamID != "team-1" || issuance.Key.ResponsibleIdentityID != "employee-1" {
		t.Fatalf("CreateKey() attribution = %#v", issuance.Key)
	}
	encoded, err := json.Marshal(issuance)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	wantSecret := "nap_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x73}, apiKeyRandomBytes))
	if strings.Contains(strings.ToLower(string(encoded)), "verification") || strings.Contains(string(encoded), wantSecret) {
		t.Fatalf("service-key issuance exposed secret material: %s", encoded)
	}
	secret, ok := issuance.Credential.Reveal()
	if !ok || secret == "" {
		t.Fatalf("first service-key reveal = (%q, %t), want a credential", secret, ok)
	}
	if second, ok := issuance.Credential.Reveal(); ok || second != "" {
		t.Fatalf("second service-key reveal = (%q, %t), want empty and false", second, ok)
	}
	wantHash := sha256.Sum256([]byte(secret))
	if !bytes.Equal(repository.createdServiceKey.VerificationHash, wantHash[:]) || strings.Contains(string(repository.createdServiceKey.VerificationHash), secret) {
		t.Fatal("service-key repository record did not contain hash-only material")
	}
	if repository.createdServiceKey.Kind != ServiceAccountKeyKind {
		t.Fatalf("service-key kind = %q, want %q", repository.createdServiceKey.Kind, ServiceAccountKeyKind)
	}
	event, err := repository.createdServiceKey.Lifecycle.ForKey(repository.createdServiceKey.ID, repository.createdServiceKey.Prefix)
	if err != nil {
		t.Fatalf("create lifecycle event error = %v", err)
	}
	if event.Action != CredentialLifecycleServiceKeyCreated || event.ActorIdentityID != "admin-1" ||
		event.TargetServiceAccountID != "service-1" || event.RequestID != "request-service-create" ||
		!event.OccurredAt.Equal(serviceAccountTestTime) {
		t.Fatalf("create lifecycle event = %#v", event)
	}
}

func TestServiceAccountKeyLimitAndRotationPreserveOwnerAttribution(t *testing.T) {
	repository := &serviceAccountRepositoryFake{}
	service := NewServiceAccountService(repository)
	service.now = func() time.Time { return serviceAccountTestTime }
	service.newID = newTestServiceAccountIDGenerator()

	for _, name := range []string{"one", "two", "three"} {
		if _, err := service.CreateKey(context.Background(), CreateServiceAccountKeyInput{
			Actor: Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator}, ServiceAccountID: "service-1", Name: name,
		}); err != nil {
			t.Fatalf("seed key %q error = %v", name, err)
		}
	}
	if _, err := service.CreateKey(context.Background(), CreateServiceAccountKeyInput{
		Actor: Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator}, ServiceAccountID: "service-1", Name: "four",
	}); !errors.Is(err, ErrServiceAccountKeyLimitReached) {
		t.Fatalf("fourth active key error = %v, want ErrServiceAccountKeyLimitReached", err)
	}

	rotated, err := service.RotateKey(context.Background(), RotateServiceAccountKeyInput{
		Actor: Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator}, ServiceAccountID: "service-1", KeyID: "key-1", Name: "rotated", RequestID: "request-service-rotate",
	})
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}
	if rotated.Key.Name != "rotated" || rotated.Key.ServiceAccountID != "service-1" || rotated.Key.TeamID != "team-1" || rotated.Key.ResponsibleIdentityID != "employee-1" {
		t.Fatalf("rotated key attribution = %#v", rotated.Key)
	}
	if repository.rotated.OldKeyID != "key-1" || repository.rotated.NewKey.Name != "rotated" {
		t.Fatalf("repository rotation = %#v", repository.rotated)
	}
	if repository.rotated.RevokedLifecycle.Action != CredentialLifecycleServiceKeyRotationRevoked ||
		repository.rotated.CreatedLifecycle.Action != CredentialLifecycleServiceKeyRotationCreated ||
		repository.rotated.RevokedLifecycle.RequestID != "request-service-rotate" ||
		repository.rotated.CreatedLifecycle.RequestID != "request-service-rotate" {
		t.Fatalf("rotation lifecycle contexts = (%#v, %#v)", repository.rotated.RevokedLifecycle, repository.rotated.CreatedLifecycle)
	}
}

func TestServiceAccountAuthenticationNeverUsesPersonalCandidatesAndReturnsFullAttribution(t *testing.T) {
	secret := "nap_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, apiKeyRandomBytes))
	hash := sha256.Sum256([]byte(secret))
	repository := &serviceAccountRepositoryFake{
		serviceCandidates: []ServiceAccountKeyAuthenticationCandidate{{
			KeyID: "key-1", ServiceAccountID: "service-1", VerificationHash: hash[:],
		}},
		serviceAuthenticated: AuthenticatedServiceAccountKey{
			KeyID: "key-1", ServiceAccountID: "service-1", TeamID: "team-1", ResponsibleIdentityID: "employee-1",
		},
	}
	service := NewServiceAccountService(repository)
	service.now = func() time.Time { return serviceAccountTestTime }

	authenticated, err := service.Authenticate(context.Background(), secret)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if authenticated != repository.serviceAuthenticated {
		t.Fatalf("Authenticate() = %#v, want %#v", authenticated, repository.serviceAuthenticated)
	}
	if repository.serviceCandidatePrefix != secret[:apiKeyPrefixLength] || repository.personalCandidateCalls != 0 {
		t.Fatalf("service authentication candidate boundary = prefix %q, personal calls %d", repository.serviceCandidatePrefix, repository.personalCandidateCalls)
	}
	if _, err := service.Authenticate(context.Background(), secret+"x"); !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatalf("malformed service credential error = %v, want ErrInvalidAPIKey", err)
	}
}

func TestServiceAccountKeyManagementRejectsRepositoryErrorsAndRevokesByOwner(t *testing.T) {
	repository := &serviceAccountRepositoryFake{revokeKeyErr: ErrServiceAccountKeyNotFound}
	service := NewServiceAccountService(repository)
	err := service.RevokeKey(context.Background(), RevokeServiceAccountKeyInput{
		Actor: Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator}, ServiceAccountID: "service-1", KeyID: "key-1", RequestID: "request-service-revoke",
	})
	if !errors.Is(err, ErrServiceAccountKeyNotFound) {
		t.Fatalf("RevokeKey() error = %v, want ErrServiceAccountKeyNotFound", err)
	}
	if repository.revokedServiceKey.ServiceAccountID != "service-1" || repository.revokedServiceKey.KeyID != "key-1" {
		t.Fatalf("revoke owner boundary = %#v", repository.revokedServiceKey)
	}
	if repository.revokedServiceKey.Lifecycle.Action != CredentialLifecycleServiceKeyRevoked ||
		repository.revokedServiceKey.Lifecycle.ActorIdentityID != "admin-1" ||
		repository.revokedServiceKey.Lifecycle.TargetServiceAccountID != "service-1" ||
		repository.revokedServiceKey.Lifecycle.RequestID != "request-service-revoke" {
		t.Fatalf("revoke lifecycle context = %#v", repository.revokedServiceKey.Lifecycle)
	}
}

func newTestServiceAccountIDGenerator() func() (string, error) {
	var mu sync.Mutex
	ids := []string{
		"service-1", "key-1", "key-2", "key-3", "key-4", "key-5",
	}
	return func() (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if len(ids) == 0 {
			return "", errors.New("test id generator exhausted")
		}
		id := ids[0]
		ids = ids[1:]
		return id, nil
	}
}

type serviceAccountRepositoryFake struct {
	mu                        sync.Mutex
	createdServiceAccount     ServiceAccountRecord
	createServiceAccountErr   error
	createServiceAccountCalls int
	listedServiceAccounts     []ServiceAccount
	listServiceAccountsErr    error
	listServiceAccountCalls   int
	createdServiceKey         ServiceAccountKeyRecord
	createKeyErr              error
	createKeyCalls            int
	listedServiceKeys         []ServiceAccountKey
	listedServiceKeyPage      ServiceAccountKeyPage
	listKeysErr               error
	listKeyCalls              int
	pageServiceAccountID      string
	pageActorIdentityID       string
	pageCursor                string
	pageLimit                 int
	rotated                   ServiceAccountKeyRotation
	rotateKeyErr              error
	rotateKeyCalls            int
	revokedServiceKey         ServiceAccountKeyRevocation
	revokeKeyErr              error
	revokeKeyCalls            int
	serviceCandidatePrefix    string
	serviceCandidates         []ServiceAccountKeyAuthenticationCandidate
	serviceCandidatesErr      error
	serviceAuthenticated      AuthenticatedServiceAccountKey
	serviceUseErr             error
	personalCandidateCalls    int
}

func (r *serviceAccountRepositoryFake) CreateServiceAccount(_ context.Context, record ServiceAccountRecord) error {
	r.createServiceAccountCalls++
	r.createdServiceAccount = record
	return r.createServiceAccountErr
}

func (r *serviceAccountRepositoryFake) ListServiceAccounts(_ context.Context, _ string) ([]ServiceAccount, error) {
	r.listServiceAccountCalls++
	return r.listedServiceAccounts, r.listServiceAccountsErr
}

func (r *serviceAccountRepositoryFake) CreateServiceAccountKey(_ context.Context, record ServiceAccountKeyRecord) (ServiceAccountKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.createKeyCalls++
	r.createdServiceKey = record
	key := ServiceAccountKey{ID: record.ID, ServiceAccountID: record.ServiceAccountID, Name: record.Name, Prefix: record.Prefix, Status: ServiceAccountKeyStatusActive, CreatedAt: record.CreatedAt, TeamID: "team-1", ResponsibleIdentityID: "employee-1"}
	if r.createKeyCalls > MaxActiveServiceAccountKeys {
		return ServiceAccountKey{}, ErrServiceAccountKeyLimitReached
	}
	return key, r.createKeyErr
}

func (r *serviceAccountRepositoryFake) ListServiceAccountKeys(_ context.Context, _, _ string) ([]ServiceAccountKey, error) {
	r.listKeyCalls++
	return r.listedServiceKeys, r.listKeysErr
}

func (r *serviceAccountRepositoryFake) ListServiceAccountKeysPage(_ context.Context, serviceAccountID, actorIdentityID, cursor string, limit int) (ServiceAccountKeyPage, error) {
	r.listKeyCalls++
	r.pageServiceAccountID = serviceAccountID
	r.pageActorIdentityID = actorIdentityID
	r.pageCursor = cursor
	r.pageLimit = limit
	return r.listedServiceKeyPage, r.listKeysErr
}

func (r *serviceAccountRepositoryFake) RotateServiceAccountKey(_ context.Context, rotation ServiceAccountKeyRotation) (ServiceAccountKey, error) {
	r.rotateKeyCalls++
	r.rotated = rotation
	key := ServiceAccountKey{ID: rotation.NewKey.ID, ServiceAccountID: rotation.NewKey.ServiceAccountID, Name: rotation.NewKey.Name, Prefix: rotation.NewKey.Prefix, Status: ServiceAccountKeyStatusActive, CreatedAt: rotation.NewKey.CreatedAt, TeamID: "team-1", ResponsibleIdentityID: "employee-1"}
	return key, r.rotateKeyErr
}

func (r *serviceAccountRepositoryFake) RevokeServiceAccountKey(_ context.Context, revocation ServiceAccountKeyRevocation) error {
	r.revokeKeyCalls++
	r.revokedServiceKey = revocation
	return r.revokeKeyErr
}

func (r *serviceAccountRepositoryFake) FindServiceAccountKeyCandidates(_ context.Context, prefix string) ([]ServiceAccountKeyAuthenticationCandidate, error) {
	r.serviceCandidatePrefix = prefix
	return r.serviceCandidates, r.serviceCandidatesErr
}

func (r *serviceAccountRepositoryFake) RecordServiceAccountKeyUse(_ context.Context, _ ServiceAccountKeyUse) (AuthenticatedServiceAccountKey, error) {
	return r.serviceAuthenticated, r.serviceUseErr
}

func (r *serviceAccountRepositoryFake) managementCalls() int {
	return r.createServiceAccountCalls + r.listServiceAccountCalls + r.createKeyCalls + r.listKeyCalls + r.rotateKeyCalls + r.revokeKeyCalls
}

var _ ServiceAccountRepository = (*serviceAccountRepositoryFake)(nil)
