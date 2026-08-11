package access

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var personalKeyTestTime = time.Date(2026, time.August, 3, 9, 30, 0, 0, time.UTC)

func TestPersonalKeyServiceCreatesHashOnlyOneTimeCredential(t *testing.T) {
	repository := &personalKeyRepositoryFake{}
	service := NewPersonalKeyService(repository)
	service.now = func() time.Time { return personalKeyTestTime }
	service.newID = func() (string, error) { return "40000000-0000-0000-0000-000000000001", nil }
	randomBytes := bytes.Repeat([]byte{0x52}, apiKeyRandomBytes)
	service.keys.random = bytes.NewReader(randomBytes)

	issuance, err := service.Create(context.Background(), CreatePersonalKeyInput{
		IdentityID: "20000000-0000-0000-0000-000000000001",
		Name:       "  workstation  ",
		RequestID:  "request-personal-create",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	wantSecret := "nap_" + base64.RawURLEncoding.EncodeToString(randomBytes)
	encoded, err := json.Marshal(issuance)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	formatted := fmt.Sprintf("%+v %#v", issuance, issuance)
	if strings.Contains(string(encoded)+formatted, wantSecret) {
		t.Fatal("personal-key issuance exposed the complete credential through JSON or formatting")
	}

	secret, ok := issuance.Credential.Reveal()
	if !ok {
		t.Fatal("first credential reveal failed")
	}
	if second, ok := issuance.Credential.Reveal(); ok || second != "" {
		t.Fatalf("second credential reveal = (%q, %t), want empty and false", second, ok)
	}
	if secret != wantSecret {
		t.Fatalf("revealed credential = %q, want deterministic generated value", secret)
	}

	record := repository.created
	if record.ID != issuance.Key.ID || record.IdentityID != issuance.Key.IdentityID || record.Name != "workstation" {
		t.Fatalf("persisted identity metadata = %#v, issuance = %#v", record, issuance.Key)
	}
	if record.Prefix != issuance.Key.Prefix || !record.CreatedAt.Equal(personalKeyTestTime) {
		t.Fatalf("persisted key metadata = %#v", record)
	}
	wantHash := sha256.Sum256([]byte(secret))
	if !bytes.Equal(record.VerificationHash, wantHash[:]) || strings.Contains(string(record.VerificationHash), secret) {
		t.Fatal("repository did not receive hash-only verification material")
	}
	event, err := record.Lifecycle.ForKey(record.ID, record.Prefix)
	if err != nil {
		t.Fatalf("create lifecycle event error = %v", err)
	}
	if event.Action != CredentialLifecyclePersonalKeyCreated || event.ActorIdentityID != record.IdentityID ||
		event.TargetIdentityID != record.IdentityID || event.TargetKeyID != record.ID ||
		event.KeyPrefix != record.Prefix || event.RequestID != "request-personal-create" ||
		event.Outcome != SecurityEventSuccess || !event.OccurredAt.Equal(personalKeyTestTime) {
		t.Fatalf("create lifecycle event = %#v", event)
	}
}

func TestPersonalKeyServiceRejectsInvalidNameAndPreservesRepositoryErrors(t *testing.T) {
	repository := &personalKeyRepositoryFake{}
	service := NewPersonalKeyService(repository)

	if _, err := service.Create(context.Background(), CreatePersonalKeyInput{IdentityID: "identity", Name: " \t "}); !errors.Is(err, ErrInvalidPersonalKeyName) {
		t.Fatalf("blank-name Create() error = %v, want ErrInvalidPersonalKeyName", err)
	}
	if repository.createCalls != 0 {
		t.Fatalf("blank-name repository calls = %d, want 0", repository.createCalls)
	}

	for _, want := range []error{ErrPersonalKeyNameConflict, ErrPersonalKeyLimitReached, ErrForbidden} {
		repository.createErr = want
		if issuance, err := service.Create(context.Background(), CreatePersonalKeyInput{IdentityID: "identity", Name: "device"}); !errors.Is(err, want) {
			t.Fatalf("Create() error = %v, want %v", err, want)
		} else if _, ok := issuance.Credential.Reveal(); ok {
			t.Fatal("failed creation returned revealable credential material")
		}
	}
}

func TestPersonalKeyServiceListsAndRevokesOnlyRequestedOwnerMetadata(t *testing.T) {
	lastUsedAt := personalKeyTestTime.Add(-time.Hour)
	repository := &personalKeyRepositoryFake{listed: []PersonalKey{{
		ID: "key-1", IdentityID: "identity-1", Name: "IDE", Prefix: "nap_prefix01",
		Status: PersonalKeyStatusActive, CreatedAt: personalKeyTestTime.Add(-2 * time.Hour), LastUsedAt: &lastUsedAt,
	}}}
	service := NewPersonalKeyService(repository)
	service.now = func() time.Time { return personalKeyTestTime }

	keys, err := service.List(context.Background(), "identity-1")
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if repository.listIdentityID != "identity-1" || len(keys) != 1 || keys[0].IdentityID != "identity-1" {
		t.Fatalf("List() = %#v, repository owner = %q", keys, repository.listIdentityID)
	}
	encoded, err := json.Marshal(keys)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	encodedText := strings.ToLower(string(encoded))
	if strings.Contains(encodedText, "hash") || strings.Contains(encodedText, "credential") {
		t.Fatalf("listed metadata contains a secret-bearing field: %s", encoded)
	}

	if err := service.Revoke(context.Background(), RevokePersonalKeyInput{IdentityID: "identity-1", KeyID: "key-1", RequestID: "request-personal-revoke"}); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if repository.revoked.IdentityID != "identity-1" || repository.revoked.KeyID != "key-1" || !repository.revoked.RevokedAt.Equal(personalKeyTestTime) {
		t.Fatalf("repository revocation = %#v", repository.revoked)
	}
	event, err := repository.revoked.Lifecycle.ForKey(repository.revoked.KeyID, "nap_prefix01")
	if err != nil {
		t.Fatalf("revoke lifecycle event error = %v", err)
	}
	if event.Action != CredentialLifecyclePersonalKeyRevoked || event.ActorIdentityID != "identity-1" ||
		event.TargetIdentityID != "identity-1" || event.RequestID != "request-personal-revoke" ||
		!event.OccurredAt.Equal(personalKeyTestTime) {
		t.Fatalf("revoke lifecycle event = %#v", event)
	}
}

func TestPersonalKeyServiceUsesBoundedCursorPagination(t *testing.T) {
	repository := &personalKeyRepositoryFake{pageListed: []PersonalKey{
		{ID: "key-2", IdentityID: "identity-1", CreatedAt: personalKeyTestTime},
		{ID: "key-1", IdentityID: "identity-1", CreatedAt: personalKeyTestTime.Add(-time.Minute)},
	}}
	service := NewPersonalKeyService(repository)
	page, err := service.ListPage(context.Background(), PersonalKeyPageRequest{IdentityID: " identity-1 ", Limit: 1})
	if err != nil {
		t.Fatalf("ListPage() error = %v", err)
	}
	if repository.pageIdentityID != "identity-1" || repository.pageLimit != 2 || len(page.Keys) != 1 || page.NextCursor == nil || page.NextCursor.ID != "key-2" {
		t.Fatalf("ListPage() = %#v, repository request = (%q, %d)", page, repository.pageIdentityID, repository.pageLimit)
	}
}

func TestPersonalKeyServiceAuthenticatesConstantTimeCandidateAndFailsClosedOnConcurrentRevocation(t *testing.T) {
	secret := "nap_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, apiKeyRandomBytes))
	hash := sha256.Sum256([]byte(secret))
	repository := &personalKeyRepositoryFake{
		candidates: []PersonalKeyAuthenticationCandidate{
			{KeyID: "collision", IdentityID: "other", VerificationHash: bytes.Repeat([]byte{0x11}, sha256.Size)},
			{KeyID: "key-1", IdentityID: "identity-1", VerificationHash: hash[:]},
		},
		authenticated: AuthenticatedPersonalKey{KeyID: "key-1", IdentityID: "identity-1"},
	}
	service := NewPersonalKeyService(repository)
	service.now = func() time.Time { return personalKeyTestTime }

	authenticated, err := service.Authenticate(context.Background(), secret)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if authenticated != repository.authenticated || repository.used.KeyID != "key-1" || !repository.used.UsedAt.Equal(personalKeyTestTime) {
		t.Fatalf("Authenticate() = %#v, recorded use = %#v", authenticated, repository.used)
	}
	if repository.candidatePrefix != secret[:apiKeyPrefixLength] {
		t.Fatalf("candidate prefix = %q, want safe lookup prefix", repository.candidatePrefix)
	}

	repository.useErr = ErrInvalidAPIKey
	if _, err := service.Authenticate(context.Background(), secret); !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatalf("concurrent-revocation Authenticate() error = %v, want ErrInvalidAPIKey", err)
	}
	if _, err := service.Authenticate(context.Background(), secret+"x"); !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatalf("malformed Authenticate() error = %v, want ErrInvalidAPIKey", err)
	}
}

type personalKeyRepositoryFake struct {
	created         PersonalKeyRecord
	createErr       error
	createCalls     int
	listed          []PersonalKey
	listIdentityID  string
	listErr         error
	pageListed      []PersonalKey
	pageIdentityID  string
	pageCursor      *PersonalKeyCursor
	pageLimit       int
	revoked         PersonalKeyRevocation
	revokeErr       error
	candidatePrefix string
	candidates      []PersonalKeyAuthenticationCandidate
	candidatesErr   error
	used            PersonalKeyUse
	authenticated   AuthenticatedPersonalKey
	useErr          error
}

func (repository *personalKeyRepositoryFake) CreatePersonalKey(_ context.Context, record PersonalKeyRecord) error {
	repository.createCalls++
	repository.created = record
	return repository.createErr
}

func (repository *personalKeyRepositoryFake) ListPersonalKeys(_ context.Context, identityID string) ([]PersonalKey, error) {
	repository.listIdentityID = identityID
	return repository.listed, repository.listErr
}

func (repository *personalKeyRepositoryFake) ListPersonalKeysPage(_ context.Context, identityID string, cursor *PersonalKeyCursor, limit int) ([]PersonalKey, error) {
	repository.pageIdentityID = identityID
	repository.pageCursor = cursor
	repository.pageLimit = limit
	return repository.pageListed, repository.listErr
}

func (repository *personalKeyRepositoryFake) RevokePersonalKey(_ context.Context, revocation PersonalKeyRevocation) error {
	repository.revoked = revocation
	return repository.revokeErr
}

func (repository *personalKeyRepositoryFake) FindPersonalKeyCandidates(_ context.Context, prefix string) ([]PersonalKeyAuthenticationCandidate, error) {
	repository.candidatePrefix = prefix
	return repository.candidates, repository.candidatesErr
}

func (repository *personalKeyRepositoryFake) RecordPersonalKeyUse(_ context.Context, use PersonalKeyUse) (AuthenticatedPersonalKey, error) {
	repository.used = use
	return repository.authenticated, repository.useErr
}

var _ PersonalKeyRepository = (*personalKeyRepositoryFake)(nil)
