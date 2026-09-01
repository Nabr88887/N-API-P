//go:build integration

package database

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"n-api-p/internal/access"
)

func TestPersonalKeyRepositoryCreateListRevokeAndAuthenticationInvalidation(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	repository := NewRepository(db)
	service := access.NewPersonalKeyService(repository)

	issuance, err := service.Create(context.Background(), access.CreatePersonalKeyInput{
		IdentityID: accessEmployeeID,
		Name:       "workstation",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	secret, ok := issuance.Credential.Reveal()
	if !ok {
		t.Fatal("created credential was not revealable once")
	}

	var prefix string
	var hash []byte
	if err := db.QueryRow(`SELECT prefix, verification_hash FROM api_keys WHERE id = $1`, issuance.Key.ID).Scan(&prefix, &hash); err != nil {
		t.Fatalf("query persisted personal key: %v", err)
	}
	if prefix != issuance.Key.Prefix || bytes.Contains(hash, []byte(secret)) || !access.VerifyAPIKey(secret, hash) {
		t.Fatal("database did not retain only the safe prefix and verification hash")
	}
	otherIssuance, err := service.Create(context.Background(), access.CreatePersonalKeyInput{
		IdentityID: accessEmployeeID,
		Name:       "terminal",
	})
	if err != nil {
		t.Fatalf("second Create() error = %v", err)
	}
	otherSecret, ok := otherIssuance.Credential.Reveal()
	if !ok {
		t.Fatal("second created credential was not revealable once")
	}

	keys, err := service.List(context.Background(), accessEmployeeID)
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("List() length = %d, want 2", len(keys))
	}
	for _, key := range keys {
		if key.IdentityID != accessEmployeeID {
			t.Fatalf("List() returned cross-owner key %#v", key)
		}
	}

	authenticated, err := service.Authenticate(context.Background(), secret)
	if err != nil {
		t.Fatalf("Authenticate() before revocation error = %v", err)
	}
	if authenticated.KeyID != issuance.Key.ID || authenticated.IdentityID != accessEmployeeID {
		t.Fatalf("Authenticate() = %#v, want created key attribution", authenticated)
	}
	var lastUsed bool
	if err := db.QueryRow(`SELECT last_used_at IS NOT NULL FROM api_keys WHERE id = $1`, issuance.Key.ID).Scan(&lastUsed); err != nil {
		t.Fatalf("query personal key last use: %v", err)
	}
	if !lastUsed {
		t.Fatal("successful authentication did not record last_used_at")
	}

	if err := service.Revoke(context.Background(), access.RevokePersonalKeyInput{IdentityID: accessEmployeeID, KeyID: issuance.Key.ID}); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	keys, err = service.List(context.Background(), accessEmployeeID)
	if err != nil {
		t.Fatalf("List() after revocation error = %v", err)
	}
	var revokedKey *access.PersonalKey
	for index := range keys {
		if keys[index].ID == issuance.Key.ID {
			revokedKey = &keys[index]
			break
		}
	}
	if revokedKey == nil {
		t.Fatal("List() after revocation omitted the retained lifecycle record")
	}
	if revokedKey.Status != access.PersonalKeyStatusRevoked || revokedKey.RevokedAt == nil {
		t.Fatalf("revoked key metadata = %#v, want status revoked and revoked_at", revokedKey)
	}
	if _, err := service.Authenticate(context.Background(), secret); !errors.Is(err, access.ErrInvalidAPIKey) {
		t.Fatalf("Authenticate() after revocation error = %v, want ErrInvalidAPIKey", err)
	}
	if authenticated, err := service.Authenticate(context.Background(), otherSecret); err != nil {
		t.Fatalf("Authenticate() other key after revocation error = %v", err)
	} else if authenticated.KeyID != otherIssuance.Key.ID {
		t.Fatalf("Authenticate() other key = %#v, want key %q", authenticated, otherIssuance.Key.ID)
	}
	if err := service.Revoke(context.Background(), access.RevokePersonalKeyInput{IdentityID: accessAdminID, KeyID: issuance.Key.ID}); !errors.Is(err, access.ErrPersonalKeyNotFound) {
		t.Fatalf("cross-owner Revoke() error = %v, want ErrPersonalKeyNotFound", err)
	}
	if _, err := service.Create(context.Background(), access.CreatePersonalKeyInput{IdentityID: accessEmployeeID, Name: "workstation"}); !errors.Is(err, access.ErrPersonalKeyNameConflict) {
		t.Fatalf("revoked-name Create() error = %v, want ErrPersonalKeyNameConflict", err)
	}
}

func TestPersonalKeyRepositoryEnforcesActiveOwnerUniqueNamesAndConcurrentLimit(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	repository := NewRepository(db)
	service := access.NewPersonalKeyService(repository)

	mustExec(t, db, `INSERT INTO identities (id, email, role, status) VALUES ($1, 'pending-key@example.internal', 'employee', 'pending')`, "21000000-0000-0000-0000-000000000099")
	if _, err := service.Create(context.Background(), access.CreatePersonalKeyInput{IdentityID: "21000000-0000-0000-0000-000000000099", Name: "pending"}); !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("pending-owner Create() error = %v, want ErrForbidden", err)
	}

	duplicateErrors := runConcurrent(2, func(int) error {
		_, err := service.Create(context.Background(), access.CreatePersonalKeyInput{IdentityID: accessEmployeeID, Name: "duplicate"})
		return err
	})
	assertOneSuccessOneError(t, duplicateErrors, access.ErrPersonalKeyNameConflict)

	for index, name := range []string{"second", "third", "fourth"} {
		if _, err := service.Create(context.Background(), access.CreatePersonalKeyInput{IdentityID: accessEmployeeID, Name: name}); err != nil {
			t.Fatalf("seed active key %d error = %v", index, err)
		}
	}
	errorsByCall := runConcurrent(2, func(index int) error {
		_, err := service.Create(context.Background(), access.CreatePersonalKeyInput{
			IdentityID: accessEmployeeID,
			Name:       []string{"fifth-a", "fifth-b"}[index],
		})
		return err
	})
	assertOneSuccessOneError(t, errorsByCall, access.ErrPersonalKeyLimitReached)

	var activeCount int
	if err := db.QueryRow(`SELECT count(*) FROM api_keys WHERE identity_id = $1 AND kind = 'personal' AND status = 'active'`, accessEmployeeID).Scan(&activeCount); err != nil {
		t.Fatalf("count active personal keys: %v", err)
	}
	if activeCount != 5 {
		t.Fatalf("active personal key count = %d, want 5", activeCount)
	}
}

var _ access.PersonalKeyRepository = (*Repository)(nil)
