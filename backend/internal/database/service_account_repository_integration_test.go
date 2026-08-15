//go:build integration

package database

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"n-api-p/internal/access"
)

func TestServiceAccountRepositoryEnforcesAdministratorAndOwnerInvariants(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, accessEmployeeID, accessTeamID)
	repository := NewRepository(db)

	untrusted := serviceAccountRecord("31000000-0000-0000-0000-000000000001", "untrusted")
	untrusted.CreatedByIdentityID = accessEmployeeID
	if err := repository.CreateServiceAccount(context.Background(), untrusted); !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("untrusted CreateServiceAccount() error = %v, want ErrForbidden", err)
	}

	const otherEmployeeID = "21000000-0000-0000-0000-000000000003"
	mustExec(t, db, `INSERT INTO identities (id, email, role, status) VALUES ($1, 'other@example.internal', 'employee', 'active')`, otherEmployeeID)
	invalidOwner := serviceAccountRecord("31000000-0000-0000-0000-000000000002", "missing-membership")
	invalidOwner.ResponsibleIdentityID = otherEmployeeID
	if err := repository.CreateServiceAccount(context.Background(), invalidOwner); !errors.Is(err, access.ErrInvalidServiceAccount) {
		t.Fatalf("missing-membership CreateServiceAccount() error = %v, want ErrInvalidServiceAccount", err)
	}

	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, accessAdminID, accessTeamID)
	invalidRole := serviceAccountRecord("31000000-0000-0000-0000-000000000003", "human-admin")
	invalidRole.ResponsibleIdentityID = accessAdminID
	if err := repository.CreateServiceAccount(context.Background(), invalidRole); !errors.Is(err, access.ErrInvalidServiceAccount) {
		t.Fatalf("non-employee owner CreateServiceAccount() error = %v, want ErrInvalidServiceAccount", err)
	}

	valid := serviceAccountRecord("31000000-0000-0000-0000-000000000004", "build-agent")
	if err := repository.CreateServiceAccount(context.Background(), valid); err != nil {
		t.Fatalf("CreateServiceAccount() error = %v", err)
	}
	duplicate := serviceAccountRecord("31000000-0000-0000-0000-000000000005", "build-agent")
	if err := repository.CreateServiceAccount(context.Background(), duplicate); !errors.Is(err, access.ErrServiceAccountNameConflict) {
		t.Fatalf("duplicate CreateServiceAccount() error = %v, want ErrServiceAccountNameConflict", err)
	}

	accounts, err := repository.ListServiceAccounts(context.Background(), accessAdminID)
	if err != nil {
		t.Fatalf("ListServiceAccounts() error = %v", err)
	}
	if len(accounts) != 1 || accounts[0].ID != valid.ID || accounts[0].TeamID != accessTeamID || accounts[0].ResponsibleIdentityID != accessEmployeeID {
		t.Fatalf("ListServiceAccounts() = %#v", accounts)
	}
	if _, err := repository.ListServiceAccounts(context.Background(), accessEmployeeID); !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("untrusted ListServiceAccounts() error = %v, want ErrForbidden", err)
	}
}

func TestServiceAccountRepositoryKeyLifecycleAndAttribution(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, accessEmployeeID, accessTeamID)
	repository := NewRepository(db)
	service := access.NewServiceAccountService(repository)
	actor := access.Actor{IdentityID: accessAdminID, Role: access.RoleSystemAdministrator}

	account, err := service.Create(context.Background(), access.CreateServiceAccountInput{
		Actor: actor, TeamID: accessTeamID, ResponsibleIdentityID: accessEmployeeID, Name: "build-agent",
	})
	if err != nil {
		t.Fatalf("Create() service account error = %v", err)
	}
	issuance, err := service.CreateKey(context.Background(), access.CreateServiceAccountKeyInput{
		Actor: actor, ServiceAccountID: account.ID, Name: "primary",
	})
	if err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}
	secret, ok := issuance.Credential.Reveal()
	if !ok {
		t.Fatal("created service credential was not revealable once")
	}
	var (
		kind       string
		prefix     string
		hash       []byte
		identityID any
	)
	if err := db.QueryRow(`SELECT kind, prefix, verification_hash, identity_id FROM api_keys WHERE id = $1`, issuance.Key.ID).Scan(&kind, &prefix, &hash, &identityID); err != nil {
		t.Fatalf("query persisted service key: %v", err)
	}
	if kind != access.ServiceAccountKeyKind || prefix != issuance.Key.Prefix || identityID != nil || bytes.Contains(hash, []byte(secret)) || !access.VerifyAPIKey(secret, hash) {
		t.Fatal("database did not retain an isolated hash-only service key")
	}
	if _, err := access.NewPersonalKeyService(repository).Authenticate(context.Background(), secret); !errors.Is(err, access.ErrInvalidAPIKey) {
		t.Fatalf("personal Authenticate(service key) error = %v, want ErrInvalidAPIKey", err)
	}
	authenticated, err := service.Authenticate(context.Background(), secret)
	if err != nil {
		t.Fatalf("service Authenticate() error = %v", err)
	}
	if authenticated.KeyID != issuance.Key.ID || authenticated.ServiceAccountID != account.ID || authenticated.TeamID != accessTeamID || authenticated.ResponsibleIdentityID != accessEmployeeID {
		t.Fatalf("service Authenticate() attribution = %#v", authenticated)
	}
	untrustedKey := access.ServiceAccountKeyRecord{
		ID: "41000000-0000-0000-0000-000000000001", ServiceAccountID: account.ID,
		Kind: access.ServiceAccountKeyKind, Name: "untrusted-create", Prefix: "nap_denied01",
		VerificationHash: []byte("untrusted-create-hash"), CreatedByIdentityID: accessEmployeeID, CreatedAt: accessNow,
	}
	if _, err := repository.CreateServiceAccountKey(context.Background(), untrustedKey); !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("untrusted CreateServiceAccountKey() error = %v, want ErrForbidden", err)
	}
	if _, err := repository.ListServiceAccountKeys(context.Background(), account.ID, accessEmployeeID); !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("untrusted ListServiceAccountKeys() error = %v, want ErrForbidden", err)
	}
	untrustedRotation := access.ServiceAccountKeyRotation{
		ServiceAccountID: account.ID, OldKeyID: issuance.Key.ID, RevokedAt: accessNow,
		NewKey: access.ServiceAccountKeyRecord{
			ID: "41000000-0000-0000-0000-000000000002", ServiceAccountID: account.ID,
			Kind: access.ServiceAccountKeyKind, Name: "untrusted-rotate", Prefix: "nap_denied02",
			VerificationHash: []byte("untrusted-rotate-hash"), CreatedByIdentityID: accessEmployeeID, CreatedAt: accessNow,
		},
	}
	if _, err := repository.RotateServiceAccountKey(context.Background(), untrustedRotation); !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("untrusted RotateServiceAccountKey() error = %v, want ErrForbidden", err)
	}
	if err := repository.RevokeServiceAccountKey(context.Background(), access.ServiceAccountKeyRevocation{
		ServiceAccountID: account.ID, KeyID: issuance.Key.ID, ActorIdentityID: accessEmployeeID, RevokedAt: accessNow,
	}); !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("untrusted RevokeServiceAccountKey() error = %v, want ErrForbidden", err)
	}

	sibling, err := service.CreateKey(context.Background(), access.CreateServiceAccountKeyInput{
		Actor: actor, ServiceAccountID: account.ID, Name: "sibling",
	})
	if err != nil {
		t.Fatalf("second CreateKey() error = %v", err)
	}
	siblingSecret, _ := sibling.Credential.Reveal()
	listed, err := service.ListKeys(context.Background(), access.ListServiceAccountKeysInput{Actor: actor, ServiceAccountID: account.ID})
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}
	if len(listed) != 2 || listed[0].ServiceAccountID != account.ID || listed[1].ServiceAccountID != account.ID {
		t.Fatalf("ListKeys() = %#v", listed)
	}
	rotated, err := service.RotateKey(context.Background(), access.RotateServiceAccountKeyInput{
		Actor: actor, ServiceAccountID: account.ID, KeyID: issuance.Key.ID, Name: "rotated",
	})
	if err != nil {
		t.Fatalf("RotateKey() error = %v", err)
	}
	rotatedSecret, ok := rotated.Credential.Reveal()
	if !ok {
		t.Fatal("rotated service credential was not revealable once")
	}
	if _, err := service.Authenticate(context.Background(), secret); !errors.Is(err, access.ErrInvalidAPIKey) {
		t.Fatalf("old credential after rotation error = %v, want ErrInvalidAPIKey", err)
	}
	if _, err := service.Authenticate(context.Background(), rotatedSecret); err != nil {
		t.Fatalf("rotated credential Authenticate() error = %v", err)
	}
	if _, err := service.Authenticate(context.Background(), siblingSecret); err != nil {
		t.Fatalf("sibling credential after rotation error = %v", err)
	}

	if err := service.RevokeKey(context.Background(), access.RevokeServiceAccountKeyInput{
		Actor: actor, ServiceAccountID: account.ID, KeyID: rotated.Key.ID,
	}); err != nil {
		t.Fatalf("RevokeKey() error = %v", err)
	}
	if _, err := service.Authenticate(context.Background(), rotatedSecret); !errors.Is(err, access.ErrInvalidAPIKey) {
		t.Fatalf("revoked credential Authenticate() error = %v, want ErrInvalidAPIKey", err)
	}
	if _, err := service.Authenticate(context.Background(), siblingSecret); err != nil {
		t.Fatalf("sibling credential after revocation error = %v", err)
	}

	mustExec(t, db, `UPDATE identities SET status = 'disabled', disabled_at = CURRENT_TIMESTAMP WHERE id = $1`, accessEmployeeID)
	if _, err := service.Authenticate(context.Background(), siblingSecret); !errors.Is(err, access.ErrInvalidAPIKey) {
		t.Fatalf("disabled responsible employee Authenticate() error = %v, want ErrInvalidAPIKey", err)
	}
}

func TestServiceAccountRepositorySerializesDuplicateNamesAndThreeKeyLimit(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, accessEmployeeID, accessTeamID)
	repository := NewRepository(db)
	service := access.NewServiceAccountService(repository)
	actor := access.Actor{IdentityID: accessAdminID, Role: access.RoleSystemAdministrator}
	account, err := service.Create(context.Background(), access.CreateServiceAccountInput{
		Actor: actor, TeamID: accessTeamID, ResponsibleIdentityID: accessEmployeeID, Name: "limit-agent",
	})
	if err != nil {
		t.Fatalf("Create() service account error = %v", err)
	}

	duplicateErrors := runConcurrent(2, func(int) error {
		_, err := service.CreateKey(context.Background(), access.CreateServiceAccountKeyInput{
			Actor: actor, ServiceAccountID: account.ID, Name: "duplicate",
		})
		return err
	})
	assertOneSuccessOneError(t, duplicateErrors, access.ErrServiceAccountKeyNameConflict)
	if _, err := service.CreateKey(context.Background(), access.CreateServiceAccountKeyInput{
		Actor: actor, ServiceAccountID: account.ID, Name: "second",
	}); err != nil {
		t.Fatalf("second active key error = %v", err)
	}

	limitErrors := runConcurrent(2, func(index int) error {
		_, err := service.CreateKey(context.Background(), access.CreateServiceAccountKeyInput{
			Actor: actor, ServiceAccountID: account.ID, Name: []string{"third-a", "third-b"}[index],
		})
		return err
	})
	assertOneSuccessOneError(t, limitErrors, access.ErrServiceAccountKeyLimitReached)
	var activeCount int
	if err := db.QueryRow(`SELECT count(*) FROM api_keys WHERE service_account_id = $1 AND kind = 'service' AND status = 'active'`, account.ID).Scan(&activeCount); err != nil {
		t.Fatalf("count active service keys: %v", err)
	}
	if activeCount != access.MaxActiveServiceAccountKeys {
		t.Fatalf("active service key count = %d, want %d", activeCount, access.MaxActiveServiceAccountKeys)
	}
}

func TestServiceAccountRepositoryRollsBackCreationWhenSecurityEventFails(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, accessEmployeeID, accessTeamID)
	repository := NewRepository(db)
	mustExec(t, db, `CREATE FUNCTION reject_service_account_creation_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type = 'service_account_created' THEN RAISE EXCEPTION 'synthetic service account event failure'; END IF; RETURN NEW; END $$`)
	mustExec(t, db, `CREATE TRIGGER reject_service_account_creation_event BEFORE INSERT ON security_events FOR EACH ROW EXECUTE FUNCTION reject_service_account_creation_event()`)

	record := serviceAccountRecord("31000000-0000-0000-0000-000000000006", "rollback-agent")
	if err := repository.CreateServiceAccount(context.Background(), record); err == nil {
		t.Fatal("CreateServiceAccount() with rejected security event succeeded")
	}
	assertCountWhere(t, db, "service_accounts", "id", record.ID, 0)
}

func serviceAccountRecord(id, name string) access.ServiceAccountRecord {
	return access.ServiceAccountRecord{
		ID: id, TeamID: accessTeamID, ResponsibleIdentityID: accessEmployeeID,
		Name: name, CreatedByIdentityID: accessAdminID, CreatedAt: accessNow,
		Event: access.SecurityEvent{ID: id, EventType: "service_account_created", ActorIdentityID: accessAdminID, TargetServiceAccountID: id, RequestID: id, Outcome: access.SecurityEventSuccess, DetailCode: "active", OccurredAt: accessNow},
	}
}
