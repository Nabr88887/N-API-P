//go:build integration

package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"n-api-p/internal/access"
)

func TestCredentialLifecycleRepositoryPersistsSafePersonalAndServiceKeyEvents(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, accessEmployeeID, accessTeamID)
	repository := NewRepository(db)

	personalService := access.NewPersonalKeyService(repository)
	personal, err := personalService.Create(context.Background(), access.CreatePersonalKeyInput{
		IdentityID: accessEmployeeID,
		Name:       "lifecycle-personal",
		RequestID:  "87000000-0000-0000-0000-000000000101",
	})
	if err != nil {
		t.Fatalf("create personal key: %v", err)
	}
	personalSecret, ok := personal.Credential.Reveal()
	if !ok {
		t.Fatal("personal credential was not revealable once")
	}
	assertCredentialLifecycleEvents(t, db, "87000000-0000-0000-0000-000000000101", []credentialLifecycleEventExpectation{{
		action: "personal_key_created", actorIdentityID: accessEmployeeID, targetIdentityID: accessEmployeeID,
		targetKeyID: personal.Key.ID, keyPrefix: personal.Key.Prefix,
	}}, personalSecret)

	if err := personalService.Revoke(context.Background(), access.RevokePersonalKeyInput{
		IdentityID: accessEmployeeID,
		KeyID:      personal.Key.ID,
		RequestID:  "87000000-0000-0000-0000-000000000102",
	}); err != nil {
		t.Fatalf("revoke personal key: %v", err)
	}
	assertCredentialLifecycleEvents(t, db, "87000000-0000-0000-0000-000000000102", []credentialLifecycleEventExpectation{{
		action: "personal_key_revoked", actorIdentityID: accessEmployeeID, targetIdentityID: accessEmployeeID,
		targetKeyID: personal.Key.ID, keyPrefix: personal.Key.Prefix,
	}}, personalSecret)

	serviceAccountService := access.NewServiceAccountService(repository)
	actor := access.Actor{IdentityID: accessAdminID, Role: access.RoleSystemAdministrator}
	account, err := serviceAccountService.Create(context.Background(), access.CreateServiceAccountInput{
		Actor: actor, TeamID: accessTeamID, ResponsibleIdentityID: accessEmployeeID, Name: "lifecycle-service",
	})
	if err != nil {
		t.Fatalf("create service account: %v", err)
	}
	serviceKey, err := serviceAccountService.CreateKey(context.Background(), access.CreateServiceAccountKeyInput{
		Actor: actor, ServiceAccountID: account.ID, Name: "primary",
		RequestID: "87000000-0000-0000-0000-000000000103",
	})
	if err != nil {
		t.Fatalf("create service key: %v", err)
	}
	serviceSecret, ok := serviceKey.Credential.Reveal()
	if !ok {
		t.Fatal("service credential was not revealable once")
	}
	assertCredentialLifecycleEvents(t, db, "87000000-0000-0000-0000-000000000103", []credentialLifecycleEventExpectation{{
		action: "service_key_created", actorIdentityID: accessAdminID, targetServiceAccountID: account.ID,
		targetKeyID: serviceKey.Key.ID, keyPrefix: serviceKey.Key.Prefix,
	}}, serviceSecret)

	rotated, err := serviceAccountService.RotateKey(context.Background(), access.RotateServiceAccountKeyInput{
		Actor: actor, ServiceAccountID: account.ID, KeyID: serviceKey.Key.ID, Name: "rotated",
		RequestID: "87000000-0000-0000-0000-000000000104",
	})
	if err != nil {
		t.Fatalf("rotate service key: %v", err)
	}
	rotatedSecret, ok := rotated.Credential.Reveal()
	if !ok {
		t.Fatal("rotated credential was not revealable once")
	}
	assertCredentialLifecycleEvents(t, db, "87000000-0000-0000-0000-000000000104", []credentialLifecycleEventExpectation{
		{action: "service_key_rotation_created", actorIdentityID: accessAdminID, targetServiceAccountID: account.ID, targetKeyID: rotated.Key.ID, keyPrefix: rotated.Key.Prefix},
		{action: "service_key_rotation_revoked", actorIdentityID: accessAdminID, targetServiceAccountID: account.ID, targetKeyID: serviceKey.Key.ID, keyPrefix: serviceKey.Key.Prefix},
	}, serviceSecret, rotatedSecret)

	if err := serviceAccountService.RevokeKey(context.Background(), access.RevokeServiceAccountKeyInput{
		Actor: actor, ServiceAccountID: account.ID, KeyID: rotated.Key.ID,
		RequestID: "87000000-0000-0000-0000-000000000105",
	}); err != nil {
		t.Fatalf("revoke service key: %v", err)
	}
	assertCredentialLifecycleEvents(t, db, "87000000-0000-0000-0000-000000000105", []credentialLifecycleEventExpectation{{
		action: "service_key_revoked", actorIdentityID: accessAdminID, targetServiceAccountID: account.ID,
		targetKeyID: rotated.Key.ID, keyPrefix: rotated.Key.Prefix,
	}}, rotatedSecret)
}

func TestCredentialLifecycleEventFailureRollsBackRevocationAndOffboarding(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	repository := NewRepository(db)
	service := access.NewPersonalKeyService(repository)
	issuance, err := service.Create(context.Background(), access.CreatePersonalKeyInput{
		IdentityID: accessEmployeeID,
		Name:       "rollback-personal",
		RequestID:  "87000000-0000-0000-0000-000000000106",
	})
	if err != nil {
		t.Fatalf("create rollback key: %v", err)
	}

	mustExec(t, db, `CREATE FUNCTION reject_credential_lifecycle_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type LIKE '%key_%' THEN RAISE EXCEPTION 'synthetic lifecycle event failure'; END IF; RETURN NEW; END $$`)
	mustExec(t, db, `CREATE TRIGGER reject_credential_lifecycle_event BEFORE INSERT ON security_events FOR EACH ROW EXECUTE FUNCTION reject_credential_lifecycle_event()`)

	if err := service.Revoke(context.Background(), access.RevokePersonalKeyInput{
		IdentityID: accessEmployeeID,
		KeyID:      issuance.Key.ID,
		RequestID:  "87000000-0000-0000-0000-000000000107",
	}); err == nil {
		t.Fatal("revoke with rejected lifecycle event succeeded")
	}
	assertCredentialLifecycleRollbackState(t, db, issuance.Key.ID, accessEmployeeID)

	offboarding := access.NewOffboardingService(repository)
	if err := offboarding.DisableEmployee(context.Background(), access.DisableEmployeeInput{
		Actor:      access.Actor{IdentityID: accessAdminID, Role: access.RoleSystemAdministrator},
		IdentityID: accessEmployeeID,
		RequestID:  "87000000-0000-0000-0000-000000000108",
	}); err == nil {
		t.Fatal("offboarding with rejected lifecycle event succeeded")
	}
	assertCredentialLifecycleRollbackState(t, db, issuance.Key.ID, accessEmployeeID)
	for _, requestID := range []string{"87000000-0000-0000-0000-000000000107", "87000000-0000-0000-0000-000000000108"} {
		var count int
		if err := db.QueryRow(`SELECT count(*) FROM security_events WHERE request_id = $1`, requestID).Scan(&count); err != nil {
			t.Fatalf("count rolled-back lifecycle events: %v", err)
		}
		if count != 0 {
			t.Fatalf("rolled-back request %s retained %d lifecycle events", requestID, count)
		}
	}
}

type credentialLifecycleEventExpectation struct {
	action                 string
	actorIdentityID        string
	targetIdentityID       string
	targetServiceAccountID string
	targetKeyID            string
	keyPrefix              string
}

func assertCredentialLifecycleEvents(t *testing.T, db *sql.DB, requestID string, want []credentialLifecycleEventExpectation, secrets ...string) {
	t.Helper()
	rows, err := db.Query(`
SELECT event_type,
       actor_identity_id::text,
       COALESCE(target_identity_id::text, ''),
       COALESCE(target_service_account_id::text, ''),
       target_key_id::text,
       outcome,
       detail_code,
       occurred_at
FROM security_events
WHERE request_id = $1
ORDER BY event_type, target_key_id`, requestID)
	if err != nil {
		t.Fatalf("query credential lifecycle events: %v", err)
	}
	defer rows.Close()

	var got []credentialLifecycleEventExpectation
	var output strings.Builder
	for rows.Next() {
		var event credentialLifecycleEventExpectation
		var outcome string
		var occurredAt time.Time
		if err := rows.Scan(
			&event.action, &event.actorIdentityID, &event.targetIdentityID,
			&event.targetServiceAccountID, &event.targetKeyID, &outcome,
			&event.keyPrefix, &occurredAt,
		); err != nil {
			t.Fatalf("scan credential lifecycle event: %v", err)
		}
		if outcome != "success" || occurredAt.IsZero() {
			t.Fatalf("credential lifecycle outcome/time = (%q, %v)", outcome, occurredAt)
		}
		output.WriteString(strings.Join([]string{
			event.action, event.actorIdentityID, event.targetIdentityID,
			event.targetServiceAccountID, event.targetKeyID, outcome,
			event.keyPrefix, occurredAt.Format(time.RFC3339Nano),
		}, "|"))
		got = append(got, event)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate credential lifecycle events: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("credential lifecycle events = %#v, want %#v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("credential lifecycle event %d = %#v, want %#v", index, got[index], want[index])
		}
	}
	for _, secret := range secrets {
		hash := sha256.Sum256([]byte(secret))
		for _, forbidden := range []string{secret, base64.RawStdEncoding.EncodeToString(hash[:]), hex.EncodeToString(hash[:])} {
			if strings.Contains(output.String(), forbidden) {
				t.Fatalf("credential material %q appeared in persisted event output", forbidden)
			}
		}
	}
}

func assertCredentialLifecycleRollbackState(t *testing.T, db *sql.DB, keyID, identityID string) {
	t.Helper()
	var keyStatus, identityStatus string
	if err := db.QueryRow(`SELECT status FROM api_keys WHERE id = $1`, keyID).Scan(&keyStatus); err != nil {
		t.Fatalf("query rolled-back key status: %v", err)
	}
	if err := db.QueryRow(`SELECT status FROM identities WHERE id = $1`, identityID).Scan(&identityStatus); err != nil {
		t.Fatalf("query rolled-back identity status: %v", err)
	}
	if keyStatus != "active" || identityStatus != "active" {
		t.Fatalf("rolled-back statuses = key %q, identity %q", keyStatus, identityStatus)
	}
}
