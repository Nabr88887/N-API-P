//go:build integration

package database

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"n-api-p/internal/access"
)

const (
	offboardingOtherTeamID     = "11000000-0000-0000-0000-000000000002"
	offboardingOtherEmployeeID = "21000000-0000-0000-0000-000000000003"
	offboardingTargetSessionID = "33000000-0000-0000-0000-000000000040"
	offboardingOtherSessionID  = "33000000-0000-0000-0000-000000000041"
)

func TestOffboardingRepositoryDisablesEmployeeAndRevokesOwnedCredentials(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, accessEmployeeID, accessTeamID)
	seedOffboardingOtherEmployee(t, db, accessTeamID)
	repository := NewRepository(db)
	actor := access.Actor{IdentityID: accessAdminID, Role: access.RoleSystemAdministrator}

	targetPersonal, targetPersonalSecret := createOffboardingPersonalKey(t, repository, accessEmployeeID, "target-personal")
	otherPersonal, otherPersonalSecret := createOffboardingPersonalKey(t, repository, offboardingOtherEmployeeID, "other-personal")
	targetAccount, targetServiceKey, targetServiceSecret := createOffboardingServiceKey(t, repository, actor, accessTeamID, accessEmployeeID, "target-agent")
	_, otherServiceKey, otherServiceSecret := createOffboardingServiceKey(t, repository, actor, accessTeamID, offboardingOtherEmployeeID, "other-agent")
	insertOffboardingSession(t, db, offboardingTargetSessionID, accessEmployeeID)
	insertOffboardingSession(t, db, offboardingOtherSessionID, offboardingOtherEmployeeID)

	service := access.NewOffboardingService(repository)
	if err := service.DisableEmployee(context.Background(), access.DisableEmployeeInput{Actor: actor, IdentityID: accessEmployeeID}); err != nil {
		t.Fatalf("DisableEmployee() error = %v", err)
	}

	assertOffboardingIdentityStatus(t, db, accessEmployeeID, "disabled")
	assertOffboardingSessionRevoked(t, db, offboardingTargetSessionID, true)
	assertOffboardingKeyStatus(t, db, targetPersonal.Key.ID, "revoked")
	assertOffboardingKeyStatus(t, db, targetServiceKey.Key.ID, "revoked")
	assertOffboardingServiceAccountStatus(t, db, targetAccount.ID, "active")
	assertOffboardingSessionRevoked(t, db, offboardingOtherSessionID, false)
	assertOffboardingKeyStatus(t, db, otherPersonal.Key.ID, "active")
	assertOffboardingKeyStatus(t, db, otherServiceKey.Key.ID, "active")

	if _, err := access.NewPersonalKeyService(repository).Authenticate(context.Background(), targetPersonalSecret); !errors.Is(err, access.ErrInvalidAPIKey) {
		t.Fatalf("disabled employee personal Authenticate() error = %v, want ErrInvalidAPIKey", err)
	}
	if _, err := access.NewServiceAccountService(repository).Authenticate(context.Background(), targetServiceSecret); !errors.Is(err, access.ErrInvalidAPIKey) {
		t.Fatalf("invalid responsible owner Authenticate() error = %v, want ErrInvalidAPIKey", err)
	}
	if _, err := access.NewPersonalKeyService(repository).Authenticate(context.Background(), otherPersonalSecret); err != nil {
		t.Fatalf("unrelated personal Authenticate() error = %v", err)
	}
	if _, err := access.NewServiceAccountService(repository).Authenticate(context.Background(), otherServiceSecret); err != nil {
		t.Fatalf("unrelated service Authenticate() error = %v", err)
	}
}

func TestOffboardingRepositoryDisablesTeamWithinItsCredentialBoundary(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, accessEmployeeID, accessTeamID)
	mustExec(t, db, `INSERT INTO teams (id, name, status) VALUES ($1, 'Other', 'active')`, offboardingOtherTeamID)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, accessEmployeeID, offboardingOtherTeamID)
	repository := NewRepository(db)
	actor := access.Actor{IdentityID: accessAdminID, Role: access.RoleSystemAdministrator}

	personal, personalSecret := createOffboardingPersonalKey(t, repository, accessEmployeeID, "team-personal")
	_, targetKey, targetSecret := createOffboardingServiceKey(t, repository, actor, accessTeamID, accessEmployeeID, "team-target")
	_, otherKey, otherSecret := createOffboardingServiceKey(t, repository, actor, offboardingOtherTeamID, accessEmployeeID, "team-other")
	insertOffboardingSession(t, db, offboardingTargetSessionID, accessEmployeeID)

	service := access.NewOffboardingService(repository)
	const requestID = "87000000-0000-0000-0000-000000000201"
	if err := service.DisableTeam(context.Background(), access.DisableTeamInput{Actor: actor, TeamID: accessTeamID, RequestID: requestID}); err != nil {
		t.Fatalf("DisableTeam() error = %v", err)
	}

	assertOffboardingTeamStatus(t, db, accessTeamID, "disabled")
	assertOffboardingKeyStatus(t, db, targetKey.Key.ID, "revoked")
	assertOffboardingKeyStatus(t, db, otherKey.Key.ID, "active")
	assertOffboardingKeyStatus(t, db, personal.Key.ID, "active")
	assertOffboardingSessionRevoked(t, db, offboardingTargetSessionID, false)
	var eventType, reason string
	if err := db.QueryRow(`SELECT event_type, reason FROM security_events WHERE request_id = $1 AND event_type = 'team_disabled'`, requestID).Scan(&eventType, &reason); err != nil {
		t.Fatalf("query team disable event: %v", err)
	}
	if eventType != "team_disabled" || reason != accessTeamID {
		t.Fatalf("team disable event = (%q, %q), want (team_disabled, %q)", eventType, reason, accessTeamID)
	}
	if _, err := access.NewServiceAccountService(repository).Authenticate(context.Background(), targetSecret); !errors.Is(err, access.ErrInvalidAPIKey) {
		t.Fatalf("disabled team Authenticate() error = %v, want ErrInvalidAPIKey", err)
	}
	if _, err := access.NewServiceAccountService(repository).Authenticate(context.Background(), otherSecret); err != nil {
		t.Fatalf("other team Authenticate() error = %v", err)
	}
	if _, err := access.NewPersonalKeyService(repository).Authenticate(context.Background(), personalSecret); err != nil {
		t.Fatalf("team member personal Authenticate() error = %v", err)
	}
}

func TestOffboardingRepositoryRollsBackTeamWhenFinalSecurityEventFails(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, accessEmployeeID, accessTeamID)
	repository := NewRepository(db)
	actor := access.Actor{IdentityID: accessAdminID, Role: access.RoleSystemAdministrator}
	_, targetKey, targetSecret := createOffboardingServiceKey(t, repository, actor, accessTeamID, accessEmployeeID, "team-event-rollback")
	mustExec(t, db, `CREATE FUNCTION reject_team_disabled_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type = 'team_disabled' THEN RAISE EXCEPTION 'synthetic team disable event failure'; END IF; RETURN NEW; END $$`)
	mustExec(t, db, `CREATE TRIGGER reject_team_disabled_event BEFORE INSERT ON security_events FOR EACH ROW EXECUTE FUNCTION reject_team_disabled_event()`)

	const requestID = "87000000-0000-0000-0000-000000000202"
	service := access.NewOffboardingService(repository)
	if err := service.DisableTeam(context.Background(), access.DisableTeamInput{Actor: actor, TeamID: accessTeamID, RequestID: requestID}); err == nil {
		t.Fatal("DisableTeam() with rejected final security event succeeded")
	}
	assertOffboardingTeamStatus(t, db, accessTeamID, "active")
	assertOffboardingKeyStatus(t, db, targetKey.Key.ID, "active")
	if _, err := access.NewServiceAccountService(repository).Authenticate(context.Background(), targetSecret); err != nil {
		t.Fatalf("rolled-back team credential Authenticate() error = %v", err)
	}
	var eventCount int
	if err := db.QueryRow(`SELECT count(*) FROM security_events WHERE request_id = $1`, requestID).Scan(&eventCount); err != nil {
		t.Fatalf("count rolled-back team disable events: %v", err)
	}
	if eventCount != 0 {
		t.Fatalf("rolled-back team disable retained %d security events", eventCount)
	}
}

func TestOffboardingRepositoryDisablesOnlyTargetServiceAccount(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, accessEmployeeID, accessTeamID)
	repository := NewRepository(db)
	actor := access.Actor{IdentityID: accessAdminID, Role: access.RoleSystemAdministrator}

	personal, personalSecret := createOffboardingPersonalKey(t, repository, accessEmployeeID, "service-personal")
	targetAccount, targetKey, targetSecret := createOffboardingServiceKey(t, repository, actor, accessTeamID, accessEmployeeID, "service-target")
	otherAccount, otherKey, otherSecret := createOffboardingServiceKey(t, repository, actor, accessTeamID, accessEmployeeID, "service-other")
	insertOffboardingSession(t, db, offboardingTargetSessionID, accessEmployeeID)

	service := access.NewOffboardingService(repository)
	if err := service.DisableServiceAccount(context.Background(), access.DisableServiceAccountInput{Actor: actor, ServiceAccountID: targetAccount.ID}); err != nil {
		t.Fatalf("DisableServiceAccount() error = %v", err)
	}

	assertOffboardingServiceAccountStatus(t, db, targetAccount.ID, "disabled")
	assertOffboardingServiceAccountStatus(t, db, otherAccount.ID, "active")
	assertOffboardingKeyStatus(t, db, targetKey.Key.ID, "revoked")
	assertOffboardingKeyStatus(t, db, otherKey.Key.ID, "active")
	assertOffboardingKeyStatus(t, db, personal.Key.ID, "active")
	assertOffboardingSessionRevoked(t, db, offboardingTargetSessionID, false)
	if _, err := access.NewServiceAccountService(repository).Authenticate(context.Background(), targetSecret); !errors.Is(err, access.ErrInvalidAPIKey) {
		t.Fatalf("disabled service account Authenticate() error = %v, want ErrInvalidAPIKey", err)
	}
	if _, err := access.NewServiceAccountService(repository).Authenticate(context.Background(), otherSecret); err != nil {
		t.Fatalf("sibling service account Authenticate() error = %v", err)
	}
	if _, err := access.NewPersonalKeyService(repository).Authenticate(context.Background(), personalSecret); err != nil {
		t.Fatalf("responsible employee personal Authenticate() error = %v", err)
	}
}

func TestOffboardingRepositoryRejectsUntrustedAdministratorAndRollsBackCascades(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, accessEmployeeID, accessTeamID)
	seedOffboardingOtherEmployee(t, db, accessTeamID)
	repository := NewRepository(db)
	service := access.NewOffboardingService(repository)

	forged := access.Actor{IdentityID: accessEmployeeID, Role: access.RoleSystemAdministrator}
	if err := service.DisableEmployee(context.Background(), access.DisableEmployeeInput{Actor: forged, IdentityID: offboardingOtherEmployeeID}); !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("forged administrator DisableEmployee() error = %v, want ErrForbidden", err)
	}
	assertOffboardingIdentityStatus(t, db, offboardingOtherEmployeeID, "active")

	actor := access.Actor{IdentityID: accessAdminID, Role: access.RoleSystemAdministrator}
	if err := service.DisableEmployee(context.Background(), access.DisableEmployeeInput{Actor: actor, IdentityID: accessAdminID}); !errors.Is(err, access.ErrInvalidOffboardingTarget) {
		t.Fatalf("administrator target DisableEmployee() error = %v, want ErrInvalidOffboardingTarget", err)
	}
	if err := service.DisableTeam(context.Background(), access.DisableTeamInput{Actor: actor, TeamID: "11000000-0000-0000-0000-000000000099"}); !errors.Is(err, access.ErrInvalidOffboardingTarget) {
		t.Fatalf("missing target DisableTeam() error = %v, want ErrInvalidOffboardingTarget", err)
	}
	if err := service.DisableServiceAccount(context.Background(), access.DisableServiceAccountInput{Actor: actor, ServiceAccountID: "31000000-0000-0000-0000-000000000099"}); !errors.Is(err, access.ErrInvalidOffboardingTarget) {
		t.Fatalf("missing target DisableServiceAccount() error = %v, want ErrInvalidOffboardingTarget", err)
	}

	personal, personalSecret := createOffboardingPersonalKey(t, repository, accessEmployeeID, "rollback-personal")
	_, serviceKey, serviceSecret := createOffboardingServiceKey(t, repository, actor, accessTeamID, accessEmployeeID, "rollback-agent")
	insertOffboardingSession(t, db, offboardingTargetSessionID, accessEmployeeID)
	mustExec(t, db, `CREATE FUNCTION reject_offboarding_key_revoke() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.status = 'active' AND NEW.status = 'revoked' THEN RAISE EXCEPTION 'synthetic key revocation failure'; END IF; RETURN NEW; END $$`)
	mustExec(t, db, `CREATE TRIGGER reject_offboarding_key_revoke BEFORE UPDATE ON api_keys FOR EACH ROW EXECUTE FUNCTION reject_offboarding_key_revoke()`)

	if err := service.DisableEmployee(context.Background(), access.DisableEmployeeInput{Actor: actor, IdentityID: accessEmployeeID}); err == nil {
		t.Fatal("DisableEmployee() with injected revocation failure succeeded")
	}
	assertOffboardingIdentityStatus(t, db, accessEmployeeID, "active")
	assertOffboardingSessionRevoked(t, db, offboardingTargetSessionID, false)
	assertOffboardingKeyStatus(t, db, personal.Key.ID, "active")
	assertOffboardingKeyStatus(t, db, serviceKey.Key.ID, "active")
	if _, err := access.NewPersonalKeyService(repository).Authenticate(context.Background(), personalSecret); err != nil {
		t.Fatalf("rolled-back personal Authenticate() error = %v", err)
	}
	if _, err := access.NewServiceAccountService(repository).Authenticate(context.Background(), serviceSecret); err != nil {
		t.Fatalf("rolled-back service Authenticate() error = %v", err)
	}
}

func createOffboardingPersonalKey(t *testing.T, repository *Repository, identityID, name string) (access.PersonalKeyIssuance, string) {
	t.Helper()
	issuance, err := access.NewPersonalKeyService(repository).Create(context.Background(), access.CreatePersonalKeyInput{IdentityID: identityID, Name: name})
	if err != nil {
		t.Fatalf("create personal key %q: %v", name, err)
	}
	secret, ok := issuance.Credential.Reveal()
	if !ok {
		t.Fatalf("reveal personal key %q failed", name)
	}
	return issuance, secret
}

func createOffboardingServiceKey(t *testing.T, repository *Repository, actor access.Actor, teamID, responsibleIdentityID, name string) (access.ServiceAccount, access.ServiceAccountKeyIssuance, string) {
	t.Helper()
	service := access.NewServiceAccountService(repository)
	account, err := service.Create(context.Background(), access.CreateServiceAccountInput{
		Actor: actor, TeamID: teamID, ResponsibleIdentityID: responsibleIdentityID, Name: name,
	})
	if err != nil {
		t.Fatalf("create service account %q: %v", name, err)
	}
	issuance, err := service.CreateKey(context.Background(), access.CreateServiceAccountKeyInput{
		Actor: actor, ServiceAccountID: account.ID, Name: "primary",
	})
	if err != nil {
		t.Fatalf("create service account key %q: %v", name, err)
	}
	secret, ok := issuance.Credential.Reveal()
	if !ok {
		t.Fatalf("reveal service account key %q failed", name)
	}
	return account, issuance, secret
}

func seedOffboardingOtherEmployee(t *testing.T, db *sql.DB, teamID string) {
	t.Helper()
	mustExec(t, db, `INSERT INTO identities (id, email, role, status) VALUES ($1, 'other@example.internal', 'employee', 'active')`, offboardingOtherEmployeeID)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, offboardingOtherEmployeeID, teamID)
}

func insertOffboardingSession(t *testing.T, db *sql.DB, sessionID, identityID string) {
	t.Helper()
	createdAt := time.Now().UTC().Add(-time.Minute)
	mustExec(t, db, `INSERT INTO sessions (id, identity_id, token_hash, csrf_token_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at) VALUES ($1, $2, $3, $4, $5, $5, $6, $7)`,
		sessionID, identityID, []byte("token-"+sessionID), []byte("csrf-"+sessionID), createdAt, createdAt.Add(time.Hour), createdAt.Add(2*time.Hour))
}

func assertOffboardingIdentityStatus(t *testing.T, db *sql.DB, id, want string) {
	t.Helper()
	assertOffboardingOwnerStatus(t, db.QueryRow(`SELECT status, disabled_at IS NOT NULL FROM identities WHERE id = $1`, id), "identity", id, want)
}

func assertOffboardingTeamStatus(t *testing.T, db *sql.DB, id, want string) {
	t.Helper()
	assertOffboardingOwnerStatus(t, db.QueryRow(`SELECT status, disabled_at IS NOT NULL FROM teams WHERE id = $1`, id), "team", id, want)
}

func assertOffboardingServiceAccountStatus(t *testing.T, db *sql.DB, id, want string) {
	t.Helper()
	assertOffboardingOwnerStatus(t, db.QueryRow(`SELECT status, disabled_at IS NOT NULL FROM service_accounts WHERE id = $1`, id), "service account", id, want)
}

func assertOffboardingOwnerStatus(t *testing.T, row *sql.Row, kind, id, want string) {
	t.Helper()
	var status string
	var disabledAtSet bool
	if err := row.Scan(&status, &disabledAtSet); err != nil {
		t.Fatalf("query %s status: %v", kind, err)
	}
	if status != want || disabledAtSet != (want == "disabled") {
		t.Fatalf("%s %s status = %q, disabled_at set = %t, want %q", kind, id, status, disabledAtSet, want)
	}
}

func assertOffboardingSessionRevoked(t *testing.T, db *sql.DB, id string, want bool) {
	t.Helper()
	var revoked bool
	if err := db.QueryRow(`SELECT revoked_at IS NOT NULL FROM sessions WHERE id = $1`, id).Scan(&revoked); err != nil {
		t.Fatalf("query session revocation: %v", err)
	}
	if revoked != want {
		t.Fatalf("session %s revoked = %t, want %t", id, revoked, want)
	}
}

func assertOffboardingKeyStatus(t *testing.T, db *sql.DB, id, want string) {
	t.Helper()
	var status string
	var revokedAtSet bool
	if err := db.QueryRow(`SELECT status, revoked_at IS NOT NULL FROM api_keys WHERE id = $1`, id).Scan(&status, &revokedAtSet); err != nil {
		t.Fatalf("query API key status: %v", err)
	}
	if status != want || revokedAtSet != (want == "revoked") {
		t.Fatalf("API key %s status = %q, revoked_at set = %t, want %q", id, status, revokedAtSet, want)
	}
}
