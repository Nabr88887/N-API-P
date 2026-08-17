//go:build integration

package database

import (
	"context"
	"errors"
	"testing"
	"time"

	"n-api-p/internal/access"
)

func TestAdministrationRepositoryReadsDeclaredResources(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, accessEmployeeID, accessTeamID)
	repository := NewRepository(db)
	administrator := access.Actor{IdentityID: accessAdminID, Role: access.RoleSystemAdministrator}
	service := access.NewAdministrationService(repository)

	invitation, err := access.NewInvitationService(repository).Create(context.Background(), access.CreateInvitationInput{
		Actor: administrator, Email: "pending@example.internal", TeamID: accessTeamID,
		RequestID: "87000000-0000-0000-0000-000000000310",
	})
	if err != nil {
		t.Fatalf("Create() invitation error = %v", err)
	}
	invitations, err := service.ListInvitations(context.Background(), administrator, access.AdministrationInvitationFilter{Limit: 50})
	if err != nil || len(invitations.Invitations) != 1 || invitations.Invitations[0].IdentityID != invitation.IdentityID || invitations.Invitations[0].TeamID != accessTeamID {
		t.Fatalf("ListInvitations() = %#v, %v", invitations, err)
	}

	account, err := service.GetAccount(context.Background(), administrator, accessEmployeeID)
	if err != nil || account.ID != accessEmployeeID || len(account.TeamIDs) != 1 || account.TeamIDs[0] != accessTeamID {
		t.Fatalf("GetAccount() = %#v, %v", account, err)
	}
	team, err := service.GetTeam(context.Background(), administrator, accessTeamID)
	if err != nil || team.ID != accessTeamID || team.MemberCount != 2 {
		t.Fatalf("GetTeam() = %#v, %v", team, err)
	}

	serviceAccount, err := access.NewServiceAccountService(repository).Create(context.Background(), access.CreateServiceAccountInput{
		Actor: administrator, TeamID: accessTeamID, ResponsibleIdentityID: accessEmployeeID, Name: "read-agent",
		RequestID: "87000000-0000-0000-0000-000000000311",
	})
	if err != nil {
		t.Fatalf("Create() service account error = %v", err)
	}
	gotServiceAccount, err := service.GetServiceAccount(context.Background(), administrator, serviceAccount.ID)
	if err != nil || gotServiceAccount.ID != serviceAccount.ID || gotServiceAccount.Name != "read-agent" {
		t.Fatalf("GetServiceAccount() = %#v, %v", gotServiceAccount, err)
	}
}

func TestAdministrationRepositoryTeamChangesAreAuditedAndAtomic(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	repository := NewRepository(db)
	service := access.NewAdministrationService(repository)
	administrator := access.Actor{IdentityID: accessAdminID, Role: access.RoleSystemAdministrator}

	const createRequestID = "87000000-0000-0000-0000-000000000312"
	team, err := service.CreateTeam(context.Background(), access.CreateAdministrationTeamInput{Actor: administrator, Name: "Core", RequestID: createRequestID})
	if err != nil || team.ID == "" || team.Name != "Core" || team.Status != "active" {
		t.Fatalf("CreateTeam() = %#v, %v", team, err)
	}
	assertAdministrationTeamEvent(t, db, createRequestID, "team_created", team.ID)

	const updateRequestID = "87000000-0000-0000-0000-000000000313"
	updated, err := service.UpdateTeam(context.Background(), access.UpdateAdministrationTeamInput{
		Actor: administrator, TeamID: team.ID, Name: "Core Platform", RequestID: updateRequestID,
	})
	if err != nil || updated.Name != "Core Platform" {
		t.Fatalf("UpdateTeam() = %#v, %v", updated, err)
	}
	assertAdministrationTeamEvent(t, db, updateRequestID, "team_updated", team.ID)

	mustExec(t, db, `CREATE FUNCTION reject_team_updated_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type = 'team_updated' THEN RAISE EXCEPTION 'synthetic team update event failure'; END IF; RETURN NEW; END $$`)
	mustExec(t, db, `CREATE TRIGGER reject_team_updated_event BEFORE INSERT ON security_events FOR EACH ROW EXECUTE FUNCTION reject_team_updated_event()`)
	const rollbackRequestID = "87000000-0000-0000-0000-000000000314"
	if _, err := service.UpdateTeam(context.Background(), access.UpdateAdministrationTeamInput{
		Actor: administrator, TeamID: team.ID, Name: "Must Roll Back", RequestID: rollbackRequestID,
	}); err == nil {
		t.Fatal("UpdateTeam() with rejected security event succeeded")
	}
	var name string
	if err := db.QueryRow(`SELECT name FROM teams WHERE id = $1`, team.ID).Scan(&name); err != nil || name != "Core Platform" {
		t.Fatalf("rolled-back team name = %q, %v", name, err)
	}
	assertAdministrationRequestEventCount(t, db, rollbackRequestID, 0)
}

func TestAdministrationRepositoryListsOnlyForActiveSystemAdministrator(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, accessEmployeeID, accessTeamID)
	repository := NewRepository(db)
	service := access.NewAdministrationService(repository)
	administrator := access.Actor{IdentityID: accessAdminID, Role: access.RoleSystemAdministrator}

	accounts, err := service.ListAccounts(context.Background(), administrator, access.AdministrationAccountFilter{Limit: 50})
	if err != nil {
		t.Fatalf("ListAccounts() error = %v", err)
	}
	if len(accounts.Accounts) != 2 || accounts.Accounts[0].ID == "" || accounts.Accounts[1].ID == "" {
		t.Fatalf("ListAccounts() = %#v", accounts)
	}
	teams, err := service.ListTeams(context.Background(), administrator, access.AdministrationTeamFilter{Limit: 50})
	if err != nil {
		t.Fatalf("ListTeams() error = %v", err)
	}
	if len(teams.Teams) != 1 || teams.Teams[0].ID != accessTeamID || teams.Teams[0].MemberCount != 1 {
		t.Fatalf("ListTeams() = %#v", teams)
	}

	if _, err := repository.ListAdministrationAccounts(context.Background(), access.AdministrationAccountFilter{ActorIdentityID: accessEmployeeID, Limit: 50}); !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("employee ListAdministrationAccounts() error = %v, want ErrForbidden", err)
	}
}

func TestAdministrationRepositoryRoleChangeRevokesInvalidOwnerKeysAndAudits(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, accessEmployeeID, accessTeamID)
	repository := NewRepository(db)
	actor := access.Actor{IdentityID: accessAdminID, Role: access.RoleSystemAdministrator}
	_, key, secret := createOffboardingServiceKey(t, repository, actor, accessTeamID, accessEmployeeID, "role-change-agent")

	const requestID = "87000000-0000-0000-0000-000000000301"
	service := access.NewAdministrationService(repository)
	if err := service.ChangeRole(context.Background(), access.ChangeRoleInput{Actor: actor, IdentityID: accessEmployeeID, Role: access.RoleTeamAdministrator, RequestID: requestID}); err != nil {
		t.Fatalf("ChangeRole() error = %v", err)
	}

	var role string
	if err := db.QueryRow(`SELECT role FROM identities WHERE id = $1`, accessEmployeeID).Scan(&role); err != nil {
		t.Fatalf("query changed role: %v", err)
	}
	if role != string(access.RoleTeamAdministrator) {
		t.Fatalf("changed role = %q, want team_administrator", role)
	}
	assertOffboardingKeyStatus(t, db, key.Key.ID, "revoked")
	if _, err := access.NewServiceAccountService(repository).Authenticate(context.Background(), secret); !errors.Is(err, access.ErrInvalidAPIKey) {
		t.Fatalf("invalid owner credential error = %v, want ErrInvalidAPIKey", err)
	}
	assertAdministrationEvent(t, db, requestID, "role_change", accessEmployeeID, "", string(access.RoleTeamAdministrator))
}

func TestAdministrationRepositoryMembershipChangesAreAuditedAndAtomic(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	mustExec(t, db, `INSERT INTO teams (id, name, status) VALUES ($1, 'Administration Other', 'active')`, offboardingOtherTeamID)
	repository := NewRepository(db)
	actor := access.Actor{IdentityID: accessAdminID, Role: access.RoleSystemAdministrator}
	service := access.NewAdministrationService(repository)

	const addRequestID = "87000000-0000-0000-0000-000000000302"
	if err := service.AddMembership(context.Background(), access.ChangeMembershipInput{Actor: actor, IdentityID: accessEmployeeID, TeamID: offboardingOtherTeamID, RequestID: addRequestID}); err != nil {
		t.Fatalf("AddMembership() error = %v", err)
	}
	assertCountWhere(t, db, "memberships", "identity_id", accessEmployeeID, 1)
	assertAdministrationEvent(t, db, addRequestID, "team_change", accessEmployeeID, offboardingOtherTeamID, string(access.MembershipAdded))

	const removeRequestID = "87000000-0000-0000-0000-000000000303"
	if err := service.RemoveMembership(context.Background(), access.ChangeMembershipInput{Actor: actor, IdentityID: accessEmployeeID, TeamID: offboardingOtherTeamID, RequestID: removeRequestID}); err != nil {
		t.Fatalf("RemoveMembership() error = %v", err)
	}
	assertCountWhere(t, db, "memberships", "identity_id", accessEmployeeID, 0)
	assertAdministrationEvent(t, db, removeRequestID, "team_change", accessEmployeeID, offboardingOtherTeamID, string(access.MembershipRemoved))

	mustExec(t, db, `CREATE FUNCTION reject_team_change_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type = 'team_change' THEN RAISE EXCEPTION 'synthetic team change event failure'; END IF; RETURN NEW; END $$`)
	mustExec(t, db, `CREATE TRIGGER reject_team_change_event BEFORE INSERT ON security_events FOR EACH ROW EXECUTE FUNCTION reject_team_change_event()`)
	const rollbackRequestID = "87000000-0000-0000-0000-000000000304"
	if err := service.AddMembership(context.Background(), access.ChangeMembershipInput{Actor: actor, IdentityID: accessEmployeeID, TeamID: offboardingOtherTeamID, RequestID: rollbackRequestID}); err == nil {
		t.Fatal("AddMembership() with rejected security event succeeded")
	}
	assertCountWhere(t, db, "memberships", "identity_id", accessEmployeeID, 0)
	assertAdministrationRequestEventCount(t, db, rollbackRequestID, 0)
}

func TestAdministrationRepositoryRollsBackRoleAndKeyEventsWhenFinalAuditFails(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, accessEmployeeID, accessTeamID)
	repository := NewRepository(db)
	actor := access.Actor{IdentityID: accessAdminID, Role: access.RoleSystemAdministrator}
	_, key, secret := createOffboardingServiceKey(t, repository, actor, accessTeamID, accessEmployeeID, "role-event-rollback")
	mustExec(t, db, `CREATE FUNCTION reject_role_change_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.event_type = 'role_change' THEN RAISE EXCEPTION 'synthetic role change event failure'; END IF; RETURN NEW; END $$`)
	mustExec(t, db, `CREATE TRIGGER reject_role_change_event BEFORE INSERT ON security_events FOR EACH ROW EXECUTE FUNCTION reject_role_change_event()`)

	const requestID = "87000000-0000-0000-0000-000000000305"
	service := access.NewAdministrationService(repository)
	if err := service.ChangeRole(context.Background(), access.ChangeRoleInput{Actor: actor, IdentityID: accessEmployeeID, Role: access.RoleTeamAdministrator, RequestID: requestID}); err == nil {
		t.Fatal("ChangeRole() with rejected final security event succeeded")
	}
	var role string
	if err := db.QueryRow(`SELECT role FROM identities WHERE id = $1`, accessEmployeeID).Scan(&role); err != nil {
		t.Fatalf("query rolled-back role: %v", err)
	}
	if role != string(access.RoleEmployee) {
		t.Fatalf("rolled-back role = %q, want employee", role)
	}
	assertOffboardingKeyStatus(t, db, key.Key.ID, "active")
	if _, err := access.NewServiceAccountService(repository).Authenticate(context.Background(), secret); err != nil {
		t.Fatalf("rolled-back owner credential Authenticate() error = %v", err)
	}
	assertAdministrationRequestEventCount(t, db, requestID, 0)
}

func assertAdministrationEvent(t *testing.T, db queryRower, requestID, eventType, targetIdentityID, reason, detailCode string) {
	t.Helper()
	var gotEventType, gotTargetIdentityID, gotReason, gotDetailCode string
	if err := db.QueryRow(`SELECT event_type, target_identity_id::text, COALESCE(reason, ''), detail_code FROM security_events WHERE request_id = $1 AND event_type = $2`, requestID, eventType).Scan(&gotEventType, &gotTargetIdentityID, &gotReason, &gotDetailCode); err != nil {
		t.Fatalf("query administration event: %v", err)
	}
	if gotEventType != eventType || gotTargetIdentityID != targetIdentityID || gotReason != reason || gotDetailCode != detailCode {
		t.Fatalf("administration event = (%q, %q, %q, %q), want (%q, %q, %q, %q)", gotEventType, gotTargetIdentityID, gotReason, gotDetailCode, eventType, targetIdentityID, reason, detailCode)
	}
}

func assertAdministrationRequestEventCount(t *testing.T, db queryRower, requestID string, want int) {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM security_events WHERE request_id = $1`, requestID).Scan(&count); err != nil {
		t.Fatalf("count administration request events: %v", err)
	}
	if count != want {
		t.Fatalf("administration request event count = %d, want %d", count, want)
	}
}

func assertAdministrationTeamEvent(t *testing.T, db queryRower, requestID, eventType, teamID string) {
	t.Helper()
	var gotEventType, reason, detailCode string
	var occurredAt time.Time
	if err := db.QueryRow(`SELECT event_type, reason, detail_code, occurred_at FROM security_events WHERE request_id = $1 AND event_type = $2`, requestID, eventType).Scan(&gotEventType, &reason, &detailCode, &occurredAt); err != nil {
		t.Fatalf("query administration team event: %v", err)
	}
	if gotEventType != eventType || reason != teamID || detailCode != "team_metadata" || occurredAt.IsZero() {
		t.Fatalf("administration team event = (%q, %q, %q, %v)", gotEventType, reason, detailCode, occurredAt)
	}
}
