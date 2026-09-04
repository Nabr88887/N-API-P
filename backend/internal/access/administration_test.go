package access

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAdministrationServiceRejectsLowerRolesBeforeRepository(t *testing.T) {
	repository := &administrationRepositoryFake{}
	service := NewAdministrationService(repository)
	for _, actor := range []Actor{{IdentityID: "employee-1", Role: RoleEmployee}, {IdentityID: "team-admin-1", Role: RoleTeamAdministrator}} {
		if _, err := service.ListAccounts(context.Background(), actor, AdministrationAccountFilter{Limit: 50}); !errors.Is(err, ErrForbidden) {
			t.Fatalf("ListAccounts(%s) error = %v, want ErrForbidden", actor.Role, err)
		}
		if _, err := service.GetAccount(context.Background(), actor, "user-1"); !errors.Is(err, ErrForbidden) {
			t.Fatalf("GetAccount(%s) error = %v, want ErrForbidden", actor.Role, err)
		}
		if _, err := service.CreateTeam(context.Background(), CreateAdministrationTeamInput{Actor: actor, Name: "Platform"}); !errors.Is(err, ErrForbidden) {
			t.Fatalf("CreateTeam(%s) error = %v, want ErrForbidden", actor.Role, err)
		}
		if err := service.ChangeRole(context.Background(), ChangeRoleInput{Actor: actor, IdentityID: "user-1", Role: RoleTeamAdministrator}); !errors.Is(err, ErrForbidden) {
			t.Fatalf("ChangeRole(%s) error = %v, want ErrForbidden", actor.Role, err)
		}
	}
	if repository.calls != 0 {
		t.Fatalf("repository calls = %d, want 0", repository.calls)
	}
}

func TestAdministrationServiceCarriesAuditableRoleAndMembershipChanges(t *testing.T) {
	repository := &administrationRepositoryFake{}
	service := NewAdministrationService(repository)
	service.now = func() time.Time { return fixedNow }
	service.newID = func() (string, error) { return "event-1", nil }
	actor := Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator, ReauthenticatedUntil: timePointer(fixedNow.Add(time.Minute))}

	if err := service.ChangeRole(context.Background(), ChangeRoleInput{Actor: actor, IdentityID: "user-1", Role: RoleTeamAdministrator, RequestID: "request-role"}); err != nil {
		t.Fatalf("ChangeRole() error = %v", err)
	}
	if repository.roleChange.EventID != "event-1" || repository.roleChange.ActorIdentityID != "admin-1" || repository.roleChange.Role != RoleTeamAdministrator || repository.roleChange.RequestID != "request-role" || !repository.roleChange.ChangedAt.Equal(fixedNow) {
		t.Fatalf("role change = %#v", repository.roleChange)
	}

	if err := service.AddMembership(context.Background(), ChangeMembershipInput{Actor: actor, IdentityID: "user-1", TeamID: "team-1", RequestID: "request-add"}); err != nil {
		t.Fatalf("AddMembership() error = %v", err)
	}
	if repository.membershipChange.Operation != MembershipAdded || repository.membershipChange.RequestID != "request-add" {
		t.Fatalf("add membership = %#v", repository.membershipChange)
	}
	if err := service.RemoveMembership(context.Background(), ChangeMembershipInput{Actor: actor, IdentityID: "user-1", TeamID: "team-1", RequestID: "request-remove"}); err != nil {
		t.Fatalf("RemoveMembership() error = %v", err)
	}
	if repository.membershipChange.Operation != MembershipRemoved || repository.membershipChange.RequestID != "request-remove" {
		t.Fatalf("remove membership = %#v", repository.membershipChange)
	}
}

func TestAdministrationSensitiveChangesRequireRecentReauthentication(t *testing.T) {
	tests := []struct {
		name      string
		operation func(*AdministrationService, Actor) error
		eventType string
		reason    string
	}{
		{
			name: "role change",
			operation: func(service *AdministrationService, actor Actor) error {
				return service.ChangeRole(context.Background(), ChangeRoleInput{Actor: actor, IdentityID: "user-1", Role: RoleTeamAdministrator, RequestID: "request-role"})
			},
			eventType: "role_change",
		},
		{
			name: "membership addition",
			operation: func(service *AdministrationService, actor Actor) error {
				return service.AddMembership(context.Background(), ChangeMembershipInput{Actor: actor, IdentityID: "user-1", TeamID: "team-1", RequestID: "request-add"})
			},
			eventType: "team_change",
			reason:    "team-1",
		},
		{
			name: "membership removal",
			operation: func(service *AdministrationService, actor Actor) error {
				return service.RemoveMembership(context.Background(), ChangeMembershipInput{Actor: actor, IdentityID: "user-1", TeamID: "team-1", RequestID: "request-remove"})
			},
			eventType: "team_change",
			reason:    "team-1",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &administrationRepositoryFake{}
			service := NewAdministrationService(repository)
			service.now = func() time.Time { return fixedNow }
			service.newID = func() (string, error) { return "event-denied", nil }

			err := test.operation(service, Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator})

			if !errors.Is(err, ErrReauthenticationRequired) {
				t.Fatalf("operation error = %v, want ErrReauthenticationRequired", err)
			}
			if repository.roleChange != (RoleChange{}) || repository.membershipChange != (MembershipChange{}) {
				t.Fatalf("sensitive mutation reached repository: role=%#v membership=%#v", repository.roleChange, repository.membershipChange)
			}
			if len(repository.events) != 1 {
				t.Fatalf("security events = %d, want 1", len(repository.events))
			}
			event := repository.events[0]
			if event.EventType != test.eventType || event.TargetIdentityID != "user-1" || event.Reason != test.reason || event.Outcome != SecurityEventDenied || event.DetailCode != "reauthentication_required" {
				t.Fatalf("denied security event = %#v", event)
			}
		})
	}
}

func TestAdministrationServiceValidatesPagesRolesAndIdentifiers(t *testing.T) {
	repository := &administrationRepositoryFake{}
	service := NewAdministrationService(repository)
	actor := Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator}
	if _, err := service.ListAccounts(context.Background(), actor, AdministrationAccountFilter{Limit: 0}); !errors.Is(err, ErrInvalidAdministrationRequest) {
		t.Fatalf("ListAccounts invalid limit error = %v", err)
	}
	invalidTeamStatus := "pending"
	if _, err := service.ListTeams(context.Background(), actor, AdministrationTeamFilter{Limit: 50, Status: &invalidTeamStatus}); !errors.Is(err, ErrInvalidAdministrationRequest) {
		t.Fatalf("ListTeams invalid status error = %v", err)
	}
	if _, err := service.ListAccounts(context.Background(), actor, AdministrationAccountFilter{Limit: 50}); err != nil || repository.accountFilter.ActorIdentityID != "admin-1" {
		t.Fatalf("ListAccounts actor filter = %#v, error = %v", repository.accountFilter, err)
	}
	if err := service.ChangeRole(context.Background(), ChangeRoleInput{Actor: actor, IdentityID: "", Role: Role("owner")}); !errors.Is(err, ErrInvalidAdministrationRequest) {
		t.Fatalf("ChangeRole invalid input error = %v", err)
	}
	if err := service.AddMembership(context.Background(), ChangeMembershipInput{Actor: actor, IdentityID: "user-1"}); !errors.Is(err, ErrInvalidAdministrationRequest) {
		t.Fatalf("AddMembership invalid input error = %v", err)
	}
}

func TestAdministrationServiceReadsResourcesAndCarriesAuditableTeamChanges(t *testing.T) {
	repository := &administrationRepositoryFake{
		account:        AdministrationAccount{ID: "user-1"},
		team:           AdministrationTeam{ID: "team-1", Name: "Platform"},
		serviceAccount: ServiceAccount{ID: "service-1"},
	}
	service := NewAdministrationService(repository)
	service.now = func() time.Time { return fixedNow }
	service.newID = func() (string, error) { return "event-1", nil }
	actor := Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator}

	if account, err := service.GetAccount(context.Background(), actor, " user-1 "); err != nil || account.ID != "user-1" || repository.resourceActor != "admin-1" {
		t.Fatalf("GetAccount() = %#v, %v; actor = %q", account, err, repository.resourceActor)
	}
	if team, err := service.GetTeam(context.Background(), actor, "team-1"); err != nil || team.ID != "team-1" {
		t.Fatalf("GetTeam() = %#v, %v", team, err)
	}
	if account, err := service.GetServiceAccount(context.Background(), actor, "service-1"); err != nil || account.ID != "service-1" {
		t.Fatalf("GetServiceAccount() = %#v, %v", account, err)
	}

	created, err := service.CreateTeam(context.Background(), CreateAdministrationTeamInput{Actor: actor, Name: " Platform ", RequestID: "request-create"})
	if err != nil || created.Name != "Platform" || repository.teamChange.Operation != TeamCreated || repository.teamChange.RequestID != "request-create" || repository.teamChange.EventID != "event-1" {
		t.Fatalf("CreateTeam() = %#v, %v; change = %#v", created, err, repository.teamChange)
	}
	updated, err := service.UpdateTeam(context.Background(), UpdateAdministrationTeamInput{Actor: actor, TeamID: "team-1", Name: " Core ", Confirmed: true, RequestID: "request-update"})
	if err != nil || updated.Name != "Core" || repository.teamChange.Operation != TeamUpdated || repository.teamChange.TeamID != "team-1" || !repository.teamChange.Confirmed {
		t.Fatalf("UpdateTeam() = %#v, %v; change = %#v", updated, err, repository.teamChange)
	}
}

type administrationRepositoryFake struct {
	calls            int
	roleChange       RoleChange
	membershipChange MembershipChange
	accountFilter    AdministrationAccountFilter
	account          AdministrationAccount
	team             AdministrationTeam
	serviceAccount   ServiceAccount
	resourceActor    string
	teamChange       TeamChange
	events           []SecurityEvent
}

func (repository *administrationRepositoryFake) ListAdministrationAccounts(_ context.Context, filter AdministrationAccountFilter) (AdministrationAccountPage, error) {
	repository.calls++
	repository.accountFilter = filter
	return AdministrationAccountPage{}, nil
}

func (repository *administrationRepositoryFake) ListAdministrationInvitations(context.Context, AdministrationInvitationFilter) (AdministrationInvitationPage, error) {
	repository.calls++
	return AdministrationInvitationPage{}, nil
}

func (repository *administrationRepositoryFake) ListAdministrationTeams(context.Context, AdministrationTeamFilter) (AdministrationTeamPage, error) {
	repository.calls++
	return AdministrationTeamPage{}, nil
}

func (repository *administrationRepositoryFake) ListAdministrationServiceAccounts(context.Context, AdministrationServiceAccountFilter) (AdministrationServiceAccountPage, error) {
	repository.calls++
	return AdministrationServiceAccountPage{}, nil
}

func (repository *administrationRepositoryFake) ListAdministrationSecurityEvents(context.Context, AdministrationSecurityEventFilter) (AdministrationSecurityEventPage, error) {
	repository.calls++
	return AdministrationSecurityEventPage{}, nil
}

func (repository *administrationRepositoryFake) GetAdministrationAccount(_ context.Context, actorIdentityID, _ string) (AdministrationAccount, error) {
	repository.calls++
	repository.resourceActor = actorIdentityID
	return repository.account, nil
}

func (repository *administrationRepositoryFake) GetAdministrationTeam(_ context.Context, actorIdentityID, _ string) (AdministrationTeam, error) {
	repository.calls++
	repository.resourceActor = actorIdentityID
	return repository.team, nil
}

func (repository *administrationRepositoryFake) GetAdministrationServiceAccount(_ context.Context, actorIdentityID, _ string) (ServiceAccount, error) {
	repository.calls++
	repository.resourceActor = actorIdentityID
	return repository.serviceAccount, nil
}

func (repository *administrationRepositoryFake) ChangeAdministrationTeam(_ context.Context, change TeamChange) (AdministrationTeam, error) {
	repository.calls++
	repository.teamChange = change
	return AdministrationTeam{ID: change.TeamID, Name: change.Name, Status: "active"}, nil
}

func (repository *administrationRepositoryFake) ChangeIdentityRole(_ context.Context, change RoleChange) error {
	repository.calls++
	repository.roleChange = change
	return nil
}

func (repository *administrationRepositoryFake) ChangeMembership(_ context.Context, change MembershipChange) error {
	repository.calls++
	repository.membershipChange = change
	return nil
}

func (repository *administrationRepositoryFake) AppendSecurityEvent(_ context.Context, event SecurityEvent) error {
	repository.events = append(repository.events, event)
	return nil
}
