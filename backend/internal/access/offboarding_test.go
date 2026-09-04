package access

import (
	"context"
	"errors"
	"testing"
	"time"
)

var offboardingTestTime = time.Date(2026, time.August, 4, 14, 0, 0, 0, time.UTC)

func TestOffboardingRejectsUnauthorizedActorsAndInvalidTargets(t *testing.T) {
	operations := []struct {
		name string
		call func(*OffboardingService, Actor, string) error
	}{
		{name: "employee", call: func(service *OffboardingService, actor Actor, id string) error {
			return service.DisableEmployee(context.Background(), DisableEmployeeInput{Actor: actor, IdentityID: id})
		}},
		{name: "team", call: func(service *OffboardingService, actor Actor, id string) error {
			return service.DisableTeam(context.Background(), DisableTeamInput{Actor: actor, TeamID: id})
		}},
		{name: "service account", call: func(service *OffboardingService, actor Actor, id string) error {
			return service.DisableServiceAccount(context.Background(), DisableServiceAccountInput{Actor: actor, ServiceAccountID: id})
		}},
	}
	unauthorized := []Actor{
		{IdentityID: "employee-1", Role: RoleEmployee},
		{IdentityID: "team-admin-1", Role: RoleTeamAdministrator},
		{IdentityID: "", Role: RoleSystemAdministrator},
	}

	for _, operation := range operations {
		t.Run(operation.name+" unauthorized", func(t *testing.T) {
			for _, actor := range unauthorized {
				repository := &offboardingRepositoryFake{}
				service := NewOffboardingService(repository)
				if err := operation.call(service, actor, "target-1"); !errors.Is(err, ErrForbidden) {
					t.Fatalf("actor %#v error = %v, want ErrForbidden", actor, err)
				}
				if repository.calls() != 0 {
					t.Fatalf("repository calls = %d, want 0", repository.calls())
				}
			}
		})

		t.Run(operation.name+" invalid target", func(t *testing.T) {
			repository := &offboardingRepositoryFake{}
			service := NewOffboardingService(repository)
			err := operation.call(service, Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator}, " \t ")
			if !errors.Is(err, ErrInvalidOffboardingTarget) {
				t.Fatalf("invalid target error = %v, want ErrInvalidOffboardingTarget", err)
			}
			if repository.calls() != 0 {
				t.Fatalf("repository calls = %d, want 0", repository.calls())
			}
		})
	}
}

func TestOffboardingNormalizesTargetsAndUsesOneTimestamp(t *testing.T) {
	repository := &offboardingRepositoryFake{}
	service := NewOffboardingService(repository)
	service.now = func() time.Time { return offboardingTestTime }
	actor := Actor{IdentityID: " admin-1 ", Role: RoleSystemAdministrator, ReauthenticatedUntil: timePointer(offboardingTestTime.Add(time.Minute))}

	if err := service.DisableEmployee(context.Background(), DisableEmployeeInput{Actor: actor, IdentityID: " employee-1 ", RequestID: "request-employee-disable"}); err != nil {
		t.Fatalf("DisableEmployee() error = %v", err)
	}
	if err := service.DisableTeam(context.Background(), DisableTeamInput{Actor: actor, TeamID: " team-1 ", RequestID: "request-team-disable"}); err != nil {
		t.Fatalf("DisableTeam() error = %v", err)
	}
	if err := service.DisableServiceAccount(context.Background(), DisableServiceAccountInput{Actor: actor, ServiceAccountID: " service-1 ", RequestID: "request-service-disable"}); err != nil {
		t.Fatalf("DisableServiceAccount() error = %v", err)
	}

	if repository.employee.IdentityID != "employee-1" || repository.employee.ActorIdentityID != "admin-1" ||
		!repository.employee.DisabledAt.Equal(offboardingTestTime) || repository.employee.RequestID != "request-employee-disable" {
		t.Fatalf("employee disablement = %#v", repository.employee)
	}
	if repository.team.TeamID != "team-1" || repository.team.ActorIdentityID != "admin-1" ||
		!repository.team.DisabledAt.Equal(offboardingTestTime) || repository.team.RequestID != "request-team-disable" {
		t.Fatalf("team disablement = %#v", repository.team)
	}
	if repository.serviceAccount.ServiceAccountID != "service-1" || repository.serviceAccount.ActorIdentityID != "admin-1" ||
		!repository.serviceAccount.DisabledAt.Equal(offboardingTestTime) || repository.serviceAccount.RequestID != "request-service-disable" {
		t.Fatalf("service account disablement = %#v", repository.serviceAccount)
	}
}

func TestOffboardingRequiresRecentReauthenticationAndAuditsDenial(t *testing.T) {
	tests := []struct {
		name      string
		operation func(*OffboardingService, Actor) error
		eventType string
		target    func(SecurityEvent) string
	}{
		{
			name: "employee",
			operation: func(service *OffboardingService, actor Actor) error {
				return service.DisableEmployee(context.Background(), DisableEmployeeInput{Actor: actor, IdentityID: "employee-1", RequestID: "request-employee"})
			},
			eventType: "employee_disabled",
			target:    func(event SecurityEvent) string { return event.TargetIdentityID },
		},
		{
			name: "team",
			operation: func(service *OffboardingService, actor Actor) error {
				return service.DisableTeam(context.Background(), DisableTeamInput{Actor: actor, TeamID: "team-1", RequestID: "request-team"})
			},
			eventType: "team_disabled",
			target:    func(event SecurityEvent) string { return event.Reason },
		},
		{
			name: "service account",
			operation: func(service *OffboardingService, actor Actor) error {
				return service.DisableServiceAccount(context.Background(), DisableServiceAccountInput{Actor: actor, ServiceAccountID: "service-1", RequestID: "request-service"})
			},
			eventType: "service_account_disabled",
			target:    func(event SecurityEvent) string { return event.TargetServiceAccountID },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &offboardingRepositoryFake{}
			service := NewOffboardingService(repository)
			service.now = func() time.Time { return offboardingTestTime }

			err := test.operation(service, Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator})

			if !errors.Is(err, ErrReauthenticationRequired) {
				t.Fatalf("operation error = %v, want ErrReauthenticationRequired", err)
			}
			if repository.calls() != 0 {
				t.Fatalf("offboarding calls = %d, want 0", repository.calls())
			}
			if len(repository.events) != 1 {
				t.Fatalf("security events = %d, want 1", len(repository.events))
			}
			event := repository.events[0]
			if event.EventType != test.eventType || test.target(event) == "" || event.Outcome != SecurityEventDenied || event.DetailCode != "reauthentication_required" {
				t.Fatalf("denied security event = %#v", event)
			}
		})
	}
}

func TestOffboardingPropagatesRepositoryFailures(t *testing.T) {
	repositoryFailure := errors.New("repository unavailable")
	repository := &offboardingRepositoryFake{
		employeeErr: repositoryFailure,
		teamErr:     repositoryFailure,
		serviceErr:  repositoryFailure,
	}
	service := NewOffboardingService(repository)
	actor := Actor{IdentityID: "admin-1", Role: RoleSystemAdministrator, ReauthenticatedUntil: timePointer(time.Now().UTC().Add(time.Minute))}

	for name, call := range map[string]func() error{
		"employee": func() error {
			return service.DisableEmployee(context.Background(), DisableEmployeeInput{Actor: actor, IdentityID: "employee-1"})
		},
		"team": func() error {
			return service.DisableTeam(context.Background(), DisableTeamInput{Actor: actor, TeamID: "team-1"})
		},
		"service account": func() error {
			return service.DisableServiceAccount(context.Background(), DisableServiceAccountInput{Actor: actor, ServiceAccountID: "service-1"})
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); !errors.Is(err, repositoryFailure) {
				t.Fatalf("error = %v, want repository failure", err)
			}
		})
	}
}

type offboardingRepositoryFake struct {
	employee       EmployeeDisablement
	team           TeamDisablement
	serviceAccount ServiceAccountDisablement
	employeeErr    error
	teamErr        error
	serviceErr     error
	employeeCalls  int
	teamCalls      int
	serviceCalls   int
	events         []SecurityEvent
}

func (repository *offboardingRepositoryFake) DisableEmployee(_ context.Context, record EmployeeDisablement) error {
	repository.employeeCalls++
	repository.employee = record
	return repository.employeeErr
}

func (repository *offboardingRepositoryFake) DisableTeam(_ context.Context, record TeamDisablement) error {
	repository.teamCalls++
	repository.team = record
	return repository.teamErr
}

func (repository *offboardingRepositoryFake) DisableServiceAccount(_ context.Context, record ServiceAccountDisablement) error {
	repository.serviceCalls++
	repository.serviceAccount = record
	return repository.serviceErr
}

func (repository *offboardingRepositoryFake) AppendSecurityEvent(_ context.Context, event SecurityEvent) error {
	repository.events = append(repository.events, event)
	return nil
}

func (repository *offboardingRepositoryFake) calls() int {
	return repository.employeeCalls + repository.teamCalls + repository.serviceCalls
}
