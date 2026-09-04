package access

import (
	"context"
	"errors"
	"strings"
	"time"
)

var ErrInvalidOffboardingTarget = errors.New("invalid offboarding target")

type DisableEmployeeInput struct {
	Actor      Actor
	IdentityID string
	RequestID  string
}

type DisableTeamInput struct {
	Actor     Actor
	TeamID    string
	RequestID string
}

type DisableServiceAccountInput struct {
	Actor            Actor
	ServiceAccountID string
	RequestID        string
}

type EmployeeDisablement struct {
	IdentityID      string
	ActorIdentityID string
	DisabledAt      time.Time
	RequestID       string
}

type TeamDisablement struct {
	TeamID          string
	ActorIdentityID string
	DisabledAt      time.Time
	RequestID       string
}

type ServiceAccountDisablement struct {
	ServiceAccountID string
	ActorIdentityID  string
	DisabledAt       time.Time
	RequestID        string
}

type OffboardingRepository interface {
	SecurityEventWriter
	DisableEmployee(context.Context, EmployeeDisablement) error
	DisableTeam(context.Context, TeamDisablement) error
	DisableServiceAccount(context.Context, ServiceAccountDisablement) error
}

type OffboardingService struct {
	repository OffboardingRepository
	now        func() time.Time
	newID      func() (string, error)
}

func NewOffboardingService(repository OffboardingRepository) *OffboardingService {
	return &OffboardingService{repository: repository, now: time.Now, newID: newIdentityID}
}

func (service *OffboardingService) DisableEmployee(ctx context.Context, input DisableEmployeeInput) error {
	if !isSystemAdministrator(input.Actor) {
		return ErrForbidden
	}
	identityID := strings.TrimSpace(input.IdentityID)
	if service == nil || service.repository == nil || identityID == "" {
		return ErrInvalidOffboardingTarget
	}
	requestID, err := credentialLifecycleRequestID(input.RequestID)
	if err != nil {
		return err
	}
	disabledAt := service.now().UTC()
	if err := service.requireRecentReauthentication(ctx, input.Actor, SecurityEvent{
		EventType: "employee_disabled", TargetIdentityID: identityID,
		RequestID: requestID, OccurredAt: disabledAt,
	}, disabledAt); err != nil {
		return err
	}
	return service.repository.DisableEmployee(ctx, EmployeeDisablement{
		IdentityID: identityID, ActorIdentityID: strings.TrimSpace(input.Actor.IdentityID), DisabledAt: disabledAt, RequestID: requestID,
	})
}

func (service *OffboardingService) DisableTeam(ctx context.Context, input DisableTeamInput) error {
	if !isSystemAdministrator(input.Actor) {
		return ErrForbidden
	}
	teamID := strings.TrimSpace(input.TeamID)
	if service == nil || service.repository == nil || teamID == "" {
		return ErrInvalidOffboardingTarget
	}
	requestID, err := credentialLifecycleRequestID(input.RequestID)
	if err != nil {
		return err
	}
	disabledAt := service.now().UTC()
	if err := service.requireRecentReauthentication(ctx, input.Actor, SecurityEvent{
		EventType: "team_disabled", RequestID: requestID,
		Reason: teamID, OccurredAt: disabledAt,
	}, disabledAt); err != nil {
		return err
	}
	return service.repository.DisableTeam(ctx, TeamDisablement{
		TeamID: teamID, ActorIdentityID: strings.TrimSpace(input.Actor.IdentityID), DisabledAt: disabledAt, RequestID: requestID,
	})
}

func (service *OffboardingService) DisableServiceAccount(ctx context.Context, input DisableServiceAccountInput) error {
	if !isSystemAdministrator(input.Actor) {
		return ErrForbidden
	}
	serviceAccountID := strings.TrimSpace(input.ServiceAccountID)
	if service == nil || service.repository == nil || serviceAccountID == "" {
		return ErrInvalidOffboardingTarget
	}
	requestID, err := credentialLifecycleRequestID(input.RequestID)
	if err != nil {
		return err
	}
	disabledAt := service.now().UTC()
	if err := service.requireRecentReauthentication(ctx, input.Actor, SecurityEvent{
		EventType: "service_account_disabled", TargetServiceAccountID: serviceAccountID,
		RequestID: requestID, OccurredAt: disabledAt,
	}, disabledAt); err != nil {
		return err
	}
	return service.repository.DisableServiceAccount(ctx, ServiceAccountDisablement{
		ServiceAccountID: serviceAccountID, ActorIdentityID: strings.TrimSpace(input.Actor.IdentityID), DisabledAt: disabledAt, RequestID: requestID,
	})
}

func (service *OffboardingService) requireRecentReauthentication(ctx context.Context, actor Actor, event SecurityEvent, now time.Time) error {
	if hasRecentActorReauthentication(actor, now) {
		return nil
	}
	eventID, err := service.newID()
	if err != nil {
		return ErrSecurityAuditUnavailable
	}
	event.ID = eventID
	return requireRecentActorReauthentication(ctx, service.repository, actor, event, now)
}
