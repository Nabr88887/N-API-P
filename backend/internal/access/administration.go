package access

import (
	"context"
	"errors"
	"strings"
	"time"
)

var (
	ErrInvalidAdministrationRequest = errors.New("invalid administration request")
	ErrAdministrationNotFound       = errors.New("administration resource not found")
	ErrAdministrationConflict       = errors.New("administration resource conflict")
)

const MaxAdministrationPageSize = 100

type AdministrationAccount struct {
	ID         string
	Email      string
	Role       Role
	Status     IdentityStatus
	TeamIDs    []string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DisabledAt *time.Time
}

type AdministrationTeam struct {
	ID          string
	Name        string
	Status      string
	MemberCount int
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DisabledAt  *time.Time
}

type AdministrationAccountFilter struct {
	ActorIdentityID string
	Status          *IdentityStatus
	Role            *Role
	Cursor          string
	Limit           int
}

type AdministrationTeamFilter struct {
	ActorIdentityID string
	Status          *string
	Cursor          string
	Limit           int
}

type AdministrationServiceAccountFilter struct {
	ActorIdentityID string
	TeamID          *string
	Status          *ServiceAccountStatus
	Cursor          string
	Limit           int
}

type AdministrationInvitationFilter struct {
	ActorIdentityID string
	Status          *IdentityStatus
	Cursor          string
	Limit           int
}

type AdministrationInvitation struct {
	IdentityID string
	Email      string
	TeamID     string
	Status     IdentityStatus
	ExpiresAt  time.Time
	CreatedAt  time.Time
}

type AdministrationAccountPage struct {
	Accounts   []AdministrationAccount
	NextCursor string
}

type AdministrationTeamPage struct {
	Teams      []AdministrationTeam
	NextCursor string
}

type AdministrationServiceAccountPage struct {
	ServiceAccounts []ServiceAccount
	NextCursor      string
}

type AdministrationInvitationPage struct {
	Invitations []AdministrationInvitation
	NextCursor  string
}

type AdministrationSecurityEventFilter struct {
	ActorIdentityID string
	EventType       *string
	Outcome         *SecurityEventOutcome
	From            *time.Time
	To              *time.Time
	Cursor          string
	Limit           int
}

type AdministrationSecurityEvent struct {
	ID                     string
	EventType              string
	ActorIdentityID        string
	TargetIdentityID       string
	TargetServiceAccountID string
	TargetKeyID            string
	TargetAuditID          string
	RequestID              string
	Outcome                SecurityEventOutcome
	Reason                 string
	DetailCode             string
	OccurredAt             time.Time
}

type AdministrationSecurityEventPage struct {
	Events     []AdministrationSecurityEvent
	NextCursor string
}

type TeamOperation string

const (
	TeamCreated TeamOperation = "team_created"
	TeamUpdated TeamOperation = "team_updated"
)

type TeamChange struct {
	EventID         string
	TeamID          string
	Name            string
	Operation       TeamOperation
	ActorIdentityID string
	RequestID       string
	ChangedAt       time.Time
	Confirmed       bool
}

type CreateAdministrationTeamInput struct {
	Actor     Actor
	Name      string
	RequestID string
}

type UpdateAdministrationTeamInput struct {
	Actor     Actor
	TeamID    string
	Name      string
	Confirmed bool
	RequestID string
}

type RoleChange struct {
	EventID         string
	IdentityID      string
	Role            Role
	ActorIdentityID string
	RequestID       string
	ChangedAt       time.Time
}

type MembershipOperation string

const (
	MembershipAdded   MembershipOperation = "membership_added"
	MembershipRemoved MembershipOperation = "membership_removed"
)

type MembershipChange struct {
	EventID         string
	IdentityID      string
	TeamID          string
	Operation       MembershipOperation
	ActorIdentityID string
	RequestID       string
	ChangedAt       time.Time
}

type ChangeRoleInput struct {
	Actor      Actor
	IdentityID string
	Role       Role
	RequestID  string
}

type ChangeMembershipInput struct {
	Actor      Actor
	IdentityID string
	TeamID     string
	RequestID  string
}

type AdministrationRepository interface {
	ListAdministrationInvitations(context.Context, AdministrationInvitationFilter) (AdministrationInvitationPage, error)
	ListAdministrationAccounts(context.Context, AdministrationAccountFilter) (AdministrationAccountPage, error)
	ListAdministrationTeams(context.Context, AdministrationTeamFilter) (AdministrationTeamPage, error)
	ListAdministrationServiceAccounts(context.Context, AdministrationServiceAccountFilter) (AdministrationServiceAccountPage, error)
	ListAdministrationSecurityEvents(context.Context, AdministrationSecurityEventFilter) (AdministrationSecurityEventPage, error)
	GetAdministrationAccount(context.Context, string, string) (AdministrationAccount, error)
	GetAdministrationTeam(context.Context, string, string) (AdministrationTeam, error)
	GetAdministrationServiceAccount(context.Context, string, string) (ServiceAccount, error)
	ChangeAdministrationTeam(context.Context, TeamChange) (AdministrationTeam, error)
	ChangeIdentityRole(context.Context, RoleChange) error
	ChangeMembership(context.Context, MembershipChange) error
}

func (service *AdministrationService) ListInvitations(ctx context.Context, actor Actor, filter AdministrationInvitationFilter) (AdministrationInvitationPage, error) {
	if !isSystemAdministrator(actor) {
		return AdministrationInvitationPage{}, ErrForbidden
	}
	if service == nil || service.repository == nil || !validAdministrationLimit(filter.Limit) || len(filter.Cursor) > 512 {
		return AdministrationInvitationPage{}, ErrInvalidAdministrationRequest
	}
	if filter.Status != nil && !validIdentityStatus(*filter.Status) {
		return AdministrationInvitationPage{}, ErrInvalidAdministrationRequest
	}
	filter.ActorIdentityID = strings.TrimSpace(actor.IdentityID)
	return service.repository.ListAdministrationInvitations(ctx, filter)
}

func (service *AdministrationService) ListServiceAccounts(ctx context.Context, actor Actor, filter AdministrationServiceAccountFilter) (AdministrationServiceAccountPage, error) {
	if !isSystemAdministrator(actor) {
		return AdministrationServiceAccountPage{}, ErrForbidden
	}
	if service == nil || service.repository == nil || !validAdministrationLimit(filter.Limit) || len(filter.Cursor) > 512 {
		return AdministrationServiceAccountPage{}, ErrInvalidAdministrationRequest
	}
	if filter.TeamID != nil && strings.TrimSpace(*filter.TeamID) == "" {
		return AdministrationServiceAccountPage{}, ErrInvalidAdministrationRequest
	}
	if filter.Status != nil && *filter.Status != ServiceAccountStatusActive && *filter.Status != ServiceAccountStatusDisabled {
		return AdministrationServiceAccountPage{}, ErrInvalidAdministrationRequest
	}
	filter.ActorIdentityID = strings.TrimSpace(actor.IdentityID)
	return service.repository.ListAdministrationServiceAccounts(ctx, filter)
}

func (service *AdministrationService) ListSecurityEvents(ctx context.Context, actor Actor, filter AdministrationSecurityEventFilter) (AdministrationSecurityEventPage, error) {
	if !isSystemAdministrator(actor) {
		return AdministrationSecurityEventPage{}, ErrForbidden
	}
	if service == nil || service.repository == nil || !validAdministrationLimit(filter.Limit) || len(filter.Cursor) > 512 {
		return AdministrationSecurityEventPage{}, ErrInvalidAdministrationRequest
	}
	if filter.EventType != nil && strings.TrimSpace(*filter.EventType) == "" {
		return AdministrationSecurityEventPage{}, ErrInvalidAdministrationRequest
	}
	if filter.Outcome != nil && *filter.Outcome != SecurityEventSuccess && *filter.Outcome != SecurityEventDenied && *filter.Outcome != SecurityEventFailure {
		return AdministrationSecurityEventPage{}, ErrInvalidAdministrationRequest
	}
	if filter.From != nil && filter.To != nil && filter.From.After(*filter.To) {
		return AdministrationSecurityEventPage{}, ErrInvalidAdministrationRequest
	}
	filter.ActorIdentityID = strings.TrimSpace(actor.IdentityID)
	return service.repository.ListAdministrationSecurityEvents(ctx, filter)
}

type AdministrationService struct {
	repository AdministrationRepository
	now        func() time.Time
	newID      func() (string, error)
}

func NewAdministrationService(repository AdministrationRepository) *AdministrationService {
	return &AdministrationService{repository: repository, now: time.Now, newID: newIdentityID}
}

func (service *AdministrationService) ListAccounts(ctx context.Context, actor Actor, filter AdministrationAccountFilter) (AdministrationAccountPage, error) {
	if !isSystemAdministrator(actor) {
		return AdministrationAccountPage{}, ErrForbidden
	}
	if service == nil || service.repository == nil || !validAdministrationLimit(filter.Limit) || len(filter.Cursor) > 512 {
		return AdministrationAccountPage{}, ErrInvalidAdministrationRequest
	}
	if filter.Role != nil && !validAdministrationRole(*filter.Role) {
		return AdministrationAccountPage{}, ErrInvalidAdministrationRequest
	}
	if filter.Status != nil && !validIdentityStatus(*filter.Status) {
		return AdministrationAccountPage{}, ErrInvalidAdministrationRequest
	}
	filter.ActorIdentityID = strings.TrimSpace(actor.IdentityID)
	return service.repository.ListAdministrationAccounts(ctx, filter)
}

func (service *AdministrationService) ListTeams(ctx context.Context, actor Actor, filter AdministrationTeamFilter) (AdministrationTeamPage, error) {
	if !isSystemAdministrator(actor) {
		return AdministrationTeamPage{}, ErrForbidden
	}
	if service == nil || service.repository == nil || !validAdministrationLimit(filter.Limit) || len(filter.Cursor) > 512 {
		return AdministrationTeamPage{}, ErrInvalidAdministrationRequest
	}
	if filter.Status != nil && *filter.Status != "active" && *filter.Status != "disabled" {
		return AdministrationTeamPage{}, ErrInvalidAdministrationRequest
	}
	filter.ActorIdentityID = strings.TrimSpace(actor.IdentityID)
	return service.repository.ListAdministrationTeams(ctx, filter)
}

func (service *AdministrationService) GetAccount(ctx context.Context, actor Actor, identityID string) (AdministrationAccount, error) {
	if !isSystemAdministrator(actor) {
		return AdministrationAccount{}, ErrForbidden
	}
	identityID = strings.TrimSpace(identityID)
	if service == nil || service.repository == nil || identityID == "" {
		return AdministrationAccount{}, ErrInvalidAdministrationRequest
	}
	return service.repository.GetAdministrationAccount(ctx, strings.TrimSpace(actor.IdentityID), identityID)
}

func (service *AdministrationService) GetTeam(ctx context.Context, actor Actor, teamID string) (AdministrationTeam, error) {
	if !isSystemAdministrator(actor) {
		return AdministrationTeam{}, ErrForbidden
	}
	teamID = strings.TrimSpace(teamID)
	if service == nil || service.repository == nil || teamID == "" {
		return AdministrationTeam{}, ErrInvalidAdministrationRequest
	}
	return service.repository.GetAdministrationTeam(ctx, strings.TrimSpace(actor.IdentityID), teamID)
}

func (service *AdministrationService) GetServiceAccount(ctx context.Context, actor Actor, serviceAccountID string) (ServiceAccount, error) {
	if !isSystemAdministrator(actor) {
		return ServiceAccount{}, ErrForbidden
	}
	serviceAccountID = strings.TrimSpace(serviceAccountID)
	if service == nil || service.repository == nil || serviceAccountID == "" {
		return ServiceAccount{}, ErrInvalidAdministrationRequest
	}
	return service.repository.GetAdministrationServiceAccount(ctx, strings.TrimSpace(actor.IdentityID), serviceAccountID)
}

func (service *AdministrationService) CreateTeam(ctx context.Context, input CreateAdministrationTeamInput) (AdministrationTeam, error) {
	if !isSystemAdministrator(input.Actor) {
		return AdministrationTeam{}, ErrForbidden
	}
	name := strings.TrimSpace(input.Name)
	if service == nil || service.repository == nil || name == "" {
		return AdministrationTeam{}, ErrInvalidAdministrationRequest
	}
	requestID, err := credentialLifecycleRequestID(input.RequestID)
	if err != nil {
		return AdministrationTeam{}, ErrInvalidAdministrationRequest
	}
	teamID, err := service.newID()
	if err != nil {
		return AdministrationTeam{}, ErrInvalidAdministrationRequest
	}
	eventID, err := service.newID()
	if err != nil {
		return AdministrationTeam{}, ErrInvalidAdministrationRequest
	}
	return service.repository.ChangeAdministrationTeam(ctx, TeamChange{
		EventID: eventID, TeamID: teamID, Name: name, Operation: TeamCreated,
		ActorIdentityID: strings.TrimSpace(input.Actor.IdentityID), RequestID: requestID, ChangedAt: service.now().UTC(),
	})
}

func (service *AdministrationService) UpdateTeam(ctx context.Context, input UpdateAdministrationTeamInput) (AdministrationTeam, error) {
	if !isSystemAdministrator(input.Actor) {
		return AdministrationTeam{}, ErrForbidden
	}
	teamID := strings.TrimSpace(input.TeamID)
	name := strings.TrimSpace(input.Name)
	if service == nil || service.repository == nil || teamID == "" || name == "" {
		return AdministrationTeam{}, ErrInvalidAdministrationRequest
	}
	requestID, err := credentialLifecycleRequestID(input.RequestID)
	if err != nil {
		return AdministrationTeam{}, ErrInvalidAdministrationRequest
	}
	eventID, err := service.newID()
	if err != nil {
		return AdministrationTeam{}, ErrInvalidAdministrationRequest
	}
	return service.repository.ChangeAdministrationTeam(ctx, TeamChange{
		EventID: eventID, TeamID: teamID, Name: name, Operation: TeamUpdated, Confirmed: input.Confirmed,
		ActorIdentityID: strings.TrimSpace(input.Actor.IdentityID), RequestID: requestID, ChangedAt: service.now().UTC(),
	})
}

func (service *AdministrationService) ChangeRole(ctx context.Context, input ChangeRoleInput) error {
	if !isSystemAdministrator(input.Actor) {
		return ErrForbidden
	}
	identityID := strings.TrimSpace(input.IdentityID)
	if service == nil || service.repository == nil || identityID == "" || !validAdministrationRole(input.Role) {
		return ErrInvalidAdministrationRequest
	}
	requestID, err := credentialLifecycleRequestID(input.RequestID)
	if err != nil {
		return ErrInvalidAdministrationRequest
	}
	eventID, err := service.newID()
	if err != nil {
		return ErrInvalidAdministrationRequest
	}
	return service.repository.ChangeIdentityRole(ctx, RoleChange{
		EventID: eventID, IdentityID: identityID, Role: input.Role, ActorIdentityID: strings.TrimSpace(input.Actor.IdentityID),
		RequestID: requestID, ChangedAt: service.now().UTC(),
	})
}

func (service *AdministrationService) AddMembership(ctx context.Context, input ChangeMembershipInput) error {
	return service.changeMembership(ctx, input, MembershipAdded)
}

func (service *AdministrationService) RemoveMembership(ctx context.Context, input ChangeMembershipInput) error {
	return service.changeMembership(ctx, input, MembershipRemoved)
}

func (service *AdministrationService) changeMembership(ctx context.Context, input ChangeMembershipInput, operation MembershipOperation) error {
	if !isSystemAdministrator(input.Actor) {
		return ErrForbidden
	}
	identityID := strings.TrimSpace(input.IdentityID)
	teamID := strings.TrimSpace(input.TeamID)
	if service == nil || service.repository == nil || identityID == "" || teamID == "" {
		return ErrInvalidAdministrationRequest
	}
	requestID, err := credentialLifecycleRequestID(input.RequestID)
	if err != nil {
		return ErrInvalidAdministrationRequest
	}
	eventID, err := service.newID()
	if err != nil {
		return ErrInvalidAdministrationRequest
	}
	return service.repository.ChangeMembership(ctx, MembershipChange{
		EventID: eventID, IdentityID: identityID, TeamID: teamID, Operation: operation,
		ActorIdentityID: strings.TrimSpace(input.Actor.IdentityID), RequestID: requestID, ChangedAt: service.now().UTC(),
	})
}

func validAdministrationLimit(limit int) bool {
	return limit >= 1 && limit <= MaxAdministrationPageSize
}

func validAdministrationRole(role Role) bool {
	return role == RoleEmployee || role == RoleTeamAdministrator || role == RoleSystemAdministrator
}

func validIdentityStatus(status IdentityStatus) bool {
	return status == IdentityStatusPending || status == IdentityStatusActive || status == IdentityStatusDisabled
}
