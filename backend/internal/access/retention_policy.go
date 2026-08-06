package access

import (
	"context"
	"errors"
	"time"
)

const hardRawRetentionMaximumDays = 30

var (
	ErrInvalidRetentionPolicy        = errors.New("invalid retention policy")
	ErrRetentionConfirmationRequired = errors.New("retention confirmation required")
	ErrRetentionPolicyUnavailable    = errors.New("retention policy unavailable")
)

type RetentionPolicy struct {
	Days        int
	MaximumDays int
	UpdatedAt   time.Time
}

type RetentionPolicyChangeInput struct {
	Days      int
	Confirmed bool
	RequestID string
}

// RetentionPolicyChange carries the successful policy mutation and security
// event that the repository must commit atomically.
type RetentionPolicyChange struct {
	Days        int
	MaximumDays int
	ChangedAt   time.Time
	Event       SecurityEvent
}

func (change RetentionPolicyChange) Validate() error {
	if change.Days < 1 || change.Days > change.MaximumDays || change.MaximumDays < 1 || change.MaximumDays > hardRawRetentionMaximumDays || change.ChangedAt.IsZero() {
		return ErrInvalidRetentionPolicy
	}
	event := change.Event
	if event.ID == "" || event.EventType != string(SensitiveActionRetentionPolicy) || event.ActorIdentityID == "" || event.RequestID == "" || event.Outcome != SecurityEventSuccess || event.OccurredAt.IsZero() || !event.OccurredAt.Equal(change.ChangedAt) {
		return ErrInvalidRetentionPolicy
	}
	return nil
}

type RetentionPolicyRepository interface {
	ReadRetentionPolicy(context.Context) (RetentionPolicy, error)
	ChangeRetentionPolicy(context.Context, RetentionPolicyChange) (RetentionPolicy, error)
	AppendSecurityEvent(context.Context, SecurityEvent) error
}

type RetentionPolicyService struct {
	repository  RetentionPolicyRepository
	maximumDays int
	now         func() time.Time
	newID       func() (string, error)
}

func NewRetentionPolicyService(repository RetentionPolicyRepository, maximumDays int) (*RetentionPolicyService, error) {
	if repository == nil || maximumDays < 1 || maximumDays > hardRawRetentionMaximumDays {
		return nil, ErrInvalidRetentionPolicy
	}
	return &RetentionPolicyService{
		repository: repository, maximumDays: maximumDays,
		now: time.Now, newID: newIdentityID,
	}, nil
}

func (service *RetentionPolicyService) Get(ctx context.Context, session ActivePortalSession) (RetentionPolicy, error) {
	if service == nil || service.repository == nil {
		return RetentionPolicy{}, ErrRetentionPolicyUnavailable
	}
	if session.IdentityID == "" || session.Role != RoleSystemAdministrator {
		return RetentionPolicy{}, ErrForbidden
	}
	policy, err := service.repository.ReadRetentionPolicy(ctx)
	if err != nil {
		return RetentionPolicy{}, ErrRetentionPolicyUnavailable
	}
	if policy.Days < 1 || policy.Days > service.maximumDays {
		return RetentionPolicy{}, ErrRetentionPolicyUnavailable
	}
	policy.MaximumDays = service.maximumDays
	return policy, nil
}

func (service *RetentionPolicyService) Change(ctx context.Context, session ActivePortalSession, input RetentionPolicyChangeInput) (RetentionPolicy, error) {
	if service == nil || service.repository == nil || service.newID == nil || input.RequestID == "" {
		return RetentionPolicy{}, ErrInvalidRetentionPolicy
	}
	now := service.now().UTC()
	event, err := service.retentionEvent(session, input.RequestID, now)
	if err != nil {
		return RetentionPolicy{}, err
	}

	var denial error
	switch {
	case session.IdentityID == "" || session.Role != RoleSystemAdministrator:
		event.DetailCode, denial = "forbidden", ErrForbidden
	case session.ReauthenticatedUntil == nil || !session.ReauthenticatedUntil.After(now):
		event.DetailCode, denial = "reauthentication_required", ErrReauthenticationRequired
	case !input.Confirmed:
		event.DetailCode, denial = "confirmation_required", ErrRetentionConfirmationRequired
	case input.Days < 1 || input.Days > service.maximumDays:
		event.DetailCode, denial = "invalid_retention_days", ErrInvalidRetentionPolicy
	}
	if denial != nil {
		event.Outcome = SecurityEventDenied
		if err := service.repository.AppendSecurityEvent(ctx, event); err != nil {
			return RetentionPolicy{}, ErrSecurityAuditUnavailable
		}
		return RetentionPolicy{}, denial
	}

	policy, err := service.repository.ChangeRetentionPolicy(ctx, RetentionPolicyChange{
		Days: input.Days, MaximumDays: service.maximumDays, ChangedAt: now, Event: event,
	})
	if err != nil {
		if errors.Is(err, ErrForbidden) {
			return RetentionPolicy{}, ErrForbidden
		}
		if errors.Is(err, ErrInvalidRetentionPolicy) {
			return RetentionPolicy{}, ErrInvalidRetentionPolicy
		}
		return RetentionPolicy{}, ErrRetentionPolicyUnavailable
	}
	if policy.Days < 1 || policy.Days > service.maximumDays {
		return RetentionPolicy{}, ErrRetentionPolicyUnavailable
	}
	policy.MaximumDays = service.maximumDays
	return policy, nil
}

func (service *RetentionPolicyService) retentionEvent(session ActivePortalSession, requestID string, occurredAt time.Time) (SecurityEvent, error) {
	eventID, err := service.newID()
	if err != nil {
		return SecurityEvent{}, ErrSecurityAuditUnavailable
	}
	return SecurityEvent{
		ID: eventID, EventType: string(SensitiveActionRetentionPolicy), ActorIdentityID: session.IdentityID,
		RequestID: requestID, Outcome: SecurityEventSuccess, DetailCode: "authorized", OccurredAt: occurredAt,
	}, nil
}
