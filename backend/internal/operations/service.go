package operations

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"n-api-p/internal/access"
)

const MaxEventPageSize = 100

var (
	ErrInvalidService     = errors.New("invalid operations service")
	ErrInvalidEventFilter = errors.New("invalid operational event filter")
	ErrInvalidFault       = errors.New("invalid operational fault")
	ErrUnavailable        = errors.New("operations unavailable")
)

type FaultCode string

const (
	FaultAuditUnavailable    FaultCode = "audit_unavailable"
	FaultRawDeletionOverdue  FaultCode = "raw_deletion_overdue"
	FaultRequiredKeyFailure  FaultCode = "required_key_failure"
	FaultDatabaseUnavailable FaultCode = "database_unavailable"
)

var criticalFaultCodes = [...]FaultCode{
	FaultAuditUnavailable,
	FaultRawDeletionOverdue,
	FaultRequiredKeyFailure,
	FaultDatabaseUnavailable,
}

type FaultState struct {
	Code      FaultCode
	Active    bool
	ChangedAt time.Time
}

type Health struct {
	Faults    []FaultState
	CheckedAt time.Time
}

type Event struct {
	ID         string
	Fault      FaultCode
	Active     bool
	OccurredAt time.Time
}

type EventFilter struct {
	Cursor string
	Limit  int
	Active *bool
	From   *time.Time
	To     *time.Time
}

type EventPage struct {
	Events     []Event
	NextCursor string
}

type FaultTransition struct {
	Fault      FaultCode
	Active     bool
	OccurredAt time.Time
}

type HealthInput struct {
	Session access.ActivePortalSession
}

type ListEventsInput struct {
	Session access.ActivePortalSession
	Filter  EventFilter
}

type Repository interface {
	ReadCriticalFaults(context.Context) ([]FaultState, error)
	ListOperationalEvents(context.Context, EventFilter) (EventPage, error)
	AppendFaultTransition(context.Context, FaultTransition) error
}

type Service struct {
	repository Repository
	now        func() time.Time
}

func NewService(repository Repository) (*Service, error) {
	if repository == nil {
		return nil, ErrInvalidService
	}
	return &Service{repository: repository, now: func() time.Time { return time.Now().UTC() }}, nil
}

func (service *Service) Health(ctx context.Context, input HealthInput) (Health, error) {
	if !systemAdministrator(input.Session) {
		return Health{}, access.ErrForbidden
	}
	if service == nil || service.repository == nil || service.now == nil {
		return Health{}, ErrInvalidService
	}
	states, err := service.repository.ReadCriticalFaults(ctx)
	if err != nil {
		return Health{}, fmt.Errorf("%w: read critical faults: %w", ErrUnavailable, err)
	}
	checkedAt := service.now().UTC()
	byCode := make(map[FaultCode]FaultState, len(criticalFaultCodes))
	for _, state := range states {
		if !ValidFaultCode(state.Code) {
			continue
		}
		state.Code = FaultCode(strings.TrimSpace(string(state.Code)))
		state.ChangedAt = state.ChangedAt.UTC()
		byCode[state.Code] = state
	}
	health := Health{Faults: make([]FaultState, 0, len(criticalFaultCodes)), CheckedAt: checkedAt}
	for _, code := range criticalFaultCodes {
		state, ok := byCode[code]
		if !ok {
			state = FaultState{Code: code, ChangedAt: checkedAt}
		}
		health.Faults = append(health.Faults, state)
	}
	return health, nil
}

func (service *Service) ListEvents(ctx context.Context, input ListEventsInput) (EventPage, error) {
	if !systemAdministrator(input.Session) {
		return EventPage{}, access.ErrForbidden
	}
	if service == nil || service.repository == nil || !validEventFilter(input.Filter) {
		return EventPage{}, ErrInvalidEventFilter
	}
	page, err := service.repository.ListOperationalEvents(ctx, input.Filter)
	if err != nil {
		return EventPage{}, fmt.Errorf("%w: list operational events: %w", ErrUnavailable, err)
	}
	filtered := make([]Event, 0, len(page.Events))
	for _, event := range page.Events {
		if !ValidFaultCode(event.Fault) {
			continue
		}
		event.Fault = FaultCode(strings.TrimSpace(string(event.Fault)))
		event.OccurredAt = event.OccurredAt.UTC()
		filtered = append(filtered, event)
	}
	page.Events = filtered
	return page, nil
}

func (service *Service) RecordFault(ctx context.Context, code FaultCode, active bool, occurredAt time.Time) error {
	if service == nil || service.repository == nil {
		return ErrInvalidService
	}
	if !ValidFaultCode(code) || occurredAt.IsZero() {
		return ErrInvalidFault
	}
	transition := FaultTransition{Fault: FaultCode(strings.TrimSpace(string(code))), Active: active, OccurredAt: occurredAt.UTC()}
	if err := service.repository.AppendFaultTransition(ctx, transition); err != nil {
		return fmt.Errorf("%w: append fault transition: %w", ErrUnavailable, err)
	}
	return nil
}

func ValidFaultCode(code FaultCode) bool {
	trimmed := FaultCode(strings.TrimSpace(string(code)))
	for _, allowed := range criticalFaultCodes {
		if trimmed == allowed {
			return true
		}
	}
	return false
}

func validEventFilter(filter EventFilter) bool {
	if filter.Limit < 1 || filter.Limit > MaxEventPageSize || len(filter.Cursor) > 512 {
		return false
	}
	if filter.From != nil && filter.From.IsZero() || filter.To != nil && filter.To.IsZero() {
		return false
	}
	return filter.From == nil || filter.To == nil || !filter.From.After(*filter.To)
}

func systemAdministrator(session access.ActivePortalSession) bool {
	return strings.TrimSpace(session.IdentityID) != "" && session.Role == access.RoleSystemAdministrator
}
