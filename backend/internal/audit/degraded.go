package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"n-api-p/internal/observability"
)

var (
	ErrInvalidDegradedStateMachine = errors.New("invalid audit degraded state machine")
	ErrInvalidGateReason           = errors.New("invalid audit gate reason")
)

type AuditGateState string

const (
	AuditGateStateOpen    AuditGateState = "open"
	AuditGateStateBlocked AuditGateState = "blocked"
)

const (
	GateReasonStartupProbe            = "startup_probe_required"
	GateReasonInitialCapture          = "initial_capture_failure"
	GateReasonFinalizationPersistence = "finalization_persistence_failure"
	GateReasonUsagePersistence        = "usage_persistence_failure"
	GateReasonGateRead                = "gate_read_failure"
	GateReasonRecovery                = "recovery_failure"
	GateReasonProcessRestart          = "process_restart_reconciliation"
)

const degradedPersistenceTimeout = 5 * time.Second

type AuditGateSnapshot struct {
	State                  AuditGateState
	ReasonCode             string
	ChangedAt              time.Time
	LastPersistenceProbeAt *time.Time
}

type DegradedRepository interface {
	ReadAuditGate(context.Context) (AuditGateSnapshot, error)
	BlockAuditGate(context.Context, string, time.Time) error
	MarkAuditIncompleteAndBlock(context.Context, string, string, string, time.Time) error
	ReconcileAndOpenAuditGate(context.Context, time.Time, time.Time) error
}

type ChatGate interface {
	CheckChatAllowed(context.Context) error
}

type FailureGate interface {
	Block(context.Context, string) error
	MarkFinalizationFailure(context.Context, string, string, time.Time) error
}

type PostDispatchFailureGate interface {
	MarkPostDispatchFailure(context.Context, string, string, string, time.Time) error
}

type DegradedStateMachine struct {
	repository DegradedRepository
	now        func() time.Time
	metrics    *observability.Metrics

	mu     sync.RWMutex
	status AuditGateSnapshot
}

func NewDegradedStateMachine(repository DegradedRepository) (*DegradedStateMachine, error) {
	if repository == nil {
		return nil, ErrInvalidDegradedStateMachine
	}
	return &DegradedStateMachine{
		repository: repository,
		now:        func() time.Time { return time.Now().UTC() },
		status: AuditGateSnapshot{
			State:      AuditGateStateBlocked,
			ReasonCode: GateReasonStartupProbe,
		},
	}, nil
}

func (machine *DegradedStateMachine) CheckChatAllowed(ctx context.Context) error {
	if machine == nil || machine.repository == nil {
		return ErrAuditUnavailable
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("check audit gate: %w", err)
	}
	machine.mu.RLock()
	status := machine.status
	machine.mu.RUnlock()
	if status.State != AuditGateStateOpen {
		return ErrAuditUnavailable
	}

	durable, err := machine.repository.ReadAuditGate(ctx)
	if err != nil {
		machine.setBlocked(GateReasonGateRead, machine.now())
		return fmt.Errorf("%w: read audit gate: %w", ErrAuditUnavailable, err)
	}
	if durable.State != AuditGateStateOpen {
		machine.setBlocked(durable.ReasonCode, durable.ChangedAt)
		return ErrAuditUnavailable
	}
	return nil
}

func (machine *DegradedStateMachine) SetMetrics(metrics *observability.Metrics) {
	if machine != nil {
		machine.metrics = metrics
		if metrics != nil {
			metrics.SetAuditGateState(string(machine.Status().State))
		}
	}
}

func (machine *DegradedStateMachine) Block(ctx context.Context, reason string) error {
	if machine == nil || machine.repository == nil {
		return ErrAuditUnavailable
	}
	if err := validateGateReason(reason); err != nil {
		return err
	}
	changedAt := machine.now()
	machine.setBlocked(reason, changedAt)
	persistenceCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), degradedPersistenceTimeout)
	defer cancel()
	if err := machine.repository.BlockAuditGate(persistenceCtx, reason, changedAt); err != nil {
		return fmt.Errorf("%w: persist audit gate: %w", ErrAuditUnavailable, err)
	}
	return nil
}

func (machine *DegradedStateMachine) MarkFinalizationFailure(ctx context.Context, auditID, requestID string, completedAt time.Time) error {
	return machine.MarkPostDispatchFailure(ctx, auditID, requestID, GateReasonFinalizationPersistence, completedAt)
}

func (machine *DegradedStateMachine) MarkPostDispatchFailure(ctx context.Context, auditID, requestID, reason string, completedAt time.Time) error {
	if machine == nil || machine.repository == nil || auditID == "" || requestID == "" || completedAt.IsZero() {
		return ErrInvalidDegradedStateMachine
	}
	if err := validateGateReason(reason); err != nil {
		return err
	}
	changedAt := completedAt.UTC()
	machine.setBlocked(reason, changedAt)
	persistenceCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), degradedPersistenceTimeout)
	defer cancel()
	if err := machine.repository.MarkAuditIncompleteAndBlock(persistenceCtx, auditID, requestID, reason, changedAt); err != nil {
		return fmt.Errorf("%w: persist post-dispatch failure: %w", ErrAuditUnavailable, err)
	}
	return nil
}

func (machine *DegradedStateMachine) Recover(ctx context.Context, staleBefore, openedAt time.Time) error {
	if machine == nil || machine.repository == nil {
		return ErrAuditUnavailable
	}
	if staleBefore.IsZero() || openedAt.IsZero() || staleBefore.After(openedAt) {
		return ErrInvalidDegradedStateMachine
	}
	if err := ctx.Err(); err != nil {
		machine.setBlocked(GateReasonRecovery, openedAt.UTC())
		return fmt.Errorf("%w: recover audit gate: %w", ErrAuditUnavailable, err)
	}
	if err := machine.repository.ReconcileAndOpenAuditGate(ctx, staleBefore.UTC(), openedAt.UTC()); err != nil {
		machine.setBlocked(GateReasonRecovery, openedAt.UTC())
		return fmt.Errorf("%w: recover audit gate: %w", ErrAuditUnavailable, err)
	}
	machine.mu.Lock()
	machine.status = AuditGateSnapshot{State: AuditGateStateOpen, ChangedAt: openedAt.UTC(), LastPersistenceProbeAt: timePtr(openedAt.UTC())}
	machine.mu.Unlock()
	if machine.metrics != nil {
		machine.metrics.SetAuditGateState(string(AuditGateStateOpen))
	}
	return nil
}

func (machine *DegradedStateMachine) Status() AuditGateSnapshot {
	if machine == nil {
		return AuditGateSnapshot{State: AuditGateStateBlocked, ReasonCode: GateReasonStartupProbe}
	}
	machine.mu.RLock()
	status := machine.status
	machine.mu.RUnlock()
	if status.LastPersistenceProbeAt != nil {
		value := *status.LastPersistenceProbeAt
		status.LastPersistenceProbeAt = &value
	}
	return status
}

func (machine *DegradedStateMachine) setBlocked(reason string, changedAt time.Time) {
	if err := validateGateReason(reason); err != nil {
		reason = GateReasonRecovery
	}
	machine.mu.Lock()
	machine.status = AuditGateSnapshot{State: AuditGateStateBlocked, ReasonCode: reason, ChangedAt: changedAt.UTC()}
	machine.mu.Unlock()
	if machine.metrics != nil {
		machine.metrics.SetAuditGateState(string(AuditGateStateBlocked))
	}
}

func validateGateReason(reason string) error {
	reason = strings.TrimSpace(reason)
	if len(reason) == 0 || len(reason) > 64 {
		return ErrInvalidGateReason
	}
	for _, character := range reason {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' && character != '-' {
			return ErrInvalidGateReason
		}
	}
	return nil
}

func ValidateGateReason(reason string) error {
	return validateGateReason(reason)
}

func timePtr(value time.Time) *time.Time {
	return &value
}
