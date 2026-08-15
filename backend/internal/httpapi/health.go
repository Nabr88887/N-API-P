package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"n-api-p/internal/audit"
	"n-api-p/internal/observability"
)

var ErrInvalidOperatorHealthDependencies = errors.New("invalid operator health dependencies")

const (
	healthComponentProcess           = "process"
	healthComponentConfiguration     = "configuration"
	healthComponentDatabase          = "database"
	healthComponentAuditKey          = "audit_key"
	healthComponentAuditGate         = "audit_gate"
	healthComponentDeletionLag       = "deletion_lag"
	healthCodeConfiguration          = "configuration_unavailable"
	healthCodeDatabase               = "database_unavailable"
	healthCodeAuditKey               = "active_audit_key_unavailable"
	healthCodeAuditGate              = "audit_gate_blocked"
	healthCodeDeletionLag            = "raw_deletion_overdue"
	healthCodeAuditGateUnavailable   = "audit_gate_unavailable"
	healthCodeDeletionLagUnavailable = "deletion_lag_unavailable"
)

type OperatorHealthDependencies struct {
	Authorize          func(*http.Request) bool
	Configuration      func(context.Context) error
	Database           func(context.Context) error
	ActiveAuditKey     func(context.Context) error
	ReadAuditGate      func(context.Context) (audit.AuditGateSnapshot, error)
	ObserveDeletionLag func(context.Context, time.Time) (audit.DeletionLagState, error)
	Now                func() time.Time
}

type OperatorHealthChecker struct {
	configuration      func(context.Context) error
	database           func(context.Context) error
	activeAuditKey     func(context.Context) error
	readAuditGate      func(context.Context) (audit.AuditGateSnapshot, error)
	observeDeletionLag func(context.Context, time.Time) (audit.DeletionLagState, error)
	now                func() time.Time
}

func NewOperatorHealthChecker(dependencies OperatorHealthDependencies) *OperatorHealthChecker {
	now := dependencies.Now
	if now == nil {
		now = time.Now
	}
	return &OperatorHealthChecker{
		configuration:      dependencies.Configuration,
		database:           dependencies.Database,
		activeAuditKey:     dependencies.ActiveAuditKey,
		readAuditGate:      dependencies.ReadAuditGate,
		observeDeletionLag: dependencies.ObserveDeletionLag,
		now:                now,
	}
}

func (checker *OperatorHealthChecker) Liveness() HealthResponse {
	checkedAt := checker.checkedAt()
	return HealthResponse{
		State: HealthStateHealthy,
		Components: []HealthComponent{{
			Name: healthComponentProcess, State: HealthStateHealthy, CheckedAt: checkedAt,
		}},
		CheckedAt: checkedAt,
	}
}

func (checker *OperatorHealthChecker) Readiness(ctx context.Context) HealthResponse {
	checkedAt := checker.checkedAt()
	response := HealthResponse{
		State: HealthStateHealthy,
		Components: []HealthComponent{
			{Name: healthComponentConfiguration, State: HealthStateHealthy, CheckedAt: checkedAt},
			{Name: healthComponentDatabase, State: HealthStateHealthy, CheckedAt: checkedAt},
			{Name: healthComponentAuditKey, State: HealthStateHealthy, CheckedAt: checkedAt},
			{Name: healthComponentAuditGate, State: HealthStateHealthy, CheckedAt: checkedAt},
			{Name: healthComponentDeletionLag, State: HealthStateHealthy, CheckedAt: checkedAt},
		},
		CheckedAt: checkedAt,
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if checker == nil {
		for index, code := range []string{
			healthCodeConfiguration,
			healthCodeDatabase,
			healthCodeAuditKey,
			healthCodeAuditGateUnavailable,
			healthCodeDeletionLagUnavailable,
		} {
			markProbeFailure(&response.Components[index], code, response.CheckedAt, true)
		}
		response.State = HealthStateUnhealthy
		return response
	}

	markProbeFailure(&response.Components[0], healthCodeConfiguration, response.CheckedAt, checker.configuration == nil)
	if checker.configuration != nil {
		if err := checker.configuration(ctx); err != nil {
			markProbeFailure(&response.Components[0], healthCodeConfiguration, response.CheckedAt, true)
		}
	}

	markProbeFailure(&response.Components[1], healthCodeDatabase, response.CheckedAt, checker.database == nil)
	if checker.database != nil {
		if err := checker.database(ctx); err != nil {
			markProbeFailure(&response.Components[1], healthCodeDatabase, response.CheckedAt, true)
		}
	}

	markProbeFailure(&response.Components[2], healthCodeAuditKey, response.CheckedAt, checker.activeAuditKey == nil)
	if checker.activeAuditKey != nil {
		if err := checker.activeAuditKey(ctx); err != nil {
			markProbeFailure(&response.Components[2], healthCodeAuditKey, response.CheckedAt, true)
		}
	}

	if checker.readAuditGate == nil {
		markProbeFailure(&response.Components[3], healthCodeAuditGateUnavailable, response.CheckedAt, true)
	} else if snapshot, err := checker.readAuditGate(ctx); err != nil {
		markProbeFailure(&response.Components[3], healthCodeAuditGateUnavailable, response.CheckedAt, true)
	} else if snapshot.State != audit.AuditGateStateOpen {
		markProbeFailure(&response.Components[3], healthCodeAuditGate, response.CheckedAt, true)
	}

	if checker.observeDeletionLag == nil {
		markProbeFailure(&response.Components[4], healthCodeDeletionLagUnavailable, response.CheckedAt, true)
	} else if lag, err := checker.observeDeletionLag(ctx, checkedAt); err != nil {
		markProbeFailure(&response.Components[4], healthCodeDeletionLagUnavailable, response.CheckedAt, true)
	} else if lag.Critical {
		markProbeFailure(&response.Components[4], healthCodeDeletionLag, response.CheckedAt, true)
	}

	for _, component := range response.Components {
		if component.State == HealthStateUnhealthy {
			response.State = HealthStateUnhealthy
			break
		}
	}
	return response
}

func (checker *OperatorHealthChecker) checkedAt() time.Time {
	if checker == nil || checker.now == nil {
		return time.Now().UTC()
	}
	return checker.now().UTC()
}

func markProbeFailure(component *HealthComponent, detailCode string, checkedAt time.Time, failed bool) {
	if !failed {
		return
	}
	component.State = HealthStateUnhealthy
	component.DetailCode = detailCode
	component.CheckedAt = checkedAt
}

func NewOperatorHealthRouter(dependencies OperatorHealthDependencies) (http.Handler, error) {
	if dependencies.Authorize == nil {
		return nil, ErrInvalidOperatorHealthDependencies
	}
	checker := NewOperatorHealthChecker(dependencies)
	liveRoute := routeByNameValue(RouteName("operations.live"))
	readyRoute := routeByNameValue(RouteName("operations.ready"))
	if liveRoute.Pattern != "/health/live" || liveRoute.Auth != AuthOperatorBoundary ||
		readyRoute.Pattern != "/health/ready" || readyRoute.Auth != AuthOperatorBoundary {
		return nil, ErrInvalidOperatorHealthDependencies
	}

	mux := http.NewServeMux()
	mux.Handle("GET /health/live", operatorHealthHandler(dependencies.Authorize, func(context.Context) HealthResponse {
		return checker.Liveness()
	}))
	mux.Handle("GET /health/ready", operatorHealthHandler(dependencies.Authorize, func(ctx context.Context) HealthResponse {
		return checker.Readiness(ctx)
	}))
	return observability.NewRequestIDMiddleware(mux, observability.DefaultLogger()), nil
}

func operatorHealthHandler(authorize func(*http.Request) bool, response func(context.Context) HealthResponse) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if !authorize(request) {
			writeErrorResponse(writer, CodeForbidden)
			return
		}
		health := response(request.Context())
		status := http.StatusOK
		if health.State == HealthStateUnhealthy {
			status = http.StatusServiceUnavailable
		}
		writeJSON(writer, status, health)
	})
}
