package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"n-api-p/internal/audit"
)

const healthTestTime = "2026-08-15T12:00:00Z"

func TestOperatorHealthRouterLivenessDoesNotUseReadinessDependencies(t *testing.T) {
	called := false
	router, err := NewOperatorHealthRouter(OperatorHealthDependencies{
		Authorize: func(*http.Request) bool { return true },
		Configuration: func(context.Context) error {
			called = true
			return errors.New("configuration should not be checked by liveness")
		},
		Database: func(context.Context) error {
			called = true
			return errors.New("database should not be checked by liveness")
		},
		ActiveAuditKey: func(context.Context) error {
			called = true
			return errors.New("audit key should not be checked by liveness")
		},
		ReadAuditGate: func(context.Context) (audit.AuditGateSnapshot, error) {
			called = true
			return audit.AuditGateSnapshot{}, errors.New("audit gate should not be checked by liveness")
		},
		ObserveDeletionLag: func(context.Context, time.Time) (audit.DeletionLagState, error) {
			called = true
			return audit.DeletionLagState{}, errors.New("deletion lag should not be checked by liveness")
		},
		Now: func() time.Time { return mustHealthTime(t) },
	})
	if err != nil {
		t.Fatalf("NewOperatorHealthRouter() error = %v", err)
	}

	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var response HealthResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode liveness response: %v", err)
	}
	if response.State != HealthStateHealthy || len(response.Components) != 1 ||
		response.Components[0].Name != healthComponentProcess ||
		response.Components[0].State != HealthStateHealthy {
		t.Fatalf("liveness response = %#v", response)
	}
	if called {
		t.Fatal("liveness invoked a readiness dependency")
	}
}

func TestOperatorHealthRouterReadinessReportsHealthyWhenLocalPrerequisitesAreAvailable(t *testing.T) {
	router := newHealthyOperatorHealthRouter(t, nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health/ready", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	var response HealthResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode readiness response: %v", err)
	}
	if response.State != HealthStateHealthy || len(response.Components) != 5 {
		t.Fatalf("readiness response = %#v", response)
	}
	for _, component := range response.Components {
		if component.State != HealthStateHealthy || component.DetailCode != "" {
			t.Fatalf("healthy component = %#v", component)
		}
	}
	if strings.Contains(recorder.Body.String(), "upstream") {
		t.Fatalf("readiness exposed historical upstream state: %s", recorder.Body.String())
	}
}

func TestOperatorHealthRouterReadinessReturnsOnlySafeCodesForLocalFailures(t *testing.T) {
	router := newHealthyOperatorHealthRouter(t, func(deps *OperatorHealthDependencies) {
		deps.Configuration = func(context.Context) error {
			return errors.New("N_API_P_DATABASE_URL=postgres://user:password@private/socket")
		}
		deps.Database = func(context.Context) error {
			return errors.New("dial tcp /private/socket:5432: password=secret")
		}
		deps.ActiveAuditKey = func(context.Context) error {
			return errors.New("audit key /etc/n-api-p/audit.json is unreadable")
		}
		deps.ReadAuditGate = func(context.Context) (audit.AuditGateSnapshot, error) {
			return audit.AuditGateSnapshot{}, errors.New("SELECT audit_gate_state FROM operational_state")
		}
		deps.ObserveDeletionLag = func(context.Context, time.Time) (audit.DeletionLagState, error) {
			return audit.DeletionLagState{}, errors.New("raw deletion SQL failed")
		}
	})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health/ready", nil))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", recorder.Code, recorder.Body.String())
	}
	var response HealthResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode readiness response: %v", err)
	}
	if response.State != HealthStateUnhealthy {
		t.Fatalf("readiness state = %q, want unhealthy", response.State)
	}
	allowed := map[string]bool{
		healthComponentConfiguration:     true,
		healthComponentDatabase:          true,
		healthComponentAuditKey:          true,
		healthComponentAuditGate:         true,
		healthComponentDeletionLag:       true,
		healthCodeConfiguration:          true,
		healthCodeDatabase:               true,
		healthCodeAuditKey:               true,
		healthCodeAuditGate:              true,
		healthCodeDeletionLag:            true,
		healthCodeAuditGateUnavailable:   true,
		healthCodeDeletionLagUnavailable: true,
	}
	for _, component := range response.Components {
		if !allowed[component.Name] || (component.DetailCode != "" && !allowed[component.DetailCode]) {
			t.Fatalf("unsafe health component = %#v", component)
		}
	}
	body := recorder.Body.String()
	for _, secret := range []string{"password", "private/socket", "SELECT", "operational_state", "audit.json", "raw deletion"} {
		if strings.Contains(body, secret) {
			t.Fatalf("readiness exposed internal detail %q: %s", secret, body)
		}
	}
}

func TestOperatorHealthRouterReadinessReportsAuditGateAndDeletionLagCodes(t *testing.T) {
	router := newHealthyOperatorHealthRouter(t, func(deps *OperatorHealthDependencies) {
		deps.ReadAuditGate = func(context.Context) (audit.AuditGateSnapshot, error) {
			return audit.AuditGateSnapshot{State: audit.AuditGateStateBlocked, ReasonCode: "internal_reason"}, nil
		}
		deps.ObserveDeletionLag = func(context.Context, time.Time) (audit.DeletionLagState, error) {
			return audit.DeletionLagState{Critical: true}, nil
		}
	})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health/ready", nil))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503: %s", recorder.Code, recorder.Body.String())
	}
	var response HealthResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode readiness response: %v", err)
	}
	got := map[string]string{}
	for _, component := range response.Components {
		got[component.Name] = component.DetailCode
	}
	if got[healthComponentAuditGate] != healthCodeAuditGate || got[healthComponentDeletionLag] != healthCodeDeletionLag {
		t.Fatalf("component detail codes = %#v", got)
	}
	if strings.Contains(recorder.Body.String(), "internal_reason") {
		t.Fatalf("readiness exposed audit gate reason: %s", recorder.Body.String())
	}
}

func TestOperatorHealthRouterHistoricalUpstreamFailureDoesNotBlockReadiness(t *testing.T) {
	router := newHealthyOperatorHealthRouter(t, nil)
	recorder := httptest.NewRecorder()
	recorder.HeaderMap = make(http.Header)
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 despite historical upstream failure: %s", recorder.Code, recorder.Body.String())
	}
}

func TestOperatorHealthRouterRejectsRequestsOutsideOperatorBoundary(t *testing.T) {
	probeCalled := false
	router, err := NewOperatorHealthRouter(OperatorHealthDependencies{
		Authorize: func(*http.Request) bool { return false },
		Configuration: func(context.Context) error {
			probeCalled = true
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewOperatorHealthRouter() error = %v", err)
	}
	for _, path := range []string{"/health/live", "/health/ready"} {
		t.Run(path, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
			if recorder.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403: %s", recorder.Code, recorder.Body.String())
			}
			if strings.Contains(recorder.Body.String(), "database") || strings.Contains(recorder.Body.String(), "secret") {
				t.Fatalf("denied response exposed component detail: %s", recorder.Body.String())
			}
		})
	}
	if probeCalled {
		t.Fatal("denied operator request invoked readiness probes")
	}
}

func TestOperatorHealthRouterLeavesLivenessReachableWhenReadinessIsUnhealthy(t *testing.T) {
	router := newHealthyOperatorHealthRouter(t, func(deps *OperatorHealthDependencies) {
		deps.Database = func(context.Context) error { return errors.New("database unavailable") }
	})
	ready := httptest.NewRecorder()
	router.ServeHTTP(ready, httptest.NewRequest(http.MethodGet, "/health/ready", nil))
	live := httptest.NewRecorder()
	router.ServeHTTP(live, httptest.NewRequest(http.MethodGet, "/health/live", nil))
	if ready.Code != http.StatusServiceUnavailable || live.Code != http.StatusOK {
		t.Fatalf("ready/live statuses = %d/%d, want 503/200", ready.Code, live.Code)
	}
}

func newHealthyOperatorHealthRouter(t *testing.T, mutate func(*OperatorHealthDependencies)) http.Handler {
	t.Helper()
	deps := OperatorHealthDependencies{
		Authorize:      func(*http.Request) bool { return true },
		Configuration:  func(context.Context) error { return nil },
		Database:       func(context.Context) error { return nil },
		ActiveAuditKey: func(context.Context) error { return nil },
		ReadAuditGate: func(context.Context) (audit.AuditGateSnapshot, error) {
			return audit.AuditGateSnapshot{State: audit.AuditGateStateOpen}, nil
		},
		ObserveDeletionLag: func(context.Context, time.Time) (audit.DeletionLagState, error) {
			return audit.DeletionLagState{Critical: false}, nil
		},
		Now: func() time.Time { return mustHealthTime(t) },
	}
	if mutate != nil {
		mutate(&deps)
	}
	router, err := NewOperatorHealthRouter(deps)
	if err != nil {
		t.Fatalf("NewOperatorHealthRouter() error = %v", err)
	}
	return router
}

func mustHealthTime(t *testing.T) time.Time {
	t.Helper()
	value, err := time.Parse(time.RFC3339, healthTestTime)
	if err != nil {
		t.Fatalf("parse health test time: %v", err)
	}
	return value
}
