package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"n-api-p/internal/observability"
)

func TestOperatorMetricsRouterRequiresOperatorAuthorization(t *testing.T) {
	metrics := observability.NewMetrics()
	router, err := NewOperatorMetricsRouter(OperatorMetricsDependencies{
		Authorize: func(*http.Request) bool { return false },
		Metrics:   metrics,
	})
	if err != nil {
		t.Fatalf("NewOperatorMetricsRouter() error = %v", err)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "n_api_p_") {
		t.Fatalf("denied metrics response exposed exposition: %s", recorder.Body.String())
	}
}

func TestOperatorMetricsRouterServesPrometheusWithoutSensitiveLabels(t *testing.T) {
	metrics := observability.NewMetrics()
	metrics.ObserveHTTPRequest("/api/v1/users/employee-1", http.MethodGet, http.StatusInternalServerError, 2)
	router, err := NewOperatorMetricsRouter(OperatorMetricsDependencies{
		Authorize: func(*http.Request) bool { return true },
		Metrics:   metrics,
	})
	if err != nil {
		t.Fatalf("NewOperatorMetricsRouter() error = %v", err)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	for _, expected := range []string{"n_api_p_http_requests_total", `route="/api/v1"`, `method="GET"`, `status_class="5xx"`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("metrics response missing %q: %s", expected, body)
		}
	}
	for _, forbidden := range []string{"employee-1", "employee_id=", "key_id=", "request_id=", "model=", "content="} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("metrics response exposed %q: %s", forbidden, body)
		}
	}
}
