package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"n-api-p/internal/observability"
)

func TestLimiterMetricsReportSaturationWithoutOwnerIdentifiers(t *testing.T) {
	metrics := observability.NewMetrics()
	limiter := NewInProcessLimiterWithMetrics(metrics)
	owner := TrafficOwner{Kind: TrafficOwnerEmployee, ID: "sensitive-employee-id"}
	reservations := make([]Reservation, 0, employeeConcurrencyLimit)
	for range employeeConcurrencyLimit {
		reservation, err := limiter.Acquire(context.Background(), owner)
		if err != nil {
			t.Fatalf("Acquire() error = %v", err)
		}
		reservations = append(reservations, reservation)
	}
	defer func() {
		for _, reservation := range reservations {
			reservation.Release()
		}
	}()
	if _, err := limiter.Acquire(context.Background(), owner); err == nil {
		t.Fatal("Acquire() succeeded after owner concurrency saturation")
	}

	recorder := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := recorder.Body.String()
	for _, expected := range []string{"n_api_p_limiter_saturation_total", `owner_kind="employee"`, `rule="employee_concurrency"`} {
		if !strings.Contains(body, expected) {
			t.Fatalf("metrics missing %q: %s", expected, body)
		}
	}
	if strings.Contains(body, owner.ID) {
		t.Fatalf("metrics exposed owner ID: %s", body)
	}
}
