package observability

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsExposeREDAndOperationalSignalsWithOnlyAllowlistedLabels(t *testing.T) {
	metrics := NewMetrics()
	metrics.ObserveHTTPRequest("/api/v1/users/employee-123", http.MethodGet, 503, 250*time.Millisecond)
	metrics.ObserveHTTPRequest("/v1/chat/completions", http.MethodPost, 200, 10*time.Millisecond)
	metrics.ObserveLimiter("employee-123", "limited", "employee_rpm")
	metrics.ObserveAuditPersistence("finalization", "failure")
	metrics.SetAuditGateState("blocked")
	oldest := time.Date(2026, time.August, 15, 10, 0, 0, 0, time.UTC)
	overdue := oldest.Add(time.Hour)
	metrics.SetDeletionLag(true, &oldest, &overdue, overdue.Add(time.Minute))
	metrics.SetBackgroundJobState("raw_cleanup", "failed")

	output := gatherMetrics(t, metrics)
	for _, name := range []string{
		"n_api_p_http_requests_total",
		"n_api_p_http_request_errors_total",
		"n_api_p_http_request_duration_seconds",
		"n_api_p_limiter_attempts_total",
		"n_api_p_limiter_saturation_total",
		"n_api_p_audit_persistence_total",
		"n_api_p_audit_gate_state",
		"n_api_p_raw_deletion_lag_seconds",
		"n_api_p_raw_deletion_overdue",
		"n_api_p_background_job_state",
	} {
		if !strings.Contains(output, name) {
			t.Fatalf("metrics output missing %q:\n%s", name, output)
		}
	}
	for _, forbidden := range []string{"employee-123", "request-123", "key-123", "gpt-secret", "prompt text", "response text"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("metrics output exposed forbidden identifier/content %q:\n%s", forbidden, output)
		}
	}
	for _, forbiddenLabel := range []string{"employee_id", "identity_id", "key_id", "request_id", "model", "content", "url", "error"} {
		if strings.Contains(output, forbiddenLabel+"=") {
			t.Fatalf("metrics output exposed forbidden label %q:\n%s", forbiddenLabel, output)
		}
	}
}

func TestMetricsRejectUnboundedValuesByMappingThemToFixedBuckets(t *testing.T) {
	metrics := NewMetrics()
	metrics.ObserveHTTPRequest("https://internal/employee-123?prompt=secret", "TRACE", 777, -time.Second)
	metrics.ObserveLimiter("employee-123", "request-id", "SELECT secret")
	metrics.ObserveAuditPersistence("model=gpt-secret", "password=secret")
	metrics.SetAuditGateState("reason=secret")
	metrics.SetBackgroundJobState("job-id-123", "stack trace")

	output := gatherMetrics(t, metrics)
	for _, forbidden := range []string{"employee-123", "prompt=secret", "request-id", "SELECT secret", "gpt-secret", "password=secret", "reason=secret", "job-id-123", "stack trace"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("unbounded value escaped metrics normalization %q:\n%s", forbidden, output)
		}
	}
}

func gatherMetrics(t *testing.T, metrics *Metrics) string {
	t.Helper()
	recorder := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("metrics handler status = %d: %s", recorder.Code, recorder.Body.String())
	}
	return recorder.Body.String()
}
