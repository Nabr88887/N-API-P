package observability

import (
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const metricsNamespace = "n_api_p"

var (
	httpMetricLabels       = []string{"route", "method", "status_class"}
	limiterMetricLabels    = []string{"owner_kind", "outcome", "rule"}
	auditMetricLabels      = []string{"operation", "outcome"}
	backgroundMetricLabels = []string{"job", "state"}
)

// Metrics owns a private registry so the operator endpoint exposes only the
// gateway's bounded, content-free metrics rather than process or dependency
// collectors registered elsewhere in the process.
type Metrics struct {
	registry *prometheus.Registry

	httpRequests     *prometheus.CounterVec
	httpErrors       *prometheus.CounterVec
	httpDuration     *prometheus.HistogramVec
	limiter          *prometheus.CounterVec
	limiterSaturated *prometheus.CounterVec
	audit            *prometheus.CounterVec
	auditGate        *prometheus.GaugeVec
	deletionLag      prometheus.Gauge
	deletionOver     prometheus.Gauge
	background       *prometheus.GaugeVec
	backgroundRun    *prometheus.CounterVec
}

// NewMetrics returns an isolated registry with only fixed-cardinality metric
// families used by the gateway and its operational jobs.
func NewMetrics() *Metrics {
	registry := prometheus.NewRegistry()
	metrics := &Metrics{
		registry: registry,
		httpRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "http_requests_total",
			Help:      "Total HTTP requests handled by the gateway.",
		}, httpMetricLabels),
		httpErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "http_request_errors_total",
			Help:      "Total HTTP requests completed with an error status.",
		}, httpMetricLabels),
		httpDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "http_request_duration_seconds",
			Help:      "HTTP request duration in seconds.",
			Buckets:   prometheus.DefBuckets,
		}, httpMetricLabels),
		limiter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "limiter_attempts_total",
			Help:      "Limiter acquisition attempts by fixed owner and outcome buckets.",
		}, limiterMetricLabels),
		limiterSaturated: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "limiter_saturation_total",
			Help:      "Limiter acquisitions denied because a fixed limit rule was saturated.",
		}, []string{"owner_kind", "rule"}),
		audit: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "audit_persistence_total",
			Help:      "Audit and usage persistence outcomes.",
		}, auditMetricLabels),
		auditGate: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "audit_gate_state",
			Help:      "Current durable audit gate state; exactly one state is 1.",
		}, []string{"state"}),
		deletionLag: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "raw_deletion_lag_seconds",
			Help:      "Age in seconds of the oldest expired raw row observed.",
		}),
		deletionOver: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "raw_deletion_overdue",
			Help:      "Whether raw deletion is beyond the one-hour target.",
		}),
		background: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "background_job_state",
			Help:      "Current state of bounded background jobs; exactly one state is 1.",
		}, backgroundMetricLabels),
		backgroundRun: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "background_job_runs_total",
			Help:      "Background job runs by bounded job and result state.",
		}, backgroundMetricLabels),
	}
	registry.MustRegister(
		metrics.httpRequests,
		metrics.httpErrors,
		metrics.httpDuration,
		metrics.limiter,
		metrics.limiterSaturated,
		metrics.audit,
		metrics.auditGate,
		metrics.deletionLag,
		metrics.deletionOver,
		metrics.background,
		metrics.backgroundRun,
	)
	metrics.SetAuditGateState("unknown")
	metrics.SetDeletionLag(false, nil, nil, time.Time{})
	metrics.SetBackgroundJobState("raw_cleanup", "unknown")
	metrics.SetBackgroundJobState("verification_hash_purge", "unknown")
	return metrics
}

func (metrics *Metrics) Registry() *prometheus.Registry {
	if metrics == nil {
		return prometheus.NewRegistry()
	}
	return metrics.registry
}

func (metrics *Metrics) Handler() http.Handler {
	if metrics == nil {
		return promhttp.HandlerFor(prometheus.NewRegistry(), promhttp.HandlerOpts{})
	}
	return promhttp.HandlerFor(metrics.Registry(), promhttp.HandlerOpts{})
}

func (metrics *Metrics) ObserveHTTPRequest(route, method string, status int, duration time.Duration) {
	if metrics == nil || metrics.httpRequests == nil || metrics.httpDuration == nil {
		return
	}
	if duration < 0 {
		duration = 0
	}
	labels := []string{metricRoute(route), metricMethod(method), metricStatusClass(status)}
	metrics.httpRequests.WithLabelValues(labels...).Inc()
	metrics.httpDuration.WithLabelValues(labels...).Observe(duration.Seconds())
	if status >= http.StatusBadRequest {
		metrics.httpErrors.WithLabelValues(labels...).Inc()
	}
}

func (metrics *Metrics) ObserveLimiter(ownerKind, outcome, rule string) {
	if metrics == nil || metrics.limiter == nil {
		return
	}
	ownerKind = metricOwnerKind(ownerKind)
	outcome = metricLimiterOutcome(outcome)
	rule = metricLimiterRule(rule)
	metrics.limiter.WithLabelValues(ownerKind, outcome, rule).Inc()
	if outcome == "limited" && metrics.limiterSaturated != nil {
		metrics.limiterSaturated.WithLabelValues(ownerKind, rule).Inc()
	}
}

func (metrics *Metrics) ObserveAuditPersistence(operation, outcome string) {
	if metrics == nil || metrics.audit == nil {
		return
	}
	metrics.audit.WithLabelValues(metricAuditOperation(operation), metricPersistenceOutcome(outcome)).Inc()
}

func (metrics *Metrics) SetAuditGateState(state string) {
	if metrics == nil || metrics.auditGate == nil {
		return
	}
	state = metricGateState(state)
	for _, candidate := range []string{"open", "blocked", "unknown"} {
		value := 0.0
		if candidate == state {
			value = 1
		}
		metrics.auditGate.WithLabelValues(candidate).Set(value)
	}
}

func (metrics *Metrics) SetDeletionLag(critical bool, oldestExpiredAt, _ *time.Time, observedAt time.Time) {
	if metrics == nil || metrics.deletionLag == nil || metrics.deletionOver == nil {
		return
	}
	lag := 0.0
	if oldestExpiredAt != nil && !oldestExpiredAt.IsZero() && !observedAt.IsZero() && observedAt.After(*oldestExpiredAt) {
		lag = observedAt.Sub(*oldestExpiredAt).Seconds()
	}
	metrics.deletionLag.Set(lag)
	if critical {
		metrics.deletionOver.Set(1)
	} else {
		metrics.deletionOver.Set(0)
	}
}

func (metrics *Metrics) SetBackgroundJobState(job, state string) {
	if metrics == nil || metrics.background == nil {
		return
	}
	job = metricJob(job)
	state = metricJobState(state)
	for _, candidate := range []string{"running", "succeeded", "failed", "stopped", "unknown"} {
		value := 0.0
		if candidate == state {
			value = 1
		}
		metrics.background.WithLabelValues(job, candidate).Set(value)
	}
}

func (metrics *Metrics) ObserveBackgroundJob(job, state string) {
	if metrics == nil {
		return
	}
	job = metricJob(job)
	state = metricJobState(state)
	metrics.SetBackgroundJobState(job, state)
	if metrics.backgroundRun != nil && state != "running" {
		metrics.backgroundRun.WithLabelValues(job, state).Inc()
	}
}

func metricRoute(route string) string {
	return routeClass(route)
}

func metricMethod(method string) string {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions:
		return strings.ToUpper(strings.TrimSpace(method))
	default:
		return "unknown"
	}
}

func metricStatusClass(status int) string {
	if status >= 100 && status <= 599 {
		return string(rune('0'+status/100)) + "xx"
	}
	return "unknown"
}

func metricOwnerKind(value string) string {
	switch strings.TrimSpace(value) {
	case "employee", "service_account":
		return strings.TrimSpace(value)
	default:
		return "unknown"
	}
}

func metricLimiterOutcome(value string) string {
	switch strings.TrimSpace(value) {
	case "admitted", "limited", "error", "rejected", "unknown":
		return strings.TrimSpace(value)
	default:
		return "unknown"
	}
}

func metricLimiterRule(value string) string {
	switch strings.TrimSpace(value) {
	case "global_concurrency", "employee_concurrency", "employee_rpm", "service_account_concurrency", "service_account_rpm", "unknown":
		return strings.TrimSpace(value)
	default:
		return "unknown"
	}
}

func metricAuditOperation(value string) string {
	switch strings.TrimSpace(value) {
	case "initial_capture", "finalization", "usage", "unknown":
		return strings.TrimSpace(value)
	default:
		return "unknown"
	}
}

func metricPersistenceOutcome(value string) string {
	switch strings.TrimSpace(value) {
	case "success", "failure", "unknown":
		return strings.TrimSpace(value)
	default:
		return "unknown"
	}
}

func metricGateState(value string) string {
	switch strings.TrimSpace(value) {
	case "open", "blocked", "unknown":
		return strings.TrimSpace(value)
	default:
		return "unknown"
	}
}

func metricJob(value string) string {
	switch strings.TrimSpace(value) {
	case "raw_cleanup", "verification_hash_purge":
		return strings.TrimSpace(value)
	default:
		return "unknown"
	}
}

func metricJobState(value string) string {
	switch strings.TrimSpace(value) {
	case "running", "succeeded", "failed", "stopped", "unknown":
		return strings.TrimSpace(value)
	default:
		return "unknown"
	}
}
