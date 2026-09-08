package audit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"n-api-p/internal/observability"
)

func TestAuditAndLifecycleMetricsExposeOutcomesWithoutIdentifiers(t *testing.T) {
	metrics := observability.NewMetrics()
	pending := &recordingPendingAuditRepository{}
	capture, err := NewInitialCaptureService(passthroughRequestEncryptor{}, pending)
	if err != nil {
		t.Fatalf("NewInitialCaptureService() error = %v", err)
	}
	capture.SetMetrics(metrics)
	if _, err := capture.CaptureValidatedRequest(context.Background(), personalCaptureInput([]byte(`{"model":"gpt-secret","messages":[]}`))); err != nil {
		t.Fatalf("CaptureValidatedRequest() error = %v", err)
	}

	repository := &degradedRepositoryFake{}
	finalization, err := NewResponseFinalizationService(&countingEncryptor{}, repository)
	if err != nil {
		t.Fatalf("NewResponseFinalizationService() error = %v", err)
	}
	finalization.SetMetrics(metrics)
	now := time.Date(2026, time.August, 15, 12, 0, 0, 0, time.UTC)
	if _, err := finalization.FinalizeResponse(context.Background(), ResponseFinalizationInput{
		AuditID: "audit-sensitive", RequestID: "request-sensitive", OwnerKind: OwnerKindPersonal,
		IdentityID: "employee-sensitive", TeamID: "team-sensitive", ModelID: "gpt-secret",
		ResponseJSON: []byte(`{"id":"response","choices":[{}]}`), CaptureStatus: CaptureStatusComplete,
		Outcome: AuditOutcomeSuccess, ObservedResponseBytes: int64(len(`{"id":"response","choices":[{}]}`)),
		CreatedAt: now.Add(-time.Minute), CompletedAt: now,
	}); err != nil {
		t.Fatalf("FinalizeResponse() error = %v", err)
	}

	oldest := now.Add(-2 * time.Hour)
	job, err := NewLifecycleJob(&lifecycleRepositoryFake{
		observeLags: []DeletionLagState{
			{Critical: true, OldestExpiredAt: &oldest},
			{Critical: false},
		},
		deletedRawRows: 1,
		purgedHashes:   1,
	})
	if err != nil {
		t.Fatalf("NewLifecycleJob() error = %v", err)
	}
	job.SetMetrics(metrics)
	if _, err := job.RunOnce(context.Background(), now); err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}

	recorder := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := recorder.Body.String()
	for _, expected := range []string{
		`operation="initial_capture"`,
		`operation="finalization"`,
		`n_api_p_raw_deletion_lag_seconds 0`,
		`n_api_p_raw_deletion_lag_critical 0`,
		`job="raw_cleanup",state="succeeded"`,
		`job="verification_hash_purge",state="succeeded"`,
	} {
		if !strings.Contains(body, expected) {
			t.Fatalf("metrics missing %q: %s", expected, body)
		}
	}
	for _, forbidden := range []string{"audit-sensitive", "request-sensitive", "employee-sensitive", "team-sensitive", "gpt-secret", "response"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("metrics exposed sensitive value %q: %s", forbidden, body)
		}
	}
}
