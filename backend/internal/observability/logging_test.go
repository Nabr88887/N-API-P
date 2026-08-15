package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestJSONLoggerEmitsOnlyAllowlistedCorrelationMetadata(t *testing.T) {
	var output bytes.Buffer
	logger := NewJSONLoggerWithClock(&output, func() time.Time {
		return time.Date(2026, 8, 15, 12, 0, 0, 123000000, time.UTC)
	})

	err := logger.Emit(LogEvent{
		Level:               LevelInfo,
		Event:               "http_request_completed",
		RequestID:           "11111111-1111-4111-8111-111111111111",
		Route:               "/v1/chat/completions",
		Method:              http.MethodPost,
		Status:              http.StatusOK,
		LatencyMilliseconds: 42,
		RequestBytes:        128,
		ResponseBytes:       256,
		ErrorCode:           "",
		AuditID:             "22222222-2222-4222-8222-222222222222",
		UsageID:             "33333333-3333-4333-8333-333333333333",
		SecurityEventID:     "44444444-4444-4444-8444-444444444444",
		UpstreamRequestID:   "upstream-request-1",
	})
	if err != nil {
		t.Fatalf("Emit() error = %v", err)
	}

	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("json.Unmarshal(log) error = %v; output = %q", err, output.String())
	}
	allowed := map[string]bool{
		"time": true, "level": true, "event": true, "request_id": true,
		"route": true, "method": true, "status": true, "latency_ms": true,
		"request_bytes": true, "response_bytes": true, "error_code": true,
		"audit_id": true, "usage_id": true, "security_event_id": true,
		"upstream_request_id": true,
	}
	for key := range record {
		if !allowed[key] {
			t.Fatalf("log field %q is not allowlisted: %s", key, output.String())
		}
	}
	if record["request_id"] != "11111111-1111-4111-8111-111111111111" || record["audit_id"] != "22222222-2222-4222-8222-222222222222" || record["usage_id"] != "33333333-3333-4333-8333-333333333333" || record["security_event_id"] != "44444444-4444-4444-8444-444444444444" || record["upstream_request_id"] != "upstream-request-1" {
		t.Fatalf("correlation fields = %#v", record)
	}
	if _, present := record["prompt"]; present {
		t.Fatalf("log unexpectedly contains prompt field: %s", output.String())
	}
	if _, present := record["authorization"]; present {
		t.Fatalf("log unexpectedly contains authorization field: %s", output.String())
	}
}

func TestJSONLoggerRejectsControlCharactersWithoutWriting(t *testing.T) {
	var output bytes.Buffer
	logger := NewJSONLogger(&output)

	err := logger.Emit(LogEvent{
		Level:     LevelInfo,
		Event:     "http_request_completed",
		RequestID: "11111111-1111-4111-8111-111111111111\nforged",
	})
	if !errors.Is(err, ErrInvalidLogEvent) {
		t.Fatalf("Emit() error = %v, want ErrInvalidLogEvent", err)
	}
	if output.Len() != 0 {
		t.Fatalf("invalid log event wrote %q", output.String())
	}
}

func TestRequestIDMiddlewareReplacesMalformedCorrelationAndReturnsIt(t *testing.T) {
	var output bytes.Buffer
	logger := NewJSONLogger(&output)
	var handlerRequestID string
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var ok bool
		handlerRequestID, ok = RequestIDFromContext(request.Context())
		if !ok {
			t.Errorf("RequestIDFromContext() found no request ID")
		}
		writer.Header().Set(RequestIDHeader, "upstream-request-id")
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte("ok"))
	})

	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString("body"))
	request.Header.Set(RequestIDHeader, "malicious\nX-Forged: true")
	recorder := httptest.NewRecorder()
	NewRequestIDMiddleware(next, logger).ServeHTTP(recorder, request)

	if !IsValidRequestID(handlerRequestID) {
		t.Fatalf("generated request ID = %q, want strict UUID", handlerRequestID)
	}
	if recorder.Header().Get(RequestIDHeader) != handlerRequestID {
		t.Fatalf("response request ID = %q, want %q", recorder.Header().Get(RequestIDHeader), handlerRequestID)
	}
	var record map[string]any
	if err := json.Unmarshal(output.Bytes(), &record); err != nil {
		t.Fatalf("json.Unmarshal(log) error = %v; output = %q", err, output.String())
	}
	if record["request_id"] != handlerRequestID {
		t.Fatalf("logged request ID = %#v, want %q", record["request_id"], handlerRequestID)
	}
	if record["route"] != "/v1/chat/completions" || record["status"] != float64(http.StatusCreated) {
		t.Fatalf("request log = %#v", record)
	}
}

func TestRequestIDMiddlewarePreservesSafeCorrelation(t *testing.T) {
	const requestID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	var handlerRequestID string
	next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		handlerRequestID, _ = RequestIDFromContext(request.Context())
		writer.WriteHeader(http.StatusNoContent)
	})
	request := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	request.Header.Set(RequestIDHeader, requestID)
	recorder := httptest.NewRecorder()
	NewRequestIDMiddleware(next, nil).ServeHTTP(recorder, request)

	if handlerRequestID != requestID || recorder.Header().Get(RequestIDHeader) != requestID {
		t.Fatalf("request ID handler=%q response=%q, want %q", handlerRequestID, recorder.Header().Get(RequestIDHeader), requestID)
	}
}

func TestCorrelationContextPreservesOperationalIDs(t *testing.T) {
	correlation := Correlation{
		RequestID:         "11111111-1111-4111-8111-111111111111",
		AuditID:           "22222222-2222-4222-8222-222222222222",
		UsageID:           "33333333-3333-4333-8333-333333333333",
		SecurityEventID:   "44444444-4444-4444-8444-444444444444",
		UpstreamRequestID: "upstream-request-1",
	}
	got, ok := CorrelationFromContext(WithCorrelation(context.Background(), correlation))
	if !ok || got != correlation {
		t.Fatalf("CorrelationFromContext() = %#v, %v; want %#v, true", got, ok, correlation)
	}
}
