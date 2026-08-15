package gateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"n-api-p/internal/audit"
	"n-api-p/internal/httpapi"
	"n-api-p/internal/observability"
	"n-api-p/internal/policy"
	"n-api-p/internal/usage"
)

func TestChatProxyHandlerProxiesSuccessAndLinksAuditUsage(t *testing.T) {
	body := []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hello"}]}`)
	responseBody := []byte(`{"id":"chatcmpl-1","object":"chat.completion","created":1700000000,"model":"gpt-test","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`)
	upstream := &fakeChatUpstream{response: &NewAPIResponse{StatusCode: 200, ContentType: "application/json", RequestID: "upstream-1", Body: io.NopCloser(bytes.NewReader(responseBody))}}
	capture := &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "request-1"}}
	finalizer := &fakeResponseFinalizer{}
	usageRepo := &fakeUsageRepository{}
	handler := newTestChatProxyHandler(t, upstream, capture, finalizer, usageRepo, nil)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req = req.WithContext(WithChatCaller(req.Context(), ChatCaller{RequestID: "request-1", KeyID: "key-1", OwnerKind: audit.OwnerKindPersonal, IdentityID: "employee-1", TeamID: "team-1", TrafficOwner: TrafficOwner{Kind: TrafficOwnerEmployee, ID: "employee-1"}}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusOK || !bytes.Equal(recorder.Body.Bytes(), responseBody) {
		t.Fatalf("response = (%d, %s), want 200 and exact upstream body", recorder.Code, recorder.Body.String())
	}
	if !bytes.Equal(upstream.body, body) || upstream.calls != 1 {
		t.Fatalf("upstream calls/body = %d/%s, want one exact request", upstream.calls, upstream.body)
	}
	if capture.input.ID != "generated-id" || !bytes.Equal(capture.input.ValidatedRequestJSON, body) {
		t.Fatalf("initial capture = %+v, want generated-id and exact request", capture.input)
	}
	if finalizer.input.AuditID != "generated-id" || finalizer.input.Outcome != audit.AuditOutcomeSuccess || !bytes.Equal(finalizer.input.ResponseJSON, responseBody) {
		t.Fatalf("final audit input = %+v, want linked complete success", finalizer.input)
	}
	if usageRepo.record.AuditID != "generated-id" || usageRepo.record.RequestID != "request-1" || usageRepo.record.UpstreamRequestID != "upstream-1" || usageRepo.record.Outcome != usage.OutcomeSuccess || usageRepo.record.Usage == nil || usageRepo.record.Usage.TotalTokens != 5 {
		t.Fatalf("usage record = %+v, want exact audit/upstream linkage", usageRepo.record)
	}
}

func TestChatProxyHandlerUsesGatewayRequestIDForAuditAndUsage(t *testing.T) {
	const requestID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	body := []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hello"}]}`)
	responseBody := []byte(`{"id":"chatcmpl-request-id","model":"gpt-test","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}`)
	upstream := &fakeChatUpstream{response: &NewAPIResponse{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(responseBody))}}
	capture := &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: requestID}}
	finalizer := &fakeResponseFinalizer{}
	usageRepo := &fakeUsageRepository{}
	handler := newTestChatProxyHandler(t, upstream, capture, finalizer, usageRepo, nil)
	request := proxyRequest(t, body, "")
	request.Header.Set(observability.RequestIDHeader, requestID)
	recorder := httptest.NewRecorder()
	observability.NewRequestIDMiddleware(handler, nil).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || recorder.Header().Get(observability.RequestIDHeader) != requestID {
		t.Fatalf("response = (%d, request_id=%q), want 200 and %q", recorder.Code, recorder.Header().Get(observability.RequestIDHeader), requestID)
	}
	if capture.input.RequestID != requestID || finalizer.input.RequestID != requestID || usageRepo.record.RequestID != requestID {
		t.Fatalf("request IDs = capture %q, finalizer %q, usage %q; want %q", capture.input.RequestID, finalizer.input.RequestID, usageRepo.record.RequestID, requestID)
	}
}

func TestChatProxyHandlerFinalizesCancelledTransportWithDurableContext(t *testing.T) {
	upstream := &fakeChatUpstream{err: context.Canceled}
	capture := &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "request-cancelled"}}
	finalizer := &fakeResponseFinalizer{}
	handler := newTestChatProxyHandler(t, upstream, capture, finalizer, &fakeUsageRepository{}, nil)
	recorder := httptest.NewRecorder()
	request := proxyRequest(t, []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hello"}]}`), "request-cancelled")
	ctx, cancel := context.WithCancel(request.Context())
	cancel()
	handler.ServeHTTP(recorder, request.WithContext(ctx))

	if finalizer.finalizeContextErr != nil {
		t.Fatalf("finalization context error = %v, want detached persistence context", finalizer.finalizeContextErr)
	}
	if finalizer.input.CaptureStatus != audit.CaptureStatusIncomplete || finalizer.input.Outcome != audit.AuditOutcomeCancelled || finalizer.input.ErrorCode != "CLIENT_DISCONNECTED" {
		t.Fatalf("finalization = %+v, want incomplete cancelled client disconnect", finalizer.input)
	}
}

func TestChatProxyHandlerGatesWhenUsagePersistenceFails(t *testing.T) {
	responseBody := []byte(`{"id":"chatcmpl-usage-fail","model":"gpt-test","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}`)
	upstream := &fakeChatUpstream{response: &NewAPIResponse{StatusCode: http.StatusOK, ContentType: "application/json", Body: io.NopCloser(bytes.NewReader(responseBody))}}
	finalizer := &fakeResponseFinalizer{}
	usageRepo := &fakeUsageRepository{err: errors.New("synthetic usage persistence failure")}
	handler := newTestChatProxyHandler(t, upstream, &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "request-usage-fail"}}, finalizer, usageRepo, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, proxyRequest(t, []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hello"}]}`), "request-usage-fail"))

	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), `"code":"AUDIT_UNAVAILABLE"`) {
		t.Fatalf("response = (%d, %s), want audit unavailable", recorder.Code, recorder.Body.String())
	}
	if finalizer.postDispatchFailures != 1 || finalizer.postDispatchAuditID != "generated-id" || finalizer.postDispatchRequestID != "request-usage-fail" {
		t.Fatalf("post-dispatch failure = (%d, %s, %s), want one linked gate event", finalizer.postDispatchFailures, finalizer.postDispatchAuditID, finalizer.postDispatchRequestID)
	}
}

func TestChatProxyHandlerRelaysToolDataWithoutExecution(t *testing.T) {
	body := []byte(`{"model":"gpt-test","messages":[{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"url\":\"http://127.0.0.1/private\",\"command\":\"whoami\"}"}}]},{"role":"tool","tool_call_id":"call_1","content":"opaque result"}],"tools":[{"type":"function","function":{"name":"lookup","description":"Return text","parameters":{"type":"object","properties":{"url":{"type":"string"}},"required":["url"]}}}],"tool_choice":{"type":"function","function":{"name":"lookup"}}}`)
	responseBody := []byte(`{"id":"chatcmpl-tool","model":"gpt-test","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_2","type":"function","function":{"name":"lookup","arguments":"{\"url\":\"http://169.254.169.254/latest\"}"}}]},"finish_reason":"tool_calls"}]}`)
	upstream := &fakeChatUpstream{response: &NewAPIResponse{StatusCode: http.StatusOK, ContentType: "application/json", Body: io.NopCloser(bytes.NewReader(responseBody))}}
	capture := &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "request-tool"}}
	finalizer := &fakeResponseFinalizer{}
	handler := newTestChatProxyHandler(t, upstream, capture, finalizer, &fakeUsageRepository{}, nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, proxyRequest(t, body, "request-tool"))

	if recorder.Code != http.StatusOK || !bytes.Equal(recorder.Body.Bytes(), responseBody) {
		t.Fatalf("response = (%d, %s), want exact opaque tool response", recorder.Code, recorder.Body.String())
	}
	if upstream.calls != 1 || !bytes.Equal(upstream.body, body) || !bytes.Equal(capture.input.ValidatedRequestJSON, body) {
		t.Fatalf("tool request was not relayed and captured exactly")
	}
	if !bytes.Equal(finalizer.input.ResponseJSON, responseBody) {
		t.Fatalf("tool response was not captured exactly")
	}
}

func TestChatProxyHandlerForwardsStructuredUpstreamErrorsWithoutSuccessOutcome(t *testing.T) {
	errorBody := []byte(`{"error":{"message":"model failed","type":"server_error","code":"MODEL_FAILED"}}`)
	upstream := &fakeChatUpstream{response: &NewAPIResponse{StatusCode: 503, ContentType: "application/json", RequestID: "upstream-error", Body: io.NopCloser(bytes.NewReader(errorBody))}}
	capture := &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "request-2"}}
	finalizer := &fakeResponseFinalizer{}
	usageRepo := &fakeUsageRepository{}
	handler := newTestChatProxyHandler(t, upstream, capture, finalizer, usageRepo, nil)
	recorder := httptest.NewRecorder()
	req := proxyRequest(t, []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hello"}]}`), "request-2")
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusServiceUnavailable || !bytes.Equal(recorder.Body.Bytes(), errorBody) {
		t.Fatalf("response = (%d, %s), want upstream 503 body", recorder.Code, recorder.Body.String())
	}
	if finalizer.input.Outcome != audit.AuditOutcomeUpstreamError || finalizer.input.ErrorCode != "MODEL_FAILED" || finalizer.input.UpstreamHTTPStatus == nil || *finalizer.input.UpstreamHTTPStatus != 503 {
		t.Fatalf("final audit input = %+v, want upstream error/503", finalizer.input)
	}
	if usageRepo.record.Outcome != usage.OutcomeUpstreamError || usageRepo.record.AuditID != "generated-id" {
		t.Fatalf("usage record = %+v, want upstream error linked to audit", usageRepo.record)
	}
}

func TestChatProxyHandlerRejectsMalformedSuccessfulOutput(t *testing.T) {
	upstream := &fakeChatUpstream{response: &NewAPIResponse{StatusCode: 200, ContentType: "application/json", Body: io.NopCloser(strings.NewReader(`{"id":"missing-choices"}`))}}
	capture := &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "request-3"}}
	finalizer := &fakeResponseFinalizer{}
	handler := newTestChatProxyHandler(t, upstream, capture, finalizer, &fakeUsageRepository{}, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, proxyRequest(t, []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hello"}]}`), "request-3"))

	if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), `"code":"UPSTREAM_ERROR"`) {
		t.Fatalf("response = (%d, %s), want safe 502 upstream error", recorder.Code, recorder.Body.String())
	}
	if finalizer.input.Outcome != audit.AuditOutcomeUpstreamError || finalizer.input.ErrorCode != string(httpapi.CodeUpstreamError) {
		t.Fatalf("final audit input = %+v, want malformed upstream error", finalizer.input)
	}
}

func TestChatProxyHandlerRecordsEmptySuccessfulOutputAsIncomplete(t *testing.T) {
	upstream := &fakeChatUpstream{response: &NewAPIResponse{StatusCode: 200, ContentType: "application/json", Body: io.NopCloser(strings.NewReader(""))}}
	capture := &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "request-empty"}}
	finalizer := &fakeResponseFinalizer{}
	handler := newTestChatProxyHandler(t, upstream, capture, finalizer, &fakeUsageRepository{}, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, proxyRequest(t, []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hello"}]}`), "request-empty"))

	if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), `"code":"UPSTREAM_ERROR"`) {
		t.Fatalf("response = (%d, %s), want safe 502 upstream error", recorder.Code, recorder.Body.String())
	}
	if finalizer.input.CaptureStatus != audit.CaptureStatusIncomplete || finalizer.input.Outcome != audit.AuditOutcomeLocalError || len(finalizer.input.ResponseJSON) != 0 {
		t.Fatalf("final audit input = %+v, want empty incomplete local error", finalizer.input)
	}
}

func TestChatProxyHandlerMapsTimeoutAndUnavailable(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		code httpapi.ErrorCode
		want int
	}{
		{name: "timeout", err: ErrUpstreamTimeout, code: httpapi.CodeUpstreamTimeout, want: http.StatusGatewayTimeout},
		{name: "unavailable", err: ErrUpstreamUnavailable, code: httpapi.CodeUpstreamUnavailable, want: http.StatusBadGateway},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream := &fakeChatUpstream{err: test.err}
			capture := &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "request-4"}}
			finalizer := &fakeResponseFinalizer{}
			handler := newTestChatProxyHandler(t, upstream, capture, finalizer, &fakeUsageRepository{}, nil)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, proxyRequest(t, []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hello"}]}`), "request-4"))
			if recorder.Code != test.want || !strings.Contains(recorder.Body.String(), `"code":"`+string(test.code)+`"`) {
				t.Fatalf("response = (%d, %s), want %d/%s", recorder.Code, recorder.Body.String(), test.want, test.code)
			}
			if finalizer.input.Outcome != audit.AuditOutcomeLocalError || finalizer.input.CaptureStatus != audit.CaptureStatusIncomplete {
				t.Fatalf("final audit input = %+v, want incomplete local error", finalizer.input)
			}
		})
	}
}

func TestChatProxyHandlerFailsClosedWhenTransportOutcomeCannotBePersisted(t *testing.T) {
	upstream := &fakeChatUpstream{err: ErrUpstreamUnavailable}
	capture := &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "request-persist-fail"}}
	finalizer := &fakeResponseFinalizer{err: errors.New("synthetic finalization failure")}
	handler := newTestChatProxyHandler(t, upstream, capture, finalizer, &fakeUsageRepository{}, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, proxyRequest(t, []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hello"}]}`), "request-persist-fail"))

	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), `"code":"AUDIT_UNAVAILABLE"`) {
		t.Fatalf("response = (%d, %s), want fail-closed audit unavailable", recorder.Code, recorder.Body.String())
	}
}

func TestChatProxyHandlerDeniesModelBeforeCaptureAndUpstream(t *testing.T) {
	upstream := &fakeChatUpstream{}
	capture := &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "audit-denied", RequestID: "request-denied"}}
	handler := newTestChatProxyHandler(t, upstream, capture, &fakeResponseFinalizer{}, &fakeUsageRepository{}, fakeModelPolicy{err: policy.ErrModelNotAllowed})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, proxyRequest(t, []byte(`{"model":"blocked","messages":[{"role":"user","content":"hello"}]}`), "request-denied"))

	if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), `"code":"MODEL_NOT_ALLOWED"`) {
		t.Fatalf("response = (%d, %s), want 403 model denial", recorder.Code, recorder.Body.String())
	}
	if upstream.calls != 0 || capture.calls != 0 {
		t.Fatalf("denial calls = upstream %d, capture %d, want zero", upstream.calls, capture.calls)
	}
}

type fakeChatUpstream struct {
	response       *NewAPIResponse
	streamResponse *NewAPIResponse
	err            error
	calls          int
	body           []byte
	streamCalls    int
	ctx            context.Context
}

func (fake *fakeChatUpstream) CreateChatCompletion(ctx context.Context, body []byte, stream bool) (*NewAPIResponse, error) {
	fake.calls++
	fake.body = bytes.Clone(body)
	if stream {
		fake.streamCalls++
		fake.ctx = ctx
		if fake.streamResponse != nil {
			return fake.streamResponse, nil
		}
		return nil, errors.New("stream unexpectedly requested")
	}
	if fake.err != nil {
		return nil, fake.err
	}
	return fake.response, nil
}

type fakeInitialCapture struct {
	input   audit.InitialCaptureInput
	receipt audit.CaptureReceipt
	err     error
	calls   int
}

func (fake *fakeInitialCapture) CaptureValidatedRequest(_ context.Context, input audit.InitialCaptureInput) (audit.CaptureReceipt, error) {
	fake.calls++
	fake.input = input
	if fake.err != nil {
		return audit.CaptureReceipt{}, fake.err
	}
	return fake.receipt, nil
}

type fakeResponseFinalizer struct {
	input                 audit.ResponseFinalizationInput
	err                   error
	finalizeContextErr    error
	postDispatchFailures  int
	postDispatchAuditID   string
	postDispatchRequestID string
}

func (fake *fakeResponseFinalizer) FinalizeResponse(ctx context.Context, input audit.ResponseFinalizationInput) (audit.FinalizationReceipt, error) {
	fake.input = input
	fake.finalizeContextErr = ctx.Err()
	if fake.err != nil {
		return audit.FinalizationReceipt{}, fake.err
	}
	return audit.FinalizationReceipt{AuditID: input.AuditID, RequestID: input.RequestID, CaptureStatus: input.CaptureStatus, Outcome: input.Outcome}, nil
}

func (fake *fakeResponseFinalizer) MarkPostDispatchFailure(_ context.Context, auditID, requestID, _ string, _ time.Time) error {
	fake.postDispatchFailures++
	fake.postDispatchAuditID = auditID
	fake.postDispatchRequestID = requestID
	return nil
}

type fakeUsageRepository struct {
	record usage.Record
	err    error
}

func (fake *fakeUsageRepository) CreateUsageRecord(_ context.Context, record usage.Record) error {
	fake.record = record
	return fake.err
}

type fakeModelPolicy struct{ err error }

func (fake fakeModelPolicy) Authorize(context.Context, string) error { return fake.err }

func newTestChatProxyHandler(t *testing.T, upstream ChatUpstream, capture InitialCapture, finalizer ResponseFinalizer, usageRepo usage.Repository, policy ModelPolicy) *ChatProxyHandler {
	t.Helper()
	if policy == nil {
		policy = fakeModelPolicy{}
	}
	handler, err := NewChatProxyHandler(ChatProxyConfig{Upstream: upstream, Capture: capture, Finalizer: finalizer, Usage: usageRepo, Policy: policy, Limiter: &testReservationLimiter{}, Now: func() time.Time { return time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC) }, NewID: func() (string, error) { return "generated-id", nil }, Retention: 24 * time.Hour, ResponseLimit: 4 * 1024 * 1024})
	if err != nil {
		t.Fatalf("NewChatProxyHandler() error = %v", err)
	}
	return handler
}

func proxyRequest(t *testing.T, body []byte, requestID string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req.WithContext(WithChatCaller(req.Context(), ChatCaller{RequestID: requestID, KeyID: "key-1", OwnerKind: audit.OwnerKindPersonal, IdentityID: "employee-1", TeamID: "team-1", TrafficOwner: TrafficOwner{Kind: TrafficOwnerEmployee, ID: "employee-1"}}))
}

type testReservationLimiter struct{}

func (*testReservationLimiter) Acquire(context.Context, TrafficOwner) (Reservation, error) {
	return testReservation{}, nil
}

type testReservation struct{}

func (testReservation) Release() {}
