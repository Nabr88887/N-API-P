package gateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"n-api-p/internal/audit"
	"n-api-p/internal/httpapi"
	"n-api-p/internal/usage"
)

func TestChatProxyHandlerForwardsValidatedSSEAndFinalizesLogicalResponse(t *testing.T) {
	stream := "data: {\"id\":\"sse-1\",\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hello\"}}]}\n\n" +
		"data: {\"id\":\"sse-1\",\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" world\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":2,\"total_tokens\":4}}\n\n" +
		"data: [DONE]\n\n"
	upstream := &fakeChatUpstream{streamResponse: &NewAPIResponse{StatusCode: http.StatusOK, ContentType: "text/event-stream", RequestID: "upstream-sse", Body: io.NopCloser(strings.NewReader(stream))}}
	capture := &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "stream-request"}}
	finalizer := &fakeResponseFinalizer{}
	usageRepo := &fakeUsageRepository{}
	handler := newTestChatProxyHandler(t, upstream, capture, finalizer, usageRepo, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, streamProxyRequest(t, "stream-request"))

	if recorder.Code != http.StatusOK || recorder.Body.String() != stream || recorder.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("response = (%d, %q, %q), want exact SSE 200", recorder.Code, recorder.Body.String(), recorder.Header().Get("Content-Type"))
	}
	if upstream.streamCalls != 1 || !bytes.Contains(upstream.body, []byte(`"stream":true`)) {
		t.Fatalf("upstream stream call/body = %d/%s", upstream.streamCalls, upstream.body)
	}
	if finalizer.input.CaptureStatus != audit.CaptureStatusComplete || finalizer.input.Outcome != audit.AuditOutcomeSuccess || finalizer.input.UpstreamRequestID != "upstream-sse" || finalizer.input.FinishReason != "stop" || !bytes.Contains(finalizer.input.ResponseJSON, []byte(`"content":"hello world"`)) {
		t.Fatalf("finalization = %+v", finalizer.input)
	}
	if usageRepo.record.Outcome != usage.OutcomeSuccess || usageRepo.record.Usage == nil || usageRepo.record.Usage.TotalTokens != 4 {
		t.Fatalf("usage = %+v", usageRepo.record)
	}
}

func TestChatProxyHandlerGatesWhenSSEUsagePersistenceFails(t *testing.T) {
	stream := "data: {\"id\":\"sse-usage-fail\",\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hello\"},\"finish_reason\":\"stop\"}]}\n\n" +
		"data: [DONE]\n\n"
	upstream := &fakeChatUpstream{streamResponse: &NewAPIResponse{StatusCode: http.StatusOK, ContentType: "text/event-stream", Body: io.NopCloser(strings.NewReader(stream))}}
	finalizer := &fakeResponseFinalizer{}
	usageRepo := &fakeUsageRepository{err: errors.New("synthetic usage persistence failure")}
	handler := newTestChatProxyHandler(t, upstream, &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "stream-usage-fail"}}, finalizer, usageRepo, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, streamProxyRequest(t, "stream-usage-fail"))

	if recorder.Code != http.StatusOK || recorder.Body.String() != stream {
		t.Fatalf("response = (%d, %q), want completed SSE response", recorder.Code, recorder.Body.String())
	}
	if finalizer.postDispatchFailures != 1 || finalizer.postDispatchAuditID != "generated-id" {
		t.Fatalf("post-dispatch failure = (%d, %s), want one linked gate event", finalizer.postDispatchFailures, finalizer.postDispatchAuditID)
	}
}

func TestChatProxyHandlerStopsForwardingMalformedSSEAndRecordsIncomplete(t *testing.T) {
	stream := "data: {\"id\":\"sse-2\",\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"safe\"}}]}\n\n" + "data: {not-json}\n\n"
	upstream := &fakeChatUpstream{streamResponse: &NewAPIResponse{StatusCode: http.StatusOK, ContentType: "text/event-stream", Body: io.NopCloser(strings.NewReader(stream))}}
	finalizer := &fakeResponseFinalizer{}
	handler := newTestChatProxyHandler(t, upstream, &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "stream-malformed"}}, finalizer, &fakeUsageRepository{}, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, streamProxyRequest(t, "stream-malformed"))
	if recorder.Body.String() != strings.Split(stream, "data: {not-json}")[0] || finalizer.input.CaptureStatus != audit.CaptureStatusIncomplete || finalizer.input.Outcome != audit.AuditOutcomeLocalError || finalizer.input.ErrorCode != "UPSTREAM_ERROR" {
		t.Fatalf("response/finalization = %q/%+v", recorder.Body.String(), finalizer.input)
	}
}

func TestChatProxyHandlerPreservesStructuredUpstreamErrorForStreamRequest(t *testing.T) {
	errorBody := `{"error":{"message":"busy","type":"server_error","code":"UPSTREAM_BUSY"}}`
	upstream := &fakeChatUpstream{streamResponse: &NewAPIResponse{StatusCode: http.StatusServiceUnavailable, ContentType: "application/json", RequestID: "upstream-busy", Body: io.NopCloser(strings.NewReader(errorBody))}}
	finalizer := &fakeResponseFinalizer{}
	handler := newTestChatProxyHandler(t, upstream, &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "stream-upstream-error"}}, finalizer, &fakeUsageRepository{}, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, streamProxyRequest(t, "stream-upstream-error"))
	if recorder.Code != http.StatusServiceUnavailable || recorder.Body.String() != errorBody || finalizer.input.CaptureStatus != audit.CaptureStatusComplete || finalizer.input.Outcome != audit.AuditOutcomeUpstreamError || finalizer.input.ErrorCode != "UPSTREAM_BUSY" {
		t.Fatalf("response/finalization = %d/%q/%+v", recorder.Code, recorder.Body.String(), finalizer.input)
	}
}

func TestChatProxyHandlerCapturesMalformedUpstreamErrorForStreamRequest(t *testing.T) {
	errorBody := []byte(`not-json`)
	upstream := &fakeChatUpstream{streamResponse: &NewAPIResponse{StatusCode: http.StatusBadGateway, ContentType: "application/json", RequestID: "upstream-malformed", Body: io.NopCloser(bytes.NewReader(errorBody))}}
	finalizer := &fakeResponseFinalizer{}
	handler := newTestChatProxyHandler(t, upstream, &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "stream-malformed-error"}}, finalizer, &fakeUsageRepository{}, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, streamProxyRequest(t, "stream-malformed-error"))

	if recorder.Code != http.StatusBadGateway || finalizer.input.CaptureStatus != audit.CaptureStatusComplete || finalizer.input.Outcome != audit.AuditOutcomeUpstreamError || finalizer.input.ErrorCode != string(httpapi.CodeUpstreamError) || !bytes.Equal(finalizer.input.ResponseJSON, errorBody) {
		t.Fatalf("response/finalization = %d/%+v, want complete captured upstream error", recorder.Code, finalizer.input)
	}
}

func TestChatProxyHandlerTruncatesOversizedUpstreamErrorForStreamRequest(t *testing.T) {
	errorBody := bytes.Repeat([]byte("x"), 4*1024*1024+1)
	upstream := &fakeChatUpstream{streamResponse: &NewAPIResponse{StatusCode: http.StatusBadGateway, ContentType: "application/json", RequestID: "upstream-oversized", Body: io.NopCloser(bytes.NewReader(errorBody))}}
	finalizer := &fakeResponseFinalizer{}
	handler := newTestChatProxyHandler(t, upstream, &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "stream-oversized-error"}}, finalizer, &fakeUsageRepository{}, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, streamProxyRequest(t, "stream-oversized-error"))

	if recorder.Code != http.StatusBadGateway || finalizer.input.CaptureStatus != audit.CaptureStatusTruncated || finalizer.input.Outcome != audit.AuditOutcomeLocalError || finalizer.input.ErrorCode != string(httpapi.CodeUpstreamResponseTooLarge) || len(finalizer.input.ResponseJSON) != 4*1024*1024 || finalizer.input.ObservedResponseBytes != 4*1024*1024+1 {
		t.Fatalf("response/finalization = %d/%+v, want bounded truncated upstream error", recorder.Code, finalizer.input)
	}
}

func TestChatProxyHandlerCancelsUpstreamOnDownstreamDisconnect(t *testing.T) {
	stream := "data: {\"id\":\"sse-3\",\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"first\"}}]}\n\n" + "data: [DONE]\n\n"
	upstream := &fakeChatUpstream{streamResponse: &NewAPIResponse{StatusCode: http.StatusOK, ContentType: "text/event-stream", Body: io.NopCloser(strings.NewReader(stream))}}
	finalizer := &fakeResponseFinalizer{}
	handler := newTestChatProxyHandler(t, upstream, &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "stream-cancel"}}, finalizer, &fakeUsageRepository{}, nil)
	writer := &failingWriter{failAfter: 0}
	handler.ServeHTTP(writer, streamProxyRequest(t, "stream-cancel"))
	if upstream.ctx == nil || !errors.Is(upstream.ctx.Err(), context.Canceled) || finalizer.input.CaptureStatus != audit.CaptureStatusIncomplete || finalizer.input.Outcome != audit.AuditOutcomeCancelled {
		t.Fatalf("upstream context/finalization = %v/%+v", upstream.ctx, finalizer.input)
	}
}

func TestChatProxyHandlerHoldsLimiterReservationDuringBackpressure(t *testing.T) {
	stream := "data: {\"id\":\"sse-4\",\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"blocked\"}}]}\n\n" + "data: [DONE]\n\n"
	upstream := &fakeChatUpstream{streamResponse: &NewAPIResponse{StatusCode: http.StatusOK, ContentType: "text/event-stream", Body: io.NopCloser(strings.NewReader(stream))}}
	limiter := &trackingLimiter{}
	handler := newTestChatProxyHandlerWithLimiter(t, upstream, &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "stream-backpressure"}}, &fakeResponseFinalizer{}, &fakeUsageRepository{}, nil, limiter)
	writer := &blockingWriter{entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() { handler.ServeHTTP(writer, streamProxyRequest(t, "stream-backpressure")); close(done) }()
	<-writer.entered
	if limiter.released() != 0 {
		t.Fatal("limiter reservation released while downstream write was blocked")
	}
	close(writer.release)
	<-done
	if limiter.released() != 1 {
		t.Fatalf("limiter releases = %d, want one after stream termination", limiter.released())
	}
}

func streamProxyRequest(t *testing.T, requestID string) *http.Request {
	t.Helper()
	return proxyRequest(t, []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hello"}],"stream":true}`), requestID)
}

type failingWriter struct {
	header    http.Header
	failAfter int
	writes    int
}

func (w *failingWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (*failingWriter) WriteHeader(int) {}
func (w *failingWriter) Write([]byte) (int, error) {
	if w.writes >= w.failAfter {
		w.writes++
		return 0, io.ErrClosedPipe
	}
	w.writes++
	return 0, nil
}

type blockingWriter struct {
	header           http.Header
	entered, release chan struct{}
	once             sync.Once
}

func (w *blockingWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}
func (*blockingWriter) WriteHeader(int) {}
func (w *blockingWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return len(p), nil
}
func (*blockingWriter) Flush() {}

type trackingLimiter struct{ reservation trackingReservation }

func (l *trackingLimiter) Acquire(context.Context, TrafficOwner) (Reservation, error) {
	return &l.reservation, nil
}
func (l *trackingLimiter) released() int {
	l.reservation.mu.Lock()
	defer l.reservation.mu.Unlock()
	return l.reservation.count
}

type trackingReservation struct {
	mu    sync.Mutex
	count int
}

func (r *trackingReservation) Release() { r.mu.Lock(); r.count++; r.mu.Unlock() }

func newTestChatProxyHandlerWithLimiter(t *testing.T, upstream ChatUpstream, capture InitialCapture, finalizer ResponseFinalizer, usageRepo usage.Repository, policy ModelPolicy, limiter Limiter) *ChatProxyHandler {
	t.Helper()
	if policy == nil {
		policy = fakeModelPolicy{}
	}
	handler, err := NewChatProxyHandler(ChatProxyConfig{Upstream: upstream, Capture: capture, Finalizer: finalizer, Usage: usageRepo, Policy: policy, Limiter: limiter, Now: func() time.Time { return time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC) }, NewID: func() (string, error) { return "generated-id", nil }, Retention: 24 * time.Hour, ResponseLimit: 4 * 1024 * 1024})
	if err != nil {
		t.Fatalf("NewChatProxyHandler() error = %v", err)
	}
	return handler
}
