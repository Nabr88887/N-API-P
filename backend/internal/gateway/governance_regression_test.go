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
	"n-api-p/internal/usage"
)

func TestChatProxyReadsCurrentRetentionForEachCapturedRequest(t *testing.T) {
	responseBody := []byte(`{"id":"chatcmpl-retention","model":"gpt-test","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	upstream := &fakeChatUpstream{response: &NewAPIResponse{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(responseBody))}}
	capture := &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "retention-request"}}
	handler := newTestChatProxyHandler(t, upstream, capture, &fakeResponseFinalizer{}, &fakeUsageRepository{}, nil)
	handler.retentionReader = func(context.Context) (time.Duration, error) { return 3 * 24 * time.Hour, nil }

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, proxyRequest(t, []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hello"}]}`), "retention-request"))

	if recorder.Code != http.StatusOK || !capture.input.ExpiresAt.Equal(capture.input.CreatedAt.Add(3*24*time.Hour)) {
		t.Fatalf("response/expiry = %d/%v, want current three-day policy", recorder.Code, capture.input.ExpiresAt)
	}
}

func TestChatProxyFailsClosedWhenCurrentRetentionIsUnavailable(t *testing.T) {
	upstream := &fakeChatUpstream{}
	capture := &fakeInitialCapture{}
	handler := newTestChatProxyHandler(t, upstream, capture, &fakeResponseFinalizer{}, &fakeUsageRepository{}, nil)
	handler.retentionReader = func(context.Context) (time.Duration, error) { return 0, errors.New("policy unavailable") }
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, proxyRequest(t, []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hello"}]}`), "retention-failure"))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), `"code":"AUDIT_UNAVAILABLE"`) || capture.calls != 0 || upstream.calls != 0 {
		t.Fatalf("response/calls = %d/%d/%d/%s, want pre-dispatch audit failure", recorder.Code, capture.calls, upstream.calls, recorder.Body.String())
	}
}

func TestChatProxyBindsAuthorizedPriceSnapshotToUsage(t *testing.T) {
	responseBody := []byte(`{"id":"chatcmpl-price","model":"gpt-test","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`)
	upstream := &fakeChatUpstream{response: &NewAPIResponse{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(responseBody))}}
	usageRepository := &fakeUsageRepository{}
	handler := newTestChatProxyHandler(t, upstream, &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "price-request"}}, &fakeResponseFinalizer{}, usageRepository, nil)
	handler.priceReader = func(context.Context, string) (*usage.PriceSnapshot, error) {
		return &usage.PriceSnapshot{Version: "price-v1", InputUnitPrice: "0.001", OutputUnitPrice: "0.003"}, nil
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, proxyRequest(t, []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hello"}]}`), "price-request"))
	if recorder.Code != http.StatusOK || usageRepository.record.Price == nil || usageRepository.record.Price.Version != "price-v1" || usageRepository.record.CalculatedAmount != "0.009000000000" {
		t.Fatalf("response/usage = %d/%+v, want bound price-v1 amount", recorder.Code, usageRepository.record)
	}
}

func TestChatProxyRejectsRequestWhenPriceSnapshotCannotBeRead(t *testing.T) {
	upstream := &fakeChatUpstream{}
	capture := &fakeInitialCapture{}
	handler := newTestChatProxyHandler(t, upstream, capture, &fakeResponseFinalizer{}, &fakeUsageRepository{}, nil)
	handler.priceReader = func(context.Context, string) (*usage.PriceSnapshot, error) {
		return nil, errors.New("price unavailable")
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, proxyRequest(t, []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hello"}]}`), "price-failure"))
	if recorder.Code != http.StatusInternalServerError || capture.calls != 0 || upstream.calls != 0 {
		t.Fatalf("response/calls = %d/%d/%d, want pre-dispatch policy failure", recorder.Code, capture.calls, upstream.calls)
	}
}

func TestStreamingChatUsesCurrentRetentionAndAuthorizedPrice(t *testing.T) {
	stream := "data: {\"id\":\"sse-price\",\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"ok\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":2,\"completion_tokens\":1,\"total_tokens\":3}}\n\n" + "data: [DONE]\n\n"
	upstream := &fakeChatUpstream{streamResponse: &NewAPIResponse{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(stream))}}
	capture := &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "stream-price"}}
	usageRepository := &fakeUsageRepository{}
	handler := newTestChatProxyHandler(t, upstream, capture, &fakeResponseFinalizer{}, usageRepository, nil)
	handler.retentionReader = func(context.Context) (time.Duration, error) { return 5 * 24 * time.Hour, nil }
	handler.priceReader = func(context.Context, string) (*usage.PriceSnapshot, error) {
		return &usage.PriceSnapshot{Version: "stream-v1", InputUnitPrice: "0.1", OutputUnitPrice: "0.2"}, nil
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, streamProxyRequest(t, "stream-price"))
	if recorder.Code != http.StatusOK || !capture.input.ExpiresAt.Equal(capture.input.CreatedAt.Add(5*24*time.Hour)) || usageRepository.record.Price == nil || usageRepository.record.Price.Version != "stream-v1" || usageRepository.record.CalculatedAmount != "0.400000000000" {
		t.Fatalf("response/capture/usage = %d/%+v/%+v", recorder.Code, capture.input, usageRepository.record)
	}
}

func TestStreamingChatFailsClosedBeforeOutputWhenFinalizationFails(t *testing.T) {
	upstream := &fakeChatUpstream{streamResponse: &NewAPIResponse{StatusCode: http.StatusBadGateway, Body: io.NopCloser(strings.NewReader(`not-json`))}}
	handler := newTestChatProxyHandler(t, upstream, &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "stream-finalization"}}, &fakeResponseFinalizer{err: errors.New("audit unavailable")}, &fakeUsageRepository{}, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, streamProxyRequest(t, "stream-finalization"))
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), `"code":"`+string(httpapi.CodeAuditUnavailable)+`"`) {
		t.Fatalf("response = %d/%s, want audit unavailable", recorder.Code, recorder.Body.String())
	}
}

func TestStreamingChatReportsFinalizationFailureAfterOutputInTrailer(t *testing.T) {
	stream := "data: {\"id\":\"sse-audit-failure\",\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"partial\"}}]}\n\n" + "data: {not-json}\n\n"
	upstream := &fakeChatUpstream{streamResponse: &NewAPIResponse{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(stream))}}
	handler := newTestChatProxyHandler(t, upstream, &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "stream-trailer"}}, &fakeResponseFinalizer{err: errors.New("audit unavailable")}, &fakeUsageRepository{}, nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, streamProxyRequest(t, "stream-trailer"))
	response := recorder.Result()
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Trailer.Get("X-N-API-P-Audit-Error") != string(httpapi.CodeAuditUnavailable) {
		t.Fatalf("response/trailer = %d/%q, want started stream with audit-unavailable trailer", response.StatusCode, response.Trailer.Get("X-N-API-P-Audit-Error"))
	}
}
