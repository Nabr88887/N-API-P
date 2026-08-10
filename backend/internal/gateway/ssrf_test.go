package gateway

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"n-api-p/internal/audit"
)

func TestChatProxyTreatsLoopbackPrivateAndMetadataURLsAsOpaqueText(t *testing.T) {
	var httpCalls atomic.Int64
	var dnsCalls atomic.Int64
	previousTransport := http.DefaultTransport
	previousResolver := net.DefaultResolver
	http.DefaultTransport = ssrfSpyRoundTripper{calls: &httpCalls}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			dnsCalls.Add(1)
			return nil, errors.New("unexpected DNS lookup in SSRF proof")
		},
	}
	t.Cleanup(func() {
		http.DefaultTransport = previousTransport
		net.DefaultResolver = previousResolver
	})

	body := []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"opaque URLs: http://127.0.0.1/private, http://10.0.0.1/internal, http://169.254.169.254/latest/meta-data, and http://metadata.internal.test/"}]}`)
	responseBody := []byte(`{"id":"chatcmpl-ssrf","model":"gpt-test","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`)
	upstream := &fakeChatUpstream{response: &NewAPIResponse{StatusCode: http.StatusOK, ContentType: "application/json", Body: io.NopCloser(bytes.NewReader(responseBody))}}
	capture := &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "request-ssrf"}}
	handler := newTestChatProxyHandler(t, upstream, capture, &fakeResponseFinalizer{}, &fakeUsageRepository{}, nil)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, proxyRequest(t, body, "request-ssrf"))

	if recorder.Code != http.StatusOK || !bytes.Equal(recorder.Body.Bytes(), responseBody) {
		t.Fatalf("response = (%d, %s), want exact successful relay", recorder.Code, recorder.Body.String())
	}
	if upstream.calls != 1 || !bytes.Equal(upstream.body, body) {
		t.Fatalf("upstream calls/body = %d/%s, want one opaque relay", upstream.calls, upstream.body)
	}
	if got := httpCalls.Load(); got != 0 {
		t.Fatalf("unexpected HTTP activity from accepted URL text: %d calls", got)
	}
	if got := dnsCalls.Load(); got != 0 {
		t.Fatalf("unexpected DNS activity from accepted URL text: %d lookups", got)
	}
}

type ssrfSpyRoundTripper struct {
	calls *atomic.Int64
}

func (spy ssrfSpyRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	spy.calls.Add(1)
	return nil, errors.New("unexpected HTTP request in SSRF proof")
}
