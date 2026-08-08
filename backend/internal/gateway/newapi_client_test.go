package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNewAPIClientUsesVerifiedBoundedTransport(t *testing.T) {
	baseURL := mustURL(t, "https://newapi.internal/base")
	client, err := NewClient(NewAPIClientConfig{
		BaseURL:               baseURL,
		Token:                 []byte("synthetic-upstream-token"),
		ConnectTimeout:        2 * time.Second,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 4 * time.Second,
		IdleConnTimeout:       5 * time.Second,
		TotalTimeout:          10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", client.httpClient.Transport)
	}
	if transport.Proxy != nil || transport.DialContext == nil {
		t.Fatal("transport must use direct connections with a bounded dialer")
	}
	if transport.TLSHandshakeTimeout != 3*time.Second || transport.ResponseHeaderTimeout != 4*time.Second || transport.IdleConnTimeout != 5*time.Second {
		t.Fatalf("transport timeouts = (%s, %s, %s), want configured values", transport.TLSHandshakeTimeout, transport.ResponseHeaderTimeout, transport.IdleConnTimeout)
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion != tls.VersionTLS12 || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatalf("TLS config = %+v, want verified TLS 1.2+", transport.TLSClientConfig)
	}
	if client.httpClient.Timeout != 10*time.Second {
		t.Fatalf("client total timeout = %s, want 10s", client.httpClient.Timeout)
	}
	if client.httpClient.CheckRedirect == nil {
		t.Fatal("redirect policy is nil")
	}
	if err := client.httpClient.CheckRedirect(&http.Request{}, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("redirect policy error = %v, want http.ErrUseLastResponse", err)
	}
}

func TestNewAPIClientReplacesAuthorizationAndReturnsOnlySafeMetadata(t *testing.T) {
	client := newTestClient(t, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.Path != "/base/v1/models" {
			t.Fatalf("request = %s %s, want GET /base/v1/models", request.Method, request.URL)
		}
		if request.Header.Get("Authorization") != "Bearer synthetic-upstream-token" {
			t.Fatalf("Authorization = %q, want server token", request.Header.Get("Authorization"))
		}
		if request.Header.Get("Accept") != "application/json" || request.Header.Get("Cookie") != "" {
			t.Fatalf("request headers = %#v, want safe model headers only", request.Header)
		}
		return response(200, "application/json; charset=utf-8", `{"object":"list","data":[]}`, map[string]string{
			"X-Request-ID":  "upstream-123",
			"Set-Cookie":    "secret-cookie=do-not-expose",
			"Authorization": "Bearer response-secret",
		}), nil
	})

	result, err := client.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels() error = %v", err)
	}
	defer result.Body.Close()
	if result.StatusCode != http.StatusOK || result.ContentType != "application/json" || result.RequestID != "upstream-123" {
		t.Fatalf("response metadata = %+v", result)
	}
}

func TestNewAPIClientChatUsesFixedPathAndValidatedMediaType(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
	client := newTestClient(t, func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.Path != "/base/v1/chat/completions" {
			t.Fatalf("request = %s %s, want POST /base/v1/chat/completions", request.Method, request.URL)
		}
		if request.Header.Get("Authorization") != "Bearer synthetic-upstream-token" || request.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("request headers = %#v, want server authorization and JSON content type", request.Header)
		}
		got, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatalf("request body read error = %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Fatalf("request body = %s, want %s", got, body)
		}
		return response(200, "text/event-stream", "data: {}\n\n", nil), nil
	})

	result, err := client.CreateChatCompletion(context.Background(), body, true)
	if err != nil {
		t.Fatalf("CreateChatCompletion() error = %v", err)
	}
	defer result.Body.Close()
	if result.ContentType != "text/event-stream" {
		t.Fatalf("ContentType = %q, want text/event-stream", result.ContentType)
	}
}

func TestNewAPIClientRejectsInvalidSuccessMediaTypeAndClosesBody(t *testing.T) {
	closed := &trackingReadCloser{Reader: strings.NewReader("not-json")}
	client := newTestClient(t, func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Content-Type": []string{"text/plain", "application/json"}},
			Body:       closed,
		}, nil
	})

	_, err := client.ListModels(context.Background())
	if !errors.Is(err, ErrInvalidUpstreamResponse) {
		t.Fatalf("ListModels() error = %v, want ErrInvalidUpstreamResponse", err)
	}
	if !closed.closed {
		t.Fatal("invalid response body was not closed")
	}
}

func TestNewAPIClientRejectsRedirects(t *testing.T) {
	client := newTestClient(t, func(*http.Request) (*http.Response, error) {
		return response(http.StatusFound, "text/html", "redirect", map[string]string{"Location": "https://other.internal"}), nil
	})

	_, err := client.ListModels(context.Background())
	if !errors.Is(err, ErrInvalidUpstreamResponse) {
		t.Fatalf("ListModels() error = %v, want ErrInvalidUpstreamResponse", err)
	}
}

func TestNewAPIClientRejectsUntrustedTLSCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("request reached server with an untrusted certificate")
	}))
	defer server.Close()

	client, err := NewClient(NewAPIClientConfig{
		BaseURL: mustURL(t, server.URL),
		Token:   []byte("synthetic-upstream-token"),
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	if _, err := client.ListModels(context.Background()); !errors.Is(err, ErrUpstreamUnavailable) {
		t.Fatalf("ListModels() error = %v, want ErrUpstreamUnavailable", err)
	}
}

func TestNewAPIClientReturnsNonSuccessResponsesForHandlerValidation(t *testing.T) {
	client := newTestClient(t, func(*http.Request) (*http.Response, error) {
		return response(http.StatusBadGateway, "application/json", `{"error":{"code":"UPSTREAM_ERROR"}}`, nil), nil
	})

	result, err := client.ListModels(context.Background())
	if err != nil {
		t.Fatalf("ListModels() error = %v, want response for handler", err)
	}
	defer result.Body.Close()
	if result.StatusCode != http.StatusBadGateway || result.ContentType != "application/json" {
		t.Fatalf("response = %+v, want status/body metadata", result)
	}
}

func TestNewAPIClientPropagatesCancellationAndMapsTimeout(t *testing.T) {
	client := newTestClient(t, func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.ListModels(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("ListModels() cancellation error = %v, want context.Canceled", err)
	}

	client.roundTripper = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, timeoutTransportError{}
	})
	if _, err := client.ListModels(context.Background()); !errors.Is(err, ErrUpstreamTimeout) {
		t.Fatalf("ListModels() timeout error = %v, want ErrUpstreamTimeout", err)
	}
}

func TestNewAPIClientRejectsInvalidConfigurationWithoutEchoingSecrets(t *testing.T) {
	for _, test := range []struct {
		name  string
		base  string
		token []byte
	}{
		{name: "insecure URL", base: "http://newapi.internal", token: []byte("synthetic-token")},
		{name: "query URL", base: "https://newapi.internal?secret=query", token: []byte("synthetic-token")},
		{name: "empty token", base: "https://newapi.internal", token: nil},
		{name: "header control", base: "https://newapi.internal", token: []byte("synthetic\ntoken")},
	} {
		t.Run(test.name, func(t *testing.T) {
			baseURL := mustURL(t, test.base)
			_, err := NewClient(NewAPIClientConfig{BaseURL: baseURL, Token: test.token})
			if err == nil {
				t.Fatal("NewClient() error = nil, want configuration error")
			}
			if (len(test.token) > 0 && strings.Contains(err.Error(), string(test.token))) || strings.Contains(err.Error(), test.base) {
				t.Fatalf("configuration error leaks input: %q", err)
			}
		})
	}
}

func newTestClient(t *testing.T, roundTripper roundTripperFunc) *NewAPIClient {
	t.Helper()
	client, err := NewClient(NewAPIClientConfig{
		BaseURL: mustURL(t, "https://newapi.internal/base"),
		Token:   []byte("synthetic-upstream-token"),
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	client.roundTripper = roundTripper
	return client
}

func mustURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatalf("url.Parse(%q) error = %v", value, err)
	}
	return parsed
}

func response(status int, contentType, body string, headers map[string]string) *http.Response {
	header := make(http.Header)
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	for key, value := range headers {
		header.Set(key, value)
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type timeoutTransportError struct{}

func (timeoutTransportError) Error() string   { return "synthetic timeout" }
func (timeoutTransportError) Timeout() bool   { return true }
func (timeoutTransportError) Temporary() bool { return true }

type trackingReadCloser struct {
	io.Reader
	closed bool
}

func (reader *trackingReadCloser) Close() error {
	reader.closed = true
	return nil
}
