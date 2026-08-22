package healthcheck

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeUsesFixedLoopbackReadinessEndpoint(t *testing.T) {
	var requestedPath string
	server, port := newLoopbackServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestedPath = request.URL.Path
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := probe(net.JoinHostPort("example.invalid", port), time.Second); err != nil {
		t.Fatalf("probe fixed loopback endpoint: %v", err)
	}
	if requestedPath != "/health/ready" {
		t.Fatalf("requested path = %q, want /health/ready", requestedPath)
	}
}

func TestProbeRejectsRedirect(t *testing.T) {
	var redirectedRequests atomic.Int32
	server, port := newLoopbackServer(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/redirected" {
			redirectedRequests.Add(1)
			writer.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(writer, request, "/redirected", http.StatusFound)
	}))
	defer server.Close()

	if err := probe(":"+port, time.Second); err == nil {
		t.Fatal("probe redirect error = nil, want rejection")
	}
	if redirectedRequests.Load() != 0 {
		t.Fatalf("redirected requests = %d, want 0", redirectedRequests.Load())
	}
}

func TestProbeRejectsNonOKStatus(t *testing.T) {
	server, port := newLoopbackServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	if err := probe(":"+port, time.Second); err == nil {
		t.Fatal("probe 503 error = nil, want rejection")
	}
}

func TestProbeTimesOut(t *testing.T) {
	server, port := newLoopbackServer(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if err := probe(":"+port, 10*time.Millisecond); err == nil {
		t.Fatal("probe timeout error = nil, want rejection")
	}
}

func TestProbeRejectsInvalidListenAddresses(t *testing.T) {
	for _, listenAddress := range []string{"localhost", ":0", ":65536", ":http", "https://localhost:8080"} {
		t.Run(strings.ReplaceAll(listenAddress, "/", "_"), func(t *testing.T) {
			if err := probe(listenAddress, time.Second); err == nil {
				t.Fatalf("probe(%q) error = nil, want rejection", listenAddress)
			}
		})
	}
}

func newLoopbackServer(t *testing.T, handler http.Handler) (*httptest.Server, string) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on loopback: %v", err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		server.Close()
		t.Fatalf("read loopback port: %v", err)
	}
	return server, port
}
