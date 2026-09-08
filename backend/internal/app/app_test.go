package app

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestApplicationStartRecoversAuditGateBeforeStartingJobs(t *testing.T) {
	openedAt := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	var gotContext context.Context
	var gotStaleBefore, gotOpenedAt time.Time
	application := &Application{
		now: func() time.Time { return openedAt },
		recoverAuditGate: func(ctx context.Context, staleBefore, recoveredAt time.Time) error {
			gotContext, gotStaleBefore, gotOpenedAt = ctx, staleBefore, recoveredAt
			return nil
		},
	}

	ctx := context.WithValue(context.Background(), struct{}{}, "startup")
	if err := application.Start(ctx); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if gotContext != ctx {
		t.Fatal("startup recovery did not receive the application context")
	}
	if !gotStaleBefore.Equal(openedAt) || !gotOpenedAt.Equal(openedAt) {
		t.Fatalf("recovery window = (%s, %s), want both %s", gotStaleBefore, gotOpenedAt, openedAt)
	}
}

func TestApplicationStartRejectsRecoveryFailure(t *testing.T) {
	recoveryErr := errors.New("synthetic startup persistence failure")
	application := &Application{
		now:              func() time.Time { return time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC) },
		recoverAuditGate: func(context.Context, time.Time, time.Time) error { return recoveryErr },
	}
	if err := application.Start(context.Background()); !errors.Is(err, recoveryErr) {
		t.Fatalf("Start() error = %v, want recovery failure", err)
	}
}

func TestApplicationStartRejectsMissingAuditRecovery(t *testing.T) {
	application := &Application{}
	if err := application.Start(context.Background()); !errors.Is(err, ErrInvalidApplication) {
		t.Fatalf("Start() error = %v, want ErrInvalidApplication", err)
	}
}

func TestTrustedOperatorRequestAllowsOnlyLoopbackPeers(t *testing.T) {
	authorize := trustedOperatorRequest(nil)
	tests := []struct {
		name       string
		remoteAddr string
		want       bool
	}{
		{name: "IPv4 loopback", remoteAddr: "127.0.0.1:1234", want: true},
		{name: "IPv6 loopback", remoteAddr: "[::1]:1234", want: true},
		{name: "private network", remoteAddr: "10.20.30.40:1234"},
		{name: "link local", remoteAddr: "169.254.1.2:1234"},
		{name: "invalid address", remoteAddr: "operator.internal:1234"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := &http.Request{RemoteAddr: test.remoteAddr}
			if got := authorize(request); got != test.want {
				t.Fatalf("authorize(%q) = %t, want %t", test.remoteAddr, got, test.want)
			}
		})
	}
	if authorize(nil) {
		t.Fatal("authorize(nil) = true, want false")
	}
}

func TestTrustedOperatorRequestAllowsOnlyConfiguredImmediateProxyPeer(t *testing.T) {
	_, trustedProxy, err := net.ParseCIDR("172.20.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	authorize := trustedOperatorRequest([]*net.IPNet{trustedProxy})

	trusted := &http.Request{RemoteAddr: "172.20.0.12:54321"}
	trusted.Header = http.Header{"X-Forwarded-For": []string{"203.0.113.8"}}
	if !authorize(trusted) {
		t.Fatal("configured immediate proxy peer was rejected")
	}

	spoofed := &http.Request{RemoteAddr: "10.20.30.40:54321"}
	spoofed.Header = http.Header{"X-Forwarded-For": []string{"127.0.0.1"}}
	if authorize(spoofed) {
		t.Fatal("untrusted immediate peer was authorized through X-Forwarded-For")
	}
}
