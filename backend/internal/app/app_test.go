package app

import (
	"context"
	"errors"
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
