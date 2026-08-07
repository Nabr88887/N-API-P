package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

var limiterTestNow = time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)

func TestInProcessLimiterEnforcesGlobalConcurrency(t *testing.T) {
	limiter := newFixedTimeLimiter(&limiterTestNow)
	reservations := make([]Reservation, 0, 10)
	for index := 0; index < 10; index++ {
		reservations = append(reservations, mustAcquireLimiter(t, limiter, TrafficOwner{
			Kind: TrafficOwnerEmployee,
			ID:   fmt.Sprintf("employee-%d", index),
		}))
	}

	assertRateLimited(t, limiter, TrafficOwner{Kind: TrafficOwnerEmployee, ID: "employee-overflow"}, LimitRuleGlobalConcurrency, time.Second)
	reservations[0].Release()
	replacement := mustAcquireLimiter(t, limiter, TrafficOwner{Kind: TrafficOwnerEmployee, ID: "employee-replacement"})
	replacement.Release()
	for _, reservation := range reservations[1:] {
		reservation.Release()
	}
}

func TestInProcessLimiterAggregatesConcurrencyByStableOwner(t *testing.T) {
	for _, test := range []struct {
		name  string
		owner TrafficOwner
		limit int
		rule  LimitRule
	}{
		{name: "employee across personal keys", owner: TrafficOwner{Kind: TrafficOwnerEmployee, ID: "employee-1"}, limit: 3, rule: LimitRuleEmployeeConcurrency},
		{name: "service account across group keys", owner: TrafficOwner{Kind: TrafficOwnerServiceAccount, ID: "service-1"}, limit: 5, rule: LimitRuleServiceAccountConcurrency},
	} {
		t.Run(test.name, func(t *testing.T) {
			limiter := newFixedTimeLimiter(&limiterTestNow)
			reservations := make([]Reservation, 0, test.limit)
			for index := 0; index < test.limit; index++ {
				reservations = append(reservations, mustAcquireLimiter(t, limiter, test.owner))
			}
			assertRateLimited(t, limiter, test.owner, test.rule, time.Second)
			reservations[0].Release()
			replacement := mustAcquireLimiter(t, limiter, test.owner)
			replacement.Release()
			for _, reservation := range reservations[1:] {
				reservation.Release()
			}
		})
	}
}

func TestInProcessLimiterRefillsBoundedRPMBucketsUniformly(t *testing.T) {
	for _, test := range []struct {
		name     string
		owner    TrafficOwner
		capacity int
		interval time.Duration
		rule     LimitRule
	}{
		{name: "employee", owner: TrafficOwner{Kind: TrafficOwnerEmployee, ID: "employee-1"}, capacity: 120, interval: 500 * time.Millisecond, rule: LimitRuleEmployeeRPM},
		{name: "service account", owner: TrafficOwner{Kind: TrafficOwnerServiceAccount, ID: "service-1"}, capacity: 300, interval: 200 * time.Millisecond, rule: LimitRuleServiceAccountRPM},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := limiterTestNow
			limiter := newFixedTimeLimiter(&now)
			drainLimiterBucket(t, limiter, test.owner, test.capacity)
			assertRateLimited(t, limiter, test.owner, test.rule, test.interval)

			now = now.Add(test.interval / 2)
			assertRateLimited(t, limiter, test.owner, test.rule, test.interval/2)
			now = now.Add(test.interval / 2)
			mustAcquireLimiter(t, limiter, test.owner).Release()

			now = now.Add(10 * time.Minute)
			drainLimiterBucket(t, limiter, test.owner, test.capacity)
			assertRateLimited(t, limiter, test.owner, test.rule, test.interval)
		})
	}
}

func TestInProcessLimiterDoesNotRefillWhenClockMovesBackward(t *testing.T) {
	now := limiterTestNow
	limiter := newFixedTimeLimiter(&now)
	owner := TrafficOwner{Kind: TrafficOwnerEmployee, ID: "employee-1"}
	drainLimiterBucket(t, limiter, owner, employeeRPMCapacity)

	now = now.Add(-time.Minute)
	assertRateLimited(t, limiter, owner, LimitRuleEmployeeRPM, 500*time.Millisecond)
	now = limiterTestNow.Add(250 * time.Millisecond)
	assertRateLimited(t, limiter, owner, LimitRuleEmployeeRPM, 250*time.Millisecond)
}

func TestInProcessLimiterRemovesFullyRefilledIdleOwners(t *testing.T) {
	now := limiterTestNow
	limiter := newFixedTimeLimiter(&now)
	for index := 0; index < 100; index++ {
		mustAcquireLimiter(t, limiter, TrafficOwner{
			Kind: TrafficOwnerEmployee,
			ID:   fmt.Sprintf("employee-%d", index),
		}).Release()
	}

	now = now.Add(limiterBucketWindow)
	trigger := TrafficOwner{Kind: TrafficOwnerEmployee, ID: "employee-trigger"}
	mustAcquireLimiter(t, limiter, trigger).Release()
	if len(limiter.owners) != 1 {
		t.Fatalf("owner states after cleanup = %d, want 1", len(limiter.owners))
	}
	if _, ok := limiter.owners[trigger]; !ok {
		t.Fatal("trigger owner state missing after cleanup")
	}
}

func TestInProcessLimiterRateLimitErrorsDoNotExposeOwnerID(t *testing.T) {
	limiter := newFixedTimeLimiter(&limiterTestNow)
	owner := TrafficOwner{Kind: TrafficOwnerEmployee, ID: "sensitive-owner-id"}
	reservations := []Reservation{
		mustAcquireLimiter(t, limiter, owner),
		mustAcquireLimiter(t, limiter, owner),
		mustAcquireLimiter(t, limiter, owner),
	}

	_, err := limiter.Acquire(context.Background(), owner)
	if err == nil || strings.Contains(err.Error(), owner.ID) {
		t.Fatalf("Acquire() error = %q, want content-free rate-limit error", err)
	}
	for _, reservation := range reservations {
		reservation.Release()
	}
}

func TestInProcessLimiterReleasesOwnerAndGlobalSlotsExactlyOnce(t *testing.T) {
	t.Run("owner slot", func(t *testing.T) {
		limiter := newFixedTimeLimiter(&limiterTestNow)
		owner := TrafficOwner{Kind: TrafficOwnerEmployee, ID: "employee-1"}
		reservations := []Reservation{
			mustAcquireLimiter(t, limiter, owner),
			mustAcquireLimiter(t, limiter, owner),
			mustAcquireLimiter(t, limiter, owner),
		}
		reservations[0].Release()
		reservations[0].Release()
		replacement := mustAcquireLimiter(t, limiter, owner)
		assertRateLimited(t, limiter, owner, LimitRuleEmployeeConcurrency, time.Second)
		replacement.Release()
		reservations[1].Release()
		reservations[2].Release()
	})

	t.Run("global slot", func(t *testing.T) {
		limiter := newFixedTimeLimiter(&limiterTestNow)
		reservations := make([]Reservation, 0, 10)
		for index := 0; index < 10; index++ {
			reservations = append(reservations, mustAcquireLimiter(t, limiter, TrafficOwner{
				Kind: TrafficOwnerEmployee,
				ID:   fmt.Sprintf("employee-%d", index),
			}))
		}
		reservations[0].Release()
		reservations[0].Release()
		replacement := mustAcquireLimiter(t, limiter, TrafficOwner{Kind: TrafficOwnerEmployee, ID: "employee-replacement"})
		assertRateLimited(t, limiter, TrafficOwner{Kind: TrafficOwnerEmployee, ID: "employee-overflow"}, LimitRuleGlobalConcurrency, time.Second)
		replacement.Release()
		for _, reservation := range reservations[1:] {
			reservation.Release()
		}
	})
}

func TestInProcessLimiterEnforcesLimitsUnderConcurrentAcquisition(t *testing.T) {
	for _, test := range []struct {
		name       string
		owner      func(int) TrafficOwner
		wantAllows int
	}{
		{name: "employee owner limit", owner: func(int) TrafficOwner {
			return TrafficOwner{Kind: TrafficOwnerEmployee, ID: "employee-1"}
		}, wantAllows: 3},
		{name: "global limit", owner: func(index int) TrafficOwner {
			return TrafficOwner{Kind: TrafficOwnerEmployee, ID: fmt.Sprintf("employee-%d", index)}
		}, wantAllows: 10},
	} {
		t.Run(test.name, func(t *testing.T) {
			limiter := newFixedTimeLimiter(&limiterTestNow)
			start := make(chan struct{})
			reservations := make(chan Reservation, 100)
			var wait sync.WaitGroup
			for index := 0; index < 100; index++ {
				wait.Add(1)
				go func(index int) {
					defer wait.Done()
					<-start
					reservation, err := limiter.Acquire(context.Background(), test.owner(index))
					if err == nil {
						reservations <- reservation
						return
					}
					if !errors.Is(err, ErrRateLimited) {
						t.Errorf("Acquire() error = %v, want ErrRateLimited", err)
					}
				}(index)
			}
			close(start)
			wait.Wait()
			close(reservations)

			allowed := 0
			for reservation := range reservations {
				allowed++
				reservation.Release()
			}
			if allowed != test.wantAllows {
				t.Fatalf("concurrent acquisitions = %d, want %d", allowed, test.wantAllows)
			}
		})
	}
}

func TestInProcessLimiterRejectsInvalidOwnersAndCanceledContextsWithoutConsumingCapacity(t *testing.T) {
	limiter := newFixedTimeLimiter(&limiterTestNow)
	for _, owner := range []TrafficOwner{
		{},
		{Kind: TrafficOwnerKind("unknown"), ID: "owner-1"},
		{Kind: TrafficOwnerEmployee, ID: ""},
		{Kind: TrafficOwnerEmployee, ID: " owner-1 "},
		{Kind: TrafficOwnerEmployee, ID: "owner\n1"},
		{Kind: TrafficOwnerEmployee, ID: string(make([]byte, 256))},
	} {
		reservation, err := limiter.Acquire(context.Background(), owner)
		if reservation != nil || !errors.Is(err, ErrInvalidTrafficOwner) {
			t.Fatalf("Acquire(%+v) = (%v, %v), want nil ErrInvalidTrafficOwner", owner, reservation, err)
		}
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if reservation, err := limiter.Acquire(canceled, TrafficOwner{Kind: TrafficOwnerEmployee, ID: "employee-canceled"}); reservation != nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire(canceled) = (%v, %v), want nil context.Canceled", reservation, err)
	}

	reservations := make([]Reservation, 0, 10)
	for index := 0; index < 10; index++ {
		reservations = append(reservations, mustAcquireLimiter(t, limiter, TrafficOwner{
			Kind: TrafficOwnerEmployee,
			ID:   fmt.Sprintf("employee-valid-%d", index),
		}))
	}
	for _, reservation := range reservations {
		reservation.Release()
	}
}

func newFixedTimeLimiter(now *time.Time) *InProcessLimiter {
	limiter := NewInProcessLimiter()
	limiter.now = func() time.Time { return *now }
	return limiter
}

func mustAcquireLimiter(t *testing.T, limiter Limiter, owner TrafficOwner) Reservation {
	t.Helper()
	reservation, err := limiter.Acquire(context.Background(), owner)
	if err != nil {
		t.Fatalf("Acquire(%+v) error = %v", owner, err)
	}
	if reservation == nil {
		t.Fatalf("Acquire(%+v) returned nil reservation", owner)
	}
	return reservation
}

func drainLimiterBucket(t *testing.T, limiter Limiter, owner TrafficOwner, count int) {
	t.Helper()
	for index := 0; index < count; index++ {
		mustAcquireLimiter(t, limiter, owner).Release()
	}
}

func assertRateLimited(t *testing.T, limiter Limiter, owner TrafficOwner, wantRule LimitRule, wantRetryAfter time.Duration) {
	t.Helper()
	reservation, err := limiter.Acquire(context.Background(), owner)
	if reservation != nil {
		reservation.Release()
		t.Fatalf("Acquire(%+v) returned a reservation, want rate limit", owner)
	}
	var limited *RateLimitError
	if !errors.As(err, &limited) || !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Acquire(%+v) error = %v, want RateLimitError", owner, err)
	}
	if limited.Rule != wantRule || limited.RetryAfter != wantRetryAfter {
		t.Fatalf("RateLimitError = %+v, want rule=%s retry_after=%s", limited, wantRule, wantRetryAfter)
	}
}
