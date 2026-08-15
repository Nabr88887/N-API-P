package gateway

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"n-api-p/internal/observability"
)

const (
	globalConcurrencyLimit      = 10
	employeeConcurrencyLimit    = 3
	employeeRPMCapacity         = 120
	serviceConcurrencyLimit     = 5
	serviceRPMCapacity          = 300
	limiterBucketWindow         = time.Minute
	concurrencyRetryAfter       = time.Second
	maxTrafficOwnerIDLength     = 255
	limiterOwnerCleanupInterval = time.Minute
)

var (
	ErrInvalidTrafficOwner = errors.New("invalid traffic owner")
	ErrLimiterUnavailable  = errors.New("limiter unavailable")
	ErrRateLimited         = errors.New("rate limited")
)

type TrafficOwnerKind string

const (
	TrafficOwnerEmployee       TrafficOwnerKind = "employee"
	TrafficOwnerServiceAccount TrafficOwnerKind = "service_account"
)

type TrafficOwner struct {
	Kind TrafficOwnerKind
	ID   string
}

type LimitRule string

const (
	LimitRuleGlobalConcurrency         LimitRule = "global_concurrency"
	LimitRuleEmployeeConcurrency       LimitRule = "employee_concurrency"
	LimitRuleEmployeeRPM               LimitRule = "employee_rpm"
	LimitRuleServiceAccountConcurrency LimitRule = "service_account_concurrency"
	LimitRuleServiceAccountRPM         LimitRule = "service_account_rpm"
)

type RateLimitError struct {
	Rule       LimitRule
	RetryAfter time.Duration
}

func (err *RateLimitError) Error() string {
	if err == nil {
		return ErrRateLimited.Error()
	}
	return fmt.Sprintf("%s: %s", ErrRateLimited, err.Rule)
}

func (err *RateLimitError) Unwrap() error {
	return ErrRateLimited
}

type Reservation interface {
	Release()
}

type Limiter interface {
	Acquire(context.Context, TrafficOwner) (Reservation, error)
}

type InProcessLimiter struct {
	mu           sync.Mutex
	now          func() time.Time
	globalActive int
	owners       map[TrafficOwner]*ownerLimitState
	lastCleanup  time.Time
	metrics      *observability.Metrics
}

// Token credit is stored as elapsed refill time so the 120/300 RPM rates remain
// exact without floating-point rounding.
type ownerLimitState struct {
	active     int
	credit     time.Duration
	lastRefill time.Time
	lastSeen   time.Time
}

type ownerLimit struct {
	concurrency     int
	interval        time.Duration
	concurrencyRule LimitRule
	rpmRule         LimitRule
}

type inProcessReservation struct {
	limiter *InProcessLimiter
	owner   TrafficOwner
	once    sync.Once
}

func NewInProcessLimiter() *InProcessLimiter {
	return NewInProcessLimiterWithMetrics(nil)
}

func NewInProcessLimiterWithMetrics(metrics *observability.Metrics) *InProcessLimiter {
	return &InProcessLimiter{
		now:     time.Now,
		owners:  make(map[TrafficOwner]*ownerLimitState),
		metrics: metrics,
	}
}

func (limiter *InProcessLimiter) Acquire(ctx context.Context, owner TrafficOwner) (Reservation, error) {
	if limiter == nil || limiter.now == nil || limiter.owners == nil {
		return nil, ErrLimiterUnavailable
	}
	if err := validateTrafficOwner(owner); err != nil {
		limiter.observe(owner, "rejected", "unknown")
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		limiter.observe(owner, "error", "unknown")
		return nil, err
	}

	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if err := ctx.Err(); err != nil {
		limiter.observe(owner, "error", "unknown")
		return nil, err
	}
	now := limiter.now().UTC()
	limiter.cleanupOwners(now)
	if limiter.globalActive >= globalConcurrencyLimit {
		limiter.observe(owner, "limited", string(LimitRuleGlobalConcurrency))
		return nil, newRateLimitError(LimitRuleGlobalConcurrency, concurrencyRetryAfter)
	}

	limits := limitsForTrafficOwner(owner.Kind)
	state := limiter.owners[owner]
	if state == nil {
		state = &ownerLimitState{credit: limiterBucketWindow, lastRefill: now, lastSeen: now}
		limiter.owners[owner] = state
	} else {
		refillOwnerLimit(state, now)
		state.lastSeen = latestTime(state.lastSeen, now)
	}
	if state.active >= limits.concurrency {
		limiter.observe(owner, "limited", string(limits.concurrencyRule))
		return nil, newRateLimitError(limits.concurrencyRule, concurrencyRetryAfter)
	}
	if state.credit < limits.interval {
		limiter.observe(owner, "limited", string(limits.rpmRule))
		return nil, newRateLimitError(limits.rpmRule, limits.interval-state.credit)
	}

	state.credit -= limits.interval
	state.active++
	limiter.globalActive++
	limiter.observe(owner, "admitted", "unknown")
	return &inProcessReservation{limiter: limiter, owner: owner}, nil
}

func (limiter *InProcessLimiter) observe(owner TrafficOwner, outcome, rule string) {
	if limiter != nil && limiter.metrics != nil {
		limiter.metrics.ObserveLimiter(string(owner.Kind), outcome, rule)
	}
}

func (reservation *inProcessReservation) Release() {
	if reservation == nil {
		return
	}
	reservation.once.Do(func() {
		if reservation.limiter != nil {
			reservation.limiter.release(reservation.owner)
		}
	})
}

func (limiter *InProcessLimiter) release(owner TrafficOwner) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	state := limiter.owners[owner]
	if state == nil || state.active == 0 || limiter.globalActive == 0 {
		return
	}
	state.active--
	limiter.globalActive--
	state.lastSeen = latestTime(state.lastSeen, limiter.now().UTC())
}

func (limiter *InProcessLimiter) cleanupOwners(now time.Time) {
	if !limiter.lastCleanup.IsZero() && now.Sub(limiter.lastCleanup) < limiterOwnerCleanupInterval {
		return
	}
	for owner, state := range limiter.owners {
		refillOwnerLimit(state, now)
		if state.active == 0 && state.credit == limiterBucketWindow && !state.lastSeen.After(now.Add(-limiterBucketWindow)) {
			delete(limiter.owners, owner)
		}
	}
	limiter.lastCleanup = latestTime(limiter.lastCleanup, now)
}

func refillOwnerLimit(state *ownerLimitState, now time.Time) {
	if state == nil || !now.After(state.lastRefill) {
		return
	}
	elapsed := now.Sub(state.lastRefill)
	remaining := limiterBucketWindow - state.credit
	if elapsed >= remaining {
		state.credit = limiterBucketWindow
	} else {
		state.credit += elapsed
	}
	state.lastRefill = now
}

func validateTrafficOwner(owner TrafficOwner) error {
	if owner.Kind != TrafficOwnerEmployee && owner.Kind != TrafficOwnerServiceAccount {
		return ErrInvalidTrafficOwner
	}
	if owner.ID == "" || len(owner.ID) > maxTrafficOwnerIDLength || owner.ID != strings.TrimSpace(owner.ID) {
		return ErrInvalidTrafficOwner
	}
	for _, char := range owner.ID {
		if unicode.IsControl(char) {
			return ErrInvalidTrafficOwner
		}
	}
	return nil
}

func limitsForTrafficOwner(kind TrafficOwnerKind) ownerLimit {
	if kind == TrafficOwnerEmployee {
		return ownerLimit{
			concurrency:     employeeConcurrencyLimit,
			interval:        limiterBucketWindow / employeeRPMCapacity,
			concurrencyRule: LimitRuleEmployeeConcurrency,
			rpmRule:         LimitRuleEmployeeRPM,
		}
	}
	return ownerLimit{
		concurrency:     serviceConcurrencyLimit,
		interval:        limiterBucketWindow / serviceRPMCapacity,
		concurrencyRule: LimitRuleServiceAccountConcurrency,
		rpmRule:         LimitRuleServiceAccountRPM,
	}
}

func newRateLimitError(rule LimitRule, retryAfter time.Duration) *RateLimitError {
	return &RateLimitError{Rule: rule, RetryAfter: retryAfter}
}

func latestTime(current, candidate time.Time) time.Time {
	if candidate.After(current) {
		return candidate
	}
	return current
}

var _ Limiter = (*InProcessLimiter)(nil)
var _ Reservation = (*inProcessReservation)(nil)
