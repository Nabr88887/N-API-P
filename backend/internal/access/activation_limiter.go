package access

import (
	"strings"
	"sync"
	"time"
)

const (
	activationPairLimit    = 5
	activationPairWindow   = 15 * time.Minute
	activationSourceLimit  = 60
	activationSourceWindow = time.Minute
)

type ActivationLimiter struct {
	mu             sync.Mutex
	pairAttempts   map[string][]time.Time
	sourceAttempts map[string][]time.Time
	lastCleanup    time.Time
}

func NewActivationLimiter() *ActivationLimiter {
	return &ActivationLimiter{
		pairAttempts:   make(map[string][]time.Time),
		sourceAttempts: make(map[string][]time.Time),
	}
}

func (limiter *ActivationLimiter) Allow(trustedSource, normalizedEmail string, attemptedAt time.Time) bool {
	trustedSource = strings.TrimSpace(trustedSource)
	if trustedSource == "" || normalizedEmail == "" {
		return false
	}
	attemptedAt = attemptedAt.UTC()

	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.cleanup(attemptedAt)

	sourceAttempts := pruneAttempts(limiter.sourceAttempts[trustedSource], attemptedAt.Add(-activationSourceWindow))
	if len(sourceAttempts) >= activationSourceLimit {
		limiter.sourceAttempts[trustedSource] = sourceAttempts
		return false
	}
	sourceAttempts = append(sourceAttempts, attemptedAt)
	limiter.sourceAttempts[trustedSource] = sourceAttempts

	pairKey := trustedSource + "\x00" + normalizedEmail
	pairAttempts := pruneAttempts(limiter.pairAttempts[pairKey], attemptedAt.Add(-activationPairWindow))
	if len(pairAttempts) >= activationPairLimit {
		limiter.pairAttempts[pairKey] = pairAttempts
		return false
	}
	limiter.pairAttempts[pairKey] = append(pairAttempts, attemptedAt)
	return true
}

func (limiter *ActivationLimiter) cleanup(now time.Time) {
	if !limiter.lastCleanup.IsZero() && now.Sub(limiter.lastCleanup) < activationSourceWindow {
		return
	}
	for key, attempts := range limiter.sourceAttempts {
		attempts = pruneAttempts(attempts, now.Add(-activationSourceWindow))
		if len(attempts) == 0 {
			delete(limiter.sourceAttempts, key)
		} else {
			limiter.sourceAttempts[key] = attempts
		}
	}
	for key, attempts := range limiter.pairAttempts {
		attempts = pruneAttempts(attempts, now.Add(-activationPairWindow))
		if len(attempts) == 0 {
			delete(limiter.pairAttempts, key)
		} else {
			limiter.pairAttempts[key] = attempts
		}
	}
	limiter.lastCleanup = now
}

func pruneAttempts(attempts []time.Time, cutoff time.Time) []time.Time {
	firstRetained := 0
	for firstRetained < len(attempts) && !attempts[firstRetained].After(cutoff) {
		firstRetained++
	}
	return attempts[firstRetained:]
}
