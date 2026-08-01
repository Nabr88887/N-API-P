package access

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestActivationLimiterEnforcesPairAndSourceWindows(t *testing.T) {
	now := time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC)
	limiter := NewActivationLimiter()

	for attempt := 1; attempt <= 5; attempt++ {
		if !limiter.Allow("source-a", "employee@example.internal", now) {
			t.Fatalf("pair attempt %d rejected before limit", attempt)
		}
	}
	if limiter.Allow("source-a", "employee@example.internal", now) {
		t.Fatal("sixth pair attempt allowed within 15 minutes")
	}
	if !limiter.Allow("source-a", "employee@example.internal", now.Add(15*time.Minute)) {
		t.Fatal("pair attempt rejected at the exact end of the 15-minute window")
	}

	limiter = NewActivationLimiter()
	for attempt := 1; attempt <= 60; attempt++ {
		email := fmt.Sprintf("employee-%02d@example.internal", attempt)
		if !limiter.Allow("source-b", email, now) {
			t.Fatalf("source attempt %d rejected before limit", attempt)
		}
	}
	if limiter.Allow("source-b", "overflow@example.internal", now) {
		t.Fatal("61st source attempt allowed within one minute")
	}
	if !limiter.Allow("source-b", "after-window@example.internal", now.Add(time.Minute)) {
		t.Fatal("source attempt rejected at the exact end of the one-minute window")
	}
}

func TestActivationLimiterEnforcesPairLimitConcurrently(t *testing.T) {
	limiter := NewActivationLimiter()
	start := make(chan struct{})
	var allowed atomic.Int32
	var wait sync.WaitGroup
	for attempt := 0; attempt < 100; attempt++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			if limiter.Allow("source-a", "employee@example.internal", fixedNow) {
				allowed.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()

	if got := allowed.Load(); got != activationPairLimit {
		t.Fatalf("concurrently allowed attempts = %d, want %d", got, activationPairLimit)
	}
}

func TestActivationRejectsLimitedAttemptBeforeRepositoryOrPasswordWork(t *testing.T) {
	repository := &orderedActivationRepository{}
	passwords := &orderedPasswordInitializer{}
	service := NewActivationService(repository, passwords, rejectingActivationLimiter{})
	service.now = func() time.Time { return fixedNow }

	err := service.Activate(context.Background(), ActivateInput{
		AttemptSource: "source-a",
		Email:         "employee@example.internal", ActivationValue: "candidate", NewPassword: "valid-password-placeholder",
	})

	if err != ErrActivationRejected {
		t.Fatalf("Activate() error = %v, want ErrActivationRejected", err)
	}
	if repository.prepareCalls != 0 || repository.activateCalls != 0 || passwords.calls != 0 {
		t.Fatalf("limited attempt reached protected work: prepare=%d activate=%d password=%d", repository.prepareCalls, repository.activateCalls, passwords.calls)
	}
}

func TestActivationPrevalidatesBeforePasswordInitialization(t *testing.T) {
	events := make([]string, 0, 3)
	repository := &orderedActivationRepository{prepareErr: ErrActivationRejected, events: &events}
	passwords := &orderedPasswordInitializer{events: &events}
	service := NewActivationService(repository, passwords, allowingActivationLimiter{})
	service.now = func() time.Time { return fixedNow }

	err := service.Activate(context.Background(), ActivateInput{
		AttemptSource: "source-a",
		Email:         "employee@example.internal", ActivationValue: "invalid", NewPassword: "valid-password-placeholder",
	})
	if err != ErrActivationRejected {
		t.Fatalf("invalid Activate() error = %v, want ErrActivationRejected", err)
	}
	if passwords.calls != 0 {
		t.Fatalf("password initializer calls = %d, want 0 for invalid activation", passwords.calls)
	}

	events = events[:0]
	repository.prepareErr = nil
	repository.candidate = ActivationCandidate{CodeID: "code-1", IdentityID: "identity-1"}
	err = service.Activate(context.Background(), ActivateInput{
		AttemptSource: "source-a",
		Email:         "employee@example.internal", ActivationValue: "valid", NewPassword: "valid-password-placeholder",
	})
	if err != nil {
		t.Fatalf("valid Activate() error = %v", err)
	}
	want := []string{"prepare", "password", "activate"}
	if len(events) != len(want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	for index := range want {
		if events[index] != want[index] {
			t.Fatalf("events = %v, want %v", events, want)
		}
	}
}

type rejectingActivationLimiter struct{}

func (rejectingActivationLimiter) Allow(string, string, time.Time) bool { return false }

type allowingActivationLimiter struct{}

func (allowingActivationLimiter) Allow(string, string, time.Time) bool { return true }

type orderedPasswordInitializer struct {
	calls  int
	events *[]string
}

func (initializer *orderedPasswordInitializer) Initialize(string) (string, error) {
	initializer.calls++
	if initializer.events != nil {
		*initializer.events = append(*initializer.events, "password")
	}
	return "password-hash", nil
}

type orderedActivationRepository struct {
	prepareCalls  int
	activateCalls int
	prepareErr    error
	candidate     ActivationCandidate
	events        *[]string
}

func (repository *orderedActivationRepository) PrepareActivation(context.Context, ActivationLookup) (ActivationCandidate, error) {
	repository.prepareCalls++
	if repository.events != nil {
		*repository.events = append(*repository.events, "prepare")
	}
	return repository.candidate, repository.prepareErr
}

func (repository *orderedActivationRepository) ActivateIdentity(context.Context, ActivationRecord) error {
	repository.activateCalls++
	if repository.events != nil {
		*repository.events = append(*repository.events, "activate")
	}
	return nil
}
