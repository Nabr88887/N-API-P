package audit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestLifecycleJobRunOnceObservesLagBeforeCleanupAndPurgesRevokedHashes(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	overdueSince := now.Add(-time.Hour)
	repository := &lifecycleRepositoryFake{
		lag:            DeletionLagState{Critical: true, OverdueSince: &overdueSince},
		deletedRawRows: 4,
		purgedHashes:   2,
		purgedMetadata: MetadataPurgeResult{UsageRows: 3, SecurityEventRows: 2, AuditRows: 1},
	}
	job, err := NewLifecycleJob(repository)
	if err != nil {
		t.Fatalf("NewLifecycleJob() error = %v", err)
	}

	result, err := job.RunOnce(context.Background(), now)
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if got := repository.calls; len(got) != 4 || got[0] != "observe" || got[1] != "delete" || got[2] != "purge" || got[3] != "metadata" {
		t.Fatalf("repository calls = %v, want observe/delete/purge/metadata", got)
	}
	if result.DeletedRawRows != 4 || result.PurgedVerificationHashes != 2 || result.PurgedMetadata.UsageRows != 3 || result.PurgedMetadata.SecurityEventRows != 2 || result.PurgedMetadata.AuditRows != 1 || !result.DeletionLag.Critical || !result.CompletedAt.Equal(now) {
		t.Fatalf("cleanup result = %+v", result)
	}
}

func TestLifecycleJobStopsBeforeDestructiveStepsWhenLagObservationFails(t *testing.T) {
	repository := &lifecycleRepositoryFake{observeErr: errors.New("database unavailable")}
	job, err := NewLifecycleJob(repository)
	if err != nil {
		t.Fatalf("NewLifecycleJob() error = %v", err)
	}

	_, err = job.RunOnce(context.Background(), time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC))
	if !errors.Is(err, ErrLifecycleUnavailable) {
		t.Fatalf("RunOnce() error = %v, want ErrLifecycleUnavailable", err)
	}
	if len(repository.calls) != 1 || repository.calls[0] != "observe" {
		t.Fatalf("repository calls = %v, want observe only", repository.calls)
	}
}

func TestLifecycleJobRunsImmediatelyAndEveryFifteenMinutes(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	repository := &lifecycleRepositoryFake{observed: make(chan time.Time, 2)}
	job, err := NewLifecycleJob(repository)
	if err != nil {
		t.Fatalf("NewLifecycleJob() error = %v", err)
	}
	current := now
	job.now = func() time.Time { return current }
	ticker := &fakeLifecycleTicker{ticks: make(chan time.Time, 1)}
	job.newTicker = func(interval time.Duration) lifecycleTicker {
		if interval != CleanupInterval {
			t.Fatalf("ticker interval = %v, want %v", interval, CleanupInterval)
		}
		return ticker
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- job.Run(ctx) }()
	if observed := receiveLifecycleTime(t, repository.observed); !observed.Equal(now) {
		t.Fatalf("immediate run = %v, want %v", observed, now)
	}
	next := now.Add(CleanupInterval)
	current = next
	ticker.ticks <- now
	if observed := receiveLifecycleTime(t, repository.observed); !observed.Equal(next) {
		t.Fatalf("scheduled run = %v, want %v", observed, next)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if !ticker.stopped {
		t.Fatal("ticker was not stopped")
	}
}

func TestLifecycleJobRetriesAfterAFailedRun(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	repository := &lifecycleRepositoryFake{
		observed:      make(chan time.Time, 2),
		observeErrors: []error{errors.New("synthetic metadata failure"), nil},
	}
	job, err := NewLifecycleJob(repository)
	if err != nil {
		t.Fatalf("NewLifecycleJob() error = %v", err)
	}
	current := now
	job.now = func() time.Time { return current }
	ticker := &fakeLifecycleTicker{ticks: make(chan time.Time, 1)}
	job.newTicker = func(time.Duration) lifecycleTicker { return ticker }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- job.Run(ctx) }()
	if observed := receiveLifecycleTime(t, repository.observed); !observed.Equal(now) {
		t.Fatalf("failed immediate run = %v, want %v", observed, now)
	}
	current = now.Add(CleanupInterval)
	ticker.ticks <- current
	if observed := receiveLifecycleTime(t, repository.observed); !observed.Equal(current) {
		t.Fatalf("retry run = %v, want %v", observed, current)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v", err)
	}
}

func receiveLifecycleTime(t *testing.T, values <-chan time.Time) time.Time {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for lifecycle run")
		return time.Time{}
	}
}

type lifecycleRepositoryFake struct {
	lag            DeletionLagState
	deletedRawRows int64
	purgedHashes   int64
	purgedMetadata MetadataPurgeResult
	observeErr     error
	observeErrors  []error
	observeCalls   int
	deleteErr      error
	purgeErr       error
	calls          []string
	observed       chan time.Time
}

func (repository *lifecycleRepositoryFake) ReadRawContent(context.Context, RawContentLookup) (RawContentRecord, error) {
	return RawContentRecord{}, ErrRawContentUnavailable
}

func (repository *lifecycleRepositoryFake) ObserveDeletionLag(_ context.Context, observedAt time.Time) (DeletionLagState, error) {
	repository.calls = append(repository.calls, "observe")
	if repository.observed != nil {
		repository.observed <- observedAt
	}
	if repository.observeCalls < len(repository.observeErrors) {
		err := repository.observeErrors[repository.observeCalls]
		repository.observeCalls++
		return repository.lag, err
	}
	repository.observeCalls++
	return repository.lag, repository.observeErr
}

func (repository *lifecycleRepositoryFake) DeleteExpiredRawContent(context.Context, time.Time) (int64, error) {
	repository.calls = append(repository.calls, "delete")
	return repository.deletedRawRows, repository.deleteErr
}

func (repository *lifecycleRepositoryFake) PurgeRevokedVerificationHashes(context.Context, time.Time) (int64, error) {
	repository.calls = append(repository.calls, "purge")
	return repository.purgedHashes, repository.purgeErr
}

func (repository *lifecycleRepositoryFake) PurgeExpiredMetadata(context.Context, time.Time) (MetadataPurgeResult, error) {
	repository.calls = append(repository.calls, "metadata")
	return repository.purgedMetadata, nil
}

type fakeLifecycleTicker struct {
	ticks   chan time.Time
	stopped bool
}

func (ticker *fakeLifecycleTicker) Chan() <-chan time.Time { return ticker.ticks }
func (ticker *fakeLifecycleTicker) Stop()                  { ticker.stopped = true }
