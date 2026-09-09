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
	if got := repository.calls; len(got) != 5 || got[0] != "observe" || got[1] != "delete" || got[2] != "observe" || got[3] != "purge" || got[4] != "metadata" {
		t.Fatalf("repository calls = %v, want observe/delete/observe/purge/metadata", got)
	}
	if result.DeletedRawRows != 4 || result.PurgedVerificationHashes != 2 || result.PurgedMetadata.UsageRows != 3 || result.PurgedMetadata.SecurityEventRows != 2 || result.PurgedMetadata.AuditRows != 1 || !result.DeletionLag.Critical || !result.CompletedAt.Equal(now) {
		t.Fatalf("cleanup result = %+v", result)
	}
}

func TestLifecycleJobRunOnceReturnsLagAfterCleanup(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	oldestExpiredAt := now.Add(-2 * time.Hour)
	repository := &lifecycleRepositoryFake{
		observeLags: []DeletionLagState{
			{Critical: true, OldestExpiredAt: &oldestExpiredAt, ObservedAt: now},
			{Critical: false, ObservedAt: now},
		},
		deletedRawRows: 1,
	}
	job, err := NewLifecycleJob(repository)
	if err != nil {
		t.Fatalf("NewLifecycleJob() error = %v", err)
	}

	result, err := job.RunOnce(context.Background(), now)
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if result.DeletionLag.Critical || result.DeletionLag.OldestExpiredAt != nil {
		t.Fatalf("deletion lag = %+v, want refreshed non-critical state", result.DeletionLag)
	}
	wantCalls := []string{"observe", "delete", "observe", "purge", "metadata"}
	if len(repository.calls) != len(wantCalls) {
		t.Fatalf("repository calls = %v, want %v", repository.calls, wantCalls)
	}
	for index := range wantCalls {
		if repository.calls[index] != wantCalls[index] {
			t.Fatalf("repository calls = %v, want %v", repository.calls, wantCalls)
		}
	}
}

func TestLifecycleJobDrainsFullRawCleanupBatchesBeforeOtherPurges(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	repository := &lifecycleRepositoryFake{
		deletedRawBatches: []int64{RawContentCleanupBatchSize, RawContentCleanupBatchSize, 7},
	}
	job, err := NewLifecycleJob(repository)
	if err != nil {
		t.Fatalf("NewLifecycleJob() error = %v", err)
	}

	result, err := job.RunOnce(context.Background(), now)
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if result.DeletedRawRows != 2*RawContentCleanupBatchSize+7 {
		t.Fatalf("deleted raw rows = %d, want %d", result.DeletedRawRows, 2*RawContentCleanupBatchSize+7)
	}
	wantCalls := []string{"observe", "delete", "delete", "delete", "observe", "purge", "metadata"}
	if len(repository.calls) != len(wantCalls) {
		t.Fatalf("repository calls = %v, want %v", repository.calls, wantCalls)
	}
	for index := range wantCalls {
		if repository.calls[index] != wantCalls[index] {
			t.Fatalf("repository calls = %v, want %v", repository.calls, wantCalls)
		}
	}
}

func TestLifecycleJobBoundsRawCleanupDrain(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	fullBatches := make([]int64, rawContentCleanupMaxBatches+1)
	for index := range fullBatches {
		fullBatches[index] = RawContentCleanupBatchSize
	}
	repository := &lifecycleRepositoryFake{deletedRawBatches: fullBatches}
	job, err := NewLifecycleJob(repository)
	if err != nil {
		t.Fatalf("NewLifecycleJob() error = %v", err)
	}

	result, err := job.RunOnce(context.Background(), now)
	if err != nil {
		t.Fatalf("RunOnce() error = %v", err)
	}
	if result.DeletedRawRows != int64(rawContentCleanupMaxBatches)*RawContentCleanupBatchSize {
		t.Fatalf("deleted raw rows = %d, want bounded drain of %d", result.DeletedRawRows, int64(rawContentCleanupMaxBatches)*RawContentCleanupBatchSize)
	}
	deleteCalls := 0
	for _, call := range repository.calls {
		if call == "delete" {
			deleteCalls++
		}
	}
	if deleteCalls != rawContentCleanupMaxBatches {
		t.Fatalf("delete calls = %d, want %d", deleteCalls, rawContentCleanupMaxBatches)
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
	repository := &lifecycleRepositoryFake{observed: make(chan time.Time, 4)}
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
	if observed := receiveLifecycleTime(t, repository.observed); !observed.Equal(now) {
		t.Fatalf("immediate post-cleanup observation = %v, want %v", observed, now)
	}
	next := now.Add(CleanupInterval)
	current = next
	ticker.ticks <- now
	if observed := receiveLifecycleTime(t, repository.observed); !observed.Equal(next) {
		t.Fatalf("scheduled run = %v, want %v", observed, next)
	}
	if observed := receiveLifecycleTime(t, repository.observed); !observed.Equal(next) {
		t.Fatalf("scheduled post-cleanup observation = %v, want %v", observed, next)
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
		observed:      make(chan time.Time, 3),
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
	if observed := receiveLifecycleTime(t, repository.observed); !observed.Equal(current) {
		t.Fatalf("retry post-cleanup observation = %v, want %v", observed, current)
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
	lag               DeletionLagState
	observeLags       []DeletionLagState
	deletedRawRows    int64
	deletedRawBatches []int64
	purgedHashes      int64
	purgedMetadata    MetadataPurgeResult
	observeErr        error
	observeErrors     []error
	observeCalls      int
	deleteErr         error
	purgeErr          error
	calls             []string
	observed          chan time.Time
}

func (repository *lifecycleRepositoryFake) ReadRawContent(context.Context, RawContentLookup) (RawContentRecord, error) {
	return RawContentRecord{}, ErrRawContentUnavailable
}

func (repository *lifecycleRepositoryFake) ObserveDeletionLag(_ context.Context, observedAt time.Time) (DeletionLagState, error) {
	repository.calls = append(repository.calls, "observe")
	if repository.observed != nil {
		repository.observed <- observedAt
	}
	index := repository.observeCalls
	repository.observeCalls++
	lag := repository.lag
	if index < len(repository.observeLags) {
		lag = repository.observeLags[index]
	}
	if index < len(repository.observeErrors) {
		return lag, repository.observeErrors[index]
	}
	return lag, repository.observeErr
}

func (repository *lifecycleRepositoryFake) DeleteExpiredRawContent(context.Context, time.Time) (int64, error) {
	repository.calls = append(repository.calls, "delete")
	if len(repository.deletedRawBatches) > 0 {
		deleted := repository.deletedRawBatches[0]
		repository.deletedRawBatches = repository.deletedRawBatches[1:]
		return deleted, repository.deleteErr
	}
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
