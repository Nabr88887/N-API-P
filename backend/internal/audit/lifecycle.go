package audit

import (
	"context"
	"errors"
	"fmt"
	"time"

	"n-api-p/internal/observability"
)

const (
	CleanupInterval = 15 * time.Minute
	DeletionTarget  = time.Hour
)

var (
	ErrInvalidLifecycle      = errors.New("invalid audit lifecycle")
	ErrLifecycleUnavailable  = errors.New("audit lifecycle unavailable")
	ErrRawContentUnavailable = errors.New("raw audit content unavailable")
)

type RawContentLookup struct {
	AuditID     string
	ContentKind ContentKind
	VisibleAt   time.Time
}

type RawContentRecord struct {
	AuditID               string
	ContentKind           ContentKind
	Content               EncryptedContent
	OwnerKind             OwnerKind
	IdentityID            string
	ServiceAccountID      string
	ResponsibleIdentityID string
	TeamID                string
	CreatedAt             time.Time
	ExpiresAt             time.Time
}

type DeletionLagState struct {
	Critical        bool
	OldestExpiredAt *time.Time
	OverdueSince    *time.Time
	ObservedAt      time.Time
}

type LifecycleCleanupResult struct {
	DeletionLag              DeletionLagState
	DeletedRawRows           int64
	PurgedVerificationHashes int64
	CompletedAt              time.Time
}

type LifecycleRepository interface {
	ReadRawContent(context.Context, RawContentLookup) (RawContentRecord, error)
	ObserveDeletionLag(context.Context, time.Time) (DeletionLagState, error)
	DeleteExpiredRawContent(context.Context, time.Time) (int64, error)
	PurgeRevokedVerificationHashes(context.Context, time.Time) (int64, error)
}

type lifecycleTicker interface {
	Chan() <-chan time.Time
	Stop()
}

type LifecycleJob struct {
	repository LifecycleRepository
	now        func() time.Time
	newTicker  func(time.Duration) lifecycleTicker
	metrics    *observability.Metrics
}

func NewLifecycleJob(repository LifecycleRepository) (*LifecycleJob, error) {
	if repository == nil {
		return nil, ErrInvalidLifecycle
	}
	return &LifecycleJob{
		repository: repository,
		now:        time.Now,
		newTicker: func(interval time.Duration) lifecycleTicker {
			return &realLifecycleTicker{Ticker: time.NewTicker(interval)}
		},
	}, nil
}

func (job *LifecycleJob) SetMetrics(metrics *observability.Metrics) {
	if job != nil {
		job.metrics = metrics
	}
}

func (job *LifecycleJob) RunOnce(ctx context.Context, completedAt time.Time) (LifecycleCleanupResult, error) {
	if job == nil || job.repository == nil || completedAt.IsZero() {
		return LifecycleCleanupResult{}, ErrInvalidLifecycle
	}
	completedAt = completedAt.UTC()
	job.observeJob("raw_cleanup", "running")
	lag, err := job.repository.ObserveDeletionLag(ctx, completedAt)
	if err != nil {
		job.observeJob("raw_cleanup", "failed")
		return LifecycleCleanupResult{}, fmt.Errorf("%w: observe deletion lag: %w", ErrLifecycleUnavailable, err)
	}
	if job.metrics != nil {
		observedAt := lag.ObservedAt
		if observedAt.IsZero() {
			observedAt = completedAt
		}
		job.metrics.SetDeletionLag(lag.Critical, lag.OldestExpiredAt, lag.OverdueSince, observedAt)
	}
	deleted, err := job.repository.DeleteExpiredRawContent(ctx, completedAt)
	if err != nil {
		job.observeJob("raw_cleanup", "failed")
		return LifecycleCleanupResult{}, fmt.Errorf("%w: delete expired raw content: %w", ErrLifecycleUnavailable, err)
	}
	job.observeJob("raw_cleanup", "succeeded")
	job.observeJob("verification_hash_purge", "running")
	purged, err := job.repository.PurgeRevokedVerificationHashes(ctx, completedAt)
	if err != nil {
		job.observeJob("verification_hash_purge", "failed")
		return LifecycleCleanupResult{}, fmt.Errorf("%w: purge revoked verification hashes: %w", ErrLifecycleUnavailable, err)
	}
	job.observeJob("verification_hash_purge", "succeeded")
	return LifecycleCleanupResult{
		DeletionLag: lag, DeletedRawRows: deleted,
		PurgedVerificationHashes: purged, CompletedAt: completedAt,
	}, nil
}

func (job *LifecycleJob) Run(ctx context.Context) error {
	if job == nil || job.repository == nil || job.now == nil || job.newTicker == nil {
		return ErrInvalidLifecycle
	}
	if _, err := job.RunOnce(ctx, job.now().UTC()); err != nil {
		return err
	}
	ticker := job.newTicker(CleanupInterval)
	if ticker == nil {
		return ErrInvalidLifecycle
	}
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			job.observeJob("raw_cleanup", "stopped")
			job.observeJob("verification_hash_purge", "stopped")
			return nil
		case _, ok := <-ticker.Chan():
			if !ok {
				job.observeJob("raw_cleanup", "failed")
				job.observeJob("verification_hash_purge", "failed")
				return ErrLifecycleUnavailable
			}
			if _, err := job.RunOnce(ctx, job.now().UTC()); err != nil {
				return err
			}
		}
	}
}

func (job *LifecycleJob) observeJob(name, state string) {
	if job != nil && job.metrics != nil {
		job.metrics.ObserveBackgroundJob(name, state)
	}
}

type realLifecycleTicker struct {
	*time.Ticker
}

func (ticker *realLifecycleTicker) Chan() <-chan time.Time { return ticker.C }
