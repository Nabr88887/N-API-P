package audit

import (
	"context"
	"errors"
	"fmt"
	"time"
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

func (job *LifecycleJob) RunOnce(ctx context.Context, completedAt time.Time) (LifecycleCleanupResult, error) {
	if job == nil || job.repository == nil || completedAt.IsZero() {
		return LifecycleCleanupResult{}, ErrInvalidLifecycle
	}
	completedAt = completedAt.UTC()
	lag, err := job.repository.ObserveDeletionLag(ctx, completedAt)
	if err != nil {
		return LifecycleCleanupResult{}, fmt.Errorf("%w: observe deletion lag: %w", ErrLifecycleUnavailable, err)
	}
	deleted, err := job.repository.DeleteExpiredRawContent(ctx, completedAt)
	if err != nil {
		return LifecycleCleanupResult{}, fmt.Errorf("%w: delete expired raw content: %w", ErrLifecycleUnavailable, err)
	}
	purged, err := job.repository.PurgeRevokedVerificationHashes(ctx, completedAt)
	if err != nil {
		return LifecycleCleanupResult{}, fmt.Errorf("%w: purge revoked verification hashes: %w", ErrLifecycleUnavailable, err)
	}
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
			return nil
		case _, ok := <-ticker.Chan():
			if !ok {
				return ErrLifecycleUnavailable
			}
			if _, err := job.RunOnce(ctx, job.now().UTC()); err != nil {
				return err
			}
		}
	}
}

type realLifecycleTicker struct {
	*time.Ticker
}

func (ticker *realLifecycleTicker) Chan() <-chan time.Time { return ticker.C }
