package audit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestInitialCaptureFailsClosedWhileAuditGateRequiresProbe(t *testing.T) {
	repository := &degradedRepositoryFake{}
	gate, err := NewDegradedStateMachine(repository)
	if err != nil {
		t.Fatalf("NewDegradedStateMachine() error = %v", err)
	}
	encryptor := &countingEncryptor{}
	service, err := NewInitialCaptureServiceWithGate(encryptor, &recordingPendingAuditRepository{}, gate)
	if err != nil {
		t.Fatalf("NewInitialCaptureServiceWithGate() error = %v", err)
	}

	_, err = service.CaptureValidatedRequest(context.Background(), InitialCaptureInput{
		ID: "audit-1", RequestID: "request-1", OwnerKind: OwnerKindPersonal,
		IdentityID: "employee-1", TeamID: "team-1", ModelID: "gpt-test",
		ValidatedRequestJSON: []byte(`{"messages":[{"role":"user","content":"hello"}]}`),
		CreatedAt:            time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC),
		ExpiresAt:            time.Date(2026, 8, 12, 10, 0, 0, 0, time.UTC),
	})
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("CaptureValidatedRequest() error = %v, want ErrAuditUnavailable", err)
	}
	if encryptor.calls != 0 {
		t.Fatalf("encryptor calls = %d, want 0 while gate is blocked", encryptor.calls)
	}
}

func TestInitialCaptureFailureBlocksSubsequentChat(t *testing.T) {
	repository := &degradedRepositoryFake{}
	gate, err := NewDegradedStateMachine(repository)
	if err != nil {
		t.Fatalf("NewDegradedStateMachine() error = %v", err)
	}
	now := time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC)
	if err := gate.Recover(context.Background(), now.Add(-time.Hour), now); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	persistenceErr := errors.New("synthetic initial persistence failure")
	pendingRepository := &recordingPendingAuditRepository{store: func(PendingAudit) error { return persistenceErr }}
	service, err := NewInitialCaptureServiceWithGate(&countingEncryptor{}, pendingRepository, gate)
	if err != nil {
		t.Fatalf("NewInitialCaptureServiceWithGate() error = %v", err)
	}

	_, err = service.CaptureValidatedRequest(context.Background(), InitialCaptureInput{
		ID: "audit-1", RequestID: "request-1", OwnerKind: OwnerKindPersonal,
		IdentityID: "employee-1", TeamID: "team-1", ModelID: "gpt-test",
		ValidatedRequestJSON: []byte(`{"messages":[]}`), CreatedAt: now, ExpiresAt: now.Add(24 * time.Hour),
	})
	if !errors.Is(err, ErrAuditUnavailable) || !errors.Is(err, persistenceErr) {
		t.Fatalf("CaptureValidatedRequest() error = %v, want audit and persistence errors", err)
	}
	if repository.blockReason != GateReasonInitialCapture {
		t.Fatalf("initial failure block reason = %q, want %q", repository.blockReason, GateReasonInitialCapture)
	}
	if err := gate.CheckChatAllowed(context.Background()); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("CheckChatAllowed() after initial failure = %v, want ErrAuditUnavailable", err)
	}
}

func TestFinalizationFailureMarksAuditIncompleteAndBlocksLaterChat(t *testing.T) {
	repository := &degradedRepositoryFake{finalizeErr: errors.New("synthetic final write failure")}
	gate, err := NewDegradedStateMachine(repository)
	if err != nil {
		t.Fatalf("NewDegradedStateMachine() error = %v", err)
	}
	if err := gate.Recover(context.Background(), time.Date(2026, 8, 5, 9, 0, 0, 0, time.UTC), time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	encryptor := &countingEncryptor{}
	service, err := NewResponseFinalizationServiceWithGate(encryptor, repository, gate)
	if err != nil {
		t.Fatalf("NewResponseFinalizationServiceWithGate() error = %v", err)
	}

	_, err = service.FinalizeResponse(context.Background(), ResponseFinalizationInput{
		AuditID: "audit-1", RequestID: "request-1", OwnerKind: OwnerKindPersonal,
		IdentityID: "employee-1", TeamID: "team-1", ModelID: "gpt-test",
		ResponseJSON: []byte(`{"id":"response-1","choices":[]}`), CaptureStatus: CaptureStatusComplete,
		Outcome: AuditOutcomeSuccess, ObservedResponseBytes: 35,
		CreatedAt:   time.Date(2026, 8, 5, 9, 0, 0, 0, time.UTC),
		CompletedAt: time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC),
	})
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("FinalizeResponse() error = %v, want ErrAuditUnavailable", err)
	}
	if repository.incompleteAuditID != "audit-1" || repository.incompleteRequestID != "request-1" {
		t.Fatalf("incomplete reconciliation = (%q, %q), want audit/request IDs", repository.incompleteAuditID, repository.incompleteRequestID)
	}
	if repository.blockReason != GateReasonFinalizationPersistence {
		t.Fatalf("block reason = %q, want %q", repository.blockReason, GateReasonFinalizationPersistence)
	}
	if err := gate.CheckChatAllowed(context.Background()); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("CheckChatAllowed() after finalization failure = %v, want ErrAuditUnavailable", err)
	}
}

func TestFinalizationFailurePersistsGateAfterClientCancellation(t *testing.T) {
	repository := &degradedRepositoryFake{finalizeErr: errors.New("synthetic post-SSE write failure")}
	gate, err := NewDegradedStateMachine(repository)
	if err != nil {
		t.Fatalf("NewDegradedStateMachine() error = %v", err)
	}
	if err := gate.Recover(context.Background(), time.Date(2026, 8, 5, 9, 0, 0, 0, time.UTC), time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	service, err := NewResponseFinalizationServiceWithGate(&countingEncryptor{}, repository, gate)
	if err != nil {
		t.Fatalf("NewResponseFinalizationServiceWithGate() error = %v", err)
	}
	requestContext, cancel := context.WithCancel(context.Background())
	repository.cancelOnFinalize = cancel

	_, err = service.FinalizeResponse(requestContext, ResponseFinalizationInput{
		AuditID: "audit-1", RequestID: "request-1", OwnerKind: OwnerKindPersonal,
		IdentityID: "employee-1", TeamID: "team-1", ModelID: "gpt-test",
		ResponseJSON: []byte(`{"id":"response-1","choices":[]}`), CaptureStatus: CaptureStatusComplete,
		Outcome: AuditOutcomeSuccess, ObservedResponseBytes: 35,
		CreatedAt:   time.Date(2026, 8, 5, 9, 0, 0, 0, time.UTC),
		CompletedAt: time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC),
	})
	if !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("FinalizeResponse() error = %v, want ErrAuditUnavailable", err)
	}
	if repository.markContextErr != nil {
		t.Fatalf("failure persistence context error = %v, want nil after client cancellation", repository.markContextErr)
	}
}

func TestPostDispatchUsageFailureMarksAuditIncompleteAndBlocksLaterChat(t *testing.T) {
	repository := &degradedRepositoryFake{}
	gate, err := NewDegradedStateMachine(repository)
	if err != nil {
		t.Fatalf("NewDegradedStateMachine() error = %v", err)
	}
	now := time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC)
	if err := gate.Recover(context.Background(), now.Add(-time.Hour), now); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	service, err := NewResponseFinalizationServiceWithGate(&countingEncryptor{}, repository, gate)
	if err != nil {
		t.Fatalf("NewResponseFinalizationServiceWithGate() error = %v", err)
	}

	if err := service.MarkPostDispatchFailure(context.Background(), "audit-usage", "request-usage", GateReasonUsagePersistence, now); err != nil {
		t.Fatalf("MarkPostDispatchFailure() error = %v", err)
	}
	if repository.incompleteAuditID != "audit-usage" || repository.incompleteRequestID != "request-usage" || repository.blockReason != GateReasonUsagePersistence {
		t.Fatalf("post-dispatch reconciliation = (%q, %q, %q)", repository.incompleteAuditID, repository.incompleteRequestID, repository.blockReason)
	}
	if err := gate.CheckChatAllowed(context.Background()); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("CheckChatAllowed() after usage failure = %v, want ErrAuditUnavailable", err)
	}
}

func TestRecoveryReconcilesBeforeOpeningGate(t *testing.T) {
	repository := &degradedRepositoryFake{}
	gate, err := NewDegradedStateMachine(repository)
	if err != nil {
		t.Fatalf("NewDegradedStateMachine() error = %v", err)
	}
	now := time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC)
	if err := gate.Recover(context.Background(), now.Add(-time.Hour), now); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	if repository.reconcileCalls != 1 || repository.probeCalls != 1 {
		t.Fatalf("recovery calls = (reconcile %d, probe %d), want (1, 1)", repository.reconcileCalls, repository.probeCalls)
	}
	if repository.reconcileAt.After(repository.probeAt) {
		t.Fatal("probe opened the gate before reconciliation completed")
	}
	if err := gate.CheckChatAllowed(context.Background()); err != nil {
		t.Fatalf("CheckChatAllowed() after recovery error = %v", err)
	}
}

func TestRecoveryFailureLeavesGateBlocked(t *testing.T) {
	repository := &degradedRepositoryFake{reconcileErr: errors.New("synthetic database unavailable")}
	gate, err := NewDegradedStateMachine(repository)
	if err != nil {
		t.Fatalf("NewDegradedStateMachine() error = %v", err)
	}
	if err := gate.Recover(context.Background(), time.Now().Add(-time.Hour), time.Now()); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("Recover() error = %v, want ErrAuditUnavailable", err)
	}
	if err := gate.CheckChatAllowed(context.Background()); !errors.Is(err, ErrAuditUnavailable) {
		t.Fatalf("CheckChatAllowed() after failed recovery = %v, want ErrAuditUnavailable", err)
	}
	if repository.probeCalls != 0 {
		t.Fatalf("probe calls = %d, want 0 when reconciliation fails", repository.probeCalls)
	}
}

type degradedRepositoryFake struct {
	finalizeErr         error
	reconcileErr        error
	probeErr            error
	blockErr            error
	markContextErr      error
	cancelOnFinalize    context.CancelFunc
	finalizeCalls       int
	reconcileCalls      int
	probeCalls          int
	blockReason         string
	incompleteAuditID   string
	incompleteRequestID string
	reconcileAt         time.Time
	probeAt             time.Time
}

func (repository *degradedRepositoryFake) CreatePendingAudit(context.Context, PendingAudit) error {
	return nil
}

func (repository *degradedRepositoryFake) FinalizeAudit(context.Context, FinalAudit) error {
	repository.finalizeCalls++
	if repository.cancelOnFinalize != nil {
		repository.cancelOnFinalize()
	}
	return repository.finalizeErr
}

func (repository *degradedRepositoryFake) ReadAuditGate(context.Context) (AuditGateSnapshot, error) {
	return AuditGateSnapshot{State: AuditGateStateOpen}, nil
}

func (repository *degradedRepositoryFake) BlockAuditGate(_ context.Context, reason string, _ time.Time) error {
	repository.blockReason = reason
	return repository.blockErr
}

func (repository *degradedRepositoryFake) MarkAuditIncompleteAndBlock(ctx context.Context, auditID, requestID, reason string, completedAt time.Time) error {
	repository.markContextErr = ctx.Err()
	repository.incompleteAuditID = auditID
	repository.incompleteRequestID = requestID
	repository.blockReason = reason
	repository.reconcileAt = completedAt
	return repository.blockErr
}

func (repository *degradedRepositoryFake) ReconcileAndOpenAuditGate(_ context.Context, staleBefore, openedAt time.Time) error {
	repository.reconcileCalls++
	repository.reconcileAt = staleBefore
	if repository.reconcileErr != nil {
		return repository.reconcileErr
	}
	repository.probeCalls++
	repository.probeAt = openedAt
	return repository.probeErr
}

type countingEncryptor struct{ calls int }

func (encryptor *countingEncryptor) Encrypt(plaintext []byte, _ EncryptionContext) (EncryptedContent, error) {
	encryptor.calls++
	return EncryptedContent{Compression: CompressionGZIP, Ciphertext: bytesClone(plaintext), CipherNonce: make([]byte, 12), WrappedDataKey: make([]byte, 32), WrapNonce: make([]byte, 12), KeyVersion: 1}, nil
}

func bytesClone(value []byte) []byte {
	return append([]byte(nil), value...)
}
