package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"n-api-p/internal/audit"
)

var responseLimitTestTime = time.Date(2026, time.August, 7, 10, 0, 0, 0, time.UTC)

func TestReadBoundedLogicalResponseStopsNonStreamingOverflowAtDetectionByte(t *testing.T) {
	source := bytes.NewReader(bytes.Repeat([]byte("a"), int(DefaultLogicalResponseLimit+32)))

	response, err := ReadBoundedLogicalResponse(source, DefaultLogicalResponseLimit)

	assertUpstreamResponseTooLargeError(t, err, DefaultLogicalResponseLimit+1)
	if !response.Truncated() {
		t.Fatal("response is not marked truncated")
	}
	if got := response.Content(); len(got) != int(DefaultLogicalResponseLimit) || !bytes.Equal(got, bytes.Repeat([]byte("a"), len(got))) {
		t.Fatalf("retained prefix length/content = %d, want exact %d-byte prefix", len(got), DefaultLogicalResponseLimit)
	}
	consumed := DefaultLogicalResponseLimit + 32 - int64(source.Len())
	if consumed != DefaultLogicalResponseLimit+1 {
		t.Fatalf("consumed bytes = %d, want %d", consumed, DefaultLogicalResponseLimit+1)
	}
}

func TestReadBoundedLogicalResponseAcceptsExactLimit(t *testing.T) {
	want := bytes.Repeat([]byte("b"), int(DefaultLogicalResponseLimit))

	response, err := ReadBoundedLogicalResponse(bytes.NewReader(want), DefaultLogicalResponseLimit)

	if err != nil {
		t.Fatalf("ReadBoundedLogicalResponse() error = %v", err)
	}
	if response.Truncated() || response.ObservedBytes() != DefaultLogicalResponseLimit {
		t.Fatalf("response state = (truncated %t, observed %d), want (false, %d)", response.Truncated(), response.ObservedBytes(), DefaultLogicalResponseLimit)
	}
	if !bytes.Equal(response.Content(), want) {
		t.Fatal("exact-limit response content changed")
	}
}

func TestNewBoundedResponseAccumulatorRejectsOverflowingLimit(t *testing.T) {
	if _, err := NewBoundedResponseAccumulator(maxInt64Value); !errors.Is(err, ErrInvalidResponseLimit) {
		t.Fatalf("NewBoundedResponseAccumulator() error = %v, want ErrInvalidResponseLimit", err)
	}
}

func TestBoundedResponseAccumulatorTerminatesSSEAtFirstOverflowByte(t *testing.T) {
	accumulator, err := NewBoundedResponseAccumulator(DefaultLogicalResponseLimit)
	if err != nil {
		t.Fatalf("NewBoundedResponseAccumulator() error = %v", err)
	}
	if err := accumulator.Append(bytes.Repeat([]byte("s"), int(DefaultLogicalResponseLimit-2))); err != nil {
		t.Fatalf("Append(prefix) error = %v", err)
	}

	err = accumulator.Append([]byte("WXYZ"))

	assertUpstreamResponseTooLargeError(t, err, DefaultLogicalResponseLimit+1)
	response := accumulator.Snapshot()
	if got := response.Content(); len(got) != int(DefaultLogicalResponseLimit) || !bytes.Equal(got[len(got)-2:], []byte("WX")) {
		t.Fatalf("retained SSE prefix length/tail = (%d, %q), want (%d, %q)", len(got), got[len(got)-2:], DefaultLogicalResponseLimit, "WX")
	}
	if err := accumulator.Append([]byte("ignored")); !errors.Is(err, ErrUpstreamResponseTooLarge) {
		t.Fatalf("Append(after overflow) error = %v, want ErrUpstreamResponseTooLarge", err)
	}
	if after := accumulator.Snapshot(); after.ObservedBytes() != response.ObservedBytes() || !bytes.Equal(after.Content(), response.Content()) {
		t.Fatal("accumulator changed after enforced SSE termination")
	}
}

func TestFinalizeBoundedSSEResponseEncryptsPrefixReleasesSlotAndLeavesGateOpen(t *testing.T) {
	accumulator, err := NewBoundedResponseAccumulator(DefaultLogicalResponseLimit)
	if err != nil {
		t.Fatalf("NewBoundedResponseAccumulator() error = %v", err)
	}
	logicalPrefix := bytes.Repeat([]byte("x"), int(DefaultLogicalResponseLimit))
	if err := accumulator.Append(logicalPrefix); err != nil {
		t.Fatalf("Append(prefix) error = %v", err)
	}
	assertUpstreamResponseTooLargeError(t, accumulator.Append([]byte("overflow")), DefaultLogicalResponseLimit+1)

	repository := &responseLimitRepository{}
	gate, err := audit.NewDegradedStateMachine(repository)
	if err != nil {
		t.Fatalf("NewDegradedStateMachine() error = %v", err)
	}
	if err := gate.Recover(context.Background(), responseLimitTestTime.Add(-time.Hour), responseLimitTestTime); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	envelope, err := audit.NewEnvelopeService(1, map[int][]byte{1: bytes.Repeat([]byte{0x51}, 32)})
	if err != nil {
		t.Fatalf("NewEnvelopeService() error = %v", err)
	}
	finalizer, err := audit.NewResponseFinalizationServiceWithGate(envelope, repository, gate)
	if err != nil {
		t.Fatalf("NewResponseFinalizationServiceWithGate() error = %v", err)
	}

	limiter := NewInProcessLimiter()
	owner := TrafficOwner{Kind: TrafficOwnerEmployee, ID: "employee-response-limit"}
	streamReservation, err := limiter.Acquire(context.Background(), owner)
	if err != nil {
		t.Fatalf("Acquire(stream) error = %v", err)
	}
	defer streamReservation.Release()
	holdOne, err := limiter.Acquire(context.Background(), owner)
	if err != nil {
		t.Fatalf("Acquire(hold one) error = %v", err)
	}
	defer holdOne.Release()
	holdTwo, err := limiter.Acquire(context.Background(), owner)
	if err != nil {
		t.Fatalf("Acquire(hold two) error = %v", err)
	}
	defer holdTwo.Release()

	receipt, err := FinalizeBoundedResponse(
		context.Background(),
		finalizer,
		streamReservation,
		responseFinalizationInput(),
		accumulator.Snapshot(),
	)

	assertUpstreamResponseTooLargeError(t, err, DefaultLogicalResponseLimit+1)
	if receipt.CaptureStatus != audit.CaptureStatusTruncated || receipt.Outcome != audit.AuditOutcomeLocalError {
		t.Fatalf("receipt status/outcome = (%q, %q), want truncated/local_error", receipt.CaptureStatus, receipt.Outcome)
	}
	if repository.final.CaptureStatus != audit.CaptureStatusTruncated || repository.final.Outcome != audit.AuditOutcomeLocalError ||
		repository.final.ErrorCode != "UPSTREAM_RESPONSE_TOO_LARGE" || repository.final.FinishReason != "" ||
		repository.final.ObservedResponseBytes != DefaultLogicalResponseLimit+1 || repository.final.UpstreamRequestID != "upstream-response-limit" {
		t.Fatalf("final audit metadata = %+v", repository.final)
	}
	if repository.final.ResponseContent == nil {
		t.Fatal("truncated response prefix was not encrypted")
	}
	opened, err := envelope.Decrypt(*repository.final.ResponseContent, audit.EncryptionContext{
		AuditID: "audit-response-limit", ContentKind: audit.ContentKindResponse, OwnerKind: audit.OwnerKindPersonal,
		IdentityID: "employee-response-limit", TeamID: "team-response-limit", CreatedAt: responseLimitTestTime,
	})
	if err != nil {
		t.Fatalf("decrypt truncated prefix: %v", err)
	}
	if !bytes.Equal(opened, logicalPrefix) {
		t.Fatalf("decrypted prefix length/content = %d, want exact bounded prefix", len(opened))
	}
	if err := gate.CheckChatAllowed(context.Background()); err != nil {
		t.Fatalf("CheckChatAllowed() after successful size truncation = %v", err)
	}
	replacement, err := limiter.Acquire(context.Background(), owner)
	if err != nil {
		t.Fatalf("Acquire() after SSE overflow finalization = %v, want released slot", err)
	}
	replacement.Release()
}

func TestBoundedResponseDiagnosticsExcludeContent(t *testing.T) {
	accumulator, err := NewBoundedResponseAccumulator(8)
	if err != nil {
		t.Fatalf("NewBoundedResponseAccumulator() error = %v", err)
	}
	plaintext := "secret-response"
	_ = accumulator.Append([]byte(plaintext))
	response := accumulator.Snapshot()
	var logBuffer bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuffer, nil)).Info("bounded response", "accumulator", accumulator, "response", response)
	output := fmt.Sprintf("%+v %#v %+v %#v", accumulator, accumulator, response, response) + logBuffer.String()
	if strings.Contains(output, plaintext[:8]) {
		t.Fatal("bounded response diagnostics exposed retained content")
	}
}

func TestFinalizeBoundedResponseReleasesReservationOnInvalidFinalizer(t *testing.T) {
	accumulator, err := NewBoundedResponseAccumulator(8)
	if err != nil {
		t.Fatalf("NewBoundedResponseAccumulator() error = %v", err)
	}
	if err := accumulator.Append([]byte("bounded")); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	reservation := &countingResponseReservation{}

	_, err = FinalizeBoundedResponse(context.Background(), nil, reservation, responseFinalizationInput(), accumulator.Snapshot())

	if !errors.Is(err, ErrResponseFinalizerMissing) {
		t.Fatalf("FinalizeBoundedResponse() error = %v, want ErrResponseFinalizerMissing", err)
	}
	if reservation.releases != 1 {
		t.Fatalf("reservation releases = %d, want 1", reservation.releases)
	}
}

func TestBoundedResponseValidationRejectsAmbiguousByteCounts(t *testing.T) {
	tests := map[string]BoundedResponse{
		"complete mismatch":               {limit: 8, content: []byte("body"), observed: 5},
		"truncated beyond detection byte": {limit: 4, content: []byte("body"), observed: 6, truncated: true},
	}
	for name, response := range tests {
		t.Run(name, func(t *testing.T) {
			if err := response.validate(); !errors.Is(err, ErrInvalidBoundedResponse) {
				t.Fatalf("validate() error = %v, want ErrInvalidBoundedResponse", err)
			}
		})
	}
}

func assertUpstreamResponseTooLargeError(t *testing.T, err error, wantObservedBytes int64) {
	t.Helper()
	if !errors.Is(err, ErrUpstreamResponseTooLarge) {
		t.Fatalf("error = %v, want ErrUpstreamResponseTooLarge", err)
	}
	var sizeErr *UpstreamResponseTooLargeError
	if !errors.As(err, &sizeErr) {
		t.Fatalf("error type = %T, want *UpstreamResponseTooLargeError", err)
	}
	if sizeErr.ObservedBytes != wantObservedBytes {
		t.Fatalf("observed bytes = %d, want %d", sizeErr.ObservedBytes, wantObservedBytes)
	}
	if err.Error() != "upstream response is too large" {
		t.Fatalf("error text = %q, want stable content-free message", err.Error())
	}
}

func responseFinalizationInput() audit.ResponseFinalizationInput {
	return audit.ResponseFinalizationInput{
		AuditID: "audit-response-limit", RequestID: "request-response-limit", OwnerKind: audit.OwnerKindPersonal,
		IdentityID: "employee-response-limit", TeamID: "team-response-limit", ModelID: "gpt-test",
		ResponseJSON: []byte("unbounded caller content must be replaced"), CaptureStatus: audit.CaptureStatusComplete,
		Outcome: audit.AuditOutcomeSuccess, UpstreamRequestID: "upstream-response-limit", FinishReason: "stop",
		ObservedResponseBytes: 999, CreatedAt: responseLimitTestTime, CompletedAt: responseLimitTestTime.Add(time.Minute),
	}
}

type responseLimitRepository struct {
	final audit.FinalAudit
	gate  audit.AuditGateSnapshot
}

type countingResponseReservation struct {
	releases int
}

func (reservation *countingResponseReservation) Release() {
	reservation.releases++
}

func (repository *responseLimitRepository) FinalizeAudit(_ context.Context, final audit.FinalAudit) error {
	repository.final = final
	return nil
}

func (repository *responseLimitRepository) ReadAuditGate(context.Context) (audit.AuditGateSnapshot, error) {
	return repository.gate, nil
}

func (repository *responseLimitRepository) BlockAuditGate(_ context.Context, reason string, changedAt time.Time) error {
	repository.gate = audit.AuditGateSnapshot{State: audit.AuditGateStateBlocked, ReasonCode: reason, ChangedAt: changedAt}
	return nil
}

func (repository *responseLimitRepository) MarkAuditIncompleteAndBlock(_ context.Context, _, _, reason string, changedAt time.Time) error {
	repository.gate = audit.AuditGateSnapshot{State: audit.AuditGateStateBlocked, ReasonCode: reason, ChangedAt: changedAt}
	return nil
}

func (repository *responseLimitRepository) ReconcileAndOpenAuditGate(_ context.Context, _, openedAt time.Time) error {
	repository.gate = audit.AuditGateSnapshot{State: audit.AuditGateStateOpen, ChangedAt: openedAt}
	return nil
}
