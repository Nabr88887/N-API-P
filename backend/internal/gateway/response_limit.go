package gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"n-api-p/internal/audit"
)

const (
	DefaultLogicalResponseLimit int64 = 4 * 1024 * 1024
	maxInt64Value                     = int64(^uint64(0) >> 1)
)

var (
	ErrUpstreamResponseTooLarge   = errors.New("upstream response is too large")
	ErrInvalidResponseLimit       = errors.New("response limit must be positive")
	ErrNilResponseReader          = errors.New("response reader is nil")
	ErrInvalidBoundedResponse     = errors.New("invalid bounded response")
	ErrResponseFinalizerMissing   = errors.New("response finalizer is missing")
	ErrResponseReservationMissing = errors.New("response reservation is missing")
)

type UpstreamResponseTooLargeError struct {
	ObservedBytes int64
}

func (err *UpstreamResponseTooLargeError) Error() string {
	return ErrUpstreamResponseTooLarge.Error()
}

func (err *UpstreamResponseTooLargeError) Unwrap() error {
	return ErrUpstreamResponseTooLarge
}

type BoundedResponseAccumulator struct {
	limit     int64
	content   []byte
	observed  int64
	truncated bool
}

type BoundedResponse struct {
	limit     int64
	content   []byte
	observed  int64
	truncated bool
}

func NewBoundedResponseAccumulator(limit int64) (*BoundedResponseAccumulator, error) {
	if !validResponseLimit(limit) {
		return nil, ErrInvalidResponseLimit
	}
	return &BoundedResponseAccumulator{limit: limit}, nil
}

func (accumulator *BoundedResponseAccumulator) Append(chunk []byte) error {
	if accumulator == nil || accumulator.limit <= 0 {
		return ErrInvalidBoundedResponse
	}
	if accumulator.truncated {
		return &UpstreamResponseTooLargeError{ObservedBytes: accumulator.observed}
	}
	if len(chunk) == 0 {
		return nil
	}

	remaining := accumulator.limit - int64(len(accumulator.content))
	if int64(len(chunk)) <= remaining {
		accumulator.content = append(accumulator.content, chunk...)
		accumulator.observed += int64(len(chunk))
		return nil
	}

	if remaining > 0 {
		accumulator.content = append(accumulator.content, chunk[:int(remaining)]...)
	}
	accumulator.observed = accumulator.limit + 1
	accumulator.truncated = true
	return &UpstreamResponseTooLargeError{ObservedBytes: accumulator.observed}
}

func (accumulator *BoundedResponseAccumulator) Snapshot() BoundedResponse {
	if accumulator == nil {
		return BoundedResponse{}
	}
	return BoundedResponse{
		limit: accumulator.limit, content: bytes.Clone(accumulator.content),
		observed: accumulator.observed, truncated: accumulator.truncated,
	}
}

func (response BoundedResponse) Content() []byte {
	return bytes.Clone(response.content)
}

func (response BoundedResponse) ObservedBytes() int64 {
	return response.observed
}

func (response BoundedResponse) Truncated() bool {
	return response.truncated
}

func ReadBoundedLogicalResponse(reader io.Reader, limit int64) (BoundedResponse, error) {
	if reader == nil {
		return BoundedResponse{}, ErrNilResponseReader
	}
	if !validResponseLimit(limit) {
		return BoundedResponse{}, ErrInvalidResponseLimit
	}

	limited := &io.LimitedReader{R: reader, N: limit}
	content, err := io.ReadAll(limited)
	if err != nil {
		return BoundedResponse{}, fmt.Errorf("read upstream response: %w", err)
	}
	if int64(len(content)) < limit {
		return BoundedResponse{limit: limit, content: content, observed: int64(len(content))}, nil
	}

	var detectionByte [1]byte
	readBytes, err := io.ReadFull(reader, detectionByte[:])
	if readBytes > 0 {
		observed := limit + int64(readBytes)
		return BoundedResponse{limit: limit, content: content, observed: observed, truncated: true},
			&UpstreamResponseTooLargeError{ObservedBytes: observed}
	}
	if errors.Is(err, io.EOF) {
		return BoundedResponse{limit: limit, content: content, observed: int64(len(content))}, nil
	}
	if err != nil {
		return BoundedResponse{}, fmt.Errorf("read upstream response: %w", err)
	}
	return BoundedResponse{limit: limit, content: content, observed: int64(len(content))}, nil
}

type ResponseFinalizer interface {
	FinalizeResponse(context.Context, audit.ResponseFinalizationInput) (audit.FinalizationReceipt, error)
}

func FinalizeBoundedResponse(
	ctx context.Context,
	finalizer ResponseFinalizer,
	reservation Reservation,
	input audit.ResponseFinalizationInput,
	response BoundedResponse,
) (audit.FinalizationReceipt, error) {
	if reservation == nil {
		return audit.FinalizationReceipt{}, ErrResponseReservationMissing
	}
	defer reservation.Release()
	if ctx == nil {
		return audit.FinalizationReceipt{}, ErrInvalidBoundedResponse
	}
	if finalizer == nil {
		return audit.FinalizationReceipt{}, ErrResponseFinalizerMissing
	}
	if err := response.validate(); err != nil {
		return audit.FinalizationReceipt{}, err
	}

	input.ResponseJSON = response.content
	input.ObservedResponseBytes = response.ObservedBytes()
	if response.Truncated() {
		input.CaptureStatus = audit.CaptureStatusTruncated
		input.Outcome = audit.AuditOutcomeLocalError
		input.ErrorCode = "UPSTREAM_RESPONSE_TOO_LARGE"
		input.FinishReason = ""
	}

	receipt, err := finalizer.FinalizeResponse(ctx, input)
	if err != nil {
		return audit.FinalizationReceipt{}, err
	}
	if response.Truncated() {
		return receipt, &UpstreamResponseTooLargeError{ObservedBytes: response.ObservedBytes()}
	}
	return receipt, nil
}

func (response BoundedResponse) validate() error {
	if !validResponseLimit(response.limit) || response.observed < int64(len(response.content)) {
		return ErrInvalidBoundedResponse
	}
	if response.truncated {
		if response.observed != response.limit+1 || int64(len(response.content)) != response.limit {
			return ErrInvalidBoundedResponse
		}
		return nil
	}
	if response.observed != int64(len(response.content)) || response.observed > response.limit {
		return ErrInvalidBoundedResponse
	}
	return nil
}

func validResponseLimit(limit int64) bool {
	return limit > 0 && limit < maxInt64Value
}

func (accumulator BoundedResponseAccumulator) String() string {
	return fmt.Sprintf("BoundedResponseAccumulator{limit=%d observed_bytes=%d content_bytes=%d truncated=%t}", accumulator.limit, accumulator.observed, len(accumulator.content), accumulator.truncated)
}

func (accumulator BoundedResponseAccumulator) GoString() string {
	return accumulator.String()
}

func (accumulator BoundedResponseAccumulator) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int64("limit", accumulator.limit),
		slog.Int64("observed_bytes", accumulator.observed),
		slog.Int("content_bytes", len(accumulator.content)),
		slog.Bool("truncated", accumulator.truncated),
	)
}

func (response BoundedResponse) String() string {
	return fmt.Sprintf("BoundedResponse{limit=%d observed_bytes=%d content_bytes=%d truncated=%t}", response.limit, response.observed, len(response.content), response.truncated)
}

func (response BoundedResponse) GoString() string {
	return response.String()
}

func (response BoundedResponse) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int64("limit", response.limit),
		slog.Int64("observed_bytes", response.observed),
		slog.Int("content_bytes", len(response.content)),
		slog.Bool("truncated", response.truncated),
	)
}
