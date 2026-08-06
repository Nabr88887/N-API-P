package audit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestResponseFinalizationCapturesCompleteRegularResponse(t *testing.T) {
	plaintext := []byte(`{"id":"chatcmpl-1","choices":[{"message":{"role":"assistant","content":"hello"}}]}`)
	envelope := newDeterministicEnvelopeService(t, 1, map[int][]byte{1: bytes.Repeat([]byte{0x41}, 32)}, sequentialBytes(56))
	repository := &recordingFinalAuditRepository{}
	service, err := NewResponseFinalizationService(envelope, repository)
	if err != nil {
		t.Fatalf("NewResponseFinalizationService() error = %v", err)
	}

	receipt, err := service.FinalizeResponse(context.Background(), finalizationInput(plaintext, CaptureStatusComplete, AuditOutcomeSuccess))
	if err != nil {
		t.Fatalf("FinalizeResponse() error = %v", err)
	}
	if receipt.AuditID != "audit-1" || receipt.RequestID != "request-1" || receipt.CaptureStatus != CaptureStatusComplete {
		t.Fatalf("receipt = %+v, want committed complete receipt", receipt)
	}
	if repository.record.CaptureStatus != CaptureStatusComplete || repository.record.Outcome != AuditOutcomeSuccess {
		t.Fatalf("final state = (%q, %q), want complete/success", repository.record.CaptureStatus, repository.record.Outcome)
	}
	if repository.record.ResponseContent == nil {
		t.Fatal("complete response did not persist encrypted response content")
	}
	opened, err := envelope.Decrypt(*repository.record.ResponseContent, responseEncryptionContext(repository.record))
	if err != nil {
		t.Fatalf("decrypt response: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("decrypted response = %q, want exact response", opened)
	}
}

func TestResponseFinalizationCapturesReconstructedSSELogicalResponse(t *testing.T) {
	logicalResponse := []byte(`{"id":"chatcmpl-stream","choices":[{"delta":{"content":"hello world"},"finish_reason":"stop"}]}`)
	envelope := newDeterministicEnvelopeService(t, 1, map[int][]byte{1: bytes.Repeat([]byte{0x42}, 32)}, sequentialBytes(56))
	repository := &recordingFinalAuditRepository{}
	service, err := NewResponseFinalizationService(envelope, repository)
	if err != nil {
		t.Fatalf("NewResponseFinalizationService() error = %v", err)
	}

	if _, err := service.FinalizeResponse(context.Background(), finalizationInput(logicalResponse, CaptureStatusComplete, AuditOutcomeSuccess)); err != nil {
		t.Fatalf("FinalizeResponse() error = %v", err)
	}
	if repository.record.ResponseContent == nil {
		t.Fatal("SSE logical response did not persist response content")
	}
	opened, err := envelope.Decrypt(*repository.record.ResponseContent, responseEncryptionContext(repository.record))
	if err != nil {
		t.Fatalf("decrypt reconstructed SSE response: %v", err)
	}
	if !bytes.Equal(opened, logicalResponse) {
		t.Fatalf("decrypted SSE response = %q, want reconstructed logical response", opened)
	}
}

func TestResponseFinalizationCapturesStructuredUpstreamErrorWithoutSuccessOutcome(t *testing.T) {
	errorBody := []byte(`{"error":{"message":"upstream unavailable","type":"server_error","code":"UPSTREAM_DOWN"}}`)
	envelope := newDeterministicEnvelopeService(t, 1, map[int][]byte{1: bytes.Repeat([]byte{0x43}, 32)}, sequentialBytes(56))
	repository := &recordingFinalAuditRepository{}
	service, err := NewResponseFinalizationService(envelope, repository)
	if err != nil {
		t.Fatalf("NewResponseFinalizationService() error = %v", err)
	}

	input := finalizationInput(errorBody, CaptureStatusComplete, AuditOutcomeUpstreamError)
	input.UpstreamHTTPStatus = intPointer(503)
	input.ErrorCode = "UPSTREAM_DOWN"
	if _, err := service.FinalizeResponse(context.Background(), input); err != nil {
		t.Fatalf("FinalizeResponse() error = %v", err)
	}
	if repository.record.Outcome != AuditOutcomeUpstreamError || repository.record.Outcome == AuditOutcomeSuccess {
		t.Fatalf("upstream error outcome = %q, must not be success", repository.record.Outcome)
	}
}

func TestResponseFinalizationRecordsCancellationAsIncomplete(t *testing.T) {
	envelope := newDeterministicEnvelopeService(t, 1, map[int][]byte{1: bytes.Repeat([]byte{0x44}, 32)}, sequentialBytes(56))
	repository := &recordingFinalAuditRepository{}
	service, err := NewResponseFinalizationService(envelope, repository)
	if err != nil {
		t.Fatalf("NewResponseFinalizationService() error = %v", err)
	}

	input := finalizationInput(nil, CaptureStatusIncomplete, AuditOutcomeCancelled)
	input.ObservedResponseBytes = 17
	if _, err := service.FinalizeResponse(context.Background(), input); err != nil {
		t.Fatalf("FinalizeResponse() error = %v", err)
	}
	if repository.record.CaptureStatus != CaptureStatusIncomplete || repository.record.Outcome != AuditOutcomeCancelled {
		t.Fatalf("cancellation state = (%q, %q), want incomplete/cancelled", repository.record.CaptureStatus, repository.record.Outcome)
	}
	if repository.record.ResponseContent != nil {
		t.Fatal("empty cancelled response unexpectedly persisted as response content")
	}
}

func TestResponseFinalizationPersistsPreclassifiedTruncation(t *testing.T) {
	prefix := []byte(`{"id":"chatcmpl-truncated","choices":[]}`)
	envelope := newDeterministicEnvelopeService(t, 1, map[int][]byte{1: bytes.Repeat([]byte{0x45}, 32)}, sequentialBytes(56))
	repository := &recordingFinalAuditRepository{}
	service, err := NewResponseFinalizationService(envelope, repository)
	if err != nil {
		t.Fatalf("NewResponseFinalizationService() error = %v", err)
	}

	input := finalizationInput(prefix, CaptureStatusTruncated, AuditOutcomeSuccess)
	input.ObservedResponseBytes = int64(len(prefix) + 1)
	if _, err := service.FinalizeResponse(context.Background(), input); err != nil {
		t.Fatalf("FinalizeResponse() error = %v", err)
	}
	if repository.record.CaptureStatus != CaptureStatusTruncated {
		t.Fatalf("capture status = %q, want truncated", repository.record.CaptureStatus)
	}
	if repository.record.ObservedResponseBytes != int64(len(prefix)+1) {
		t.Fatalf("observed response bytes = %d, want %d", repository.record.ObservedResponseBytes, len(prefix)+1)
	}
}

func TestResponseFinalizationRejectsInvalidPendingTransitionsWithoutPersistence(t *testing.T) {
	envelope := newDeterministicEnvelopeService(t, 1, map[int][]byte{1: bytes.Repeat([]byte{0x46}, 32)}, sequentialBytes(56))
	repository := &recordingFinalAuditRepository{}
	service, err := NewResponseFinalizationService(envelope, repository)
	if err != nil {
		t.Fatalf("NewResponseFinalizationService() error = %v", err)
	}

	for name, input := range map[string]ResponseFinalizationInput{
		"pending status":     finalizationInput([]byte(`{"ok":true}`), CaptureStatusPending, AuditOutcomePending),
		"cancelled complete": finalizationInput([]byte(`{"ok":true}`), CaptureStatusComplete, AuditOutcomeCancelled),
		"success incomplete": finalizationInput([]byte(`{"ok":true}`), CaptureStatusIncomplete, AuditOutcomeSuccess),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := service.FinalizeResponse(context.Background(), input)
			if !errors.Is(err, ErrInvalidFinalization) {
				t.Fatalf("FinalizeResponse() error = %v, want ErrInvalidFinalization", err)
			}
			if repository.calls != 0 {
				t.Fatal("invalid finalization reached repository")
			}
		})
	}
}

func TestResponseFinalizationReturnsNoReceiptWhenEncryptionOrPersistenceFails(t *testing.T) {
	plaintext := []byte(`{"ok":true}`)
	persistenceErr := errors.New("synthetic final commit failure")
	for name, encryptor := range map[string]ContentEncryptor{
		"encryption":  failingContentEncryptor{err: ErrInvalidMasterKey},
		"persistence": passthroughContentEncryptor{},
	} {
		t.Run(name, func(t *testing.T) {
			repository := &recordingFinalAuditRepository{}
			if name == "persistence" {
				repository.err = persistenceErr
			}
			service, err := NewResponseFinalizationService(encryptor, repository)
			if err != nil {
				t.Fatalf("NewResponseFinalizationService() error = %v", err)
			}
			receipt, err := service.FinalizeResponse(context.Background(), finalizationInput(plaintext, CaptureStatusComplete, AuditOutcomeSuccess))
			if receipt != (FinalizationReceipt{}) {
				t.Fatalf("receipt = %+v, want empty receipt on failure", receipt)
			}
			if !errors.Is(err, ErrAuditUnavailable) {
				t.Fatalf("FinalizeResponse() error = %v, want ErrAuditUnavailable", err)
			}
		})
	}
}

func TestResponseFinalizationOutputExcludesPlaintextAndCiphertext(t *testing.T) {
	plaintext := []byte(`{"secret":"response plaintext"}`)
	input := finalizationInput(plaintext, CaptureStatusComplete, AuditOutcomeSuccess)
	record := FinalAudit{
		ID: "audit-1", RequestID: "request-1", OwnerKind: OwnerKindPersonal, IdentityID: "employee-1", TeamID: "team-1",
		CaptureStatus: CaptureStatusComplete, Outcome: AuditOutcomeSuccess,
		ResponseContent: &EncryptedContent{Compression: CompressionGZIP, Ciphertext: bytes.Repeat([]byte{0x61}, 37), CipherNonce: bytes.Repeat([]byte{0x62}, 12), WrappedDataKey: bytes.Repeat([]byte{0x63}, 48), WrapNonce: bytes.Repeat([]byte{0x64}, 12), KeyVersion: 1},
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var logBuffer bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuffer, nil)).Info("final audit", "record", record)
	output := string(encoded) + fmt.Sprintf("%+v %#v", input, input) + fmt.Sprintf("%+v %#v", record, record) + logBuffer.String()
	if strings.Contains(output, string(plaintext)) {
		t.Fatal("response plaintext appeared in finalization output")
	}
	for _, value := range [][]byte{record.ResponseContent.Ciphertext, record.ResponseContent.CipherNonce, record.ResponseContent.WrappedDataKey, record.ResponseContent.WrapNonce} {
		for _, forbidden := range []string{base64.StdEncoding.EncodeToString(value), hex.EncodeToString(value), fmt.Sprint(value)} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("encrypted response material %q appeared in output", forbidden)
			}
		}
	}
}

func finalizationInput(response []byte, status CaptureStatus, outcome AuditOutcome) ResponseFinalizationInput {
	return ResponseFinalizationInput{
		AuditID: "audit-1", RequestID: "request-1", OwnerKind: OwnerKindPersonal, IdentityID: "employee-1", TeamID: "team-1",
		ModelID: "gpt-test", ResponseJSON: response, CaptureStatus: status, Outcome: outcome,
		ObservedResponseBytes: int64(len(response)), CreatedAt: captureTestCreatedAt, CompletedAt: captureTestCreatedAt.Add(time.Minute),
		UpstreamRequestID: "upstream-1", FinishReason: "stop",
	}
}

func responseEncryptionContext(record FinalAudit) EncryptionContext {
	return EncryptionContext{AuditID: record.ID, ContentKind: ContentKindResponse, OwnerKind: record.OwnerKind, IdentityID: record.IdentityID, ServiceAccountID: record.ServiceAccountID, ResponsibleIdentityID: record.ResponsibleIdentityID, TeamID: record.TeamID, CreatedAt: record.CreatedAt}
}

func intPointer(value int) *int { return &value }

type recordingFinalAuditRepository struct {
	record FinalAudit
	err    error
	calls  int
}

func (repository *recordingFinalAuditRepository) FinalizeAudit(_ context.Context, record FinalAudit) error {
	repository.calls++
	if repository.err != nil {
		return repository.err
	}
	repository.record = record
	return nil
}

type failingContentEncryptor struct{ err error }

func (encryptor failingContentEncryptor) Encrypt([]byte, EncryptionContext) (EncryptedContent, error) {
	return EncryptedContent{}, encryptor.err
}

type passthroughContentEncryptor struct{}

func (passthroughContentEncryptor) Encrypt(plaintext []byte, _ EncryptionContext) (EncryptedContent, error) {
	return EncryptedContent{Compression: CompressionGZIP, Ciphertext: bytes.Clone(plaintext), CipherNonce: bytes.Repeat([]byte{0x61}, 12), WrappedDataKey: bytes.Repeat([]byte{0x62}, 48), WrapNonce: bytes.Repeat([]byte{0x63}, 12), KeyVersion: 1}, nil
}
