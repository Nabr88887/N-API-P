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

var (
	captureTestCreatedAt = time.Date(2026, time.August, 4, 9, 30, 0, 0, time.UTC)
	captureTestExpiresAt = time.Date(2026, time.August, 11, 0, 0, 0, 0, time.UTC)
)

func TestInitialCaptureCommitsEncryptedPendingRequestBeforeDispatch(t *testing.T) {
	plaintext := []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"confidential prompt"}]}`)
	envelope := newDeterministicEnvelopeService(
		t,
		1,
		map[int][]byte{1: bytes.Repeat([]byte{0x31}, 32)},
		sequentialBytes(56),
	)
	events := make([]string, 0, 2)
	repository := &recordingPendingAuditRepository{store: func(record PendingAudit) error {
		events = append(events, "commit")
		if record.CaptureStatus != CaptureStatusPending || record.Outcome != AuditOutcomePending {
			t.Fatalf("pending state = (%q, %q), want (%q, %q)", record.CaptureStatus, record.Outcome, CaptureStatusPending, AuditOutcomePending)
		}
		if record.ObservedRequestBytes != int64(len(plaintext)) {
			t.Fatalf("observed request bytes = %d, want %d", record.ObservedRequestBytes, len(plaintext))
		}
		if !record.ExpiresAt.Equal(captureTestExpiresAt) {
			t.Fatalf("expires at = %s, want %s", record.ExpiresAt, captureTestExpiresAt)
		}
		decrypted, err := envelope.Decrypt(record.RequestContent, EncryptionContext{
			AuditID: record.ID, ContentKind: ContentKindRequest, OwnerKind: record.OwnerKind,
			IdentityID: record.IdentityID, TeamID: record.TeamID, CreatedAt: record.CreatedAt,
		})
		if err != nil {
			t.Fatalf("decrypt persisted request: %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("decrypted request = %q, want original validated JSON", decrypted)
		}
		return nil
	}}
	service, err := NewInitialCaptureService(envelope, repository)
	if err != nil {
		t.Fatalf("NewInitialCaptureService() error = %v", err)
	}

	receipt, err := service.CaptureValidatedRequest(context.Background(), personalCaptureInput(plaintext))
	if err != nil {
		t.Fatalf("CaptureValidatedRequest() error = %v", err)
	}
	events = append(events, "dispatch")

	if receipt.AuditID != "audit-1" || receipt.RequestID != "request-1" {
		t.Fatalf("receipt = %+v, want committed audit/request IDs", receipt)
	}
	if strings.Join(events, ",") != "commit,dispatch" {
		t.Fatalf("event order = %v, want commit before dispatch", events)
	}
	if repository.calls != 1 {
		t.Fatalf("repository calls = %d, want 1", repository.calls)
	}
	assertPendingAuditContainsNoPlaintext(t, repository.record, plaintext)
}

func TestInitialCaptureFailsClosedBeforePersistenceWhenEncryptionFails(t *testing.T) {
	plaintext := []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"never persist plaintext"}]}`)
	repository := &recordingPendingAuditRepository{}
	service, err := NewInitialCaptureService(failingRequestEncryptor{err: ErrInvalidMasterKey}, repository)
	if err != nil {
		t.Fatalf("NewInitialCaptureService() error = %v", err)
	}

	receipt, err := service.CaptureValidatedRequest(context.Background(), personalCaptureInput(plaintext))
	if !errors.Is(err, ErrAuditUnavailable) || !errors.Is(err, ErrInvalidMasterKey) {
		t.Fatalf("CaptureValidatedRequest() error = %v, want ErrAuditUnavailable wrapping ErrInvalidMasterKey", err)
	}
	if receipt != (CaptureReceipt{}) {
		t.Fatalf("receipt = %+v, want zero value", receipt)
	}
	if repository.calls != 0 {
		t.Fatalf("repository calls = %d, want 0", repository.calls)
	}
}

func TestInitialCaptureFailsClosedBeforeDispatchWhenPersistenceFails(t *testing.T) {
	plaintext := []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"do not dispatch"}]}`)
	persistenceErr := errors.New("synthetic commit failure")
	repository := &recordingPendingAuditRepository{store: func(PendingAudit) error { return persistenceErr }}
	service, err := NewInitialCaptureService(passthroughRequestEncryptor{}, repository)
	if err != nil {
		t.Fatalf("NewInitialCaptureService() error = %v", err)
	}
	dispatched := false

	receipt, err := service.CaptureValidatedRequest(context.Background(), personalCaptureInput(plaintext))
	if err == nil {
		dispatched = true
	}

	if dispatched {
		t.Fatal("request dispatched after pending-audit persistence failure")
	}
	if !errors.Is(err, ErrAuditUnavailable) || !errors.Is(err, persistenceErr) {
		t.Fatalf("CaptureValidatedRequest() error = %v, want ErrAuditUnavailable wrapping persistence failure", err)
	}
	if receipt != (CaptureReceipt{}) {
		t.Fatalf("receipt = %+v, want zero value", receipt)
	}
	assertPendingAuditContainsNoPlaintext(t, repository.record, plaintext)
}

func TestInitialCapturePropagatesCancelledContextWithoutEncryptingOrPersisting(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	encryptor := &recordingRequestEncryptor{}
	repository := &recordingPendingAuditRepository{}
	service, err := NewInitialCaptureService(encryptor, repository)
	if err != nil {
		t.Fatalf("NewInitialCaptureService() error = %v", err)
	}

	receipt, err := service.CaptureValidatedRequest(ctx, personalCaptureInput([]byte(`{"model":"gpt-test"}`)))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("CaptureValidatedRequest() error = %v, want context.Canceled", err)
	}
	if receipt != (CaptureReceipt{}) || encryptor.calls != 0 || repository.calls != 0 {
		t.Fatalf("cancelled capture = (receipt=%+v encrypt=%d persist=%d), want no work", receipt, encryptor.calls, repository.calls)
	}
}

func TestInitialCaptureInputAndPendingAuditRedactContentFromOutput(t *testing.T) {
	plaintext := []byte(`{"messages":[{"role":"user","content":"output boundary secret"}]}`)
	input := personalCaptureInput(plaintext)
	record := PendingAudit{
		ID: "audit-1", RequestID: "request-1", KeyID: "key-1", OwnerKind: OwnerKindPersonal,
		IdentityID: "employee-1", TeamID: "team-1", ModelID: "gpt-test",
		CaptureStatus: CaptureStatusPending, Outcome: AuditOutcomePending,
		ObservedRequestBytes: int64(len(plaintext)), CreatedAt: captureTestCreatedAt, ExpiresAt: captureTestExpiresAt,
		RequestContent: EncryptedContent{
			Compression: CompressionGZIP, Ciphertext: bytes.Repeat([]byte{0x71}, 37),
			CipherNonce: bytes.Repeat([]byte{0x72}, 12), WrappedDataKey: bytes.Repeat([]byte{0x73}, 48),
			WrapNonce: bytes.Repeat([]byte{0x74}, 12), KeyVersion: 3,
		},
	}

	encodedInput, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("json.Marshal(input) error = %v", err)
	}
	encodedRecord, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json.Marshal(record) error = %v", err)
	}
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	logger.Info("capture", "input", input, "record", record)
	output := string(encodedInput) + string(encodedRecord) + fmt.Sprintf("%+v %#v %+v %#v", input, input, record, record) + logs.String()
	for _, forbidden := range []string{
		string(plaintext), base64.StdEncoding.EncodeToString(plaintext), hex.EncodeToString(plaintext), fmt.Sprint(plaintext),
		base64.StdEncoding.EncodeToString(record.RequestContent.Ciphertext), hex.EncodeToString(record.RequestContent.Ciphertext), fmt.Sprint(record.RequestContent.Ciphertext),
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("sensitive capture material %q appeared in output", forbidden)
		}
	}
}

func personalCaptureInput(plaintext []byte) InitialCaptureInput {
	return InitialCaptureInput{
		ID: "audit-1", RequestID: "request-1", KeyID: "key-1", OwnerKind: OwnerKindPersonal,
		IdentityID: "employee-1", TeamID: "team-1", ModelID: "gpt-test",
		ValidatedRequestJSON: plaintext, CreatedAt: captureTestCreatedAt, ExpiresAt: captureTestExpiresAt,
	}
}

func assertPendingAuditContainsNoPlaintext(t *testing.T, record PendingAudit, plaintext []byte) {
	t.Helper()
	output := fmt.Sprintf("%+v %#v", record, record)
	for _, forbidden := range []string{string(plaintext), base64.StdEncoding.EncodeToString(plaintext), hex.EncodeToString(plaintext), fmt.Sprint(plaintext)} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("plaintext representation %q appeared in pending audit", forbidden)
		}
	}
}

type recordingPendingAuditRepository struct {
	record PendingAudit
	calls  int
	store  func(PendingAudit) error
}

func (repository *recordingPendingAuditRepository) CreatePendingAudit(_ context.Context, record PendingAudit) error {
	repository.calls++
	repository.record = record
	if repository.store != nil {
		return repository.store(record)
	}
	return nil
}

type failingRequestEncryptor struct{ err error }

func (encryptor failingRequestEncryptor) Encrypt([]byte, EncryptionContext) (EncryptedContent, error) {
	return EncryptedContent{}, encryptor.err
}

type passthroughRequestEncryptor struct{}

func (passthroughRequestEncryptor) Encrypt([]byte, EncryptionContext) (EncryptedContent, error) {
	return EncryptedContent{
		Compression: CompressionGZIP, Ciphertext: bytes.Repeat([]byte{0x41}, 37),
		CipherNonce: bytes.Repeat([]byte{0x42}, 12), WrappedDataKey: bytes.Repeat([]byte{0x43}, 48),
		WrapNonce: bytes.Repeat([]byte{0x44}, 12), KeyVersion: 1,
	}, nil
}

type recordingRequestEncryptor struct{ calls int }

func (encryptor *recordingRequestEncryptor) Encrypt([]byte, EncryptionContext) (EncryptedContent, error) {
	encryptor.calls++
	return EncryptedContent{}, nil
}
