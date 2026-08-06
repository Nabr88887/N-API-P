package audit

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

var (
	ErrAuditUnavailable      = errors.New("audit unavailable")
	ErrInvalidCaptureService = errors.New("invalid initial capture service")
	ErrInvalidFinalization   = errors.New("invalid audit finalization")
	ErrAuditNotPending       = errors.New("audit is not pending")
)

type CaptureStatus string

const (
	CaptureStatusPending    CaptureStatus = "pending"
	CaptureStatusComplete   CaptureStatus = "complete"
	CaptureStatusTruncated  CaptureStatus = "truncated"
	CaptureStatusIncomplete CaptureStatus = "incomplete"
)

type AuditOutcome string

const (
	AuditOutcomePending       AuditOutcome = "pending"
	AuditOutcomeSuccess       AuditOutcome = "success"
	AuditOutcomeUpstreamError AuditOutcome = "upstream_error"
	AuditOutcomeCancelled     AuditOutcome = "cancelled"
	AuditOutcomeLocalError    AuditOutcome = "local_error"
)

type InitialCaptureInput struct {
	ID                    string
	RequestID             string
	KeyID                 string
	OwnerKind             OwnerKind
	IdentityID            string
	ServiceAccountID      string
	ResponsibleIdentityID string
	TeamID                string
	ModelID               string
	ValidatedRequestJSON  []byte `json:"-"`
	CreatedAt             time.Time
	ExpiresAt             time.Time
}

type PendingAudit struct {
	ID                    string
	RequestID             string
	KeyID                 string
	OwnerKind             OwnerKind
	IdentityID            string
	ServiceAccountID      string
	ResponsibleIdentityID string
	TeamID                string
	ModelID               string
	CaptureStatus         CaptureStatus
	Outcome               AuditOutcome
	ObservedRequestBytes  int64
	CreatedAt             time.Time
	ExpiresAt             time.Time
	RequestContent        EncryptedContent
}

type CaptureReceipt struct {
	AuditID   string
	RequestID string
}

type RequestEncryptor interface {
	Encrypt([]byte, EncryptionContext) (EncryptedContent, error)
}

type ContentEncryptor = RequestEncryptor

type PendingAuditRepository interface {
	CreatePendingAudit(context.Context, PendingAudit) error
}

type ResponseFinalizationInput struct {
	AuditID               string
	RequestID             string
	OwnerKind             OwnerKind
	IdentityID            string
	ServiceAccountID      string
	ResponsibleIdentityID string
	TeamID                string
	ModelID               string
	ResponseJSON          []byte `json:"-"`
	CaptureStatus         CaptureStatus
	Outcome               AuditOutcome
	UpstreamRequestID     string
	UpstreamHTTPStatus    *int
	ErrorCode             string
	FinishReason          string
	ObservedResponseBytes int64
	CreatedAt             time.Time
	CompletedAt           time.Time
}

type FinalAudit struct {
	ID                    string
	RequestID             string
	OwnerKind             OwnerKind
	IdentityID            string
	ServiceAccountID      string
	ResponsibleIdentityID string
	TeamID                string
	ModelID               string
	ResponseContent       *EncryptedContent `json:"response_content,omitempty"`
	CaptureStatus         CaptureStatus
	Outcome               AuditOutcome
	UpstreamRequestID     string
	UpstreamHTTPStatus    *int
	ErrorCode             string
	FinishReason          string
	ObservedResponseBytes int64
	CreatedAt             time.Time
	CompletedAt           time.Time
}

type FinalizationReceipt struct {
	AuditID       string
	RequestID     string
	CaptureStatus CaptureStatus
	Outcome       AuditOutcome
}

type FinalAuditRepository interface {
	FinalizeAudit(context.Context, FinalAudit) error
}

type ResponseFinalizationService struct {
	encryptor  ContentEncryptor
	repository FinalAuditRepository
	gate       FailureGate
}

func NewResponseFinalizationService(encryptor ContentEncryptor, repository FinalAuditRepository) (*ResponseFinalizationService, error) {
	return NewResponseFinalizationServiceWithGate(encryptor, repository, nil)
}

func NewResponseFinalizationServiceWithGate(encryptor ContentEncryptor, repository FinalAuditRepository, gate FailureGate) (*ResponseFinalizationService, error) {
	if encryptor == nil || repository == nil {
		return nil, ErrInvalidFinalization
	}
	return &ResponseFinalizationService{encryptor: encryptor, repository: repository, gate: gate}, nil
}

func (service *ResponseFinalizationService) FinalizeResponse(ctx context.Context, input ResponseFinalizationInput) (FinalizationReceipt, error) {
	if service == nil || service.encryptor == nil || service.repository == nil {
		return FinalizationReceipt{}, ErrInvalidFinalization
	}
	if err := validateFinalizationInput(input); err != nil {
		return FinalizationReceipt{}, err
	}
	if err := ctx.Err(); err != nil {
		return FinalizationReceipt{}, fmt.Errorf("finalize audit response: %w", err)
	}
	encryptionContext := EncryptionContext{
		AuditID: input.AuditID, ContentKind: ContentKindResponse, OwnerKind: input.OwnerKind,
		IdentityID: input.IdentityID, ServiceAccountID: input.ServiceAccountID,
		ResponsibleIdentityID: input.ResponsibleIdentityID, TeamID: input.TeamID, CreatedAt: input.CreatedAt,
	}
	if err := encryptionContext.validate(); err != nil {
		return FinalizationReceipt{}, ErrInvalidFinalization
	}

	var responseContent *EncryptedContent
	if len(input.ResponseJSON) > 0 {
		encrypted, err := service.encryptor.Encrypt(input.ResponseJSON, encryptionContext)
		if err != nil {
			failureErr := fmt.Errorf("%w: encrypt final response: %w", ErrAuditUnavailable, err)
			if gateErr := service.markFinalizationFailure(ctx, input); gateErr != nil {
				return FinalizationReceipt{}, errors.Join(failureErr, gateErr)
			}
			return FinalizationReceipt{}, failureErr
		}
		responseContent = &encrypted
	}
	if err := ctx.Err(); err != nil {
		return FinalizationReceipt{}, fmt.Errorf("finalize audit response: %w", err)
	}

	record := FinalAudit{
		ID: input.AuditID, RequestID: input.RequestID, OwnerKind: input.OwnerKind,
		IdentityID: input.IdentityID, ServiceAccountID: input.ServiceAccountID,
		ResponsibleIdentityID: input.ResponsibleIdentityID, TeamID: input.TeamID, ModelID: input.ModelID,
		ResponseContent: responseContent,
		CaptureStatus:   input.CaptureStatus, Outcome: input.Outcome,
		UpstreamRequestID: input.UpstreamRequestID, UpstreamHTTPStatus: input.UpstreamHTTPStatus,
		ErrorCode: input.ErrorCode, FinishReason: input.FinishReason,
		ObservedResponseBytes: input.ObservedResponseBytes, CreatedAt: input.CreatedAt, CompletedAt: input.CompletedAt,
	}
	if err := service.repository.FinalizeAudit(ctx, record); err != nil {
		failureErr := fmt.Errorf("%w: persist final audit response: %w", ErrAuditUnavailable, err)
		if gateErr := service.markFinalizationFailure(ctx, input); gateErr != nil {
			return FinalizationReceipt{}, errors.Join(failureErr, gateErr)
		}
		return FinalizationReceipt{}, failureErr
	}
	return FinalizationReceipt{AuditID: input.AuditID, RequestID: input.RequestID, CaptureStatus: input.CaptureStatus, Outcome: input.Outcome}, nil
}

func (service *ResponseFinalizationService) markFinalizationFailure(ctx context.Context, input ResponseFinalizationInput) error {
	if service == nil || service.gate == nil {
		return nil
	}
	return service.gate.MarkFinalizationFailure(ctx, input.AuditID, input.RequestID, input.CompletedAt)
}

func validateFinalizationInput(input ResponseFinalizationInput) error {
	if input.AuditID == "" || input.RequestID == "" || input.TeamID == "" || input.ModelID == "" || input.CreatedAt.IsZero() {
		return ErrInvalidFinalization
	}
	if input.CompletedAt.IsZero() || input.CompletedAt.Before(input.CreatedAt) || input.ObservedResponseBytes < int64(len(input.ResponseJSON)) {
		return ErrInvalidFinalization
	}
	if err := ValidateFinalizationStatus(input.CaptureStatus, input.Outcome); err != nil {
		return ErrInvalidFinalization
	}
	if input.CaptureStatus == CaptureStatusComplete && len(input.ResponseJSON) == 0 {
		return ErrInvalidFinalization
	}
	if input.CaptureStatus == CaptureStatusTruncated && len(input.ResponseJSON) == 0 {
		return ErrInvalidFinalization
	}
	if input.UpstreamHTTPStatus != nil && (*input.UpstreamHTTPStatus < 100 || *input.UpstreamHTTPStatus > 599) {
		return ErrInvalidFinalization
	}
	return nil
}

func ValidateFinalizationStatus(status CaptureStatus, outcome AuditOutcome) error {
	switch status {
	case CaptureStatusComplete:
		if outcome != AuditOutcomeSuccess && outcome != AuditOutcomeUpstreamError {
			return ErrInvalidFinalization
		}
	case CaptureStatusTruncated:
		if outcome != AuditOutcomeSuccess && outcome != AuditOutcomeUpstreamError && outcome != AuditOutcomeLocalError {
			return ErrInvalidFinalization
		}
	case CaptureStatusIncomplete:
		if outcome != AuditOutcomeCancelled && outcome != AuditOutcomeLocalError {
			return ErrInvalidFinalization
		}
	default:
		return ErrInvalidFinalization
	}
	return nil
}

func (input ResponseFinalizationInput) String() string {
	return fmt.Sprintf(
		"ResponseFinalizationInput{audit_id=%s request_id=%s owner_kind=%s team_id=%s model_id=%s capture_status=%s outcome=%s response_bytes=%d observed_response_bytes=%d completed_at=%s}",
		input.AuditID, input.RequestID, input.OwnerKind, input.TeamID, input.ModelID,
		input.CaptureStatus, input.Outcome, len(input.ResponseJSON), input.ObservedResponseBytes,
		input.CompletedAt.UTC().Format(time.RFC3339Nano),
	)
}

func (input ResponseFinalizationInput) GoString() string {
	return input.String()
}

func (input ResponseFinalizationInput) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("audit_id", input.AuditID),
		slog.String("request_id", input.RequestID),
		slog.String("owner_kind", string(input.OwnerKind)),
		slog.String("team_id", input.TeamID),
		slog.String("model_id", input.ModelID),
		slog.String("capture_status", string(input.CaptureStatus)),
		slog.String("outcome", string(input.Outcome)),
		slog.Int("response_bytes", len(input.ResponseJSON)),
		slog.Int64("observed_response_bytes", input.ObservedResponseBytes),
		slog.Time("completed_at", input.CompletedAt),
	)
}

func (record FinalAudit) String() string {
	responseContent := "none"
	if record.ResponseContent != nil {
		responseContent = record.ResponseContent.String()
	}
	return fmt.Sprintf(
		"FinalAudit{audit_id=%s request_id=%s owner_kind=%s team_id=%s model_id=%s capture_status=%s outcome=%s observed_response_bytes=%d completed_at=%s content=%s}",
		record.ID, record.RequestID, record.OwnerKind, record.TeamID, record.ModelID,
		record.CaptureStatus, record.Outcome, record.ObservedResponseBytes,
		record.CompletedAt.UTC().Format(time.RFC3339Nano), responseContent,
	)
}

func (record FinalAudit) GoString() string {
	return record.String()
}

func (record FinalAudit) LogValue() slog.Value {
	value := slog.GroupValue(
		slog.String("audit_id", record.ID),
		slog.String("request_id", record.RequestID),
		slog.String("owner_kind", string(record.OwnerKind)),
		slog.String("team_id", record.TeamID),
		slog.String("model_id", record.ModelID),
		slog.String("capture_status", string(record.CaptureStatus)),
		slog.String("outcome", string(record.Outcome)),
		slog.Int64("observed_response_bytes", record.ObservedResponseBytes),
		slog.Time("completed_at", record.CompletedAt),
	)
	if record.ResponseContent != nil {
		return slog.GroupValue(
			slog.String("audit_id", record.ID),
			slog.String("request_id", record.RequestID),
			slog.String("owner_kind", string(record.OwnerKind)),
			slog.String("team_id", record.TeamID),
			slog.String("model_id", record.ModelID),
			slog.String("capture_status", string(record.CaptureStatus)),
			slog.String("outcome", string(record.Outcome)),
			slog.Int64("observed_response_bytes", record.ObservedResponseBytes),
			slog.Time("completed_at", record.CompletedAt),
			slog.Any("content", *record.ResponseContent),
		)
	}
	return value
}

type InitialCaptureService struct {
	encryptor   RequestEncryptor
	repository  PendingAuditRepository
	gate        ChatGate
	failureGate FailureGate
}

func NewInitialCaptureService(encryptor RequestEncryptor, repository PendingAuditRepository) (*InitialCaptureService, error) {
	return NewInitialCaptureServiceWithGate(encryptor, repository, nil)
}

func NewInitialCaptureServiceWithGate(encryptor RequestEncryptor, repository PendingAuditRepository, gate ChatGate) (*InitialCaptureService, error) {
	if encryptor == nil || repository == nil {
		return nil, ErrInvalidCaptureService
	}
	service := &InitialCaptureService{encryptor: encryptor, repository: repository, gate: gate}
	if failureGate, ok := gate.(FailureGate); ok {
		service.failureGate = failureGate
	}
	return service, nil
}

func (service *InitialCaptureService) CaptureValidatedRequest(ctx context.Context, input InitialCaptureInput) (CaptureReceipt, error) {
	if service == nil || service.encryptor == nil || service.repository == nil {
		return CaptureReceipt{}, ErrInvalidCaptureService
	}
	if service.gate != nil {
		if err := service.gate.CheckChatAllowed(ctx); err != nil {
			return CaptureReceipt{}, fmt.Errorf("%w: chat gate: %w", ErrAuditUnavailable, err)
		}
	}
	if err := ctx.Err(); err != nil {
		return CaptureReceipt{}, fmt.Errorf("capture pending audit: %w", err)
	}

	encrypted, err := service.encryptor.Encrypt(input.ValidatedRequestJSON, EncryptionContext{
		AuditID:               input.ID,
		ContentKind:           ContentKindRequest,
		OwnerKind:             input.OwnerKind,
		IdentityID:            input.IdentityID,
		ServiceAccountID:      input.ServiceAccountID,
		ResponsibleIdentityID: input.ResponsibleIdentityID,
		TeamID:                input.TeamID,
		CreatedAt:             input.CreatedAt,
	})
	if err != nil {
		failureErr := fmt.Errorf("%w: encrypt validated request: %w", ErrAuditUnavailable, err)
		if gateErr := service.markInitialFailure(ctx); gateErr != nil {
			return CaptureReceipt{}, errors.Join(failureErr, gateErr)
		}
		return CaptureReceipt{}, failureErr
	}
	if err := ctx.Err(); err != nil {
		return CaptureReceipt{}, fmt.Errorf("capture pending audit: %w", err)
	}

	record := PendingAudit{
		ID:                    input.ID,
		RequestID:             input.RequestID,
		KeyID:                 input.KeyID,
		OwnerKind:             input.OwnerKind,
		IdentityID:            input.IdentityID,
		ServiceAccountID:      input.ServiceAccountID,
		ResponsibleIdentityID: input.ResponsibleIdentityID,
		TeamID:                input.TeamID,
		ModelID:               input.ModelID,
		CaptureStatus:         CaptureStatusPending,
		Outcome:               AuditOutcomePending,
		ObservedRequestBytes:  int64(len(input.ValidatedRequestJSON)),
		CreatedAt:             input.CreatedAt,
		ExpiresAt:             input.ExpiresAt,
		RequestContent:        encrypted,
	}
	if err := service.repository.CreatePendingAudit(ctx, record); err != nil {
		failureErr := fmt.Errorf("%w: persist pending audit: %w", ErrAuditUnavailable, err)
		if gateErr := service.markInitialFailure(ctx); gateErr != nil {
			return CaptureReceipt{}, errors.Join(failureErr, gateErr)
		}
		return CaptureReceipt{}, failureErr
	}
	return CaptureReceipt{AuditID: record.ID, RequestID: record.RequestID}, nil
}

func (service *InitialCaptureService) markInitialFailure(ctx context.Context) error {
	if service == nil || service.failureGate == nil {
		return nil
	}
	return service.failureGate.Block(ctx, GateReasonInitialCapture)
}

func (input InitialCaptureInput) String() string {
	return fmt.Sprintf(
		"InitialCaptureInput{id=%s request_id=%s key_id=%s owner_kind=%s team_id=%s model_id=%s request_bytes=%d created_at=%s expires_at=%s}",
		input.ID, input.RequestID, input.KeyID, input.OwnerKind, input.TeamID, input.ModelID,
		len(input.ValidatedRequestJSON), input.CreatedAt.UTC().Format(time.RFC3339Nano), input.ExpiresAt.UTC().Format(time.RFC3339Nano),
	)
}

func (input InitialCaptureInput) GoString() string {
	return input.String()
}

func (input InitialCaptureInput) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("audit_id", input.ID),
		slog.String("request_id", input.RequestID),
		slog.String("key_id", input.KeyID),
		slog.String("owner_kind", string(input.OwnerKind)),
		slog.String("team_id", input.TeamID),
		slog.String("model_id", input.ModelID),
		slog.Int("request_bytes", len(input.ValidatedRequestJSON)),
		slog.Time("created_at", input.CreatedAt),
		slog.Time("expires_at", input.ExpiresAt),
	)
}

func (record PendingAudit) String() string {
	return fmt.Sprintf(
		"PendingAudit{id=%s request_id=%s key_id=%s owner_kind=%s team_id=%s model_id=%s capture_status=%s outcome=%s request_bytes=%d created_at=%s expires_at=%s content=%s}",
		record.ID, record.RequestID, record.KeyID, record.OwnerKind, record.TeamID, record.ModelID,
		record.CaptureStatus, record.Outcome, record.ObservedRequestBytes,
		record.CreatedAt.UTC().Format(time.RFC3339Nano), record.ExpiresAt.UTC().Format(time.RFC3339Nano), record.RequestContent,
	)
}

func (record PendingAudit) GoString() string {
	return record.String()
}

func (record PendingAudit) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("audit_id", record.ID),
		slog.String("request_id", record.RequestID),
		slog.String("key_id", record.KeyID),
		slog.String("owner_kind", string(record.OwnerKind)),
		slog.String("team_id", record.TeamID),
		slog.String("model_id", record.ModelID),
		slog.String("capture_status", string(record.CaptureStatus)),
		slog.String("outcome", string(record.Outcome)),
		slog.Int64("request_bytes", record.ObservedRequestBytes),
		slog.Time("created_at", record.CreatedAt),
		slog.Time("expires_at", record.ExpiresAt),
		slog.Any("content", record.RequestContent),
	)
}
