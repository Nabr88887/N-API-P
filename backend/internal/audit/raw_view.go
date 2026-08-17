package audit

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"n-api-p/internal/access"
)

var (
	ErrInvalidRawView          = errors.New("invalid raw audit view")
	ErrRawViewReasonRequired   = errors.New("raw audit view reason required")
	ErrRawViewNotFound         = errors.New("raw audit content not found")
	ErrRawViewDecryptionFailed = errors.New("raw audit content decryption failed")
	ErrRawViewUnavailable      = errors.New("raw audit view unavailable")
)

type RawViewInput struct {
	Session   access.ActivePortalSession
	AuditID   string
	RequestID string
	Reason    string
}

type RawView struct {
	AuditID      string          `json:"audit_id"`
	RequestJSON  json.RawMessage `json:"request"`
	ResponseJSON json.RawMessage `json:"response"`
}

type RawViewDecryptor interface {
	Decrypt(EncryptedContent, EncryptionContext) ([]byte, error)
}

type RawViewRepository interface {
	ReadRawContent(context.Context, RawContentLookup) (RawContentRecord, error)
	AppendSecurityEvent(context.Context, access.SecurityEvent) error
}

type RawViewService struct {
	repository   RawViewRepository
	decryptor    RawViewDecryptor
	guard        *access.SensitiveActionGuard
	now          func() time.Time
	newRequestID func() (string, error)
}

func NewRawViewService(repository RawViewRepository, decryptor RawViewDecryptor) (*RawViewService, error) {
	if repository == nil || decryptor == nil {
		return nil, ErrInvalidRawView
	}
	return &RawViewService{
		repository:   repository,
		decryptor:    decryptor,
		guard:        access.NewSensitiveActionGuard(repository),
		now:          time.Now,
		newRequestID: newRawViewRequestID,
	}, nil
}

func (service *RawViewService) Inspect(ctx context.Context, input RawViewInput) (RawView, error) {
	if service == nil || service.repository == nil || service.decryptor == nil || service.guard == nil || service.now == nil || service.newRequestID == nil {
		return RawView{}, ErrInvalidRawView
	}
	auditID := strings.TrimSpace(input.AuditID)
	if auditID == "" {
		return RawView{}, ErrInvalidRawView
	}
	requestID := strings.TrimSpace(input.RequestID)
	if requestID == "" {
		generated, err := service.newRequestID()
		if err != nil || generated == "" {
			return RawView{}, access.ErrSecurityAuditUnavailable
		}
		requestID = generated
	}
	reason := strings.TrimSpace(input.Reason)
	visibleAt := service.now().UTC()
	view := RawView{}

	err := service.guard.ExecuteAt(ctx, access.SensitiveActionRequest{
		Session: input.Session, Action: access.SensitiveActionRawView,
		RequestID: requestID, TargetAuditID: auditID, Reason: reason,
	}, visibleAt, func() (access.SensitiveActionExecution, error) {
		if reason == "" {
			return access.SensitiveActionExecution{
				TargetAuditID: auditID, Outcome: access.SecurityEventDenied, DetailCode: "reason_required",
			}, ErrRawViewReasonRequired
		}

		requestRecord, err := service.readContent(ctx, auditID, ContentKindRequest, visibleAt)
		if err != nil {
			return rawViewReadFailure("", err)
		}
		knownTarget := auditID
		responseRecord, err := service.readContent(ctx, auditID, ContentKindResponse, visibleAt)
		if err != nil {
			return rawViewReadFailure(knownTarget, err)
		}

		requestJSON, err := service.decryptor.Decrypt(requestRecord.Content, rawViewEncryptionContext(requestRecord))
		if err != nil {
			clear(requestJSON)
			return access.SensitiveActionExecution{
				TargetAuditID: knownTarget, Outcome: access.SecurityEventFailure, DetailCode: "decryption_failed",
			}, ErrRawViewDecryptionFailed
		}
		responseJSON, err := service.decryptor.Decrypt(responseRecord.Content, rawViewEncryptionContext(responseRecord))
		if err != nil {
			clear(requestJSON)
			clear(responseJSON)
			return access.SensitiveActionExecution{
				TargetAuditID: knownTarget, Outcome: access.SecurityEventFailure, DetailCode: "decryption_failed",
			}, ErrRawViewDecryptionFailed
		}
		if !json.Valid(requestJSON) || !json.Valid(responseJSON) {
			clear(requestJSON)
			clear(responseJSON)
			return access.SensitiveActionExecution{
				TargetAuditID: knownTarget, Outcome: access.SecurityEventFailure, DetailCode: "decryption_failed",
			}, ErrRawViewDecryptionFailed
		}
		view = RawView{AuditID: auditID, RequestJSON: requestJSON, ResponseJSON: responseJSON}
		return access.SensitiveActionExecution{
			TargetAuditID: knownTarget, Outcome: access.SecurityEventSuccess, DetailCode: "raw_viewed",
		}, nil
	})
	if err != nil {
		clear(view.RequestJSON)
		clear(view.ResponseJSON)
		return RawView{}, err
	}
	return view, nil
}

func (service *RawViewService) readContent(ctx context.Context, auditID string, kind ContentKind, visibleAt time.Time) (RawContentRecord, error) {
	record, err := service.repository.ReadRawContent(ctx, RawContentLookup{
		AuditID: auditID, ContentKind: kind, VisibleAt: visibleAt,
	})
	if err != nil {
		return RawContentRecord{}, err
	}
	if !record.ExpiresAt.After(visibleAt) {
		return RawContentRecord{}, ErrRawContentUnavailable
	}
	if record.AuditID != auditID || record.ContentKind != kind {
		return RawContentRecord{}, ErrRawViewDecryptionFailed
	}
	return record, nil
}

func rawViewReadFailure(targetAuditID string, err error) (access.SensitiveActionExecution, error) {
	detailCode := "raw_repository_unavailable"
	result := ErrRawViewUnavailable
	if errors.Is(err, ErrRawContentUnavailable) {
		detailCode = "raw_content_unavailable"
		result = ErrRawViewNotFound
	} else if errors.Is(err, ErrRawViewDecryptionFailed) {
		detailCode = "decryption_failed"
		result = ErrRawViewDecryptionFailed
	}
	return access.SensitiveActionExecution{
		TargetAuditID: targetAuditID, Outcome: access.SecurityEventFailure, DetailCode: detailCode,
	}, result
}

func rawViewEncryptionContext(record RawContentRecord) EncryptionContext {
	return EncryptionContext{
		AuditID:               record.AuditID,
		ContentKind:           record.ContentKind,
		OwnerKind:             record.OwnerKind,
		IdentityID:            record.IdentityID,
		ServiceAccountID:      record.ServiceAccountID,
		ResponsibleIdentityID: record.ResponsibleIdentityID,
		TeamID:                record.TeamID,
		CreatedAt:             record.CreatedAt,
	}
}

func newRawViewRequestID() (string, error) {
	randomBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, randomBytes); err != nil {
		return "", err
	}
	randomBytes[6] = (randomBytes[6] & 0x0f) | 0x40
	randomBytes[8] = (randomBytes[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", randomBytes[0:4], randomBytes[4:6], randomBytes[6:8], randomBytes[8:10], randomBytes[10:16]), nil
}

func (view RawView) String() string {
	return fmt.Sprintf("RawView{audit_id=%s request_bytes=%d response_bytes=%d}", view.AuditID, len(view.RequestJSON), len(view.ResponseJSON))
}

func (view RawView) GoString() string { return view.String() }

func (view RawView) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("audit_id", view.AuditID),
		slog.Int("request_bytes", len(view.RequestJSON)),
		slog.Int("response_bytes", len(view.ResponseJSON)),
	)
}

var _ RawViewDecryptor = (*EnvelopeService)(nil)
