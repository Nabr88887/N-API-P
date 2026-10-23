package audit

import (
	"context"
	"errors"
	"strings"
	"time"

	"n-api-p/internal/access"
)

const MaxMetadataPageSize = 100

var (
	ErrInvalidMetadataRequest = errors.New("invalid audit metadata request")
	ErrMetadataNotFound       = errors.New("audit metadata not found")
	ErrMetadataUnavailable    = errors.New("audit metadata unavailable")
)

type Metadata struct {
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
	UpstreamRequestID     string
	UpstreamHTTPStatus    *int
	ErrorCode             string
	FinishReason          string
	ObservedRequestBytes  int64
	ObservedResponseBytes int64
	CreatedAt             time.Time
	UpdatedAt             time.Time
	CompletedAt           *time.Time
}

type MetadataFilter struct {
	IdentityID    *string
	TeamID        *string
	ModelID       *string
	CaptureStatus *CaptureStatus
	Cursor        string
	Limit         int
}

type MetadataPage struct {
	Records    []Metadata
	NextCursor string
}

type MetadataListInput struct {
	Session access.ActivePortalSession
	Filter  MetadataFilter
}

type MetadataGetInput struct {
	Session access.ActivePortalSession
	AuditID string
}

type MetadataRepository interface {
	ListAuditMetadata(context.Context, MetadataFilter) (MetadataPage, error)
	GetAuditMetadata(context.Context, string) (Metadata, error)
}

type MetadataService struct {
	repository MetadataRepository
}

func NewMetadataService(repository MetadataRepository) (*MetadataService, error) {
	if repository == nil {
		return nil, ErrInvalidMetadataRequest
	}
	return &MetadataService{repository: repository}, nil
}

func (service *MetadataService) List(ctx context.Context, input MetadataListInput) (MetadataPage, error) {
	if !systemAdministrator(input.Session) {
		return MetadataPage{}, access.ErrForbidden
	}
	if service == nil || service.repository == nil || !validMetadataFilter(input.Filter) {
		return MetadataPage{}, ErrInvalidMetadataRequest
	}
	page, err := service.repository.ListAuditMetadata(ctx, input.Filter)
	if err != nil {
		return MetadataPage{}, err
	}
	return page, nil
}

func (service *MetadataService) Get(ctx context.Context, input MetadataGetInput) (Metadata, error) {
	if !systemAdministrator(input.Session) {
		return Metadata{}, access.ErrForbidden
	}
	auditID := strings.TrimSpace(input.AuditID)
	if service == nil || service.repository == nil || !validMetadataID(auditID) {
		return Metadata{}, ErrInvalidMetadataRequest
	}
	record, err := service.repository.GetAuditMetadata(ctx, auditID)
	if err != nil {
		return Metadata{}, err
	}
	return record, nil
}

func validMetadataFilter(filter MetadataFilter) bool {
	if filter.Limit < 1 || filter.Limit > MaxMetadataPageSize || len(filter.Cursor) > 512 {
		return false
	}
	if !validOptionalMetadataID(filter.IdentityID) || !validOptionalMetadataID(filter.TeamID) {
		return false
	}
	if filter.ModelID != nil && strings.TrimSpace(*filter.ModelID) == "" {
		return false
	}
	if filter.CaptureStatus != nil {
		switch *filter.CaptureStatus {
		case CaptureStatusPending, CaptureStatusComplete, CaptureStatusTruncated, CaptureStatusIncomplete:
		default:
			return false
		}
	}
	return true
}

func validOptionalMetadataID(value *string) bool {
	return value == nil || validMetadataID(strings.TrimSpace(*value))
}

func validMetadataID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}

func systemAdministrator(session access.ActivePortalSession) bool {
	return strings.TrimSpace(session.IdentityID) != "" && session.Role == access.RoleSystemAdministrator
}
