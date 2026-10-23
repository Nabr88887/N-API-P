package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
)

type AdminAuditMetadataService interface {
	List(context.Context, audit.MetadataListInput) (audit.MetadataPage, error)
	Get(context.Context, audit.MetadataGetInput) (audit.Metadata, error)
}

func NewAdminAuditMetadataListHandler(service AdminAuditMetadataService) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		if service == nil {
			writeErrorResponse(writer, CodeInternalError)
			return
		}
		limit, err := parsePageLimit(request)
		if err != nil {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		filter := audit.MetadataFilter{Limit: limit, Cursor: request.URL.Query().Get("cursor")}
		if raw := strings.TrimSpace(request.URL.Query().Get("account_id")); raw != "" {
			filter.IdentityID = &raw
		}
		if raw := strings.TrimSpace(request.URL.Query().Get("team_id")); raw != "" {
			filter.TeamID = &raw
		}
		if raw := strings.TrimSpace(request.URL.Query().Get("model_id")); raw != "" {
			filter.ModelID = &raw
		}
		if raw := strings.TrimSpace(request.URL.Query().Get("capture_status")); raw != "" {
			value := audit.CaptureStatus(raw)
			filter.CaptureStatus = &value
		}
		page, err := service.List(request.Context(), audit.MetadataListInput{Session: session, Filter: filter})
		if err != nil {
			writeAuditMetadataError(writer, err)
			return
		}
		data := make([]AuditMetadata, 0, len(page.Records))
		for _, record := range page.Records {
			data = append(data, auditMetadataResponse(record))
		}
		writePagedJSON(writer, http.StatusOK, PagedResponse[AuditMetadata]{Data: data, Pagination: Pagination{NextCursor: page.NextCursor, HasMore: page.NextCursor != ""}})
	})
}

func NewAdminAuditMetadataGetHandler(service AdminAuditMetadataService) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		auditID := pathIdentifier(request, "auditID", "audits")
		if !validRawViewAuditID(auditID) || service == nil {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		record, err := service.Get(request.Context(), audit.MetadataGetInput{Session: session, AuditID: auditID})
		if err != nil {
			writeAuditMetadataError(writer, err)
			return
		}
		writeJSON(writer, http.StatusOK, auditMetadataResponse(record))
	})
}

func writeAuditMetadataError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, access.ErrForbidden):
		writeErrorResponse(writer, CodeForbidden)
	case errors.Is(err, audit.ErrInvalidMetadataRequest):
		writeErrorResponse(writer, CodeInvalidRequest)
	case errors.Is(err, audit.ErrMetadataNotFound):
		writeErrorResponse(writer, CodeNotFound)
	case errors.Is(err, audit.ErrMetadataUnavailable):
		writeErrorResponse(writer, CodeAuditUnavailable)
	default:
		writeErrorResponse(writer, CodeInternalError)
	}
}

func auditMetadataResponse(record audit.Metadata) AuditMetadata {
	return AuditMetadata{
		ID: record.ID, RequestID: record.RequestID, KeyID: record.KeyID, OwnerAccountID: record.IdentityID,
		ServiceAccountID: record.ServiceAccountID, ResponsibleAccountID: record.ResponsibleIdentityID,
		TeamID: record.TeamID, ModelID: record.ModelID, CaptureStatus: AuditCaptureStatus(record.CaptureStatus),
		Outcome: AuditOutcome(record.Outcome), UpstreamRequestID: record.UpstreamRequestID,
		UpstreamHTTPStatus: record.UpstreamHTTPStatus, ErrorCode: record.ErrorCode, FinishReason: record.FinishReason,
		ObservedRequestBytes: record.ObservedRequestBytes, ObservedResponseBytes: record.ObservedResponseBytes,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt, CompletedAt: record.CompletedAt,
	}
}
