package httpapi

import (
	"errors"
	"net/http"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
)

const elevatedAuditBatchRequestBodyLimit int64 = 64 << 10

type elevatedAuditGrantRequest struct {
	Purpose string `json:"purpose"`
}

type elevatedAuditGrantResponse struct {
	ID        string    `json:"id"`
	Status    string    `json:"status"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type elevatedAuditQueryRequest struct {
	IdentityID            *string              `json:"identity_id,omitempty"`
	ServiceAccountID      *string              `json:"service_account_id,omitempty"`
	ResponsibleIdentityID *string              `json:"responsible_identity_id,omitempty"`
	From                  *time.Time           `json:"from,omitempty"`
	To                    *time.Time           `json:"to,omitempty"`
	ModelID               *string              `json:"model_id,omitempty"`
	CaptureStatus         *audit.CaptureStatus `json:"capture_status,omitempty"`
	Outcome               *audit.AuditOutcome  `json:"outcome,omitempty"`
	OwnerKind             *audit.OwnerKind     `json:"owner_kind,omitempty"`
	FullText              string               `json:"full_text,omitempty"`
	AuditIDs              []string             `json:"audit_ids,omitempty"`
	Cursor                string               `json:"cursor,omitempty"`
	Limit                 int                  `json:"limit"`
}

func NewElevatedAuditGrantHandler(service AdminElevatedAuditAccessService) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		var body elevatedAuditGrantRequest
		if !decodeStrictJSON(writer, request, &body) {
			return
		}
		grant, err := service.Issue(request.Context(), audit.IssueElevatedAuditGrantInput{Session: session, Purpose: body.Purpose, RequestID: adminRequestID(request)})
		if err != nil {
			writeElevatedAuditError(writer, err)
			return
		}
		writeJSON(writer, http.StatusCreated, elevatedAuditGrantResponse{ID: grant.ID, Status: "active", IssuedAt: grant.IssuedAt, ExpiresAt: grant.ExpiresAt})
	})
}

func NewElevatedAuditGrantRevokeHandler(service AdminElevatedAuditAccessService) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		if err := service.Revoke(request.Context(), audit.RevokeElevatedAuditGrantInput{Session: session, RequestID: adminRequestID(request)}); err != nil {
			writeElevatedAuditError(writer, err)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusNoContent)
	})
}

func NewElevatedAuditQueryHandler(service AdminElevatedAuditQueryService, batch bool) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		var body elevatedAuditQueryRequest
		decode := decodeStrictJSON
		if batch {
			decode = func(writer http.ResponseWriter, request *http.Request, destination any) bool {
				return decodeStrictJSONWithLimit(writer, request, destination, elevatedAuditBatchRequestBodyLimit)
			}
		}
		if !decode(writer, request, &body) {
			return
		}
		query := audit.ElevatedAuditQuery{
			IdentityID: body.IdentityID, ServiceAccountID: body.ServiceAccountID, ResponsibleIdentityID: body.ResponsibleIdentityID,
			From: body.From, To: body.To, ModelID: body.ModelID, CaptureStatus: body.CaptureStatus, Outcome: body.Outcome,
			OwnerKind: body.OwnerKind, FullText: body.FullText, AuditIDs: body.AuditIDs, Cursor: body.Cursor, Limit: body.Limit,
		}
		if batch && len(query.AuditIDs) == 0 {
			writeErrorResponse(writer, CodeInvalidQuery)
			return
		}
		input := audit.ElevatedAuditQueryInput{Session: session, RequestID: adminRequestID(request), Query: query}
		if batch {
			input.EventType = "audit_batch_view"
		}
		page, err := service.Query(request.Context(), input)
		if err != nil {
			writeElevatedAuditError(writer, err)
			return
		}
		defer page.Clear()
		writeJSON(writer, http.StatusOK, PagedResponse[audit.ElevatedAuditRecord]{Data: page.Records, Pagination: Pagination{NextCursor: page.NextCursor, HasMore: page.NextCursor != ""}})
	})
}

func NewElevatedAuditExportHandler(service AdminElevatedAuditExportService) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		var body elevatedAuditQueryRequest
		if !decodeStrictJSON(writer, request, &body) {
			return
		}
		writer.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		stream := &elevatedAuditExportResponseWriter{ResponseWriter: writer}
		err := service.Export(request.Context(), audit.ElevatedAuditExportInput{Session: session, RequestID: adminRequestID(request), Query: audit.ElevatedAuditQuery{
			IdentityID: body.IdentityID, ServiceAccountID: body.ServiceAccountID, ResponsibleIdentityID: body.ResponsibleIdentityID,
			From: body.From, To: body.To, ModelID: body.ModelID, CaptureStatus: body.CaptureStatus, Outcome: body.Outcome,
			OwnerKind: body.OwnerKind, FullText: body.FullText, AuditIDs: body.AuditIDs, Cursor: body.Cursor, Limit: body.Limit,
		}}, stream)
		if err != nil && stream.started {
			panic(http.ErrAbortHandler)
		}
		if err != nil && request.Context().Err() == nil && !stream.started {
			writeElevatedAuditError(writer, err)
		}
	})
}

type elevatedAuditExportResponseWriter struct {
	http.ResponseWriter
	started bool
}

func (writer *elevatedAuditExportResponseWriter) Write(value []byte) (int, error) {
	writer.started = true
	controller := http.NewResponseController(writer.ResponseWriter)
	if err := controller.SetWriteDeadline(time.Now().Add(10 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return 0, err
	}
	written, err := writer.ResponseWriter.Write(value)
	if err != nil {
		return written, err
	}
	if err := controller.Flush(); err != nil && !errors.Is(err, http.ErrNotSupported) {
		return written, err
	}
	return written, nil
}

func writeElevatedAuditError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, access.ErrForbidden), errors.Is(err, audit.ErrElevatedAuditForbidden):
		writeErrorResponse(writer, CodeForbidden)
	case errors.Is(err, access.ErrReauthenticationRequired):
		writeErrorResponse(writer, CodeReauthenticationRequired)
	case errors.Is(err, audit.ErrElevatedAuditGrantNotFound):
		writeErrorResponse(writer, CodeGrantExpired)
	case errors.Is(err, audit.ErrElevatedAuditGrantExpired):
		writeErrorResponse(writer, CodeGrantExpired)
	case errors.Is(err, audit.ErrElevatedAuditGrantRevoked):
		writeErrorResponse(writer, CodeGrantRevoked)
	case errors.Is(err, audit.ErrInvalidElevatedAuditCursor):
		writeErrorResponse(writer, CodeInvalidCursor)
	case errors.Is(err, audit.ErrInvalidElevatedAuditQuery), errors.Is(err, audit.ErrInvalidElevatedAuditAccess), errors.Is(err, audit.ErrInvalidElevatedAuditExport):
		writeErrorResponse(writer, CodeInvalidQuery)
	case errors.Is(err, audit.ErrElevatedAuditExportIncomplete):
		writeErrorResponse(writer, CodeExportIncomplete)
	case errors.Is(err, access.ErrSecurityAuditUnavailable):
		writeErrorResponse(writer, CodeAuditUnavailable)
	default:
		writeErrorResponse(writer, CodeInternalError)
	}
}
