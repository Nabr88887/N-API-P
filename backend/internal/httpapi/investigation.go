package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
)

type investigationCreateRequest struct {
	SubjectIdentityID string    `json:"subject_identity_id"`
	PolicyConcern     string    `json:"policy_concern"`
	Reason            string    `json:"reason"`
	StartAt           time.Time `json:"start_at"`
	EndAt             time.Time `json:"end_at"`
	Confirmed         bool      `json:"confirmed"`
}

type investigationGrantRequest struct {
	Confirmed bool `json:"confirmed"`
}

type investigationClosureRequest struct {
	Disposition audit.InvestigationDisposition `json:"disposition"`
	Note        string                         `json:"note,omitempty"`
	Confirmed   bool                           `json:"confirmed"`
}

type investigationCaseResponse struct {
	ID                string                         `json:"id"`
	SubjectIdentityID string                         `json:"subject_identity_id"`
	PolicyConcern     string                         `json:"policy_concern"`
	Reason            string                         `json:"reason"`
	StartAt           time.Time                      `json:"start_at"`
	EndAt             time.Time                      `json:"end_at"`
	Status            audit.InvestigationCaseStatus  `json:"status"`
	CreatedBy         string                         `json:"created_by"`
	CreatedAt         time.Time                      `json:"created_at"`
	ClosedBy          string                         `json:"closed_by,omitempty"`
	ClosedAt          *time.Time                     `json:"closed_at,omitempty"`
	Disposition       audit.InvestigationDisposition `json:"disposition,omitempty"`
	ClosureNote       string                         `json:"closure_note,omitempty"`
}

type investigationCandidateResponse struct {
	AuditID       string              `json:"audit_id"`
	CaptureStatus audit.CaptureStatus `json:"capture_status"`
	CreatedAt     time.Time           `json:"created_at"`
	ExpiresAt     time.Time           `json:"expires_at"`
}

type investigationGrantResponse struct {
	CaseID    string    `json:"case_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

func NewAdminInvestigationCreateHandler(service interface {
	Create(context.Context, audit.CreateInvestigationCaseInput) (audit.InvestigationCaseCreate, error)
}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		var body investigationCreateRequest
		if !decodeStrictJSON(writer, request, &body) {
			return
		}
		result, err := service.Create(request.Context(), audit.CreateInvestigationCaseInput{
			Session: session, SubjectIdentityID: strings.TrimSpace(body.SubjectIdentityID), PolicyConcern: body.PolicyConcern,
			Reason: body.Reason, StartAt: body.StartAt, EndAt: body.EndAt, Confirmed: body.Confirmed, RequestID: adminRequestID(request),
		})
		if err != nil {
			writeInvestigationError(writer, err)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writeJSON(writer, http.StatusCreated, struct {
			Case  investigationCaseResponse  `json:"case"`
			Grant investigationGrantResponse `json:"grant"`
		}{Case: investigationCaseResponseFrom(result.Case), Grant: investigationGrantResponse{CaseID: result.Grant.CaseID, ExpiresAt: result.Grant.ExpiresAt}})
	})
}

func NewAdminInvestigationListHandler(service interface {
	List(context.Context, access.ActivePortalSession, audit.InvestigationCaseListFilter) (audit.InvestigationCasePage, error)
}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		limit, err := parsePageLimit(request)
		if err != nil {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		filter := audit.InvestigationCaseListFilter{Limit: limit, Cursor: request.URL.Query().Get("cursor")}
		if value := strings.TrimSpace(request.URL.Query().Get("status")); value != "" {
			filter.Status = audit.InvestigationCaseStatus(value)
		}
		page, err := service.List(request.Context(), session, filter)
		if err != nil {
			writeInvestigationError(writer, err)
			return
		}
		data := make([]investigationCaseResponse, 0, len(page.Cases))
		for _, item := range page.Cases {
			data = append(data, investigationCaseResponseFrom(item))
		}
		writePagedJSON(writer, http.StatusOK, PagedResponse[investigationCaseResponse]{Data: data, Pagination: Pagination{NextCursor: page.NextCursor, HasMore: page.NextCursor != ""}})
	})
}

func NewAdminInvestigationCandidatesHandler(service interface {
	Candidates(context.Context, access.ActivePortalSession, string) ([]audit.InvestigationCandidate, error)
}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		caseID := pathIdentifier(request, "caseID", "investigation-cases")
		if caseID == "" {
			writeErrorResponse(writer, CodeNotFound)
			return
		}
		if !validRawViewAuditID(caseID) {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		candidates, err := service.Candidates(request.Context(), session, caseID)
		if err != nil {
			writeInvestigationError(writer, err)
			return
		}
		data := make([]investigationCandidateResponse, 0, len(candidates))
		for _, candidate := range candidates {
			data = append(data, investigationCandidateResponse{AuditID: candidate.AuditID, CaptureStatus: candidate.CaptureStatus, CreatedAt: candidate.CreatedAt, ExpiresAt: candidate.ExpiresAt})
		}
		writeJSON(writer, http.StatusOK, PagedResponse[investigationCandidateResponse]{Data: data, Pagination: Pagination{HasMore: false}})
	})
}

func NewAdminInvestigationRawViewHandler(service interface {
	Inspect(context.Context, audit.CaseRawViewInput) (audit.CaseRawView, error)
}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		caseID := pathIdentifier(request, "caseID", "investigation-cases")
		auditID := pathIdentifier(request, "auditID", "audits")
		if caseID == "" || auditID == "" {
			writeErrorResponse(writer, CodeNotFound)
			return
		}
		if !validRawViewAuditID(caseID) || !validRawViewAuditID(auditID) {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		view, err := service.Inspect(request.Context(), audit.CaseRawViewInput{Session: session, CaseID: caseID, AuditID: auditID, RequestID: adminRequestID(request)})
		if err != nil {
			writeInvestigationError(writer, err)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writeJSON(writer, http.StatusOK, view)
	})
}

func NewAdminInvestigationGrantHandler(service interface {
	IssueGrant(context.Context, audit.IssueInvestigationGrantInput) (audit.AccessGrant, error)
}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		caseID := pathIdentifier(request, "caseID", "investigation-cases")
		if caseID == "" {
			writeErrorResponse(writer, CodeNotFound)
			return
		}
		if !validRawViewAuditID(caseID) {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		var body investigationGrantRequest
		if !decodeStrictJSON(writer, request, &body) {
			return
		}
		grant, err := service.IssueGrant(request.Context(), audit.IssueInvestigationGrantInput{Session: session, CaseID: caseID, Confirmed: body.Confirmed, RequestID: adminRequestID(request)})
		if err != nil {
			writeInvestigationError(writer, err)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writeJSON(writer, http.StatusCreated, investigationGrantResponse{CaseID: grant.CaseID, ExpiresAt: grant.ExpiresAt})
	})
}

func NewAdminInvestigationCloseHandler(service interface {
	Close(context.Context, audit.InvestigationCaseClosure) error
}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := requireSystemAdministrator(writer, request)
		if !ok {
			return
		}
		caseID := pathIdentifier(request, "caseID", "investigation-cases")
		if caseID == "" {
			writeErrorResponse(writer, CodeNotFound)
			return
		}
		if !validRawViewAuditID(caseID) {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		var body investigationClosureRequest
		if !decodeStrictJSON(writer, request, &body) {
			return
		}
		err := service.Close(request.Context(), audit.InvestigationCaseClosure{CaseID: caseID, Actor: session, Disposition: body.Disposition, Note: body.Note, Confirmed: body.Confirmed, ClosedAt: time.Now().UTC(), RequestID: adminRequestID(request)})
		if err != nil {
			writeInvestigationError(writer, err)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
}

func investigationCaseResponseFrom(item audit.InvestigationCase) investigationCaseResponse {
	return investigationCaseResponse{ID: item.ID, SubjectIdentityID: item.SubjectIdentityID, PolicyConcern: item.PolicyConcern, Reason: item.Reason, StartAt: item.StartAt, EndAt: item.EndAt, Status: item.Status, CreatedBy: item.CreatedBy, CreatedAt: item.CreatedAt, ClosedBy: item.ClosedBy, ClosedAt: item.ClosedAt, Disposition: item.Disposition, ClosureNote: item.ClosureNote}
}

func writeInvestigationError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, access.ErrSecurityAuditUnavailable):
		writeErrorResponse(writer, CodeAuditUnavailable)
	case errors.Is(err, access.ErrReauthenticationRequired):
		writeErrorResponse(writer, CodeReauthenticationRequired)
	case errors.Is(err, audit.ErrInvestigationForbidden):
		writeErrorResponse(writer, CodeForbidden)
	case errors.Is(err, audit.ErrInvestigationClosed):
		writeErrorResponse(writer, CodeConflict)
	case errors.Is(err, audit.ErrInvestigationNotFound), errors.Is(err, audit.ErrInvestigationGrantNotFound):
		writeErrorResponse(writer, CodeNotFound)
	case errors.Is(err, audit.ErrInvestigationScopeTooBroad):
		writeErrorResponse(writer, CodeInvestigationScopeTooBroad)
	case errors.Is(err, audit.ErrInvestigationSnapshotChanged):
		writeErrorResponse(writer, CodeConflict)
	case errors.Is(err, audit.ErrInvestigationNoCandidates):
		writeErrorResponse(writer, CodeInvestigationNoCandidates)
	case errors.Is(err, audit.ErrInvalidInvestigation):
		writeErrorResponse(writer, CodeInvalidRequest)
	default:
		writeErrorResponse(writer, CodeInternalError)
	}
}
