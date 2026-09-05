package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
)

const (
	httpInvestigationCaseID  = "83000000-0000-0000-0000-000000000001"
	httpInvestigationAuditID = "84000000-0000-0000-0000-000000000001"
)

func TestInvestigationHandlersRejectNonAdministratorsAndInvalidIDs(t *testing.T) {
	service := &httpInvestigationService{}
	nonAdmin := withEmployeeSession(NewAdminInvestigationCandidatesHandler(service), access.ActivePortalSession{
		IdentityID: "82000000-0000-0000-0000-000000000001", Role: access.RoleEmployee,
	})
	recorder := httptest.NewRecorder()
	nonAdmin.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/investigation-cases/"+httpInvestigationCaseID+"/audits", nil))
	assertHTTPError(t, recorder, http.StatusForbidden, CodeForbidden)
	if service.candidatesCalled {
		t.Fatal("candidate service ran for a non-administrator")
	}

	admin := access.ActivePortalSession{IdentityID: "82000000-0000-0000-0000-000000000002", Role: access.RoleSystemAdministrator}
	for _, test := range []struct {
		name    string
		handler http.Handler
		method  string
		path    string
		body    string
	}{
		{name: "candidates", handler: NewAdminInvestigationCandidatesHandler(service), method: http.MethodGet, path: "/api/v1/investigation-cases/not-a-uuid/audits"},
		{name: "grant", handler: NewAdminInvestigationGrantHandler(service), method: http.MethodPost, path: "/api/v1/investigation-cases/not-a-uuid/access-grants", body: `{ "confirmed": true }`},
		{name: "raw view case", handler: NewAdminInvestigationRawViewHandler(service), method: http.MethodPost, path: "/api/v1/investigation-cases/not-a-uuid/audits/" + httpInvestigationAuditID + "/raw-views", body: `{}`},
		{name: "raw view audit", handler: NewAdminInvestigationRawViewHandler(service), method: http.MethodPost, path: "/api/v1/investigation-cases/" + httpInvestigationCaseID + "/audits/not-a-uuid/raw-views", body: `{}`},
		{name: "close", handler: NewAdminInvestigationCloseHandler(service), method: http.MethodPost, path: "/api/v1/investigation-cases/not-a-uuid/closures", body: `{ "disposition": "inconclusive", "confirmed": true }`},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(test.method, test.path, bytes.NewBufferString(test.body))
			request = request.WithContext(context.WithValue(request.Context(), portalSessionContextKey{}, admin))
			test.handler.ServeHTTP(recorder, request)
			assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
		})
	}
}

func TestInvestigationHandlersUseStrictJSONAndNoStoreForRawView(t *testing.T) {
	service := &httpInvestigationService{view: audit.CaseRawView{
		AuditID:  httpInvestigationAuditID,
		Request:  audit.CaseContentView{Status: audit.ContentViewComplete, JSON: json.RawMessage(`{"prompt":"synthetic"}`)},
		Response: audit.CaseContentView{Status: audit.ContentViewComplete, JSON: json.RawMessage(`{"answer":"synthetic"}`)},
	}}
	admin := access.ActivePortalSession{IdentityID: "82000000-0000-0000-0000-000000000002", Role: access.RoleSystemAdministrator}
	for _, body := range []string{`{"confirmed":true,"unknown":true}`, `{"confirmed":true}{}`} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/api/v1/investigation-cases/"+httpInvestigationCaseID+"/access-grants", bytes.NewBufferString(body))
		request = request.WithContext(context.WithValue(request.Context(), portalSessionContextKey{}, admin))
		NewAdminInvestigationGrantHandler(service).ServeHTTP(recorder, request)
		assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
	}

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/investigation-cases/"+httpInvestigationCaseID+"/audits/"+httpInvestigationAuditID+"/raw-views", bytes.NewBufferString(`{}`))
	request = request.WithContext(context.WithValue(request.Context(), portalSessionContextKey{}, admin))
	NewAdminInvestigationRawViewHandler(service).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || !bytes.Contains(recorder.Body.Bytes(), []byte(`"audit_id":"`+httpInvestigationAuditID+`"`)) {
		t.Fatalf("raw view response = %d, cache=%q, body=%s", recorder.Code, recorder.Header().Get("Cache-Control"), recorder.Body.String())
	}
}

func TestInvestigationScopeErrorsExposeSpecificSafeCodes(t *testing.T) {
	for _, test := range []struct {
		name     string
		err      error
		wantCode string
	}{
		{name: "scope too broad", err: audit.ErrInvestigationScopeTooBroad, wantCode: "INVESTIGATION_SCOPE_TOO_BROAD"},
		{name: "no candidates", err: audit.ErrInvestigationNoCandidates, wantCode: "INVESTIGATION_NO_CANDIDATES"},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			writeInvestigationError(recorder, test.err)
			if recorder.Code != http.StatusConflict && test.err == audit.ErrInvestigationScopeTooBroad {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusConflict)
			}
			if recorder.Code != http.StatusBadRequest && test.err == audit.ErrInvestigationNoCandidates {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
			}
			if !bytes.Contains(recorder.Body.Bytes(), []byte(`"code":"`+test.wantCode+`"`)) {
				t.Fatalf("body = %s, want code %s", recorder.Body.String(), test.wantCode)
			}
		})
	}
}

type httpInvestigationService struct {
	view             audit.CaseRawView
	candidatesCalled bool
}

func (service *httpInvestigationService) Create(context.Context, audit.CreateInvestigationCaseInput) (audit.InvestigationCaseCreate, error) {
	return audit.InvestigationCaseCreate{}, errors.New("unexpected create call")
}

func (service *httpInvestigationService) List(context.Context, access.ActivePortalSession, audit.InvestigationCaseListFilter) (audit.InvestigationCasePage, error) {
	return audit.InvestigationCasePage{}, nil
}

func (service *httpInvestigationService) Candidates(context.Context, access.ActivePortalSession, string) ([]audit.InvestigationCandidate, error) {
	service.candidatesCalled = true
	return nil, nil
}

func (service *httpInvestigationService) Inspect(context.Context, audit.CaseRawViewInput) (audit.CaseRawView, error) {
	return service.view, nil
}

func (service *httpInvestigationService) IssueGrant(context.Context, audit.IssueInvestigationGrantInput) (audit.AccessGrant, error) {
	return audit.AccessGrant{CaseID: httpInvestigationCaseID, ExpiresAt: time.Now().UTC().Add(time.Minute)}, nil
}

func (service *httpInvestigationService) Close(context.Context, audit.InvestigationCaseClosure) error {
	return nil
}

var _ AdminInvestigationService = (*httpInvestigationService)(nil)
