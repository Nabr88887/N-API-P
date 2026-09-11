package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
)

const rawViewHTTPAuditID = "84000000-0000-0000-0000-000000000058"

func TestRawViewHandlerReturnsTypedNoStoreResponse(t *testing.T) {
	service := &fakeRawViewService{view: audit.RawView{
		AuditID:      rawViewHTTPAuditID,
		RequestJSON:  json.RawMessage(`{"messages":[{"role":"user","content":"secret prompt"}]}`),
		ResponseJSON: json.RawMessage(`{"choices":[{"message":{"content":"secret answer"}}]}`),
	}}
	request := rawViewHTTPRequest(`{"reason":"incident investigation"}`, access.RoleSystemAdministrator)
	recorder := httptest.NewRecorder()

	NewRawViewHandler(service).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusOK)
	}
	if recorder.Header().Get("Content-Type") != "application/json" || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response headers = %+v", recorder.Header())
	}
	if service.input.AuditID != rawViewHTTPAuditID || service.input.Reason != "incident investigation" || service.input.Session.Role != access.RoleSystemAdministrator {
		t.Fatalf("inspect input = %+v", service.input)
	}
	var response struct {
		AuditID  string          `json:"audit_id"`
		Request  json.RawMessage `json:"request"`
		Response json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.AuditID != rawViewHTTPAuditID || !bytes.Equal(response.Request, service.view.RequestJSON) || !bytes.Equal(response.Response, service.view.ResponseJSON) {
		t.Fatalf("response = %+v", response)
	}
}

func TestRawViewHandlerRejectsMalformedBodiesAndMissingSession(t *testing.T) {
	service := &fakeRawViewService{}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/audits/"+rawViewHTTPAuditID+"/raw-views", strings.NewReader(`{"reason":"investigate"}`))
	recorder := httptest.NewRecorder()
	NewRawViewHandler(service).ServeHTTP(recorder, request)
	assertHTTPError(t, recorder, http.StatusUnauthorized, CodeAuthenticationRequired)

	for _, body := range []string{
		`{"reason":"investigate","unknown":true}`,
		`{"reason":"investigate"}{}`,
		`not-json`,
	} {
		t.Run(body, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			NewRawViewHandler(service).ServeHTTP(recorder, rawViewHTTPRequest(body, access.RoleSystemAdministrator))
			assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
			if recorder.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("cache header = %q", recorder.Header().Get("Cache-Control"))
			}
		})
	}

	recorder = httptest.NewRecorder()
	invalidIDRequest := httptest.NewRequest(http.MethodPost, "/api/v1/audits/not-a-uuid/raw-views", strings.NewReader(`{"reason":"investigate"}`))
	grantUntil := time.Date(2026, 8, 6, 12, 5, 0, 0, time.UTC)
	invalidIDRequest = invalidIDRequest.WithContext(context.WithValue(invalidIDRequest.Context(), portalSessionContextKey{}, access.ActivePortalSession{
		SessionID: "session-1", IdentityID: "identity-1", Role: access.RoleSystemAdministrator, ReauthenticatedUntil: &grantUntil,
	}))
	NewRawViewHandler(service).ServeHTTP(recorder, invalidIDRequest)
	assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
}

func TestRawViewHandlerMapsFailuresWithoutReturningPlaintext(t *testing.T) {
	tests := map[string]struct {
		err    error
		status int
		code   ErrorCode
		reason string
		role   access.Role
	}{
		"employee forbidden":     {err: access.ErrSensitiveActionForbidden, status: http.StatusForbidden, code: CodeForbidden, reason: "investigate", role: access.RoleEmployee},
		"team forbidden":         {err: access.ErrSensitiveActionForbidden, status: http.StatusForbidden, code: CodeForbidden, reason: "investigate", role: access.RoleTeamAdministrator},
		"stale reauthentication": {err: access.ErrReauthenticationRequired, status: http.StatusForbidden, code: CodeReauthenticationRequired, reason: "investigate", role: access.RoleSystemAdministrator},
		"blank reason":           {err: audit.ErrRawViewReasonRequired, status: http.StatusBadRequest, code: CodeInvalidRequest, reason: "   ", role: access.RoleSystemAdministrator},
		"missing or expired":     {err: audit.ErrRawViewNotFound, status: http.StatusNotFound, code: CodeNotFound, reason: "investigate", role: access.RoleSystemAdministrator},
		"decryption failure":     {err: audit.ErrRawViewDecryptionFailed, status: http.StatusInternalServerError, code: CodeInternalError, reason: "investigate", role: access.RoleSystemAdministrator},
		"event failure":          {err: access.ErrSecurityAuditUnavailable, status: http.StatusServiceUnavailable, code: CodeAuditUnavailable, reason: "investigate", role: access.RoleSystemAdministrator},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			service := &fakeRawViewService{
				view: audit.RawView{RequestJSON: json.RawMessage(`{"secret":"prompt"}`), ResponseJSON: json.RawMessage(`{"secret":"answer"}`)},
				err:  test.err,
			}
			recorder := httptest.NewRecorder()
			NewRawViewHandler(service).ServeHTTP(recorder, rawViewHTTPRequest(`{"reason":"`+test.reason+`"}`, test.role))
			assertHTTPError(t, recorder, test.status, test.code)
			if recorder.Header().Get("Cache-Control") != "no-store" || strings.Contains(recorder.Body.String(), "prompt") || strings.Contains(recorder.Body.String(), "answer") {
				t.Fatalf("failure response leaked or was cacheable: headers=%v body=%s", recorder.Header(), recorder.Body.String())
			}
		})
	}
}

func TestRawViewRouteIsSingleRecordOnlyWithoutSearchBulkOrExport(t *testing.T) {
	var rawRoutes []Route
	for _, route := range Routes() {
		text := strings.ToLower(string(route.Name) + " " + route.Pattern)
		if strings.HasPrefix(string(route.Name), "admin.elevated_audit.") {
			continue
		}
		if strings.Contains(text, "raw") {
			rawRoutes = append(rawRoutes, route)
		}
		for _, forbidden := range []string{"full-text", "full_text", "search", "bulk", "export"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("forbidden raw inspection capability in route inventory: %+v", route)
			}
		}
	}
	if len(rawRoutes) != 2 {
		t.Fatalf("raw routes = %+v, want the existing and case-scoped single-record routes", rawRoutes)
	}
	want := map[string]struct {
		name    RouteName
		pattern string
	}{
		"POST /api/v1/audits/{auditID}/raw-views":                              {name: RouteName("admin.audits.view_raw"), pattern: "/api/v1/audits/{auditID}/raw-views"},
		"POST /api/v1/investigation-cases/{caseID}/audits/{auditID}/raw-views": {name: RouteName("admin.investigations.raw_view"), pattern: "/api/v1/investigation-cases/{caseID}/audits/{auditID}/raw-views"},
	}
	for _, route := range rawRoutes {
		expected, ok := want[routeKey(route.Method, route.Pattern)]
		if !ok || route.Name != expected.name || route.Pattern != expected.pattern || route.Method != MethodPost || len(route.Roles) != 1 || route.Roles[0] != RoleSystemAdministrator {
			t.Fatalf("raw route = %+v", route)
		}
	}
}

func rawViewHTTPRequest(body string, role access.Role) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/audits/"+rawViewHTTPAuditID+"/raw-views", strings.NewReader(body))
	grantUntil := time.Date(2026, 8, 6, 12, 5, 0, 0, time.UTC)
	return request.WithContext(context.WithValue(request.Context(), portalSessionContextKey{}, access.ActivePortalSession{
		SessionID: "session-1", IdentityID: "identity-1", Role: role, ReauthenticatedUntil: &grantUntil,
	}))
}

type fakeRawViewService struct {
	view  audit.RawView
	input audit.RawViewInput
	err   error
}

func (service *fakeRawViewService) Inspect(_ context.Context, input audit.RawViewInput) (audit.RawView, error) {
	service.input = input
	return service.view, service.err
}

var _ RawViewInspector = (*fakeRawViewService)(nil)
