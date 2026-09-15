package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
)

func TestElevatedAuditGrantHandlerRequiresSystemAdministratorAndNoStore(t *testing.T) {
	service := &fakeElevatedAuditAccessService{grant: audit.ElevatedAuditGrant{ID: "grant-1", IssuedAt: time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, 9, 12, 9, 0, 0, 0, time.UTC)}}
	denied := httptest.NewRecorder()
	withEmployeeSession(NewElevatedAuditGrantHandler(service), access.ActivePortalSession{IdentityID: "employee-1", Role: access.RoleEmployee}).ServeHTTP(denied, httptest.NewRequest(http.MethodPost, "/api/v1/admin/audit-access/grants", bytes.NewBufferString(`{"purpose":"synthetic"}`)))
	assertHTTPError(t, denied, http.StatusForbidden, CodeForbidden)
	if service.called {
		t.Fatal("grant service called for denied role")
	}

	service.called = false
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/audit-access/grants", bytes.NewBufferString(`{"purpose":"synthetic"}`))
	recorder := httptest.NewRecorder()
	withEmployeeSession(NewElevatedAuditGrantHandler(service), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator}).ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated || recorder.Header().Get("Cache-Control") != "no-store" || !service.called {
		t.Fatalf("grant response = (%d, %q), called=%t", recorder.Code, recorder.Header().Get("Cache-Control"), service.called)
	}
	var response elevatedAuditGrantResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode grant response: %v", err)
	}
	if response.ID != "grant-1" || response.Status != "active" {
		t.Fatalf("grant response = %+v", response)
	}
}

func TestElevatedAuditHandlersMapGrantStateAndBatchValidation(t *testing.T) {
	service := &fakeElevatedAuditQueryService{err: audit.ErrElevatedAuditGrantRevoked}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/audits/query", bytes.NewBufferString(`{"limit":1}`))
	recorder := httptest.NewRecorder()
	withEmployeeSession(NewElevatedAuditQueryHandler(service, false), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator}).ServeHTTP(recorder, request)
	assertHTTPError(t, recorder, http.StatusForbidden, CodeGrantRevoked)

	batch := httptest.NewRecorder()
	withEmployeeSession(NewElevatedAuditQueryHandler(&fakeElevatedAuditQueryService{}, true), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator}).ServeHTTP(batch, httptest.NewRequest(http.MethodPost, "/api/v1/audits/batch", bytes.NewBufferString(`{"limit":1}`)))
	assertHTTPError(t, batch, http.StatusBadRequest, CodeInvalidQuery)
}

func TestElevatedAuditBatchHandlerAcceptsMaximumBatchPayload(t *testing.T) {
	const auditID = "84000000-0000-0000-0000-000000000070"
	auditIDs := strings.TrimSuffix(strings.Repeat(`"`+auditID+`",`, audit.MaxElevatedAuditBatchIDs), ",")
	requestBody := `{"audit_ids":[` + auditIDs + `],"limit":1000}`
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/audits/batch", strings.NewReader(requestBody))

	withEmployeeSession(NewElevatedAuditQueryHandler(&fakeElevatedAuditQueryService{}, true), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator}).ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("maximum batch payload returned status %d, body %q", recorder.Code, recorder.Body.String())
	}
}

func TestElevatedAuditExportHandlerMapsPreStreamErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		code   ErrorCode
		status int
	}{
		{name: "expired", err: audit.ErrElevatedAuditGrantExpired, code: CodeGrantExpired, status: http.StatusForbidden},
		{name: "revoked", err: audit.ErrElevatedAuditGrantRevoked, code: CodeGrantRevoked, status: http.StatusForbidden},
		{name: "incomplete", err: audit.ErrElevatedAuditExportIncomplete, code: CodeExportIncomplete, status: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &fakeElevatedAuditExportService{err: test.err}
			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodPost, "/api/v1/audits/exports", bytes.NewBufferString(`{"limit":1}`))
			withEmployeeSession(NewElevatedAuditExportHandler(service), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator}).ServeHTTP(recorder, request)
			if recorder.Header().Get("Cache-Control") != "no-store" || recorder.Code != test.status || recorder.Header().Get("Content-Type") != "application/json" {
				t.Fatalf("export response = status %d, headers %#v, body %q", recorder.Code, recorder.Header(), recorder.Body.String())
			}
			assertHTTPError(t, recorder, test.status, test.code)
		})
	}
}

func TestElevatedAuditExportHandlerAbortsStartedStreamOnFailure(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/audits/exports", bytes.NewBufferString(`{"limit":1}`))
	defer func() {
		if recovered := recover(); recovered != http.ErrAbortHandler {
			t.Fatalf("stream termination = %v, want HTTP abort", recovered)
		}
		if recorder.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("stream response is cacheable")
		}
	}()
	withEmployeeSession(NewElevatedAuditExportHandler(partialElevatedExportService{}), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator}).ServeHTTP(recorder, request)
}

func TestElevatedAuditExportFlushesRecordAndClientDetectsIncompleteBody(t *testing.T) {
	server := httptest.NewServer(withEmployeeSession(NewElevatedAuditExportHandler(partialElevatedExportService{}), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator}))
	defer server.Close()
	response, err := server.Client().Post(server.URL, "application/json", bytes.NewBufferString(`{"limit":1}`))
	if err != nil {
		t.Fatalf("first export record was not flushed: %v", err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(response.Body)
	if err == nil || !bytes.Contains(payload, []byte("synthetic-audit")) {
		t.Fatalf("client did not see flushed partial stream: bytes=%d, error=%v", len(payload), err)
	}
}

type partialElevatedExportService struct{}

func (partialElevatedExportService) Export(_ context.Context, _ audit.ElevatedAuditExportInput, writer io.Writer) error {
	if _, err := io.WriteString(writer, "{\"id\":\"synthetic-audit\"}\n"); err != nil {
		return err
	}
	return audit.ErrElevatedAuditExportIncomplete
}

type fakeElevatedAuditAccessService struct {
	grant  audit.ElevatedAuditGrant
	err    error
	called bool
}

func (service *fakeElevatedAuditAccessService) Issue(context.Context, audit.IssueElevatedAuditGrantInput) (audit.ElevatedAuditGrant, error) {
	service.called = true
	return service.grant, service.err
}

func (*fakeElevatedAuditAccessService) Revoke(context.Context, audit.RevokeElevatedAuditGrantInput) error {
	return nil
}

type fakeElevatedAuditQueryService struct {
	err error
}

func (service *fakeElevatedAuditQueryService) Query(context.Context, audit.ElevatedAuditQueryInput) (audit.ElevatedAuditPage, error) {
	return audit.ElevatedAuditPage{}, service.err
}

type fakeElevatedAuditExportService struct {
	err error
}

func (service *fakeElevatedAuditExportService) Export(context.Context, audit.ElevatedAuditExportInput, io.Writer) error {
	return service.err
}

var _ AdminElevatedAuditAccessService = (*fakeElevatedAuditAccessService)(nil)
var _ AdminElevatedAuditQueryService = (*fakeElevatedAuditQueryService)(nil)
var _ AdminElevatedAuditExportService = (*fakeElevatedAuditExportService)(nil)

func TestElevatedAuditHTTPBoundaryDeniesEveryNonAdministrator(t *testing.T) {
	for _, role := range []access.Role{access.RoleEmployee, access.RoleTeamAdministrator, ""} {
		for name, handler := range map[string]http.Handler{
			"issue":  NewElevatedAuditGrantHandler(&fakeElevatedAuditAccessService{}),
			"revoke": NewElevatedAuditGrantRevokeHandler(&fakeElevatedAuditAccessService{}),
			"query":  NewElevatedAuditQueryHandler(&fakeElevatedAuditQueryService{}, false),
			"batch":  NewElevatedAuditQueryHandler(&fakeElevatedAuditQueryService{}, true),
			"export": NewElevatedAuditExportHandler(&fakeElevatedAuditExportService{}),
		} {
			t.Run(name+string(role), func(t *testing.T) {
				recorder := httptest.NewRecorder()
				request := httptest.NewRequest(http.MethodPost, "/api/v1/audits", bytes.NewBufferString(`{"limit":1}`))
				if role != "" {
					handler = withEmployeeSession(handler, access.ActivePortalSession{IdentityID: "synthetic-user", Role: role})
				}
				handler.ServeHTTP(recorder, request)
				if recorder.Code != http.StatusForbidden && recorder.Code != http.StatusUnauthorized {
					t.Fatalf("role denial returned %d", recorder.Code)
				}
			})
		}
	}
}
