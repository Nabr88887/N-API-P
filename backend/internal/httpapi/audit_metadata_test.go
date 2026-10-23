package httpapi

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
	"n-api-p/internal/database"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestAuditMetadataListHandlerReturnsNoStorePagedMetadataWithoutRawContent(t *testing.T) {
	service := &fakeAuditMetadataService{page: audit.MetadataPage{
		Records: []audit.Metadata{{
			ID: "84000000-0000-0000-0000-000000000001", RequestID: "87000000-0000-0000-0000-000000000001",
			ModelID: "<script>alert(1)</script>", CaptureStatus: audit.CaptureStatusComplete,
			Outcome: audit.AuditOutcomeSuccess, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
		}},
		NextCursor: "next-page",
	}}
	handler := withEmployeeSession(NewAdminAuditMetadataListHandler(service), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/audits?limit=25&cursor=opaque&model_id=gpt-test&capture_status=complete", nil))

	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status/headers = %d / %v: %s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	if service.listInput.Filter.Limit != 25 || service.listInput.Filter.Cursor != "opaque" || value(service.listInput.Filter.ModelID) != "gpt-test" || value(service.listInput.Filter.CaptureStatus) != "complete" {
		t.Fatalf("list filter = %+v", service.listInput.Filter)
	}
	if !strings.Contains(recorder.Body.String(), `"next_cursor":"next-page"`) || strings.Contains(recorder.Body.String(), "ciphertext") || strings.Contains(recorder.Body.String(), "raw_content") {
		t.Fatalf("metadata response = %s", recorder.Body.String())
	}
}

func TestAuditMetadataGetHandlerReturnsOneRecordAndEnforcesRole(t *testing.T) {
	service := &fakeAuditMetadataService{record: audit.Metadata{ID: rawViewHTTPAuditID, ModelID: "gpt-test", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}}
	handler := withEmployeeSession(NewAdminAuditMetadataGetHandler(service), access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/audits/"+rawViewHTTPAuditID, nil))
	if recorder.Code != http.StatusOK || recorder.Header().Get("Cache-Control") != "no-store" || service.getInput.AuditID != rawViewHTTPAuditID {
		t.Fatalf("status/header/input = %d / %q / %+v", recorder.Code, recorder.Header().Get("Cache-Control"), service.getInput)
	}

	denied := httptest.NewRecorder()
	withEmployeeSession(NewAdminAuditMetadataListHandler(service), access.ActivePortalSession{IdentityID: "employee-1", Role: access.RoleEmployee}).ServeHTTP(denied, httptest.NewRequest(http.MethodGet, "/api/v1/audits?limit=50", nil))
	assertHTTPError(t, denied, http.StatusForbidden, CodeForbidden)
	if service.listCalls != 0 {
		t.Fatal("audit metadata service called for denied role")
	}
}

func TestAuditMetadataHandlersClassifyRepositoryFailuresWithoutExposingDetails(t *testing.T) {
	session := access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator}
	failures := []struct {
		name   string
		err    error
		status int
		code   ErrorCode
	}{
		{name: "unexpected repository failure", err: errors.New("synthetic metadata repository failure"), status: http.StatusInternalServerError, code: CodeInternalError},
		{name: "database unavailable", err: audit.ErrMetadataUnavailable, status: http.StatusServiceUnavailable, code: CodeAuditUnavailable},
		{name: "connection exception", err: &pgconn.PgError{Code: "08006", Message: "synthetic connection failure"}, status: http.StatusServiceUnavailable, code: CodeAuditUnavailable},
		{name: "closed pgx connection", err: pgconn.ErrConnClosed, status: http.StatusServiceUnavailable, code: CodeAuditUnavailable},
		{name: "bad driver connection", err: driver.ErrBadConn, status: http.StatusServiceUnavailable, code: CodeAuditUnavailable},
		{name: "wrapped connection failure", err: fmt.Errorf("%w: %w", audit.ErrMetadataUnavailable, pgconn.ErrConnClosed), status: http.StatusServiceUnavailable, code: CodeAuditUnavailable},
		{name: "SQL syntax failure", err: &pgconn.PgError{Code: "42601", Message: "synthetic SQL failure"}, status: http.StatusInternalServerError, code: CodeInternalError},
		{name: "SQL resource failure", err: &pgconn.PgError{Code: "53200", Message: "synthetic SQL failure"}, status: http.StatusInternalServerError, code: CodeInternalError},
		{name: "request deadline", err: context.DeadlineExceeded, status: http.StatusInternalServerError, code: CodeInternalError},
		{name: "request cancellation", err: context.Canceled, status: http.StatusInternalServerError, code: CodeInternalError},
		{name: "network wrapped deadline", err: &net.OpError{Op: "read", Net: "tcp", Err: context.DeadlineExceeded}, status: http.StatusInternalServerError, code: CodeInternalError},
		{name: "invalid request", err: audit.ErrInvalidMetadataRequest, status: http.StatusBadRequest, code: CodeInvalidRequest},
		{name: "not found", err: audit.ErrMetadataNotFound, status: http.StatusNotFound, code: CodeNotFound},
	}
	for _, failure := range failures {
		t.Run(failure.name, func(t *testing.T) {
			connection := sql.OpenDB(&auditMetadataFailureConnector{err: failure.err})
			t.Cleanup(func() {
				if err := connection.Close(); err != nil {
					t.Errorf("close synthetic database: %v", err)
				}
			})
			repository := database.NewRepository(connection)
			service, err := audit.NewMetadataService(repository)
			if err != nil {
				t.Fatalf("NewMetadataService() error = %v", err)
			}
			handlers := []struct {
				name    string
				handler http.Handler
				path    string
			}{
				{name: "list", handler: NewAdminAuditMetadataListHandler(service), path: "/api/v1/audits?limit=25"},
				{name: "get", handler: NewAdminAuditMetadataGetHandler(service), path: "/api/v1/audits/" + rawViewHTTPAuditID},
			}
			for _, test := range handlers {
				t.Run(test.name, func(t *testing.T) {
					recorder := httptest.NewRecorder()
					withEmployeeSession(test.handler, session).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))

					assertHTTPError(t, recorder, failure.status, failure.code)
					if recorder.Header().Get("Cache-Control") != "no-store" {
						t.Fatal("metadata failure response must not be cached")
					}
					if strings.Contains(recorder.Body.String(), failure.err.Error()) {
						t.Fatalf("response exposed repository error: %s", recorder.Body.String())
					}
				})
			}
		})
	}
}

func TestAuditMetadataHandlersRejectUnauthorizedSessionsBeforeRepositoryCalls(t *testing.T) {
	tests := []struct {
		name    string
		session access.ActivePortalSession
		status  int
		code    ErrorCode
	}{
		{name: "anonymous", status: http.StatusUnauthorized, code: CodeAuthenticationRequired},
		{name: "employee", session: access.ActivePortalSession{IdentityID: "employee-1", Role: access.RoleEmployee}, status: http.StatusForbidden, code: CodeForbidden},
		{name: "team administrator", session: access.ActivePortalSession{IdentityID: "team-admin-1", Role: access.RoleTeamAdministrator}, status: http.StatusForbidden, code: CodeForbidden},
	}
	for _, test := range tests {
		for _, operation := range []string{"list", "get"} {
			t.Run(test.name+"/"+operation, func(t *testing.T) {
				repository := &failingAuditMetadataRepository{err: audit.ErrMetadataUnavailable}
				service, err := audit.NewMetadataService(repository)
				if err != nil {
					t.Fatalf("NewMetadataService() error = %v", err)
				}
				handler := NewAdminAuditMetadataListHandler(service)
				path := "/api/v1/audits?limit=25"
				if operation == "get" {
					handler = NewAdminAuditMetadataGetHandler(service)
					path = "/api/v1/audits/" + rawViewHTTPAuditID
				}
				if test.session.IdentityID != "" {
					handler = withEmployeeSession(handler, test.session)
				}
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
				assertHTTPError(t, recorder, test.status, test.code)
				if repository.calls != 0 {
					t.Fatal("unauthorized metadata request reached the repository")
				}
			})
		}
	}
}

func value[T ~string](input *T) string {
	if input == nil {
		return ""
	}
	return string(*input)
}

type fakeAuditMetadataService struct {
	page      audit.MetadataPage
	record    audit.Metadata
	listInput audit.MetadataListInput
	getInput  audit.MetadataGetInput
	listCalls int
}

type failingAuditMetadataRepository struct {
	err   error
	calls int
}

type auditMetadataFailureConnector struct{ err error }

func (connector *auditMetadataFailureConnector) Connect(context.Context) (driver.Conn, error) {
	return nil, connector.err
}
func (connector *auditMetadataFailureConnector) Driver() driver.Driver { return connector }
func (connector *auditMetadataFailureConnector) Open(string) (driver.Conn, error) {
	return nil, connector.err
}

func (repository *failingAuditMetadataRepository) ListAuditMetadata(context.Context, audit.MetadataFilter) (audit.MetadataPage, error) {
	repository.calls++
	return audit.MetadataPage{}, repository.err
}

func (repository *failingAuditMetadataRepository) GetAuditMetadata(context.Context, string) (audit.Metadata, error) {
	repository.calls++
	return audit.Metadata{}, repository.err
}

func (service *fakeAuditMetadataService) List(_ context.Context, input audit.MetadataListInput) (audit.MetadataPage, error) {
	service.listInput = input
	service.listCalls++
	return service.page, nil
}

func (service *fakeAuditMetadataService) Get(_ context.Context, input audit.MetadataGetInput) (audit.Metadata, error) {
	service.getInput = input
	return service.record, nil
}
