package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
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

func (service *fakeAuditMetadataService) List(_ context.Context, input audit.MetadataListInput) (audit.MetadataPage, error) {
	service.listInput = input
	service.listCalls++
	return service.page, nil
}

func (service *fakeAuditMetadataService) Get(_ context.Context, input audit.MetadataGetInput) (audit.Metadata, error) {
	service.getInput = input
	return service.record, nil
}
