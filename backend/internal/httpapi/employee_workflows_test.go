package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/database"
	"n-api-p/internal/observability"
)

func TestPersonalKeyCreateUsesAuthenticatedIdentityAndRevealsCredentialOnce(t *testing.T) {
	service := &fakeEmployeePersonalKeys{issuance: access.PersonalKeyIssuance{
		Key: access.PersonalKey{ID: "key-1", IdentityID: "session-owner", Name: "laptop", Prefix: "nap_12345678", Status: access.PersonalKeyStatusActive},
	}}
	service.issuance.Credential = *mustGeneratedKey(t)
	handler := withEmployeeSession(NewPersonalKeyCreateHandler(service), access.ActivePortalSession{IdentityID: "session-owner", SessionID: "session-1"})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/me/personal-keys", bytes.NewBufferString(`{"name":"laptop"}`))
	request.Header.Set(observability.RequestIDHeader, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated || service.createInput.IdentityID != "session-owner" || service.createInput.RequestID != "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" {
		t.Fatalf("create result = (%d, %#v), want authenticated owner", recorder.Code, service.createInput)
	}
	var response KeyIssuance
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode issuance: %v", err)
	}
	if response.Credential.Value == "" {
		t.Fatal("create response did not contain the one-time credential")
	}
	if bytes.Contains(recorder.Body.Bytes(), []byte("verification_hash")) {
		t.Fatal("create response exposed verification material")
	}
}

func TestPersonalKeyRevokeRejectsForeignResourceWithoutCallingOwnerOverride(t *testing.T) {
	service := &fakeEmployeePersonalKeys{revokeErr: access.ErrPersonalKeyNotFound}
	handler := withEmployeeSession(NewPersonalKeyRevokeHandler(service), access.ActivePortalSession{IdentityID: "session-owner", SessionID: "session-1"})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/me/personal-keys/foreign-key", nil)
	request.Header.Set(observability.RequestIDHeader, "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
	handler.ServeHTTP(recorder, request)

	assertHTTPError(t, recorder, http.StatusNotFound, CodeNotFound)
	if service.revokeInput.IdentityID != "session-owner" || service.revokeInput.KeyID != "foreign-key" || service.revokeInput.RequestID != "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" {
		t.Fatalf("revoke input = %#v, want session-owned target", service.revokeInput)
	}
}

func TestPersonalKeyRevokeReturnsNoContent(t *testing.T) {
	service := &fakeEmployeePersonalKeys{}
	handler := withEmployeeSession(NewPersonalKeyRevokeHandler(service), access.ActivePortalSession{IdentityID: "session-owner", SessionID: "session-1"})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/api/v1/me/personal-keys/key-1", nil)
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent || service.revokeInput.IdentityID != "session-owner" || service.revokeInput.KeyID != "key-1" {
		t.Fatalf("revoke response/input = (%d, %#v), want 204 and session-owned key", recorder.Code, service.revokeInput)
	}
}

func TestPersonalKeyListUsesSessionOwnerAndOpaquePagination(t *testing.T) {
	service := &fakeEmployeePersonalKeys{page: access.PersonalKeyPage{Keys: []access.PersonalKey{{ID: "10000000-0000-0000-0000-000000000001", IdentityID: "session-owner", Name: "workstation", Prefix: "nap_12345678", Status: access.PersonalKeyStatusActive, CreatedAt: time.Date(2026, 8, 11, 1, 0, 0, 0, time.UTC)}}, NextCursor: &access.PersonalKeyCursor{ID: "10000000-0000-0000-0000-000000000001", CreatedAt: time.Date(2026, 8, 11, 1, 0, 0, 0, time.UTC)}}}
	handler := withEmployeeSession(NewPersonalKeyListHandler(service), access.ActivePortalSession{IdentityID: "session-owner"})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/me/personal-keys?account_id=foreign&limit=1", nil)
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || service.pageRequest.IdentityID != "session-owner" || service.pageRequest.Limit != 1 {
		t.Fatalf("list request = (%d, %#v), want bounded session-owned request", recorder.Code, service.pageRequest)
	}
	var response PagedResponse[Key]
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode key page: %v", err)
	}
	if !response.Pagination.HasMore || response.Pagination.NextCursor == "" || response.Data[0].OwnerAccountID != "session-owner" {
		t.Fatalf("key page = %#v, want opaque next cursor and owner metadata", response)
	}
}

func TestPersonalKeyListReturnsRevokedLifecycleMetadata(t *testing.T) {
	revokedAt := time.Date(2026, 8, 27, 8, 0, 0, 0, time.UTC)
	service := &fakeEmployeePersonalKeys{page: access.PersonalKeyPage{Keys: []access.PersonalKey{{
		ID: "10000000-0000-0000-0000-000000000001", IdentityID: "session-owner", Name: "workstation", Prefix: "nap_12345678",
		Status: access.PersonalKeyStatusRevoked, CreatedAt: revokedAt.Add(-time.Hour), RevokedAt: &revokedAt,
	}}}}
	handler := withEmployeeSession(NewPersonalKeyListHandler(service), access.ActivePortalSession{IdentityID: "session-owner"})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/me/personal-keys", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("list response status = %d, want %d", recorder.Code, http.StatusOK)
	}
	var response PagedResponse[Key]
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode revoked key page: %v", err)
	}
	if len(response.Data) != 1 || response.Data[0].Status != KeyStatusRevoked || response.Data[0].RevokedAt == nil || !response.Data[0].RevokedAt.Equal(revokedAt) {
		t.Fatalf("revoked key page = %#v, want retained revoked lifecycle metadata", response)
	}
}

func TestOwnUsageRejectsClientOwnerFilterAndUsesBoundedCursor(t *testing.T) {
	reader := &fakeOwnUsageReader{records: []database.UsageRecord{{ID: "usage-1", IdentityID: "session-owner", KeyID: "key-1", TeamID: "team-1", ModelID: "gpt-test", Outcome: "success", CreatedAt: time.Date(2026, 8, 11, 1, 2, 3, 0, time.UTC)}}}
	handler := withEmployeeSession(NewOwnUsageHandler(reader), access.ActivePortalSession{IdentityID: "session-owner", SessionID: "session-1"})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/me/usage?account_id=foreign&limit=1", nil)
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK || reader.filter.IdentityID != "session-owner" || reader.filter.Limit != 2 {
		t.Fatalf("usage request = (%d, %#v), want session owner and bounded limit", recorder.Code, reader.filter)
	}
}

func TestOwnUsageRejectsOversizedLimitAndMalformedCursor(t *testing.T) {
	for _, query := range []string{"limit=101", "cursor=not-a-valid-cursor"} {
		t.Run(query, func(t *testing.T) {
			handler := withEmployeeSession(NewOwnUsageHandler(&fakeOwnUsageReader{}), access.ActivePortalSession{IdentityID: "session-owner"})
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/me/usage?"+query, nil))
			assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
		})
	}
}

func TestLoginHandlerPublishesCSRFOnlyInResponseHeader(t *testing.T) {
	handler := NewLoginHandler(&fakePortalAuthenticator{session: access.PortalSession{Token: "session-token", CSRFToken: "csrf-token", IdentityID: "identity-1"}})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", bytes.NewBufferString(`{"email":"employee@example.internal","password":"correct"}`))
	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent || recorder.Header().Get(CSRFHeaderName) != "csrf-token" {
		t.Fatalf("login response = (%d, %q)", recorder.Code, recorder.Header().Get(CSRFHeaderName))
	}
	if bytes.Contains(recorder.Body.Bytes(), []byte("csrf-token")) || bytes.Contains(recorder.Body.Bytes(), []byte("session-token")) {
		t.Fatal("login response body exposed session credentials")
	}
}

type fakeEmployeePersonalKeys struct {
	issuance    access.PersonalKeyIssuance
	createInput access.CreatePersonalKeyInput
	page        access.PersonalKeyPage
	pageRequest access.PersonalKeyPageRequest
	revokeInput access.RevokePersonalKeyInput
	revokeErr   error
}

func (fake *fakeEmployeePersonalKeys) Create(_ context.Context, input access.CreatePersonalKeyInput) (access.PersonalKeyIssuance, error) {
	fake.createInput = input
	return fake.issuance, nil
}
func (fake *fakeEmployeePersonalKeys) List(context.Context, string) ([]access.PersonalKey, error) {
	return nil, nil
}
func (fake *fakeEmployeePersonalKeys) ListPage(_ context.Context, request access.PersonalKeyPageRequest) (access.PersonalKeyPage, error) {
	fake.pageRequest = request
	return fake.page, nil
}
func (fake *fakeEmployeePersonalKeys) Revoke(_ context.Context, input access.RevokePersonalKeyInput) error {
	fake.revokeInput = input
	return fake.revokeErr
}

type fakeOwnUsageReader struct {
	filter  database.UsageListFilter
	records []database.UsageRecord
}

func (fake *fakeOwnUsageReader) ListUsageRecords(_ context.Context, filter database.UsageListFilter) ([]database.UsageRecord, error) {
	fake.filter = filter
	return fake.records, nil
}

type fakePortalAuthenticator struct {
	session access.PortalSession
	err     error
}

func (fake *fakePortalAuthenticator) Login(context.Context, access.LoginInput) (access.PortalSession, error) {
	return fake.session, fake.err
}

func mustGeneratedKey(t *testing.T) *access.GeneratedAPIKey {
	t.Helper()
	generator := access.NewAPIKeyGenerator()
	key, err := generator.Generate()
	if err != nil {
		t.Fatalf("generate fake key: %v", err)
	}
	return key
}

func withEmployeeSession(handler http.Handler, session access.ActivePortalSession) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		request = request.WithContext(context.WithValue(request.Context(), portalSessionContextKey{}, session))
		handler.ServeHTTP(writer, request)
	})
}
