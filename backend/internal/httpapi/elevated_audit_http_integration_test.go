//go:build integration

package httpapi_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratepgx "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"n-api-p/internal/access"
	"n-api-p/internal/audit"
	"n-api-p/internal/database"
	"n-api-p/internal/httpapi"
	"n-api-p/internal/operations"
)

func TestElevatedAuditAdminRouterUsesSessionCSRFAndPostgresChain(t *testing.T) {
	db := migrateHTTPIntegrationSchema(t)
	fixture, data := insertHTTPAuditFixture(t, db)

	adminToken := "synthetic-router-admin-token"
	adminCSRF := "synthetic-router-admin-csrf"
	adminSessionID := "85000000-0000-0000-0000-000000000070"
	insertRouterSession(t, db, adminSessionID, fixture.identityID, adminToken, adminCSRF, data.issuedAt)
	employeeToken := "synthetic-router-employee-token"
	employeeCSRF := "synthetic-router-employee-csrf"
	employeeSessionID := "85000000-0000-0000-0000-000000000071"
	insertRouterSession(t, db, employeeSessionID, data.employeeID, employeeToken, employeeCSRF, data.issuedAt)
	teamAdminID := "82000000-0000-0000-0000-000000000072"
	teamAdminToken := "synthetic-router-team-admin-token"
	teamAdminCSRF := "synthetic-router-team-admin-csrf"
	teamAdminSessionID := "85000000-0000-0000-0000-000000000072"
	mustHTTPExec(t, db, `INSERT INTO identities (id, email, role, status) VALUES ($1, 'router-team-admin@example.internal', 'team_administrator', 'active')`, teamAdminID)
	insertRouterSession(t, db, teamAdminSessionID, teamAdminID, teamAdminToken, teamAdminCSRF, data.issuedAt)

	router := newIntegratedPortalRouter(t, db)
	origin := "https://portal.example.internal"
	for _, test := range []struct {
		name, method, path, body string
		status                   int
		code                     httpapi.ErrorCode
	}{
		{name: "anonymous issue", method: http.MethodPost, path: "/api/v1/admin/audit-access/grants", body: `{"purpose":"anonymous"}`, status: http.StatusUnauthorized, code: httpapi.CodeAuthenticationRequired},
		{name: "anonymous query", method: http.MethodPost, path: "/api/v1/audits/query", body: `{}`, status: http.StatusUnauthorized, code: httpapi.CodeAuthenticationRequired},
		{name: "anonymous batch", method: http.MethodPost, path: "/api/v1/audits/batch", body: `{"audit_ids":["84000000-0000-0000-0000-000000000070"]}`, status: http.StatusUnauthorized, code: httpapi.CodeAuthenticationRequired},
		{name: "anonymous export", method: http.MethodPost, path: "/api/v1/audits/exports", body: `{}`, status: http.StatusUnauthorized, code: httpapi.CodeAuthenticationRequired},
		{name: "anonymous revoke", method: http.MethodDelete, path: "/api/v1/admin/audit-access/grants/current", status: http.StatusUnauthorized, code: httpapi.CodeAuthenticationRequired},
		{name: "team administrator issue", method: http.MethodPost, path: "/api/v1/admin/audit-access/grants", body: `{"purpose":"team admin"}`, status: http.StatusForbidden, code: httpapi.CodeForbidden},
		{name: "team administrator query", method: http.MethodPost, path: "/api/v1/audits/query", body: `{}`, status: http.StatusForbidden, code: httpapi.CodeForbidden},
		{name: "team administrator batch", method: http.MethodPost, path: "/api/v1/audits/batch", body: `{"audit_ids":["84000000-0000-0000-0000-000000000070"]}`, status: http.StatusForbidden, code: httpapi.CodeForbidden},
		{name: "team administrator export", method: http.MethodPost, path: "/api/v1/audits/exports", body: `{}`, status: http.StatusForbidden, code: httpapi.CodeForbidden},
		{name: "team administrator revoke", method: http.MethodDelete, path: "/api/v1/admin/audit-access/grants/current", status: http.StatusForbidden, code: httpapi.CodeForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			token, csrf := "", ""
			if strings.HasPrefix(test.name, "team administrator") {
				token, csrf = teamAdminToken, teamAdminCSRF
			}
			request := routerRequest(test.method, test.path, token, csrf, origin, test.body)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			assertHTTPIntegrationError(t, recorder, test.status, test.code)
		})
	}

	missingCSRF := routerRequest(http.MethodPost, "/api/v1/admin/audit-access/grants", adminToken, "", origin, `{"purpose":"router integration"}`)
	missingCSRFRecorder := httptest.NewRecorder()
	router.ServeHTTP(missingCSRFRecorder, missingCSRF)
	assertHTTPIntegrationError(t, missingCSRFRecorder, http.StatusForbidden, httpapi.CodeCSRFRejected)

	missingOrigin := routerRequest(http.MethodPost, "/api/v1/admin/audit-access/grants", adminToken, adminCSRF, "", `{"purpose":"router integration"}`)
	missingOriginRecorder := httptest.NewRecorder()
	router.ServeHTTP(missingOriginRecorder, missingOrigin)
	assertHTTPIntegrationError(t, missingOriginRecorder, http.StatusForbidden, httpapi.CodeCSRFRejected)

	wrongCSRF := routerRequest(http.MethodPost, "/api/v1/admin/audit-access/grants", adminToken, "wrong-csrf", origin, `{"purpose":"router integration"}`)
	wrongCSRFRecorder := httptest.NewRecorder()
	router.ServeHTTP(wrongCSRFRecorder, wrongCSRF)
	assertHTTPIntegrationError(t, wrongCSRFRecorder, http.StatusForbidden, httpapi.CodeCSRFRejected)

	foreignOrigin := routerRequest(http.MethodPost, "/api/v1/admin/audit-access/grants", adminToken, adminCSRF, "https://evil.example.internal", `{"purpose":"router integration"}`)
	foreignOriginRecorder := httptest.NewRecorder()
	router.ServeHTTP(foreignOriginRecorder, foreignOrigin)
	assertHTTPIntegrationError(t, foreignOriginRecorder, http.StatusForbidden, httpapi.CodeCSRFRejected)

	employeeRequest := routerRequest(http.MethodPost, "/api/v1/admin/audit-access/grants", employeeToken, employeeCSRF, origin, `{"purpose":"employee must fail"}`)
	employeeRecorder := httptest.NewRecorder()
	router.ServeHTTP(employeeRecorder, employeeRequest)
	assertHTTPIntegrationError(t, employeeRecorder, http.StatusForbidden, httpapi.CodeForbidden)

	issueRequest := routerRequest(http.MethodPost, "/api/v1/admin/audit-access/grants", adminToken, adminCSRF, origin, `{"purpose":"router integration"}`)
	issueRecorder := httptest.NewRecorder()
	router.ServeHTTP(issueRecorder, issueRequest)
	if issueRecorder.Code != http.StatusCreated || issueRecorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("grant route status/cache = (%d, %q), want (201, no-store): %s", issueRecorder.Code, issueRecorder.Header().Get("Cache-Control"), issueRecorder.Body.String())
	}
	var grantResponse struct {
		ID        string    `json:"id"`
		Status    string    `json:"status"`
		IssuedAt  time.Time `json:"issued_at"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(issueRecorder.Body.Bytes(), &grantResponse); err != nil {
		t.Fatalf("decode grant response: %v", err)
	}
	if grantResponse.ID == "" || grantResponse.Status != "active" || !grantResponse.ExpiresAt.After(grantResponse.IssuedAt) || grantResponse.ExpiresAt.Sub(grantResponse.IssuedAt) > 24*time.Hour {
		t.Fatalf("grant response = %+v", grantResponse)
	}
	if strings.Contains(issueRecorder.Body.String(), "bearer") || strings.Contains(issueRecorder.Body.String(), "token") {
		t.Fatalf("grant response appears to contain a bearer secret: %s", issueRecorder.Body.String())
	}

	batchRequest := routerRequest(http.MethodPost, "/api/v1/audits/batch", adminToken, adminCSRF, origin, `{"audit_ids":["84000000-0000-0000-0000-000000000070"],"limit":1}`)
	batchRecorder := httptest.NewRecorder()
	router.ServeHTTP(batchRecorder, batchRequest)
	if batchRecorder.Code != http.StatusOK || !bytes.Contains(batchRecorder.Body.Bytes(), []byte(data.auditID)) || batchRecorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("batch route status/cache/body = (%d, %q, %s)", batchRecorder.Code, batchRecorder.Header().Get("Cache-Control"), batchRecorder.Body.String())
	}

	exportRequest := routerRequest(http.MethodPost, "/api/v1/audits/exports", adminToken, adminCSRF, origin, `{"full_text":"needle","limit":1}`)
	exportRecorder := httptest.NewRecorder()
	router.ServeHTTP(exportRecorder, exportRequest)
	if exportRecorder.Code != http.StatusOK || exportRecorder.Header().Get("Content-Type") != "application/x-ndjson; charset=utf-8" || exportRecorder.Header().Get("Cache-Control") != "no-store" || !bytes.Contains(exportRecorder.Body.Bytes(), []byte(data.auditID)) || !bytes.Contains(exportRecorder.Body.Bytes(), []byte("synthetic needle")) {
		t.Fatalf("export route status/content-type/cache/body = (%d, %q, %q, %s)", exportRecorder.Code, exportRecorder.Header().Get("Content-Type"), exportRecorder.Header().Get("Cache-Control"), exportRecorder.Body.String())
	}

	firstPageRequest := routerRequest(http.MethodPost, "/api/v1/audits/query", adminToken, adminCSRF, origin, `{"limit":1}`)
	firstPageRecorder := httptest.NewRecorder()
	router.ServeHTTP(firstPageRecorder, firstPageRequest)
	var firstPage struct {
		Data []struct {
			ID         string `json:"id"`
			IdentityID string `json:"identity_id"`
		} `json:"data"`
		Pagination struct {
			NextCursor string `json:"next_cursor"`
			HasMore    bool   `json:"has_more"`
		} `json:"pagination"`
	}
	if firstPageRecorder.Code != http.StatusOK || json.Unmarshal(firstPageRecorder.Body.Bytes(), &firstPage) != nil || len(firstPage.Data) != 1 || firstPage.Data[0].ID != data.auditID || firstPage.Data[0].IdentityID != data.employeeID || !firstPage.Pagination.HasMore || firstPage.Pagination.NextCursor == "" {
		t.Fatalf("first cursor page = status %d body %s parsed %+v", firstPageRecorder.Code, firstPageRecorder.Body.String(), firstPage)
	}
	cursorBody, err := json.Marshal(struct {
		Cursor string `json:"cursor"`
		Limit  int    `json:"limit"`
	}{Cursor: firstPage.Pagination.NextCursor, Limit: 1})
	if err != nil {
		t.Fatalf("encode cursor continuation request: %v", err)
	}
	secondPageRequest := routerRequest(http.MethodPost, "/api/v1/audits/query", adminToken, adminCSRF, origin, string(cursorBody))
	secondPageRecorder := httptest.NewRecorder()
	router.ServeHTTP(secondPageRecorder, secondPageRequest)
	var secondPage struct {
		Data []struct {
			ID         string `json:"id"`
			IdentityID string `json:"identity_id"`
		} `json:"data"`
	}
	if secondPageRecorder.Code != http.StatusOK || json.Unmarshal(secondPageRecorder.Body.Bytes(), &secondPage) != nil || len(secondPage.Data) != 1 || secondPage.Data[0].ID != data.secondAuditID || secondPage.Data[0].IdentityID != data.secondEmployeeID {
		t.Fatalf("second cursor page = status %d body %s parsed %+v", secondPageRecorder.Code, secondPageRecorder.Body.String(), secondPage)
	}

	employeeFilterRequest := routerRequest(http.MethodPost, "/api/v1/audits/query", adminToken, adminCSRF, origin, `{"identity_id":"`+data.secondEmployeeID+`","limit":1}`)
	employeeFilterRecorder := httptest.NewRecorder()
	router.ServeHTTP(employeeFilterRecorder, employeeFilterRequest)
	var employeeFilterPage struct {
		Data []struct {
			ID         string `json:"id"`
			IdentityID string `json:"identity_id"`
		} `json:"data"`
	}
	if employeeFilterRecorder.Code != http.StatusOK || json.Unmarshal(employeeFilterRecorder.Body.Bytes(), &employeeFilterPage) != nil || len(employeeFilterPage.Data) != 1 || employeeFilterPage.Data[0].ID != data.secondAuditID || employeeFilterPage.Data[0].IdentityID != data.secondEmployeeID {
		t.Fatalf("employee filter page = status %d body %s parsed %+v", employeeFilterRecorder.Code, employeeFilterRecorder.Body.String(), employeeFilterPage)
	}

	serviceFilterRequest := routerRequest(http.MethodPost, "/api/v1/audits/query", adminToken, adminCSRF, origin, `{"service_account_id":"`+data.serviceAccountID+`","responsible_identity_id":"`+data.secondEmployeeID+`","limit":1}`)
	serviceFilterRecorder := httptest.NewRecorder()
	router.ServeHTTP(serviceFilterRecorder, serviceFilterRequest)
	var serviceFilterPage struct {
		Data []struct {
			ID                    string `json:"id"`
			ServiceAccountID      string `json:"service_account_id"`
			ResponsibleIdentityID string `json:"responsible_identity_id"`
		} `json:"data"`
	}
	if serviceFilterRecorder.Code != http.StatusOK || json.Unmarshal(serviceFilterRecorder.Body.Bytes(), &serviceFilterPage) != nil || len(serviceFilterPage.Data) != 1 || serviceFilterPage.Data[0].ID != data.serviceAuditID || serviceFilterPage.Data[0].ServiceAccountID != data.serviceAccountID || serviceFilterPage.Data[0].ResponsibleIdentityID != data.secondEmployeeID {
		t.Fatalf("service-account filter page = status %d body %s parsed %+v", serviceFilterRecorder.Code, serviceFilterRecorder.Body.String(), serviceFilterPage)
	}

	tamperedCursorRequest := routerRequest(http.MethodPost, "/api/v1/audits/query", adminToken, adminCSRF, origin, `{"cursor":"tampered","limit":1}`)
	tamperedCursorRecorder := httptest.NewRecorder()
	router.ServeHTTP(tamperedCursorRecorder, tamperedCursorRequest)
	assertHTTPIntegrationError(t, tamperedCursorRecorder, http.StatusBadRequest, httpapi.CodeInvalidCursor)

	queryRequest := routerRequest(http.MethodPost, "/api/v1/audits/query", adminToken, adminCSRF, origin, `{"full_text":"needle","limit":1}`)
	queryRecorder := httptest.NewRecorder()
	router.ServeHTTP(queryRecorder, queryRequest)
	if queryRecorder.Code != http.StatusOK || queryRecorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("query route status/cache = (%d, %q), want (200, no-store): %s", queryRecorder.Code, queryRecorder.Header().Get("Cache-Control"), queryRecorder.Body.String())
	}
	if !bytes.Contains(queryRecorder.Body.Bytes(), []byte(data.auditID)) || !bytes.Contains(queryRecorder.Body.Bytes(), []byte("synthetic needle")) {
		t.Fatalf("query route body does not contain PostgreSQL result: %s", queryRecorder.Body.String())
	}
	for _, forbidden := range []string{"query-one-key-hash", "verification_hash", "upstream_token", "ciphertext"} {
		if strings.Contains(queryRecorder.Body.String(), forbidden) {
			t.Fatalf("query route body contains forbidden field %q: %s", forbidden, queryRecorder.Body.String())
		}
	}
	var queryMetadata sql.NullString
	var queryReason, queryDetailCode string
	var queryResultCount int64
	if err := db.QueryRow(`SELECT query_metadata::text, COALESCE(reason, ''), COALESCE(detail_code, ''), COALESCE(result_count, 0) FROM security_events WHERE event_type = 'audit_query' AND grant_id = $1 ORDER BY occurred_at DESC LIMIT 1`, grantResponse.ID).Scan(&queryMetadata, &queryReason, &queryDetailCode, &queryResultCount); err != nil {
		t.Fatalf("read query security event: %v", err)
	}
	if !queryMetadata.Valid || strings.Contains(queryMetadata.String, "needle") || strings.Contains(queryMetadata.String, "synthetic") || queryReason != "router integration" || queryDetailCode != "query_completed" || queryResultCount != 1 {
		t.Fatalf("query security event metadata = (%q, %q, %q, %d), want content-free metadata with purpose and count 1", queryMetadata.String, queryReason, queryDetailCode, queryResultCount)
	}

	revokeRequest := routerRequest(http.MethodDelete, "/api/v1/admin/audit-access/grants/current", adminToken, adminCSRF, origin, "")
	revokeRecorder := httptest.NewRecorder()
	router.ServeHTTP(revokeRecorder, revokeRequest)
	if revokeRecorder.Code != http.StatusNoContent {
		t.Fatalf("revoke route status = %d, want 204: %s", revokeRecorder.Code, revokeRecorder.Body.String())
	}
	staleRequest := routerRequest(http.MethodPost, "/api/v1/audits/query", adminToken, adminCSRF, origin, `{"limit":1}`)
	staleRecorder := httptest.NewRecorder()
	router.ServeHTTP(staleRecorder, staleRequest)
	assertHTTPIntegrationError(t, staleRecorder, http.StatusForbidden, httpapi.CodeGrantRevoked)
}

func TestElevatedAuditPortalRouterRejectsCrossSessionAndExpiredGrants(t *testing.T) {
	db := migrateHTTPIntegrationSchema(t)
	fixture, data := insertHTTPAuditFixture(t, db)
	adminToken := "synthetic-router-expiry-admin-token"
	adminCSRF := "synthetic-router-expiry-admin-csrf"
	adminSessionID := "85000000-0000-0000-0000-000000000073"
	insertRouterSession(t, db, adminSessionID, fixture.identityID, adminToken, adminCSRF, data.issuedAt)
	otherToken := "synthetic-router-other-session-token"
	otherCSRF := "synthetic-router-other-session-csrf"
	otherSessionID := "85000000-0000-0000-0000-000000000074"
	insertRouterSession(t, db, otherSessionID, fixture.identityID, otherToken, otherCSRF, data.issuedAt)
	router := newIntegratedPortalRouter(t, db)
	origin := "https://portal.example.internal"
	issueRequest := routerRequest(http.MethodPost, "/api/v1/admin/audit-access/grants", adminToken, adminCSRF, origin, `{"purpose":"session binding"}`)
	issueRecorder := httptest.NewRecorder()
	router.ServeHTTP(issueRecorder, issueRequest)
	if issueRecorder.Code != http.StatusCreated {
		t.Fatalf("issue status = %d: %s", issueRecorder.Code, issueRecorder.Body.String())
	}
	otherRequest := routerRequest(http.MethodPost, "/api/v1/audits/query", otherToken, otherCSRF, origin, `{"limit":1}`)
	otherRecorder := httptest.NewRecorder()
	router.ServeHTTP(otherRecorder, otherRequest)
	assertHTTPIntegrationError(t, otherRecorder, http.StatusForbidden, httpapi.CodeGrantExpired)
	var grantID string
	if err := json.Unmarshal(issueRecorder.Body.Bytes(), &struct {
		ID *string `json:"id"`
	}{ID: &grantID}); err != nil || grantID == "" {
		t.Fatalf("decode issued grant id: %v", err)
	}
	expiredIssuedAt := time.Now().UTC().Add(-2 * time.Hour)
	expiredAt := expiredIssuedAt.Add(time.Hour)
	mustHTTPExec(t, db, `UPDATE elevated_audit_grants SET issued_at = $1, expires_at = $2 WHERE id = $3`, expiredIssuedAt, expiredAt, grantID)
	expiredRequest := routerRequest(http.MethodPost, "/api/v1/audits/query", adminToken, adminCSRF, origin, `{"limit":1}`)
	expiredRecorder := httptest.NewRecorder()
	router.ServeHTTP(expiredRecorder, expiredRequest)
	assertHTTPIntegrationError(t, expiredRecorder, http.StatusForbidden, httpapi.CodeGrantExpired)
}

func newIntegratedPortalRouter(t *testing.T, db *sql.DB) http.Handler {
	t.Helper()
	repository := database.NewRepository(db)
	passwords := access.NewArgon2idPasswordHasher()
	authenticator, err := access.NewAuthenticationService(repository, passwords)
	if err != nil {
		t.Fatalf("NewAuthenticationService() error = %v", err)
	}
	sessions := access.NewSessionService(repository)
	sensitiveActions := access.NewSensitiveActionGuard(repository)
	passwordReset := access.NewPasswordResetService(repository, passwords, sensitiveActions)
	modelAllowlist, err := access.NewModelAllowlistService(repository)
	if err != nil {
		t.Fatalf("NewModelAllowlistService() error = %v", err)
	}
	retention, err := access.NewRetentionPolicyService(repository, 30)
	if err != nil {
		t.Fatalf("NewRetentionPolicyService() error = %v", err)
	}
	envelope, err := audit.NewEnvelopeService(1, map[int][]byte{1: bytes.Repeat([]byte{0x41}, 32)})
	if err != nil {
		t.Fatalf("NewEnvelopeService() error = %v", err)
	}
	metadata, err := audit.NewMetadataService(repository)
	if err != nil {
		t.Fatalf("NewMetadataService() error = %v", err)
	}
	rawView, err := audit.NewRawViewService(repository, envelope)
	if err != nil {
		t.Fatalf("NewRawViewService() error = %v", err)
	}
	investigations, err := audit.NewInvestigationService(repository, envelope)
	if err != nil {
		t.Fatalf("NewInvestigationService() error = %v", err)
	}
	elevatedAccess, err := audit.NewElevatedAuditAccessService(repository)
	if err != nil {
		t.Fatalf("NewElevatedAuditAccessService() error = %v", err)
	}
	elevatedQuery, err := audit.NewElevatedAuditQueryService(repository, envelope)
	if err != nil {
		t.Fatalf("NewElevatedAuditQueryService() error = %v", err)
	}
	elevatedExport, err := audit.NewElevatedAuditExportService(elevatedQuery)
	if err != nil {
		t.Fatalf("NewElevatedAuditExportService() error = %v", err)
	}
	admin := access.NewAdministrationService(repository)
	offboarding := access.NewOffboardingService(repository)
	serviceAccounts := access.NewServiceAccountService(repository)
	identity := access.NewIdentityService(repository)
	invitation := access.NewInvitationService(repository)
	operationsService, err := operations.NewService(repository)
	if err != nil {
		t.Fatalf("operations.NewService() error = %v", err)
	}
	activation := access.NewActivationService(repository, passwords, access.NewActivationLimiter())
	reauthentication := access.NewReauthenticationService(repository, passwords)
	personalKeys := access.NewPersonalKeyService(repository)
	router, err := httpapi.NewPortalRouter(httpapi.PortalRouterDependencies{
		Sessions: sessions, AllowedOrigin: "https://portal.example.internal", Authenticator: authenticator,
		Activation: activation, PasswordReset: passwordReset, Identity: repository,
		Reauthentication: reauthentication, EmployeeKeys: personalKeys, OwnUsage: repository, Team: repository,
		Admin: httpapi.AdminPortalDependencies{
			Sessions: sessions, AllowedOrigin: "https://portal.example.internal", Invitations: invitation,
			PasswordResets: passwordReset, ServiceKeys: serviceAccounts, ServiceKeyRevoke: serviceAccounts,
			Models: modelAllowlist, Retention: retention, Administration: admin, Audits: metadata, RawView: rawView,
			Operations: operationsService, Offboarding: offboarding, ServiceAccount: serviceAccounts, Identity: identity,
			SecurityEvents: admin, Investigations: investigations, ElevatedAccess: elevatedAccess, ElevatedQuery: elevatedQuery,
			ElevatedExport: elevatedExport,
		},
	})
	if err != nil {
		t.Fatalf("NewPortalRouter() error = %v", err)
	}
	return router
}

func insertRouterSession(t *testing.T, db *sql.DB, sessionID, identityID, token, csrf string, issuedAt time.Time) {
	t.Helper()
	tokenHash := sha256.Sum256([]byte(token))
	csrfHash := sha256.Sum256([]byte(csrf))
	mustHTTPExec(t, db, `INSERT INTO sessions (id, identity_id, token_hash, csrf_token_hash, created_at, last_seen_at, idle_expires_at, absolute_expires_at, reauthenticated_until) VALUES ($1, $2, $3, $4, $5, $5, $6, $7, $8)`, sessionID, identityID, tokenHash[:], csrfHash[:], issuedAt.Add(-time.Minute), issuedAt.Add(time.Hour), issuedAt.Add(12*time.Hour), issuedAt.Add(time.Hour))
}

func routerRequest(method, path, token, csrf, origin, body string) *http.Request {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.AddCookie(&http.Cookie{Name: httpapi.PortalSessionCookieName, Value: token})
	if csrf != "" {
		request.Header.Set(httpapi.CSRFHeaderName, csrf)
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	return request
}

func assertHTTPIntegrationError(t *testing.T, recorder *httptest.ResponseRecorder, status int, code httpapi.ErrorCode) {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("HTTP status = %d, want %d: %s", recorder.Code, status, recorder.Body.String())
	}
	var response struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode HTTP error: %v; body=%s", err, recorder.Body.String())
	}
	if response.Error.Code != string(code) {
		t.Fatalf("HTTP error code = %q, want %q", response.Error.Code, code)
	}
}

type httpAuditFixture struct {
	teamID     string
	identityID string
}

type httpAuditData struct {
	employeeID       string
	secondEmployeeID string
	keyID            string
	secondKeyID      string
	serviceAccountID string
	serviceKeyID     string
	auditID          string
	requestID        string
	secondAuditID    string
	secondRequestID  string
	serviceAuditID   string
	serviceRequestID string
	issuedAt         time.Time
}

func migrateHTTPIntegrationSchema(t *testing.T) *sql.DB {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("N_API_P_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Fatal("N_API_P_TEST_DATABASE_URL is required for integration tests")
	}
	const schemaName = "elevated_audit_http_test"
	adminDB := openHTTPIntegrationDatabase(t, databaseURL)
	identifier := pgx.Identifier{schemaName}.Sanitize()
	if _, err := adminDB.Exec("DROP SCHEMA IF EXISTS " + identifier + " CASCADE"); err != nil {
		t.Fatalf("drop stale HTTP integration schema: %v", err)
	}
	if _, err := adminDB.Exec("CREATE SCHEMA " + identifier); err != nil {
		t.Fatalf("create HTTP integration schema: %v", err)
	}
	t.Cleanup(func() {
		if _, err := adminDB.Exec("DROP SCHEMA IF EXISTS " + identifier + " CASCADE"); err != nil {
			t.Errorf("drop HTTP integration schema: %v", err)
		}
	})

	schemaURL := databaseURLWithHTTPSearchPath(t, databaseURL, schemaName)
	schemaDB := openHTTPIntegrationDatabase(t, schemaURL)
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate database migrations")
	}
	migrationRoot := filepath.Join(filepath.Dir(sourceFile), "..", "database")
	sourceDriver, err := iofs.New(os.DirFS(migrationRoot), "migrations")
	if err != nil {
		t.Fatalf("open embedded migrations: %v", err)
	}
	databaseDriver, err := migratepgx.WithInstance(schemaDB, &migratepgx.Config{SchemaName: schemaName})
	if err != nil {
		t.Fatalf("open migration database driver: %v", err)
	}
	migrator, err := migrate.NewWithInstance("iofs", sourceDriver, "pgx5", databaseDriver)
	if err != nil {
		t.Fatalf("open migrator: %v", err)
	}
	t.Cleanup(func() {
		sourceErr, databaseErr := migrator.Close()
		if sourceErr != nil || databaseErr != nil {
			t.Errorf("close migrator: source=%v database=%v", sourceErr, databaseErr)
		}
	})
	if err := migrator.Up(); err != nil {
		t.Fatalf("apply HTTP integration migrations: %v", err)
	}
	return schemaDB
}

func openHTTPIntegrationDatabase(t *testing.T, databaseURL string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("open HTTP integration database: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close HTTP integration database: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping HTTP integration database: %v", err)
	}
	return db
}

func databaseURLWithHTTPSearchPath(t *testing.T, databaseURL, schemaName string) string {
	t.Helper()
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse HTTP integration database URL: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schemaName)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func insertHTTPAuditFixture(t *testing.T, db *sql.DB) (httpAuditFixture, httpAuditData) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	fixture := httpAuditFixture{teamID: "81000000-0000-0000-0000-000000000070", identityID: "82000000-0000-0000-0000-000000000070"}
	data := httpAuditData{
		employeeID:       "82000000-0000-0000-0000-000000000071",
		secondEmployeeID: "82000000-0000-0000-0000-000000000073",
		keyID:            "83000000-0000-0000-0000-000000000070",
		secondKeyID:      "83000000-0000-0000-0000-000000000071",
		serviceAccountID: "88000000-0000-0000-0000-000000000070",
		serviceKeyID:     "83000000-0000-0000-0000-000000000072",
		auditID:          "84000000-0000-0000-0000-000000000070",
		requestID:        "87000000-0000-0000-0000-000000000070",
		secondAuditID:    "84000000-0000-0000-0000-000000000071",
		secondRequestID:  "87000000-0000-0000-0000-000000000071",
		serviceAuditID:   "84000000-0000-0000-0000-000000000072",
		serviceRequestID: "87000000-0000-0000-0000-000000000072",
		issuedAt:         now,
	}
	mustHTTPExec(t, db, `INSERT INTO teams (id, name, status) VALUES ($1, $2, 'active')`, fixture.teamID, "HTTP audit")
	mustHTTPExec(t, db, `INSERT INTO identities (id, email, role, status) VALUES ($1, 'router-admin@example.internal', 'system_administrator', 'active'), ($2, 'router-employee@example.internal', 'employee', 'active'), ($3, 'router-second-employee@example.internal', 'employee', 'active')`, fixture.identityID, data.employeeID, data.secondEmployeeID)
	mustHTTPExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2), ($3, $2)`, data.employeeID, fixture.teamID, data.secondEmployeeID)
	mustHTTPExec(t, db, `INSERT INTO api_keys (id, identity_id, kind, name, prefix, verification_hash, status, created_at) VALUES ($1, $2, 'personal', 'router-key', 'nap_router', $3, 'active', $4)`, data.keyID, data.employeeID, []byte("router-key-hash"), now)
	mustHTTPExec(t, db, `INSERT INTO api_keys (id, identity_id, kind, name, prefix, verification_hash, status, created_at) VALUES ($1, $2, 'personal', 'router-second-key', 'nap_router2', $3, 'active', $4)`, data.secondKeyID, data.secondEmployeeID, []byte("router-second-key-hash"), now)
	mustHTTPExec(t, db, `INSERT INTO service_accounts (id, team_id, responsible_identity_id, name, status, created_at, updated_at) VALUES ($1, $2, $3, 'router-service', 'active', $4, $4)`, data.serviceAccountID, fixture.teamID, data.secondEmployeeID, now)
	mustHTTPExec(t, db, `INSERT INTO api_keys (id, service_account_id, kind, name, prefix, verification_hash, status, created_at) VALUES ($1, $2, 'service', 'router-service-key', 'nap_router3', $3, 'active', $4)`, data.serviceKeyID, data.serviceAccountID, []byte("router-service-key-hash"), now)
	mustHTTPExec(t, db, `INSERT INTO model_allowlist (model_id, status, updated_by_identity_id) VALUES ('gpt-router', 'allowed', $1)`, fixture.identityID)
	mustHTTPExec(t, db, `INSERT INTO audit_records (id, request_id, key_id, owner_kind, identity_id, team_id, model_id, capture_status, outcome, observed_request_bytes, observed_response_bytes, created_at, updated_at, completed_at) VALUES ($1, $2, $3, 'personal', $4, $5, 'gpt-router', 'complete', 'success', 128, 64, $6, $6, $6)`, data.auditID, data.requestID, data.keyID, data.employeeID, fixture.teamID, now)
	mustHTTPExec(t, db, `INSERT INTO usage_records (id, audit_id, request_id, key_id, owner_kind, identity_id, team_id, model_id, outcome, usage_reported, input_tokens, output_tokens, total_tokens, created_at) VALUES ('85000000-0000-0000-0000-000000000070', $1, $2, $3, 'personal', $4, $5, 'gpt-router', 'success', true, 3, 2, 5, $6)`, data.auditID, data.requestID, data.keyID, data.employeeID, fixture.teamID, now)
	secondCreatedAt := now.Add(-time.Second)
	mustHTTPExec(t, db, `INSERT INTO audit_records (id, request_id, key_id, owner_kind, identity_id, team_id, model_id, capture_status, outcome, observed_request_bytes, observed_response_bytes, created_at, updated_at, completed_at) VALUES ($1, $2, $3, 'personal', $4, $5, 'gpt-router-second', 'complete', 'success', 128, 64, $6, $6, $6)`, data.secondAuditID, data.secondRequestID, data.secondKeyID, data.secondEmployeeID, fixture.teamID, secondCreatedAt)
	mustHTTPExec(t, db, `INSERT INTO usage_records (id, audit_id, request_id, key_id, owner_kind, identity_id, team_id, model_id, outcome, usage_reported, input_tokens, output_tokens, total_tokens, created_at) VALUES ('85000000-0000-0000-0000-000000000071', $1, $2, $3, 'personal', $4, $5, 'gpt-router-second', 'success', true, 6, 4, 10, $6)`, data.secondAuditID, data.secondRequestID, data.secondKeyID, data.secondEmployeeID, fixture.teamID, secondCreatedAt)
	serviceCreatedAt := now.Add(-2 * time.Second)
	mustHTTPExec(t, db, `INSERT INTO audit_records (id, request_id, key_id, owner_kind, service_account_id, responsible_identity_id, team_id, model_id, capture_status, outcome, observed_request_bytes, observed_response_bytes, created_at, updated_at, completed_at) VALUES ($1, $2, $3, 'service', $4, $5, $6, 'gpt-router-service', 'complete', 'success', 128, 64, $7, $7, $7)`, data.serviceAuditID, data.serviceRequestID, data.serviceKeyID, data.serviceAccountID, data.secondEmployeeID, fixture.teamID, serviceCreatedAt)
	mustHTTPExec(t, db, `INSERT INTO usage_records (id, audit_id, request_id, key_id, owner_kind, service_account_id, responsible_identity_id, team_id, model_id, outcome, usage_reported, input_tokens, output_tokens, total_tokens, created_at) VALUES ('85000000-0000-0000-0000-000000000072', $1, $2, $3, 'service', $4, $5, $6, 'gpt-router-service', 'success', true, 8, 5, 13, $7)`, data.serviceAuditID, data.serviceRequestID, data.serviceKeyID, data.serviceAccountID, data.secondEmployeeID, fixture.teamID, serviceCreatedAt)

	envelope, err := audit.NewEnvelopeService(1, map[int][]byte{1: bytes.Repeat([]byte{0x41}, 32)})
	if err != nil {
		t.Fatalf("NewEnvelopeService() error = %v", err)
	}
	requestContext := audit.EncryptionContext{AuditID: data.auditID, ContentKind: audit.ContentKindRequest, OwnerKind: audit.OwnerKindPersonal, IdentityID: data.employeeID, TeamID: fixture.teamID, CreatedAt: now}
	responseContext := requestContext
	responseContext.ContentKind = audit.ContentKindResponse
	requestContent, err := envelope.Encrypt([]byte(`{"messages":[{"content":"synthetic needle"}]}`), requestContext)
	if err != nil {
		t.Fatalf("encrypt request fixture: %v", err)
	}
	responseContent, err := envelope.Encrypt([]byte(`{"response":"synthetic answer"}`), responseContext)
	if err != nil {
		t.Fatalf("encrypt response fixture: %v", err)
	}
	insertHTTPRawContent(t, db, data.auditID, "request", requestContent, now)
	insertHTTPRawContent(t, db, data.auditID, "response", responseContent, now)
	secondRequestContext := audit.EncryptionContext{AuditID: data.secondAuditID, ContentKind: audit.ContentKindRequest, OwnerKind: audit.OwnerKindPersonal, IdentityID: data.secondEmployeeID, TeamID: fixture.teamID, CreatedAt: secondCreatedAt}
	secondResponseContext := secondRequestContext
	secondResponseContext.ContentKind = audit.ContentKindResponse
	secondRequestContent, err := envelope.Encrypt([]byte(`{"messages":[{"content":"synthetic second record"}]}`), secondRequestContext)
	if err != nil {
		t.Fatalf("encrypt second request fixture: %v", err)
	}
	secondResponseContent, err := envelope.Encrypt([]byte(`{"response":"synthetic second answer"}`), secondResponseContext)
	if err != nil {
		t.Fatalf("encrypt second response fixture: %v", err)
	}
	insertHTTPRawContent(t, db, data.secondAuditID, "request", secondRequestContent, secondCreatedAt)
	insertHTTPRawContent(t, db, data.secondAuditID, "response", secondResponseContent, secondCreatedAt)
	serviceRequestContext := audit.EncryptionContext{AuditID: data.serviceAuditID, ContentKind: audit.ContentKindRequest, OwnerKind: audit.OwnerKindService, ServiceAccountID: data.serviceAccountID, ResponsibleIdentityID: data.secondEmployeeID, TeamID: fixture.teamID, CreatedAt: serviceCreatedAt}
	serviceResponseContext := serviceRequestContext
	serviceResponseContext.ContentKind = audit.ContentKindResponse
	serviceRequestContent, err := envelope.Encrypt([]byte(`{"messages":[{"content":"synthetic service record"}]}`), serviceRequestContext)
	if err != nil {
		t.Fatalf("encrypt service request fixture: %v", err)
	}
	serviceResponseContent, err := envelope.Encrypt([]byte(`{"response":"synthetic service answer"}`), serviceResponseContext)
	if err != nil {
		t.Fatalf("encrypt service response fixture: %v", err)
	}
	insertHTTPRawContent(t, db, data.serviceAuditID, "request", serviceRequestContent, serviceCreatedAt)
	insertHTTPRawContent(t, db, data.serviceAuditID, "response", serviceResponseContent, serviceCreatedAt)
	return fixture, data
}

func insertHTTPRawContent(t *testing.T, db *sql.DB, auditID, contentKind string, content audit.EncryptedContent, createdAt time.Time) {
	t.Helper()
	mustHTTPExec(t, db, `INSERT INTO audit_raw_content (audit_id, content_kind, compression, ciphertext, cipher_nonce, wrapped_data_key, wrap_nonce, key_version, created_at, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, auditID, contentKind, content.Compression, content.Ciphertext, content.CipherNonce, content.WrappedDataKey, content.WrapNonce, content.KeyVersion, createdAt, createdAt.Add(time.Hour))
}

func mustHTTPExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("execute HTTP integration fixture: %v", err)
	}
}
