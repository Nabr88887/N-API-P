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

	router := newIntegratedPortalRouter(t, db)
	origin := "https://portal.example.internal"

	missingCSRF := routerRequest(http.MethodPost, "/api/v1/admin/audit-access/grants", adminToken, "", origin, `{"purpose":"router integration"}`)
	missingCSRFRecorder := httptest.NewRecorder()
	router.ServeHTTP(missingCSRFRecorder, missingCSRF)
	assertHTTPIntegrationError(t, missingCSRFRecorder, http.StatusForbidden, httpapi.CodeCSRFRejected)

	missingOrigin := routerRequest(http.MethodPost, "/api/v1/admin/audit-access/grants", adminToken, adminCSRF, "", `{"purpose":"router integration"}`)
	missingOriginRecorder := httptest.NewRecorder()
	router.ServeHTTP(missingOriginRecorder, missingOrigin)
	assertHTTPIntegrationError(t, missingOriginRecorder, http.StatusForbidden, httpapi.CodeCSRFRejected)

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
	if grantResponse.ID == "" || grantResponse.Status != "active" || !grantResponse.ExpiresAt.After(grantResponse.IssuedAt) {
		t.Fatalf("grant response = %+v", grantResponse)
	}
	if strings.Contains(issueRecorder.Body.String(), "bearer") || strings.Contains(issueRecorder.Body.String(), "token") {
		t.Fatalf("grant response appears to contain a bearer secret: %s", issueRecorder.Body.String())
	}

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
	employeeID string
	keyID      string
	auditID    string
	requestID  string
	issuedAt   time.Time
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
		employeeID: "82000000-0000-0000-0000-000000000071",
		keyID:      "83000000-0000-0000-0000-000000000070",
		auditID:    "84000000-0000-0000-0000-000000000070",
		requestID:  "87000000-0000-0000-0000-000000000070",
		issuedAt:   now,
	}
	mustHTTPExec(t, db, `INSERT INTO teams (id, name, status) VALUES ($1, $2, 'active')`, fixture.teamID, "HTTP audit")
	mustHTTPExec(t, db, `INSERT INTO identities (id, email, role, status) VALUES ($1, 'router-admin@example.internal', 'system_administrator', 'active'), ($2, 'router-employee@example.internal', 'employee', 'active')`, fixture.identityID, data.employeeID)
	mustHTTPExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, data.employeeID, fixture.teamID)
	mustHTTPExec(t, db, `INSERT INTO api_keys (id, identity_id, kind, name, prefix, verification_hash, status, created_at) VALUES ($1, $2, 'personal', 'router-key', 'nap_router', $3, 'active', $4)`, data.keyID, data.employeeID, []byte("router-key-hash"), now)
	mustHTTPExec(t, db, `INSERT INTO model_allowlist (model_id, status, updated_by_identity_id) VALUES ('gpt-router', 'allowed', $1)`, fixture.identityID)
	mustHTTPExec(t, db, `INSERT INTO audit_records (id, request_id, key_id, owner_kind, identity_id, team_id, model_id, capture_status, outcome, observed_request_bytes, observed_response_bytes, created_at, updated_at, completed_at) VALUES ($1, $2, $3, 'personal', $4, $5, 'gpt-router', 'complete', 'success', 128, 64, $6, $6, $6)`, data.auditID, data.requestID, data.keyID, data.employeeID, fixture.teamID, now)
	mustHTTPExec(t, db, `INSERT INTO usage_records (id, audit_id, request_id, key_id, owner_kind, identity_id, team_id, model_id, outcome, usage_reported, input_tokens, output_tokens, total_tokens, created_at) VALUES ('85000000-0000-0000-0000-000000000070', $1, $2, $3, 'personal', $4, $5, 'gpt-router', 'success', true, 3, 2, 5, $6)`, data.auditID, data.requestID, data.keyID, data.employeeID, fixture.teamID, now)

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
