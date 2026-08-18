//go:build integration

package database_test

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"

	"n-api-p/internal/audit"
	"n-api-p/internal/database"
	"n-api-p/internal/gateway"
	"n-api-p/internal/httpapi"
	"n-api-p/internal/observability"
	"n-api-p/internal/operations"
)

const task102SyntheticPrompt = "synthetic-task-10-2-prompt"

//go:embed migrations/*.up.sql
var task102MigrationFiles embed.FS

func TestTask102InitialKeyAndDatabaseFailuresFailClosed(t *testing.T) {
	for _, test := range []struct {
		name     string
		stream   bool
		keyFault bool
	}{
		{name: "regular key failure", keyFault: true},
		{name: "SSE key failure", stream: true, keyFault: true},
		{name: "regular initial database failure"},
		{name: "SSE initial database failure", stream: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream := &task102Upstream{mode: task102UpstreamSuccess}
			var captureEncryptor audit.RequestEncryptor
			if test.keyFault {
				captureEncryptor = task102FailingEncryptor{}
			}
			harness := newTask102Harness(t, upstream, captureEncryptor)
			if !test.keyFault {
				installTask102RequestPersistenceFault(t, harness.db)
			}

			requestID := task102RequestID(1)
			response := harness.serve(t, test.stream, requestID)
			assertTask102Error(t, response, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE")
			if upstream.calls != 0 {
				t.Fatalf("upstream calls = %d, want 0", upstream.calls)
			}
			assertTask102AuditAbsent(t, harness.db, requestID)
			assertTask102Gate(t, harness.repository, audit.AuditGateStateBlocked, audit.GateReasonInitialCapture)
			assertTask102AuditFault(t, harness.repository, true)
			assertTask102Metrics(t, harness.metrics,
				`n_api_p_audit_persistence_total{operation="initial_capture",outcome="failure"} 1`,
				`n_api_p_audit_gate_state{state="blocked"} 1`,
			)

			blocked := harness.serve(t, !test.stream, task102RequestID(2))
			assertTask102Error(t, blocked, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE")
			if upstream.calls != 0 {
				t.Fatalf("upstream calls after gate = %d, want 0", upstream.calls)
			}
			keyProbeErr := error(nil)
			if test.keyFault {
				keyProbeErr = audit.ErrInvalidMasterKey
			}
			readiness := task102Readiness(harness, keyProbeErr)
			if readiness.State != httpapi.HealthStateUnhealthy {
				t.Fatalf("readiness state = %q, want unhealthy", readiness.State)
			}
			assertTask102HealthComponent(t, readiness, "audit_gate", httpapi.HealthStateUnhealthy, "audit_gate_blocked")
			if test.keyFault {
				assertTask102HealthComponent(t, readiness, "audit_key", httpapi.HealthStateUnhealthy, "active_audit_key_unavailable")
			}
			assertTask102ContentFree(t, response.Body.String(), task102MetricsBody(t, harness.metrics))
		})
	}
}

func TestTask102RegularAndSSEPersistenceFailuresGateAndRecover(t *testing.T) {
	for _, test := range []struct {
		name       string
		stream     bool
		fault      string
		reason     string
		metricLine string
	}{
		{name: "regular final audit", fault: "final", reason: audit.GateReasonFinalizationPersistence, metricLine: `n_api_p_audit_persistence_total{operation="finalization",outcome="failure"} 1`},
		{name: "SSE final audit", stream: true, fault: "final", reason: audit.GateReasonFinalizationPersistence, metricLine: `n_api_p_audit_persistence_total{operation="finalization",outcome="failure"} 1`},
		{name: "regular token usage", fault: "usage", reason: audit.GateReasonUsagePersistence, metricLine: `n_api_p_audit_persistence_total{operation="usage",outcome="failure"} 1`},
		{name: "SSE token usage", stream: true, fault: "usage", reason: audit.GateReasonUsagePersistence, metricLine: `n_api_p_audit_persistence_total{operation="usage",outcome="failure"} 1`},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream := &task102Upstream{mode: task102UpstreamSuccess}
			harness := newTask102Harness(t, upstream, nil)
			clearFault := installTask102PostDispatchFault(t, harness.db, test.fault)
			requestID := task102RequestID(10)

			response := harness.serve(t, test.stream, requestID)
			if test.stream {
				if response.Code != http.StatusOK || response.Body.String() != task102SSEBody() {
					t.Fatalf("SSE response = (%d, %q), want completed synthetic stream", response.Code, response.Body.String())
				}
			} else {
				assertTask102Error(t, response, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE")
			}
			if upstream.calls != 1 {
				t.Fatalf("upstream calls = %d, want 1", upstream.calls)
			}
			auditID := assertTask102AuditState(t, harness.db, requestID, audit.CaptureStatusIncomplete, audit.AuditOutcomeLocalError, test.reason)
			assertTask102EncryptedContent(t, harness.db, auditID)
			assertTask102Gate(t, harness.repository, audit.AuditGateStateBlocked, test.reason)
			assertTask102AuditFault(t, harness.repository, true)
			assertTask102Metrics(t, harness.metrics, test.metricLine, `n_api_p_audit_gate_state{state="blocked"} 1`)

			blocked := harness.serve(t, !test.stream, task102RequestID(11))
			assertTask102Error(t, blocked, http.StatusServiceUnavailable, "AUDIT_UNAVAILABLE")
			if upstream.calls != 1 {
				t.Fatalf("upstream calls after gate = %d, want 1", upstream.calls)
			}

			clearFault()
			recoveredAt := harness.clock.now().Add(time.Minute)
			if err := harness.gate.Recover(context.Background(), recoveredAt.Add(-time.Hour), recoveredAt); err != nil {
				t.Fatalf("Recover() error = %v", err)
			}
			assertTask102Gate(t, harness.repository, audit.AuditGateStateOpen, "")
			assertTask102AuditFault(t, harness.repository, false)
			assertTask102AuditFaultHistory(t, harness.repository)
			if readiness := task102Readiness(harness, nil); readiness.State != httpapi.HealthStateHealthy {
				t.Fatalf("recovered readiness = %+v, want healthy", readiness)
			}

			recoveredRequestID := task102RequestID(12)
			recovered := harness.serve(t, false, recoveredRequestID)
			if recovered.Code != http.StatusOK {
				t.Fatalf("recovered response = (%d, %s), want 200", recovered.Code, recovered.Body.String())
			}
			if upstream.calls != 2 {
				t.Fatalf("upstream calls after recovery = %d, want 2", upstream.calls)
			}
			assertTask102Usage(t, harness.db, recoveredRequestID, true, 11, 7, 18)
			assertTask102ContentFree(t, response.Body.String(), blocked.Body.String(), task102MetricsBody(t, harness.metrics))
		})
	}
}

func TestTask102UpstreamFaultsRemainContentFreeAndDoNotGate(t *testing.T) {
	for _, test := range []struct {
		name   string
		stream bool
		mode   string
		status int
		code   string
	}{
		{name: "regular timeout", mode: task102UpstreamTimeout, status: http.StatusGatewayTimeout, code: "UPSTREAM_TIMEOUT"},
		{name: "SSE timeout", stream: true, mode: task102UpstreamTimeout, status: http.StatusGatewayTimeout, code: "UPSTREAM_TIMEOUT"},
		{name: "regular unavailable", mode: task102UpstreamUnavailable, status: http.StatusBadGateway, code: "UPSTREAM_UNAVAILABLE"},
		{name: "SSE unavailable", stream: true, mode: task102UpstreamUnavailable, status: http.StatusBadGateway, code: "UPSTREAM_UNAVAILABLE"},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream := &task102Upstream{mode: test.mode}
			harness := newTask102Harness(t, upstream, nil)
			requestID := task102RequestID(20)

			response := harness.serve(t, test.stream, requestID)
			assertTask102Error(t, response, test.status, test.code)
			if upstream.calls != 1 {
				t.Fatalf("upstream calls = %d, want 1", upstream.calls)
			}
			auditID := assertTask102AuditState(t, harness.db, requestID, audit.CaptureStatusIncomplete, audit.AuditOutcomeLocalError, test.code)
			assertTask102EncryptedContent(t, harness.db, auditID)
			assertTask102Usage(t, harness.db, requestID, false, 0, 0, 0)
			assertTask102Gate(t, harness.repository, audit.AuditGateStateOpen, "")
			assertTask102AuditFault(t, harness.repository, false)
			if readiness := task102Readiness(harness, nil); readiness.State != httpapi.HealthStateHealthy {
				t.Fatalf("readiness after upstream fault = %+v, want healthy", readiness)
			}

			upstream.mode = task102UpstreamSuccess
			recoveredRequestID := task102RequestID(21)
			success := harness.serve(t, test.stream, recoveredRequestID)
			if success.Code != http.StatusOK {
				t.Fatalf("request after upstream fault = (%d, %s), want 200", success.Code, success.Body.String())
			}
			if upstream.calls != 2 {
				t.Fatalf("upstream calls after retry request = %d, want 2", upstream.calls)
			}
			assertTask102Usage(t, harness.db, recoveredRequestID, true, 11, 7, 18)
			assertTask102ContentFree(t, response.Body.String(), task102MetricsBody(t, harness.metrics))
		})
	}
}

type task102Fixture struct {
	now        time.Time
	teamID     string
	identityID string
	keyID      string
}

func openTask102Schema(t *testing.T) *sql.DB {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("N_API_P_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Fatal("N_API_P_TEST_DATABASE_URL is required for integration tests")
	}
	const schemaName = "task102_failure_injection_test"
	adminDB := openTask102Database(t, databaseURL)
	identifier := pgx.Identifier{schemaName}.Sanitize()
	if _, err := adminDB.Exec("DROP SCHEMA IF EXISTS " + identifier + " CASCADE"); err != nil {
		t.Fatalf("drop stale task 10.2 schema: %v", err)
	}
	if _, err := adminDB.Exec("CREATE SCHEMA " + identifier); err != nil {
		t.Fatalf("create task 10.2 schema: %v", err)
	}
	t.Cleanup(func() {
		if _, err := adminDB.Exec("DROP SCHEMA IF EXISTS " + identifier + " CASCADE"); err != nil {
			t.Errorf("drop task 10.2 schema: %v", err)
		}
	})

	schemaDB := openTask102Database(t, task102DatabaseURL(t, databaseURL, schemaName))
	entries, err := fs.ReadDir(task102MigrationFiles, "migrations")
	if err != nil {
		t.Fatalf("read embedded migrations: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		migration, err := task102MigrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			t.Fatalf("read migration %s: %v", entry.Name(), err)
		}
		if _, err := schemaDB.Exec(string(migration)); err != nil {
			t.Fatalf("apply migration %s: %v", entry.Name(), err)
		}
	}
	return schemaDB
}

func openTask102Database(t *testing.T, databaseURL string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("open task 10.2 database: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close task 10.2 database: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping task 10.2 database: %v", err)
	}
	return db
}

func task102DatabaseURL(t *testing.T, databaseURL, schemaName string) string {
	t.Helper()
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse task 10.2 database URL: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schemaName)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func insertTask102Fixture(t *testing.T, db *sql.DB) task102Fixture {
	t.Helper()
	fixture := task102Fixture{
		now:        time.Date(2026, 8, 18, 0, 0, 0, 0, time.UTC),
		teamID:     "81000000-0000-0000-0000-000000000102",
		identityID: "82000000-0000-0000-0000-000000000102",
		keyID:      "83000000-0000-0000-0000-000000000102",
	}
	task102MustExec(t, db, `INSERT INTO teams (id, name, status) VALUES ($1, $2, $3)`, fixture.teamID, "Task 10.2", "active")
	task102MustExec(t, db, `INSERT INTO identities (id, email, role, status) VALUES ($1, $2, $3, $4)`, fixture.identityID, "task102@example.internal", "system_administrator", "active")
	task102MustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, fixture.identityID, fixture.teamID)
	task102MustExec(t, db, `INSERT INTO api_keys (id, identity_id, kind, name, prefix, verification_hash, status, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, fixture.keyID, fixture.identityID, "personal", "task102", "nap_t102", []byte("synthetic-hash-only"), "active", fixture.now)
	task102MustExec(t, db, `INSERT INTO model_allowlist (model_id, status, updated_by_identity_id) VALUES ($1, $2, $3)`, "gpt-test", "allowed", fixture.identityID)
	return fixture
}

func task102MustExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("execute task 10.2 statement: %v", err)
	}
}

type task102Harness struct {
	db         *sql.DB
	fixture    task102Fixture
	repository *database.Repository
	gate       *audit.DegradedStateMachine
	metrics    *observability.Metrics
	handler    *gateway.ChatProxyHandler
	clock      *task102Clock
}

func newTask102Harness(t *testing.T, upstream *task102Upstream, captureEncryptor audit.RequestEncryptor) *task102Harness {
	t.Helper()
	db := openTask102Schema(t)
	fixture := insertTask102Fixture(t, db)
	repository := database.NewRepository(db)
	metrics := observability.NewMetrics()
	gate, err := audit.NewDegradedStateMachine(repository)
	if err != nil {
		t.Fatalf("NewDegradedStateMachine() error = %v", err)
	}
	gate.SetMetrics(metrics)
	base := time.Now().UTC().Truncate(time.Second)
	if err := gate.Recover(context.Background(), base.Add(-2*time.Minute), base.Add(-time.Minute)); err != nil {
		t.Fatalf("initial Recover() error = %v", err)
	}
	envelope, err := audit.NewEnvelopeService(1, map[int][]byte{1: bytes.Repeat([]byte{0x42}, 32)})
	if err != nil {
		t.Fatalf("NewEnvelopeService() error = %v", err)
	}
	if captureEncryptor == nil {
		captureEncryptor = envelope
	}
	capture, err := audit.NewInitialCaptureServiceWithGate(captureEncryptor, repository, gate)
	if err != nil {
		t.Fatalf("NewInitialCaptureServiceWithGate() error = %v", err)
	}
	finalizer, err := audit.NewResponseFinalizationServiceWithGate(envelope, repository, gate)
	if err != nil {
		t.Fatalf("NewResponseFinalizationServiceWithGate() error = %v", err)
	}
	capture.SetMetrics(metrics)
	finalizer.SetMetrics(metrics)
	clock := &task102Clock{current: base}
	ids := &task102IDGenerator{}
	handler, err := gateway.NewChatProxyHandler(gateway.ChatProxyConfig{
		Upstream: upstream, Capture: capture, Finalizer: finalizer, Usage: repository,
		Policy: task102Policy{}, Limiter: task102Limiter{}, Now: clock.now, NewID: ids.next,
		Retention: 24 * time.Hour, ResponseLimit: 4 * 1024 * 1024, Metrics: metrics,
	})
	if err != nil {
		t.Fatalf("NewChatProxyHandler() error = %v", err)
	}
	return &task102Harness{db: db, fixture: fixture, repository: repository, gate: gate, metrics: metrics, handler: handler, clock: clock}
}

func (harness *task102Harness) serve(t *testing.T, stream bool, requestID string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"model":"gpt-test","messages":[{"role":"user","content":"%s"}],"stream":%t}`, task102SyntheticPrompt, stream)
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(gateway.WithChatCaller(request.Context(), gateway.ChatCaller{
		RequestID: requestID, KeyID: harness.fixture.keyID, OwnerKind: audit.OwnerKindPersonal,
		IdentityID: harness.fixture.identityID, TeamID: harness.fixture.teamID,
		TrafficOwner: gateway.TrafficOwner{Kind: gateway.TrafficOwnerEmployee, ID: harness.fixture.identityID},
	}))
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	return response
}

const (
	task102UpstreamSuccess     = "success"
	task102UpstreamTimeout     = "timeout"
	task102UpstreamUnavailable = "unavailable"
)

type task102Upstream struct {
	mode        string
	calls       int
	streamCalls int
}

func (upstream *task102Upstream) CreateChatCompletion(_ context.Context, _ []byte, stream bool) (*gateway.NewAPIResponse, error) {
	upstream.calls++
	if stream {
		upstream.streamCalls++
	}
	switch upstream.mode {
	case task102UpstreamTimeout:
		return nil, gateway.ErrUpstreamTimeout
	case task102UpstreamUnavailable:
		return nil, gateway.ErrUpstreamUnavailable
	case task102UpstreamSuccess:
		if stream {
			return &gateway.NewAPIResponse{StatusCode: http.StatusOK, ContentType: "text/event-stream", RequestID: "synthetic-upstream-sse", Body: io.NopCloser(strings.NewReader(task102SSEBody()))}, nil
		}
		body := `{"id":"synthetic-chat","model":"gpt-test","choices":[{"index":0,"message":{"role":"assistant","content":"synthetic-response"},"finish_reason":"stop"}],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}`
		return &gateway.NewAPIResponse{StatusCode: http.StatusOK, ContentType: "application/json", RequestID: "synthetic-upstream", Body: io.NopCloser(strings.NewReader(body))}, nil
	default:
		return nil, errors.New("unknown synthetic upstream mode")
	}
}

func task102SSEBody() string {
	return "data: {\"id\":\"synthetic-sse\",\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"synthetic-response\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18}}\n\n" +
		"data: [DONE]\n\n"
}

type task102FailingEncryptor struct{}

func (task102FailingEncryptor) Encrypt([]byte, audit.EncryptionContext) (audit.EncryptedContent, error) {
	return audit.EncryptedContent{}, audit.ErrInvalidMasterKey
}

type task102Policy struct{}

func (task102Policy) Authorize(context.Context, string) error { return nil }

type task102Limiter struct{}

func (task102Limiter) Acquire(context.Context, gateway.TrafficOwner) (gateway.Reservation, error) {
	return task102Reservation{}, nil
}

type task102Reservation struct{}

func (task102Reservation) Release() {}

type task102Clock struct{ current time.Time }

func (clock *task102Clock) now() time.Time {
	clock.current = clock.current.Add(time.Second)
	return clock.current
}

type task102IDGenerator struct{ value int }

func (generator *task102IDGenerator) next() (string, error) {
	generator.value++
	return fmt.Sprintf("88000000-0000-0000-0000-%012d", generator.value), nil
}

func task102RequestID(value int) string {
	return fmt.Sprintf("89000000-0000-0000-0000-%012d", value)
}

func installTask102RequestPersistenceFault(t *testing.T, db *sql.DB) {
	t.Helper()
	task102MustExec(t, db, `CREATE FUNCTION task102_reject_request_content() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.content_kind = 'request' THEN RAISE EXCEPTION 'synthetic request persistence failure'; END IF; RETURN NEW; END $$`)
	task102MustExec(t, db, `CREATE TRIGGER task102_reject_request_content BEFORE INSERT ON audit_raw_content FOR EACH ROW EXECUTE FUNCTION task102_reject_request_content()`)
}

func installTask102PostDispatchFault(t *testing.T, db *sql.DB, fault string) func() {
	t.Helper()
	switch fault {
	case "final":
		task102MustExec(t, db, `CREATE FUNCTION task102_reject_response_content() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.content_kind = 'response' THEN RAISE EXCEPTION 'synthetic response persistence failure'; END IF; RETURN NEW; END $$`)
		task102MustExec(t, db, `CREATE TRIGGER task102_reject_response_content BEFORE INSERT ON audit_raw_content FOR EACH ROW EXECUTE FUNCTION task102_reject_response_content()`)
		return func() {
			task102MustExec(t, db, `DROP TRIGGER task102_reject_response_content ON audit_raw_content`)
			task102MustExec(t, db, `DROP FUNCTION task102_reject_response_content()`)
		}
	case "usage":
		task102MustExec(t, db, `CREATE FUNCTION task102_reject_usage_record() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic usage persistence failure'; END $$`)
		task102MustExec(t, db, `CREATE TRIGGER task102_reject_usage_record BEFORE INSERT ON usage_records FOR EACH ROW EXECUTE FUNCTION task102_reject_usage_record()`)
		return func() {
			task102MustExec(t, db, `DROP TRIGGER task102_reject_usage_record ON usage_records`)
			task102MustExec(t, db, `DROP FUNCTION task102_reject_usage_record()`)
		}
	default:
		t.Fatalf("unsupported task 10.2 fault %q", fault)
		return func() {}
	}
}

func assertTask102Error(t *testing.T, response *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if response.Code != status || !strings.Contains(response.Body.String(), `"code":"`+code+`"`) {
		t.Fatalf("response = (%d, %s), want %d/%s", response.Code, response.Body.String(), status, code)
	}
}

func assertTask102AuditAbsent(t *testing.T, db *sql.DB, requestID string) {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM audit_records WHERE request_id = $1`, requestID).Scan(&count); err != nil {
		t.Fatalf("count failed audit: %v", err)
	}
	if count != 0 {
		t.Fatalf("audit rows for %s = %d, want 0", requestID, count)
	}
}

func assertTask102AuditState(t *testing.T, db *sql.DB, requestID string, status audit.CaptureStatus, outcome audit.AuditOutcome, code string) string {
	t.Helper()
	var auditID, gotStatus, gotOutcome string
	var gotCode sql.NullString
	if err := db.QueryRow(`SELECT id::text, capture_status, outcome, error_code FROM audit_records WHERE request_id = $1`, requestID).Scan(&auditID, &gotStatus, &gotOutcome, &gotCode); err != nil {
		t.Fatalf("read audit state: %v", err)
	}
	if gotStatus != string(status) || gotOutcome != string(outcome) || !gotCode.Valid || gotCode.String != code {
		t.Fatalf("audit state = (%q, %q, %q), want (%q, %q, %q)", gotStatus, gotOutcome, gotCode.String, status, outcome, code)
	}
	return auditID
}

func assertTask102EncryptedContent(t *testing.T, db *sql.DB, auditID string) {
	t.Helper()
	rows, err := db.Query(`SELECT ciphertext FROM audit_raw_content WHERE audit_id = $1`, auditID)
	if err != nil {
		t.Fatalf("query encrypted content: %v", err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var ciphertext []byte
		if err := rows.Scan(&ciphertext); err != nil {
			t.Fatalf("scan encrypted content: %v", err)
		}
		count++
		if bytes.Contains(ciphertext, []byte(task102SyntheticPrompt)) {
			t.Fatal("synthetic prompt appeared in ciphertext storage")
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate encrypted content: %v", err)
	}
	if count == 0 {
		t.Fatal("no encrypted request content was retained")
	}
}

func assertTask102Usage(t *testing.T, db *sql.DB, requestID string, reported bool, input, output, total int64) {
	t.Helper()
	var gotReported bool
	var gotInput, gotOutput, gotTotal sql.NullInt64
	if err := db.QueryRow(`SELECT usage_reported, input_tokens, output_tokens, total_tokens FROM usage_records WHERE request_id = $1`, requestID).Scan(&gotReported, &gotInput, &gotOutput, &gotTotal); err != nil {
		t.Fatalf("read token usage: %v", err)
	}
	if gotReported != reported {
		t.Fatalf("usage_reported = %t, want %t", gotReported, reported)
	}
	if !reported {
		if gotInput.Valid || gotOutput.Valid || gotTotal.Valid {
			t.Fatalf("unreported token usage = (%v, %v, %v), want nulls", gotInput, gotOutput, gotTotal)
		}
		return
	}
	if !gotInput.Valid || !gotOutput.Valid || !gotTotal.Valid || gotInput.Int64 != input || gotOutput.Int64 != output || gotTotal.Int64 != total {
		t.Fatalf("token usage = (%v, %v, %v), want (%d, %d, %d)", gotInput, gotOutput, gotTotal, input, output, total)
	}
}

func assertTask102Gate(t *testing.T, repository *database.Repository, state audit.AuditGateState, reason string) {
	t.Helper()
	snapshot, err := repository.ReadAuditGate(context.Background())
	if err != nil {
		t.Fatalf("ReadAuditGate() error = %v", err)
	}
	if snapshot.State != state || snapshot.ReasonCode != reason {
		t.Fatalf("audit gate = (%q, %q), want (%q, %q)", snapshot.State, snapshot.ReasonCode, state, reason)
	}
}

func assertTask102AuditFault(t *testing.T, repository *database.Repository, active bool) {
	t.Helper()
	faults, err := repository.ReadCriticalFaults(context.Background())
	if err != nil {
		t.Fatalf("ReadCriticalFaults() error = %v", err)
	}
	for _, fault := range faults {
		if fault.Code == operations.FaultAuditUnavailable {
			if fault.Active != active {
				t.Fatalf("audit fault active = %t, want %t", fault.Active, active)
			}
			return
		}
	}
	t.Fatal("audit_unavailable critical fault missing")
}

func assertTask102AuditFaultHistory(t *testing.T, repository *database.Repository) {
	t.Helper()
	page, err := repository.ListOperationalEvents(context.Background(), operations.EventFilter{Limit: 10})
	if err != nil {
		t.Fatalf("ListOperationalEvents() error = %v", err)
	}
	var began, recovered bool
	for _, event := range page.Events {
		if event.Fault != operations.FaultAuditUnavailable {
			continue
		}
		if event.Active {
			began = true
		} else {
			recovered = true
		}
	}
	if !began || !recovered {
		t.Fatalf("audit fault history = %+v, want failure and recovery evidence", page.Events)
	}
}

func task102Readiness(harness *task102Harness, keyErr error) httpapi.HealthResponse {
	checker := httpapi.NewOperatorHealthChecker(httpapi.OperatorHealthDependencies{
		Configuration: func(context.Context) error { return nil },
		Database:      func(ctx context.Context) error { return harness.db.PingContext(ctx) },
		ActiveAuditKey: func(context.Context) error {
			return keyErr
		},
		ReadAuditGate: harness.repository.ReadAuditGate,
		ObserveDeletionLag: func(context.Context, time.Time) (audit.DeletionLagState, error) {
			return audit.DeletionLagState{}, nil
		},
		Now: harness.clock.now,
	})
	return checker.Readiness(context.Background())
}

func assertTask102HealthComponent(t *testing.T, response httpapi.HealthResponse, name string, state httpapi.HealthState, code string) {
	t.Helper()
	for _, component := range response.Components {
		if component.Name == name {
			if component.State != state || component.DetailCode != code {
				t.Fatalf("health component %s = (%q, %q), want (%q, %q)", name, component.State, component.DetailCode, state, code)
			}
			return
		}
	}
	t.Fatalf("health component %s missing", name)
}

func assertTask102Metrics(t *testing.T, metrics *observability.Metrics, lines ...string) {
	t.Helper()
	body := task102MetricsBody(t, metrics)
	for _, line := range lines {
		if !strings.Contains(body, line) {
			t.Fatalf("metrics missing %q\n%s", line, body)
		}
	}
}

func task102MetricsBody(t *testing.T, metrics *observability.Metrics) string {
	t.Helper()
	response := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", response.Code)
	}
	return response.Body.String()
}

func assertTask102ContentFree(t *testing.T, values ...string) {
	t.Helper()
	for _, value := range values {
		if strings.Contains(value, task102SyntheticPrompt) || strings.Contains(value, "synthetic-only") {
			t.Fatalf("content or synthetic credential appeared in diagnostic output: %q", value)
		}
	}
}
