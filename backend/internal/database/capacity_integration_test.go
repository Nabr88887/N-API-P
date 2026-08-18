//go:build integration

package database_test

import (
	"bytes"
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"

	"n-api-p/internal/audit"
	"n-api-p/internal/database"
	"n-api-p/internal/gateway"
	"n-api-p/internal/observability"
	"n-api-p/internal/policy"
)

const (
	task104EmployeeCount     = 50
	task104ConcurrentWorkers = 10
	task104Model             = "gpt-synthetic-capacity"
	task104UpstreamDelay     = 20 * time.Millisecond
)

//go:embed migrations/*.up.sql
var task104MigrationFiles embed.FS

type task104Employee struct {
	identityID string
	keyID      string
	teamID     string
}

type task104Job struct {
	employee task104Employee
	index    int
	stream   bool
	tool     bool
}

type task104Sample struct {
	descriptor string
	stream     bool
	tool       bool
	elapsed    time.Duration
	status     int
	body       []byte
	err        error
}

func TestTask104SyntheticCapacity(t *testing.T) {
	harness := newTask104Harness(t)
	jobs := task104Jobs(harness.employees)
	assertTask104WorkloadMix(t, jobs)
	baselineGoroutines := runtime.NumGoroutine()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	peakHeap := atomic.Uint64{}
	peakHeap.Store(before.HeapAlloc)
	monitorDone := make(chan struct{})
	monitorStopped := make(chan struct{})
	go func() {
		defer close(monitorStopped)
		ticker := time.NewTicker(5 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-monitorDone:
				return
			case <-ticker.C:
				var stats runtime.MemStats
				runtime.ReadMemStats(&stats)
				for current := peakHeap.Load(); stats.HeapAlloc > current; {
					if peakHeap.CompareAndSwap(current, stats.HeapAlloc) {
						break
					}
				}
			}
		}
	}()

	samples := runTask104Jobs(t, harness, jobs)
	close(monitorDone)
	<-monitorStopped

	if len(samples) != len(jobs) {
		t.Fatalf("samples = %d, want %d", len(samples), len(jobs))
	}
	for _, sample := range samples {
		if sample.err != nil {
			t.Fatalf("%s request failed: %v", sample.descriptor, sample.err)
		}
		if sample.status != http.StatusOK {
			t.Fatalf("%s response status = %d, want 200", sample.descriptor, sample.status)
		}
	}

	assertTask104DatabaseResults(t, harness.db)
	assertTask104SSEAndToolResults(t, samples)
	if task104RaceDetected {
		t.Log("race-instrumented run: latency threshold is not asserted")
	} else {
		assertTask104Latency(t, harness.upstream, samples)
	}
	assertTask104Bounds(t, harness, baselineGoroutines, before.HeapAlloc, peakHeap.Load())
}

type task104Harness struct {
	db        *sql.DB
	employees []task104Employee
	handler   *gateway.ChatProxyHandler
	limiter   *task104ObservedLimiter
	upstream  *task104Upstream
}

func newTask104Harness(t *testing.T) *task104Harness {
	t.Helper()
	db := openTask104Schema(t)
	employees := insertTask104Fixture(t, db)
	repository := database.NewRepository(db)
	metrics := observability.NewMetrics()
	gate, err := audit.NewDegradedStateMachine(repository)
	if err != nil {
		t.Fatalf("NewDegradedStateMachine() error = %v", err)
	}
	gate.SetMetrics(metrics)
	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := gate.Recover(context.Background(), now.Add(-2*time.Minute), now.Add(-time.Minute)); err != nil {
		t.Fatalf("Recover() error = %v", err)
	}
	envelope, err := audit.NewEnvelopeService(1, map[int][]byte{1: bytes.Repeat([]byte{0x42}, 32)})
	if err != nil {
		t.Fatalf("NewEnvelopeService() error = %v", err)
	}
	capture, err := audit.NewInitialCaptureServiceWithGate(envelope, repository, gate)
	if err != nil {
		t.Fatalf("NewInitialCaptureServiceWithGate() error = %v", err)
	}
	finalizer, err := audit.NewResponseFinalizationServiceWithGate(envelope, repository, gate)
	if err != nil {
		t.Fatalf("NewResponseFinalizationServiceWithGate() error = %v", err)
	}
	capture.SetMetrics(metrics)
	finalizer.SetMetrics(metrics)
	resolver, err := policy.NewResolver(repository)
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	upstream := &task104Upstream{delay: task104UpstreamDelay, durations: make(map[string]time.Duration)}
	limiter := &task104ObservedLimiter{delegate: gateway.NewInProcessLimiterWithMetrics(metrics)}
	idGenerator := &task104IDGenerator{}
	handler, err := gateway.NewChatProxyHandler(gateway.ChatProxyConfig{
		Upstream: upstream, Capture: capture, Finalizer: finalizer, Usage: repository,
		Policy: resolver, Limiter: limiter, Retention: 24 * time.Hour,
		ResponseLimit: 4 * 1024 * 1024, Metrics: metrics, NewID: idGenerator.next,
	})
	if err != nil {
		t.Fatalf("NewChatProxyHandler() error = %v", err)
	}
	return &task104Harness{db: db, employees: employees, handler: handler, limiter: limiter, upstream: upstream}
}

func task104Jobs(employees []task104Employee) []task104Job {
	jobs := make([]task104Job, 0, len(employees))
	for index, employee := range employees {
		stream, tool := false, false
		switch {
		case index < 20:
		case index < 35:
			stream = true
		case index < 45:
			tool = true
		default:
			stream, tool = true, true
		}
		jobs = append(jobs, task104Job{
			employee: employee, index: index, stream: stream, tool: tool,
		})
	}
	return jobs
}

func assertTask104WorkloadMix(t *testing.T, jobs []task104Job) {
	t.Helper()
	var mix [4]int
	for _, job := range jobs {
		switch {
		case !job.stream && !job.tool:
			mix[0]++
		case job.stream && !job.tool:
			mix[1]++
		case !job.stream && job.tool:
			mix[2]++
		case job.stream && job.tool:
			mix[3]++
		}
	}
	if mix != [4]int{20, 15, 10, 5} {
		t.Fatalf("workload mix = %v, want [20 regular, 15 SSE, 10 regular tool, 5 SSE tool]", mix)
	}
}

func runTask104Jobs(t *testing.T, harness *task104Harness, jobs []task104Job) []task104Sample {
	t.Helper()
	jobQueue := make(chan task104Job, len(jobs))
	results := make(chan task104Sample, len(jobs))
	ready := make(chan struct{}, task104ConcurrentWorkers)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for worker := 0; worker < task104ConcurrentWorkers; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			ready <- struct{}{}
			<-start
			for job := range jobQueue {
				results <- runTask104Request(harness, job)
			}
		}()
	}
	for worker := 0; worker < task104ConcurrentWorkers; worker++ {
		<-ready
	}
	for _, job := range jobs {
		jobQueue <- job
	}
	close(jobQueue)
	close(start)
	workers.Wait()
	close(results)
	samples := make([]task104Sample, 0, len(jobs))
	for sample := range results {
		samples = append(samples, sample)
	}
	return samples
}

func runTask104Request(harness *task104Harness, job task104Job) task104Sample {
	descriptor := fmt.Sprintf("task104-employee-%02d", job.index)
	body, err := task104RequestBody(descriptor, job.stream, job.tool)
	if err != nil {
		return task104Sample{descriptor: descriptor, stream: job.stream, tool: job.tool, err: err}
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	requestID := fmt.Sprintf("a1040000-0000-0000-0000-%012d", job.index+1)
	request = request.WithContext(gateway.WithChatCaller(request.Context(), gateway.ChatCaller{
		RequestID: requestID, KeyID: job.employee.keyID, OwnerKind: audit.OwnerKindPersonal,
		IdentityID: job.employee.identityID, TeamID: job.employee.teamID,
		TrafficOwner: gateway.TrafficOwner{Kind: gateway.TrafficOwnerEmployee, ID: job.employee.identityID},
	}))
	response := httptest.NewRecorder()
	started := time.Now()
	harness.handler.ServeHTTP(response, request)
	elapsed := time.Since(started)
	return task104Sample{descriptor: descriptor, stream: job.stream, tool: job.tool, elapsed: elapsed, status: response.Code, body: append([]byte(nil), response.Body.Bytes()...), err: nil}
}

func task104RequestBody(descriptor string, stream, tool bool) ([]byte, error) {
	payload := map[string]any{
		"model":    task104Model,
		"messages": []any{map[string]any{"role": "user", "content": descriptor}},
		"stream":   stream,
	}
	if tool {
		payload["tools"] = []any{map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        "synthetic_tool",
				"description": "synthetic acceptance tool",
				"parameters":  map[string]any{"type": "object", "properties": map[string]any{}},
			},
		}}
		payload["tool_choice"] = "auto"
	}
	return json.Marshal(payload)
}

type task104Upstream struct {
	mu        sync.Mutex
	delay     time.Duration
	active    int
	maxActive int
	durations map[string]time.Duration
}

func (upstream *task104Upstream) CreateChatCompletion(ctx context.Context, body []byte, stream bool) (*gateway.NewAPIResponse, error) {
	descriptor, tool, err := task104RequestDescriptor(body)
	if err != nil {
		return nil, err
	}
	started := time.Now()
	upstream.mu.Lock()
	upstream.active++
	if upstream.active > upstream.maxActive {
		upstream.maxActive = upstream.active
	}
	upstream.mu.Unlock()
	defer func() {
		upstream.mu.Lock()
		upstream.active--
		upstream.durations[descriptor] = time.Since(started)
		upstream.mu.Unlock()
	}()
	select {
	case <-time.After(upstream.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if stream {
		return &gateway.NewAPIResponse{StatusCode: http.StatusOK, ContentType: "text/event-stream", RequestID: "upstream-" + descriptor, Body: io.NopCloser(strings.NewReader(task104SSEBody(descriptor, tool)))}, nil
	}
	return &gateway.NewAPIResponse{StatusCode: http.StatusOK, ContentType: "application/json", RequestID: "upstream-" + descriptor, Body: io.NopCloser(bytes.NewReader(task104RegularBody(descriptor, tool)))}, nil
}

func task104RequestDescriptor(body []byte) (string, bool, error) {
	var request struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(body, &request); err != nil || len(request.Messages) != 1 || request.Messages[0].Content == "" {
		return "", false, fmt.Errorf("decode synthetic request")
	}
	return request.Messages[0].Content, len(request.Tools) != 0, nil
}

func task104RegularBody(descriptor string, tool bool) []byte {
	message := map[string]any{"role": "assistant", "content": "synthetic-response-" + descriptor}
	finish := "stop"
	if tool {
		message["content"] = nil
		message["tool_calls"] = []any{map[string]any{
			"id": "call-" + descriptor, "type": "function",
			"function": map[string]any{"name": "synthetic_tool", "arguments": `{"value":"synthetic"}`},
		}}
		finish = "tool_calls"
	}
	response := map[string]any{
		"id": "completion-" + descriptor, "model": task104Model,
		"choices": []any{map[string]any{"index": 0, "message": message, "finish_reason": finish}},
		"usage":   map[string]any{"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
	}
	body, _ := json.Marshal(response)
	return body
}

func task104SSEBody(descriptor string, tool bool) string {
	finish := "stop"
	delta := map[string]any{"role": "assistant", "content": "synthetic-response-" + descriptor}
	if tool {
		finish = "tool_calls"
		delta["content"] = nil
		delta["tool_calls"] = []any{map[string]any{
			"index": 0, "id": "call-" + descriptor, "type": "function",
			"function": map[string]any{"name": "synthetic_tool", "arguments": `{"value":"synthetic"}`},
		}}
	}
	chunk := map[string]any{
		"id": "completion-" + descriptor, "model": task104Model,
		"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": finish}},
		"usage":   map[string]any{"prompt_tokens": 11, "completion_tokens": 7, "total_tokens": 18},
	}
	encoded, _ := json.Marshal(chunk)
	return "data: " + string(encoded) + "\n\ndata: [DONE]\n\n"
}

func assertTask104SSEAndToolResults(t *testing.T, samples []task104Sample) {
	t.Helper()
	for _, sample := range samples {
		if sample.stream {
			logical, err := gateway.ReadSSEStream(bytes.NewReader(sample.body), 4*1024*1024, func(gateway.SSEEvent) error { return nil })
			if err != nil || logical.ID != "completion-"+sample.descriptor || logical.Model != task104Model || len(logical.Choices) != 1 || logical.Usage == nil || logical.Usage.TotalTokens != 18 {
				t.Fatalf("%s SSE logical response = (%+v, %v)", sample.descriptor, logical, err)
			}
			choice := logical.Choices[0]
			if !sample.tool && (choice.Content != "synthetic-response-"+sample.descriptor || choice.FinishReason != "stop" || len(choice.ToolCalls) != 0) {
				t.Fatalf("%s SSE text choice = %+v", sample.descriptor, choice)
			}
			if sample.tool && (choice.Content != "" || choice.FinishReason != "tool_calls" || len(choice.ToolCalls) != 1 || choice.ToolCalls[0].ID != "call-"+sample.descriptor || choice.ToolCalls[0].Type != "function" || choice.ToolCalls[0].Function.Name != "synthetic_tool" || choice.ToolCalls[0].Function.Arguments != `{"value":"synthetic"}`) {
				t.Fatalf("%s SSE tool choice = %+v", sample.descriptor, choice)
			}
			continue
		}
		var response struct {
			ID      string `json:"id"`
			Model   string `json:"model"`
			Choices []struct {
				Message struct {
					Content   *string `json:"content"`
					ToolCalls []struct {
						ID       string `json:"id"`
						Type     string `json:"type"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"message"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Usage struct {
				TotalTokens int64 `json:"total_tokens"`
			} `json:"usage"`
		}
		if err := json.Unmarshal(sample.body, &response); err != nil || response.ID != "completion-"+sample.descriptor || response.Model != task104Model || len(response.Choices) != 1 || response.Usage.TotalTokens != 18 {
			t.Fatalf("%s regular response invalid: %v %s", sample.descriptor, err, sample.body)
		}
		choice := response.Choices[0]
		if !sample.tool && (choice.Message.Content == nil || *choice.Message.Content != "synthetic-response-"+sample.descriptor || choice.FinishReason != "stop" || len(choice.Message.ToolCalls) != 0) {
			t.Fatalf("%s regular text choice invalid: %s", sample.descriptor, sample.body)
		}
		if sample.tool && (choice.Message.Content != nil || choice.FinishReason != "tool_calls" || len(choice.Message.ToolCalls) != 1 || choice.Message.ToolCalls[0].ID != "call-"+sample.descriptor || choice.Message.ToolCalls[0].Type != "function" || choice.Message.ToolCalls[0].Function.Name != "synthetic_tool" || choice.Message.ToolCalls[0].Function.Arguments != `{"value":"synthetic"}`) {
			t.Fatalf("%s regular tool choice invalid: %s", sample.descriptor, sample.body)
		}
	}
}

func assertTask104Latency(t *testing.T, upstream *task104Upstream, samples []task104Sample) {
	t.Helper()
	values := make([]time.Duration, 0, len(samples))
	upstream.mu.Lock()
	durations := make(map[string]time.Duration, len(upstream.durations))
	for descriptor, duration := range upstream.durations {
		durations[descriptor] = duration
	}
	upstream.mu.Unlock()
	for _, sample := range samples {
		upstreamDuration, ok := durations[sample.descriptor]
		if !ok {
			t.Fatalf("%s upstream duration missing", sample.descriptor)
		}
		gatewayDuration := sample.elapsed - upstreamDuration
		if gatewayDuration < 0 {
			t.Fatalf("%s gateway-added duration = %s, upstream duration = %s", sample.descriptor, gatewayDuration, upstreamDuration)
		}
		values = append(values, gatewayDuration)
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	index := (95*len(values)+99)/100 - 1
	if index < 0 {
		index = 0
	}
	if values[index] > 200*time.Millisecond {
		t.Fatalf("gateway-added P95 = %s, want <= 200ms", values[index])
	}
	t.Logf("gateway-added P95 = %s", values[index])
}

func assertTask104Bounds(t *testing.T, harness *task104Harness, baselineGoroutines int, beforeHeap, peakHeap uint64) {
	t.Helper()
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if peakHeap > beforeHeap+128*1024*1024 {
		t.Fatalf("peak heap delta = %d bytes, want <= 128 MiB", peakHeap-beforeHeap)
	}
	if after.HeapAlloc > beforeHeap+32*1024*1024 {
		t.Fatalf("retained heap delta = %d bytes, want <= 32 MiB", after.HeapAlloc-beforeHeap)
	}
	if got := runtime.NumGoroutine(); got > baselineGoroutines+5 {
		t.Fatalf("goroutines after workload = %d, baseline %d", got, baselineGoroutines)
	}
	harness.limiter.mu.Lock()
	active, maximum := harness.limiter.active, harness.limiter.maxActive
	harness.limiter.mu.Unlock()
	if active != 0 || maximum < 1 || maximum > task104ConcurrentWorkers {
		t.Fatalf("limiter activity = (%d, max %d), want (0, max 1..%d)", active, maximum, task104ConcurrentWorkers)
	}
	harness.upstream.mu.Lock()
	upstreamActive, upstreamMaximum := harness.upstream.active, harness.upstream.maxActive
	harness.upstream.mu.Unlock()
	if upstreamActive != 0 || upstreamMaximum < 1 || upstreamMaximum > task104ConcurrentWorkers {
		t.Fatalf("upstream activity = (%d, max %d), want (0, max 1..%d)", upstreamActive, upstreamMaximum, task104ConcurrentWorkers)
	}
	stats := harness.db.Stats()
	if stats.InUse != 0 || stats.OpenConnections > task104ConcurrentWorkers+2 {
		t.Fatalf("database stats = %+v, want no in-use connections and <= 12 open", stats)
	}
}

func assertTask104DatabaseResults(t *testing.T, db *sql.DB) {
	t.Helper()
	var completed, usage, linked, raw int
	if err := db.QueryRow(`SELECT count(*) FROM audit_records WHERE capture_status = 'complete' AND outcome = 'success'`).Scan(&completed); err != nil {
		t.Fatalf("count completed audits: %v", err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM usage_records WHERE usage_reported AND input_tokens = 11 AND output_tokens = 7 AND total_tokens = 18`).Scan(&usage); err != nil {
		t.Fatalf("count usage records: %v", err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM usage_records u JOIN audit_records a ON a.id = u.audit_id AND a.request_id = u.request_id WHERE a.capture_status = 'complete' AND a.outcome = 'success' AND u.usage_reported`).Scan(&linked); err != nil {
		t.Fatalf("count linked usage records: %v", err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM audit_raw_content`).Scan(&raw); err != nil {
		t.Fatalf("count raw content: %v", err)
	}
	if completed != task104EmployeeCount || usage != task104EmployeeCount || linked != task104EmployeeCount || raw != task104EmployeeCount*2 {
		t.Fatalf("database counts = completed:%d usage:%d linked:%d raw:%d, want 50/50/50/100", completed, usage, linked, raw)
	}
}

type task104ObservedLimiter struct {
	delegate  *gateway.InProcessLimiter
	mu        sync.Mutex
	active    int
	maxActive int
}

func (limiter *task104ObservedLimiter) Acquire(ctx context.Context, owner gateway.TrafficOwner) (gateway.Reservation, error) {
	reservation, err := limiter.delegate.Acquire(ctx, owner)
	if err != nil {
		return nil, err
	}
	limiter.mu.Lock()
	limiter.active++
	if limiter.active > limiter.maxActive {
		limiter.maxActive = limiter.active
	}
	limiter.mu.Unlock()
	return &task104ObservedReservation{parent: limiter, delegate: reservation}, nil
}

type task104ObservedReservation struct {
	once     sync.Once
	parent   *task104ObservedLimiter
	delegate gateway.Reservation
}

func (reservation *task104ObservedReservation) Release() {
	if reservation == nil {
		return
	}
	reservation.once.Do(func() {
		reservation.delegate.Release()
		reservation.parent.mu.Lock()
		reservation.parent.active--
		reservation.parent.mu.Unlock()
	})
}

type task104IDGenerator struct{ value atomic.Uint64 }

func (generator *task104IDGenerator) next() (string, error) {
	return fmt.Sprintf("b1040000-0000-0000-0000-%012d", generator.value.Add(1)), nil
}

func openTask104Schema(t *testing.T) *sql.DB {
	t.Helper()
	databaseURL := strings.TrimSpace(os.Getenv("N_API_P_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Fatal("N_API_P_TEST_DATABASE_URL is required for integration tests")
	}
	const schemaName = "task104_capacity_test"
	adminDB := openTask104Database(t, databaseURL)
	identifier := pgx.Identifier{schemaName}.Sanitize()
	if _, err := adminDB.Exec("DROP SCHEMA IF EXISTS " + identifier + " CASCADE"); err != nil {
		t.Fatalf("drop stale task 10.4 schema: %v", err)
	}
	if _, err := adminDB.Exec("CREATE SCHEMA " + identifier); err != nil {
		t.Fatalf("create task 10.4 schema: %v", err)
	}
	t.Cleanup(func() {
		if _, err := adminDB.Exec("DROP SCHEMA IF EXISTS " + identifier + " CASCADE"); err != nil {
			t.Errorf("drop task 10.4 schema: %v", err)
		}
	})
	schemaDB := openTask104Database(t, task104DatabaseURL(t, databaseURL, schemaName))
	schemaDB.SetMaxOpenConns(task104ConcurrentWorkers + 2)
	schemaDB.SetMaxIdleConns(task104ConcurrentWorkers + 2)
	entries, err := fs.ReadDir(task104MigrationFiles, "migrations")
	if err != nil {
		t.Fatalf("read embedded migrations: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		migration, err := task104MigrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			t.Fatalf("read migration %s: %v", entry.Name(), err)
		}
		if _, err := schemaDB.Exec(string(migration)); err != nil {
			t.Fatalf("apply migration %s: %v", entry.Name(), err)
		}
	}
	return schemaDB
}

func openTask104Database(t *testing.T, databaseURL string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		t.Fatalf("open task 10.4 database: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("close task 10.4 database: %v", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping task 10.4 database: %v", err)
	}
	return db
}

func task104DatabaseURL(t *testing.T, databaseURL, schemaName string) string {
	t.Helper()
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse task 10.4 database URL: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schemaName)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func insertTask104Fixture(t *testing.T, db *sql.DB) []task104Employee {
	t.Helper()
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin task 10.4 fixture: %v", err)
	}
	defer tx.Rollback()
	teamID := "81000000-0000-0000-0000-000000000104"
	adminID := "82000000-0000-0000-0000-000000000104"
	if _, err := tx.Exec(`INSERT INTO teams (id, name, status) VALUES ($1, $2, 'active')`, teamID, "synthetic-capacity-team"); err != nil {
		t.Fatalf("insert capacity team: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO identities (id, email, role, status) VALUES ($1, $2, 'system_administrator', 'active')`, adminID, "synthetic-capacity-admin@example.invalid"); err != nil {
		t.Fatalf("insert capacity admin: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, adminID, teamID); err != nil {
		t.Fatalf("insert capacity admin membership: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO model_allowlist (model_id, status, updated_by_identity_id) VALUES ($1, 'allowed', $2)`, task104Model, adminID); err != nil {
		t.Fatalf("insert capacity model: %v", err)
	}
	employees := make([]task104Employee, 0, task104EmployeeCount)
	for index := 0; index < task104EmployeeCount; index++ {
		identityID := fmt.Sprintf("83000000-0000-0000-0000-%012d", index+1)
		keyID := fmt.Sprintf("84000000-0000-0000-0000-%012d", index+1)
		if _, err := tx.Exec(`INSERT INTO identities (id, email, role, status) VALUES ($1, $2, 'employee', 'active')`, identityID, fmt.Sprintf("synthetic.capacity.%02d@example.invalid", index)); err != nil {
			t.Fatalf("insert capacity employee %d: %v", index, err)
		}
		if _, err := tx.Exec(`INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, identityID, teamID); err != nil {
			t.Fatalf("insert capacity membership %d: %v", index, err)
		}
		if _, err := tx.Exec(`INSERT INTO api_keys (id, identity_id, kind, name, prefix, verification_hash, status, created_at) VALUES ($1, $2, 'personal', $3, $4, $5, 'active', CURRENT_TIMESTAMP)`, keyID, identityID, fmt.Sprintf("capacity-%02d", index), fmt.Sprintf("nap_t104_%02d", index), []byte(fmt.Sprintf("synthetic-hash-%02d", index))); err != nil {
			t.Fatalf("insert capacity key %d: %v", index, err)
		}
		employees = append(employees, task104Employee{identityID: identityID, keyID: keyID, teamID: teamID})
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit task 10.4 fixture: %v", err)
	}
	return employees
}
