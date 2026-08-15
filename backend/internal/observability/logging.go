package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const RequestIDHeader = "X-Request-ID"

var ErrInvalidLogEvent = errors.New("invalid log event")

type Level string

const (
	LevelDebug Level = "debug"
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// LogEvent is deliberately closed over the operational fields that may leave
// the process. Callers cannot attach arbitrary request or content attributes.
type LogEvent struct {
	Level               Level
	Event               string
	RequestID           string
	Route               string
	Method              string
	Status              int
	LatencyMilliseconds int64
	RequestBytes        int64
	ResponseBytes       int64
	ErrorCode           string
	AuditID             string
	UsageID             string
	SecurityEventID     string
	UpstreamRequestID   string
}

type jsonLogRecord struct {
	Time                string `json:"time"`
	Level               Level  `json:"level"`
	Event               string `json:"event"`
	RequestID           string `json:"request_id,omitempty"`
	Route               string `json:"route,omitempty"`
	Method              string `json:"method,omitempty"`
	Status              int    `json:"status,omitempty"`
	LatencyMilliseconds int64  `json:"latency_ms,omitempty"`
	RequestBytes        int64  `json:"request_bytes,omitempty"`
	ResponseBytes       int64  `json:"response_bytes,omitempty"`
	ErrorCode           string `json:"error_code,omitempty"`
	AuditID             string `json:"audit_id,omitempty"`
	UsageID             string `json:"usage_id,omitempty"`
	SecurityEventID     string `json:"security_event_id,omitempty"`
	UpstreamRequestID   string `json:"upstream_request_id,omitempty"`
}

type Logger struct {
	writer       io.Writer
	now          func() time.Time
	mu           sync.Mutex
	writeFailure atomic.Uint64
}

var defaultLogger = NewStdoutLogger()

func NewJSONLogger(writer io.Writer) *Logger {
	return NewJSONLoggerWithClock(writer, time.Now)
}

func NewJSONLoggerWithClock(writer io.Writer, now func() time.Time) *Logger {
	if writer == nil {
		writer = io.Discard
	}
	if now == nil {
		now = time.Now
	}
	return &Logger{writer: writer, now: now}
}

func NewStdoutLogger() *Logger {
	return NewJSONLogger(os.Stdout)
}

func DefaultLogger() *Logger {
	return defaultLogger
}

func (logger *Logger) Emit(event LogEvent) error {
	if logger == nil || logger.writer == nil || logger.now == nil {
		return ErrInvalidLogEvent
	}
	if err := validateLogEvent(event); err != nil {
		return err
	}
	record := jsonLogRecord{
		Time:                logger.now().UTC().Format(time.RFC3339Nano),
		Level:               event.Level,
		Event:               event.Event,
		RequestID:           event.RequestID,
		Route:               event.Route,
		Method:              event.Method,
		Status:              event.Status,
		LatencyMilliseconds: event.LatencyMilliseconds,
		RequestBytes:        event.RequestBytes,
		ResponseBytes:       event.ResponseBytes,
		ErrorCode:           event.ErrorCode,
		AuditID:             event.AuditID,
		UsageID:             event.UsageID,
		SecurityEventID:     event.SecurityEventID,
		UpstreamRequestID:   event.UpstreamRequestID,
	}
	logger.mu.Lock()
	defer logger.mu.Unlock()
	if err := json.NewEncoder(logger.writer).Encode(record); err != nil {
		return fmt.Errorf("write structured log: %w", err)
	}
	return nil
}

func (logger *Logger) noteWriteFailure() {
	if logger != nil {
		logger.writeFailure.Add(1)
	}
}

func (logger *Logger) WriteFailures() uint64 {
	if logger == nil {
		return 0
	}
	return logger.writeFailure.Load()
}

func validateLogEvent(event LogEvent) error {
	if !validToken(event.Event, 64) || !validLevel(event.Level) || (event.RequestID != "" && !IsValidRequestID(event.RequestID)) {
		return ErrInvalidLogEvent
	}
	if event.Route != "" && !validValue(event.Route, 255) {
		return ErrInvalidLogEvent
	}
	if event.Method != "" && !validToken(event.Method, 16) {
		return ErrInvalidLogEvent
	}
	if event.Status != 0 && (event.Status < 100 || event.Status > 599) {
		return ErrInvalidLogEvent
	}
	if event.LatencyMilliseconds < 0 || event.RequestBytes < 0 || event.ResponseBytes < 0 {
		return ErrInvalidLogEvent
	}
	for _, value := range []string{event.ErrorCode, event.AuditID, event.UsageID, event.SecurityEventID, event.UpstreamRequestID} {
		if value != "" && !validValue(value, 255) {
			return ErrInvalidLogEvent
		}
	}
	return nil
}

func validLevel(level Level) bool {
	switch level {
	case LevelDebug, LevelInfo, LevelWarn, LevelError:
		return true
	default:
		return false
	}
}

func validToken(value string, maximum int) bool {
	if value == "" || len(value) > maximum || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-' || character == '.' || character == '/' {
			continue
		}
		return false
	}
	return true
}

func validValue(value string, maximum int) bool {
	if value == "" || len(value) > maximum || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func NewRequestID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("generate request ID: %w", err)
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

func ResolveRequestID(candidate string) (string, error) {
	if IsValidRequestID(candidate) {
		return candidate, nil
	}
	return NewRequestID()
}

func IsValidRequestID(value string) bool {
	if len(value) != 36 || value != strings.TrimSpace(value) {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}

type requestIDContextKey struct{}

func WithRequestID(ctx context.Context, requestID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, requestIDContextKey{}, requestID)
}

func RequestIDFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	requestID, ok := ctx.Value(requestIDContextKey{}).(string)
	return requestID, ok && IsValidRequestID(requestID)
}

type Correlation struct {
	RequestID         string
	AuditID           string
	UsageID           string
	SecurityEventID   string
	UpstreamRequestID string
}

type correlationContextKey struct{}

func WithCorrelation(ctx context.Context, correlation Correlation) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, correlationContextKey{}, correlation)
}

func CorrelationFromContext(ctx context.Context) (Correlation, bool) {
	if ctx == nil {
		return Correlation{}, false
	}
	correlation, ok := ctx.Value(correlationContextKey{}).(Correlation)
	return correlation, ok
}

func NewRequestIDMiddleware(next http.Handler, logger *Logger) http.Handler {
	return NewRequestIDMiddlewareWithMetrics(next, logger, nil)
}

func NewRequestIDMiddlewareWithMetrics(next http.Handler, logger *Logger, metrics *Metrics) http.Handler {
	if next == nil {
		return http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusInternalServerError)
		})
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestID, err := ResolveRequestID(request.Header.Get(RequestIDHeader))
		if err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		started := time.Now()
		capture := &responseCapture{ResponseWriter: writer, requestID: requestID}
		capture.Header().Set(RequestIDHeader, requestID)
		request = request.WithContext(WithRequestID(request.Context(), requestID))
		next.ServeHTTP(capture, request)
		if capture.status == 0 {
			capture.status = http.StatusOK
		}
		if logger != nil {
			event := LogEvent{
				Level:               LevelInfo,
				Event:               "http_request_completed",
				RequestID:           requestID,
				Route:               routeClass(request.URL.Path),
				Method:              request.Method,
				Status:              capture.status,
				LatencyMilliseconds: time.Since(started).Milliseconds(),
				ResponseBytes:       capture.bytes,
			}
			if request.ContentLength >= 0 {
				event.RequestBytes = request.ContentLength
			}
			if err := logger.Emit(event); err != nil {
				logger.noteWriteFailure()
			}
		}
		if metrics != nil {
			metrics.ObserveHTTPRequest(routeClass(request.URL.Path), request.Method, capture.status, time.Since(started))
		}
	})
}

func routeClass(path string) string {
	switch {
	case path == "/v1/models":
		return "/v1/models"
	case path == "/v1/chat/completions":
		return "/v1/chat/completions"
	case path == "/health/live":
		return "/health/live"
	case path == "/health/ready":
		return "/health/ready"
	case path == "/metrics":
		return "/metrics"
	case strings.HasPrefix(path, "/api/v1/"):
		return "/api/v1"
	default:
		return "unknown"
	}
}

type responseCapture struct {
	http.ResponseWriter
	requestID string
	status    int
	bytes     int64
}

func (capture *responseCapture) WriteHeader(status int) {
	if capture.status != 0 {
		return
	}
	capture.Header().Set(RequestIDHeader, capture.requestID)
	capture.status = status
	capture.ResponseWriter.WriteHeader(status)
}

func (capture *responseCapture) Write(data []byte) (int, error) {
	if capture.status == 0 {
		capture.WriteHeader(http.StatusOK)
	}
	written, err := capture.ResponseWriter.Write(data)
	capture.bytes += int64(written)
	return written, err
}

func (capture *responseCapture) Flush() {
	if capture.status == 0 {
		capture.WriteHeader(http.StatusOK)
	}
	if flusher, ok := capture.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (capture *responseCapture) ReadFrom(reader io.Reader) (int64, error) {
	if capture.status == 0 {
		capture.WriteHeader(http.StatusOK)
	}
	count, err := io.Copy(capture.ResponseWriter, reader)
	capture.bytes += count
	return count, err
}

func (capture *responseCapture) Unwrap() http.ResponseWriter {
	return capture.ResponseWriter
}
