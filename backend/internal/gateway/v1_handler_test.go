package gateway

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAIV1HandlerDispatchesOnlySupportedMethodPaths(t *testing.T) {
	modelsCalls := 0
	chatCalls := 0
	handler, err := NewOpenAIV1Handler(
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { modelsCalls++ }),
		http.HandlerFunc(func(http.ResponseWriter, *http.Request) { chatCalls++ }),
	)
	if err != nil {
		t.Fatalf("NewOpenAIV1Handler() error = %v", err)
	}

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/v1/models", nil))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
	if modelsCalls != 1 || chatCalls != 1 {
		t.Fatalf("models/chat calls = %d/%d, want 1/1", modelsCalls, chatCalls)
	}

	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodPost, "/v1/models", nil),
		httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil),
		httptest.NewRequest(http.MethodPost, "/v1/responses", nil),
		httptest.NewRequest(http.MethodPost, "/v1/embeddings", nil),
		httptest.NewRequest(http.MethodPost, "/v1/images/generations", nil),
		httptest.NewRequest(http.MethodPost, "/v1/audio/speech", nil),
		httptest.NewRequest(http.MethodPost, "/v1/files", nil),
	} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound || !strings.Contains(recorder.Body.String(), `"code":"UNSUPPORTED_ENDPOINT"`) {
			t.Fatalf("%s %s response = (%d, %s), want structured unsupported endpoint", request.Method, request.URL.Path, recorder.Code, recorder.Body.String())
		}
	}
	if modelsCalls != 1 || chatCalls != 1 {
		t.Fatalf("unsupported routes reached handlers: models/chat = %d/%d", modelsCalls, chatCalls)
	}
}

func TestNewOpenAIV1HandlerRequiresBothSupportedHandlers(t *testing.T) {
	valid := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if _, err := NewOpenAIV1Handler(nil, valid); !errors.Is(err, ErrInvalidOpenAIV1Handler) {
		t.Fatalf("nil models error = %v, want ErrInvalidOpenAIV1Handler", err)
	}
	if _, err := NewOpenAIV1Handler(valid, nil); !errors.Is(err, ErrInvalidOpenAIV1Handler) {
		t.Fatalf("nil chat error = %v, want ErrInvalidOpenAIV1Handler", err)
	}
}
