package gateway

import (
	"bytes"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"n-api-p/internal/audit"
)

func TestOpenAIClientCompatibilityWithMockNewAPIModels(t *testing.T) {
	responseBody := []byte(`{"object":"list","data":[{"id":"gpt-test","object":"model","owned_by":"internal"}]}`)
	client := newMockNewAPIClient(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/base/v1/models" {
			t.Errorf("request = %s %s, want GET /base/v1/models", request.Method, request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer synthetic-upstream-token" || request.Header.Get("Accept") != "application/json" {
			t.Errorf("headers = %#v, want server authorization and JSON accept", request.Header)
		}
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.Header().Set("X-Request-ID", "mock-models")
		_, _ = writer.Write(responseBody)
	})
	gateway := newCompatibilityGateway(t, client)
	recorder := httptest.NewRecorder()

	gateway.ServeHTTP(recorder, compatibilityRequest(t, http.MethodGet, "/v1/models", nil, "compat-models"))

	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/json" || recorder.Header().Get("X-Request-ID") != "mock-models" || !bytes.Equal(recorder.Body.Bytes(), responseBody) {
		t.Fatalf("model response = (%d, %q, %q, %s), want exact public gateway response", recorder.Code, recorder.Header().Get("Content-Type"), recorder.Header().Get("X-Request-ID"), recorder.Body.Bytes())
	}
}

func TestOpenAIClientCompatibilityWithMockNewAPIRegularChat(t *testing.T) {
	requestBody := []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hello"}],"temperature":0.2}`)
	responseBody := []byte(`{"id":"chatcmpl-regular","object":"chat.completion","model":"gpt-test","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}`)
	client := newMockNewAPIClient(t, func(writer http.ResponseWriter, request *http.Request) {
		assertMockChatRequest(t, request, requestBody, "application/json")
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Request-ID", "mock-regular")
		_, _ = writer.Write(responseBody)
	})
	gateway := newCompatibilityGateway(t, client)
	recorder := httptest.NewRecorder()

	gateway.ServeHTTP(recorder, compatibilityRequest(t, http.MethodPost, "/v1/chat/completions", requestBody, "compat-request"))

	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/json" || recorder.Header().Get("X-Request-ID") != "mock-regular" || !bytes.Equal(recorder.Body.Bytes(), responseBody) {
		t.Fatalf("regular response = (%d, %q, %q, %s), want exact public gateway response", recorder.Code, recorder.Header().Get("Content-Type"), recorder.Header().Get("X-Request-ID"), recorder.Body.Bytes())
	}
}

func TestOpenAIClientCompatibilityWithMockNewAPIStreamingChat(t *testing.T) {
	requestBody := []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"stream"}],"stream":true}`)
	responseBody := []byte("data: {\"id\":\"chatcmpl-stream\",\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"hi\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n")
	client := newMockNewAPIClient(t, func(writer http.ResponseWriter, request *http.Request) {
		assertMockChatRequest(t, request, requestBody, "text/event-stream")
		writer.Header().Set("Content-Type", "text/event-stream")
		writer.Header().Set("X-Request-ID", "mock-stream")
		_, _ = writer.Write(responseBody)
	})
	gateway := newCompatibilityGateway(t, client)
	recorder := httptest.NewRecorder()

	gateway.ServeHTTP(recorder, compatibilityRequest(t, http.MethodPost, "/v1/chat/completions", requestBody, "compat-request"))

	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "text/event-stream" || recorder.Header().Get("X-Request-ID") != "mock-stream" || !bytes.Equal(recorder.Body.Bytes(), responseBody) {
		t.Fatalf("stream response = (%d, %q, %q, %s), want exact public gateway response", recorder.Code, recorder.Header().Get("Content-Type"), recorder.Header().Get("X-Request-ID"), recorder.Body.Bytes())
	}
}

func TestOpenAIClientCompatibilityWithMockNewAPIToolCalls(t *testing.T) {
	requestBody := []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"look this up"}],"tools":[{"type":"function","function":{"name":"lookup","description":"Return text","parameters":{"type":"object","properties":{"query":{"type":"string"}},"required":["query"]}}}],"tool_choice":{"type":"function","function":{"name":"lookup"}}}`)
	responseBody := []byte(`{"id":"chatcmpl-tool","model":"gpt-test","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"query\":\"status\"}"}}]},"finish_reason":"tool_calls"}]}`)
	client := newMockNewAPIClient(t, func(writer http.ResponseWriter, request *http.Request) {
		assertMockChatRequest(t, request, requestBody, "application/json")
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Request-ID", "mock-tool")
		_, _ = writer.Write(responseBody)
	})
	gateway := newCompatibilityGateway(t, client)
	recorder := httptest.NewRecorder()

	gateway.ServeHTTP(recorder, compatibilityRequest(t, http.MethodPost, "/v1/chat/completions", requestBody, "compat-request"))

	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != "application/json" || recorder.Header().Get("X-Request-ID") != "mock-tool" || !bytes.Equal(recorder.Body.Bytes(), responseBody) {
		t.Fatalf("tool response = (%d, %q, %q, %s), want exact public gateway response", recorder.Code, recorder.Header().Get("Content-Type"), recorder.Header().Get("X-Request-ID"), recorder.Body.Bytes())
	}
}

func assertMockChatRequest(t *testing.T, request *http.Request, body []byte, accept string) {
	t.Helper()
	if request.Method != http.MethodPost || request.URL.Path != "/base/v1/chat/completions" {
		t.Errorf("request = %s %s, want POST /base/v1/chat/completions", request.Method, request.URL.Path)
	}
	if request.Header.Get("Authorization") != "Bearer synthetic-upstream-token" || request.Header.Get("Accept") != accept || request.Header.Get("Content-Type") != "application/json" {
		t.Errorf("headers = %#v, want server authorization and %s/JSON media types", request.Header, accept)
	}
	got, err := io.ReadAll(request.Body)
	if err != nil {
		t.Errorf("read request body: %v", err)
	} else if !bytes.Equal(got, body) {
		t.Errorf("request body = %s, want %s", got, body)
	}
}

func newCompatibilityGateway(t *testing.T, client *NewAPIClient) *OpenAIV1Handler {
	t.Helper()
	models := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if _, ok := chatCallerFromContext(request.Context()); !ok {
			writeChatError(writer, "INVALID_API_KEY")
			return
		}
		response, err := client.ListModels(request.Context())
		if err != nil {
			t.Errorf("ListModels() error = %v", err)
			writeChatError(writer, "UPSTREAM_UNAVAILABLE")
			return
		}
		defer response.Body.Close()
		writer.Header().Set("Content-Type", response.ContentType)
		if response.RequestID != "" {
			writer.Header().Set("X-Request-ID", response.RequestID)
		}
		writer.WriteHeader(response.StatusCode)
		_, _ = io.Copy(writer, response.Body)
	})
	chat := newTestChatProxyHandler(t, client, &fakeInitialCapture{receipt: audit.CaptureReceipt{AuditID: "generated-id", RequestID: "compat-request"}}, &fakeResponseFinalizer{}, &fakeUsageRepository{}, nil)
	gateway, err := NewOpenAIV1Handler(models, chat)
	if err != nil {
		t.Fatalf("NewOpenAIV1Handler() error = %v", err)
	}
	return gateway
}

func compatibilityRequest(t *testing.T, method, path string, body []byte, requestID string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return request.WithContext(WithChatCaller(request.Context(), ChatCaller{
		RequestID: requestID, KeyID: "key-compat", OwnerKind: audit.OwnerKindPersonal,
		IdentityID: "employee-compat", TeamID: "team-compat",
		TrafficOwner: TrafficOwner{Kind: TrafficOwnerEmployee, ID: "employee-compat"},
	}))
}

func newMockNewAPIClient(t *testing.T, handler http.HandlerFunc) *NewAPIClient {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	client, err := NewClient(NewAPIClientConfig{
		BaseURL: mustURL(t, server.URL+"/base"),
		Token:   []byte("synthetic-upstream-token"),
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}
	transport, ok := client.httpClient.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil {
		t.Fatal("client transport does not expose TLS configuration")
	}
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.RootCAs = roots
	return client
}
