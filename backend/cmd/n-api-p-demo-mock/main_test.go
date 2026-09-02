package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDemoHandlerServesModelsAndRegularChat(t *testing.T) {
	server := httptest.NewServer(demoHandler())
	defer server.Close()

	modelsRequest, err := http.NewRequest(http.MethodGet, server.URL+"/v1/models", nil)
	if err != nil {
		t.Fatal(err)
	}
	modelsRequest.Header.Set("Authorization", "Bearer local-demo")
	models, err := http.DefaultClient.Do(modelsRequest)
	if err != nil || models.StatusCode != http.StatusOK {
		t.Fatalf("models request = (%v, %d)", err, models.StatusCode)
	}
	modelBody, err := io.ReadAll(models.Body)
	if err != nil || !strings.Contains(string(modelBody), `"created":1700000000`) {
		t.Fatalf("models body = %q, want strict model metadata", modelBody)
	}
	_ = models.Body.Close()

	chatRequest, err := http.NewRequest(http.MethodPost, server.URL+"/v1/chat/completions", strings.NewReader(`{"model":"demo-model","messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	chatRequest.Header.Set("Authorization", "Bearer local-demo")
	response, err := http.DefaultClient.Do(chatRequest)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("chat request = (%v, %d)", err, response.StatusCode)
	}
	_ = response.Body.Close()
}

func TestDemoHandlerRejectsUnknownModels(t *testing.T) {
	server := httptest.NewServer(demoHandler())
	defer server.Close()
	request, err := http.NewRequest(http.MethodPost, server.URL+"/v1/chat/completions", strings.NewReader(`{"model":"unknown","messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer local-demo")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusBadRequest)
	}
}

func TestDemoHandlerRequiresBearerAndServesStreamingChat(t *testing.T) {
	server := httptest.NewServer(demoHandler())
	defer server.Close()

	unauthorized, err := http.Get(server.URL + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d, want %d", unauthorized.StatusCode, http.StatusUnauthorized)
	}

	request, err := http.NewRequest(http.MethodPost, server.URL+"/v1/chat/completions", strings.NewReader(`{"model":"demo-model","stream":true,"messages":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer local-demo")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" || !strings.Contains(string(body), "[DONE]") {
		t.Fatalf("stream response = (%d, %q, %q)", response.StatusCode, response.Header.Get("Content-Type"), body)
	}
}
