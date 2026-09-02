// Command n-api-p-demo-mock serves a local-only HTTPS OpenAI-compatible fake.
// It must never be used as a production or NewAPI integration endpoint.
package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

const demoModel = "demo-model"
const demoModelCreated int64 = 1700000000

type chatRequest struct {
	Model  string `json:"model"`
	Stream bool   `json:"stream"`
}

func main() {
	address := envOr("N_API_P_DEMO_MOCK_LISTEN_ADDRESS", ":8443")
	certFile := os.Getenv("N_API_P_DEMO_MOCK_CERT_FILE")
	keyFile := os.Getenv("N_API_P_DEMO_MOCK_KEY_FILE")
	if certFile == "" || keyFile == "" {
		log.Fatal("demo mock TLS files are required")
	}

	server := &http.Server{Addr: address, Handler: demoHandler()}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatal("load demo mock TLS certificate")
	}
	server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate}}
	log.Printf("demo mock listening on %s", address)
	if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("demo mock stopped")
	}
}

func demoHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/models", func(writer http.ResponseWriter, request *http.Request) {
		if !hasBearerToken(request.Header.Get("Authorization")) {
			writeJSON(writer, http.StatusUnauthorized, map[string]any{"error": map[string]string{"message": "authorization required"}})
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{
			"object": "list",
			"data":   []map[string]any{{"id": demoModel, "object": "model", "created": demoModelCreated, "owned_by": "local-demo"}},
		})
	})
	mux.HandleFunc("POST /v1/chat/completions", func(writer http.ResponseWriter, request *http.Request) {
		if !hasBearerToken(request.Header.Get("Authorization")) {
			writeJSON(writer, http.StatusUnauthorized, map[string]any{"error": map[string]string{"message": "authorization required"}})
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, 2<<20))
		if err != nil {
			writeJSON(writer, http.StatusBadRequest, map[string]any{"error": map[string]string{"message": "invalid demo request"}})
			return
		}
		var input chatRequest
		if err := json.Unmarshal(body, &input); err != nil || input.Model != demoModel {
			writeJSON(writer, http.StatusBadRequest, map[string]any{"error": map[string]string{"message": "demo-model is required"}})
			return
		}
		if input.Stream {
			writeSSE(writer)
			return
		}
		writeJSON(writer, http.StatusOK, map[string]any{
			"id":      "demo-chat-completion",
			"object":  "chat.completion",
			"model":   demoModel,
			"choices": []map[string]any{{"index": 0, "message": map[string]string{"role": "assistant", "content": "Local demo response."}, "finish_reason": "stop"}},
			"usage":   map[string]int{"prompt_tokens": 3, "completion_tokens": 3, "total_tokens": 6},
		})
		_ = body
	})
	return mux
}

func hasBearerToken(value string) bool {
	trimmed := strings.TrimSpace(value)
	return strings.HasPrefix(trimmed, "Bearer ") && len(trimmed) > len("Bearer ")
}

func writeSSE(writer http.ResponseWriter) {
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	flusher, ok := writer.(http.Flusher)
	if !ok {
		writeJSON(writer, http.StatusInternalServerError, map[string]string{"error": "streaming unavailable"})
		return
	}
	for _, chunk := range []string{
		`{"id":"demo-chat-stream","object":"chat.completion.chunk","model":"demo-model","choices":[{"index":0,"delta":{"role":"assistant","content":"Local "},"finish_reason":null}]}`,
		`{"id":"demo-chat-stream","object":"chat.completion.chunk","model":"demo-model","choices":[{"index":0,"delta":{"content":"demo response."},"finish_reason":null}]}`,
		`{"id":"demo-chat-stream","object":"chat.completion.chunk","model":"demo-model","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
	} {
		_, _ = fmt.Fprintf(writer, "data: %s\n\n", chunk)
		flusher.Flush()
	}
	_, _ = io.WriteString(writer, "data: [DONE]\n\n")
	flusher.Flush()
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
