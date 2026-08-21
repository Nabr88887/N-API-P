package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"n-api-p/internal/httpapi"
)

const maxModelListResponseBytes = 2 << 20

type ModelListUpstream interface {
	ListModels(context.Context) (*NewAPIResponse, error)
}

type ModelListPolicy interface {
	FilterModelIDs(context.Context, []string) ([]string, error)
}

type modelListEnvelope struct {
	Object string        `json:"object"`
	Data   []modelRecord `json:"data"`
}

type modelRecord struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created,omitempty"`
	OwnedBy string `json:"owned_by"`
}

func NewModelListHandler(upstream ModelListUpstream, policy ModelListPolicy) (http.Handler, error) {
	if upstream == nil || policy == nil {
		return nil, errors.New("model list dependencies are required")
	}
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		response, err := upstream.ListModels(request.Context())
		if err != nil || response == nil || response.Body == nil {
			writeChatError(writer, httpapi.CodeUpstreamError)
			return
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, maxModelListResponseBytes+1))
		if err != nil || len(body) > maxModelListResponseBytes || response.StatusCode < 200 || response.StatusCode >= 300 {
			writeChatError(writer, httpapi.CodeUpstreamError)
			return
		}
		decoder := json.NewDecoder(strings.NewReader(string(body)))
		decoder.DisallowUnknownFields()
		var envelope modelListEnvelope
		if err := decoder.Decode(&envelope); err != nil || envelope.Object != "list" || len(envelope.Data) == 0 && !strings.Contains(string(body), `"data"`) {
			writeChatError(writer, httpapi.CodeUpstreamError)
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); err != io.EOF {
			writeChatError(writer, httpapi.CodeUpstreamError)
			return
		}
		ids := make([]string, 0, len(envelope.Data))
		seen := make(map[string]struct{}, len(envelope.Data))
		for _, model := range envelope.Data {
			if model.ID == "" || model.ID != strings.TrimSpace(model.ID) || model.Object != "model" || model.OwnedBy == "" || model.OwnedBy != strings.TrimSpace(model.OwnedBy) {
				writeChatError(writer, httpapi.CodeUpstreamError)
				return
			}
			if _, exists := seen[model.ID]; exists {
				writeChatError(writer, httpapi.CodeUpstreamError)
				return
			}
			seen[model.ID] = struct{}{}
			ids = append(ids, model.ID)
		}
		allowed, err := policy.FilterModelIDs(request.Context(), ids)
		if err != nil {
			writeChatError(writer, httpapi.CodeInternalError)
			return
		}
		allowedSet := make(map[string]struct{}, len(allowed))
		for _, id := range allowed {
			allowedSet[id] = struct{}{}
		}
		filtered := modelListEnvelope{Object: "list", Data: make([]modelRecord, 0, len(allowed))}
		for _, model := range envelope.Data {
			if _, ok := allowedSet[model.ID]; ok {
				filtered.Data = append(filtered.Data, model)
			}
		}
		encoded, err := json.Marshal(filtered)
		if err != nil {
			writeChatError(writer, httpapi.CodeInternalError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		if response.RequestID != "" {
			writer.Header().Set("X-Request-ID", response.RequestID)
		}
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(encoded)
	}), nil
}
