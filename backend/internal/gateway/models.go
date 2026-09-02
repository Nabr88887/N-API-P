package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"n-api-p/internal/httpapi"
)

const maxModelListResponseBytes = 2 << 20

type ModelListUpstream interface {
	ListModels(context.Context) (*NewAPIResponse, error)
}

type ModelListPolicy interface {
	FilterModelIDs(context.Context, []string) ([]string, error)
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
		envelope, err := DecodeModelListResponse(body)
		if err != nil {
			writeChatError(writer, httpapi.CodeUpstreamError)
			return
		}
		ids := make([]string, 0, len(envelope.Data))
		seen := make(map[string]struct{}, len(envelope.Data))
		for _, model := range envelope.Data {
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
		filtered := ModelListResponse{Object: "list", Data: make([]Model, 0, len(allowed))}
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
