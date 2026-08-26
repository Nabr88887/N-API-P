package gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestModelListHandlerFiltersValidatedUpstreamModels(t *testing.T) {
	upstream := &fakeModelUpstream{response: &NewAPIResponse{
		StatusCode: http.StatusOK, ContentType: "application/json", RequestID: "upstream-models",
		Body: io.NopCloser(strings.NewReader(`{"success":true,"object":"list","data":[{"id":"gpt-allowed","object":"model","created":1,"owned_by":"internal"},{"id":"gpt-blocked","object":"model","created":2,"owned_by":"internal"}]}`)),
	}}
	handler, err := NewModelListHandler(upstream, &fakeModelFilter{allowed: []string{"gpt-allowed"}})
	if err != nil {
		t.Fatalf("NewModelListHandler() error = %v", err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/models", nil))

	if recorder.Code != http.StatusOK || recorder.Header().Get("X-Request-ID") != "upstream-models" {
		t.Fatalf("status/request ID = %d/%q", recorder.Code, recorder.Header().Get("X-Request-ID"))
	}
	if got := strings.TrimSpace(recorder.Body.String()); got != `{"object":"list","data":[{"id":"gpt-allowed","object":"model","created":1,"owned_by":"internal"}]}` {
		t.Fatalf("body = %s, want filtered compatible list", got)
	}
}

func TestModelListHandlerRejectsInvalidUpstreamData(t *testing.T) {
	for name, body := range map[string]string{
		"malformed":       `{"object":"list","data":[`,
		"wrong envelope":  `{"object":"models","data":[]}`,
		"failed envelope": `{"success":false,"object":"list","data":[]}`,
		"unknown field":   `{"success":true,"object":"list","data":[],"unexpected":true}`,
		"duplicate id":    `{"object":"list","data":[{"id":"gpt-a","object":"model","owned_by":"internal"},{"id":"gpt-a","object":"model","owned_by":"internal"}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			handler, err := NewModelListHandler(&fakeModelUpstream{response: &NewAPIResponse{
				StatusCode: http.StatusOK, ContentType: "application/json", Body: io.NopCloser(strings.NewReader(body)),
			}}, &fakeModelFilter{allowed: []string{"gpt-a"}})
			if err != nil {
				t.Fatal(err)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/models", nil))
			if recorder.Code != http.StatusBadGateway || !strings.Contains(recorder.Body.String(), `"code":"UPSTREAM_ERROR"`) {
				t.Fatalf("response = %d/%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

type fakeModelUpstream struct {
	response *NewAPIResponse
	err      error
}

func (fake *fakeModelUpstream) ListModels(context.Context) (*NewAPIResponse, error) {
	return fake.response, fake.err
}

type fakeModelFilter struct{ allowed []string }

func (fake *fakeModelFilter) FilterModelIDs(_ context.Context, upstream []string) ([]string, error) {
	allowed := make(map[string]struct{}, len(fake.allowed))
	for _, value := range fake.allowed {
		allowed[value] = struct{}{}
	}
	result := make([]string, 0, len(upstream))
	for _, value := range upstream {
		if _, ok := allowed[value]; ok {
			result = append(result, value)
		}
	}
	return result, nil
}
