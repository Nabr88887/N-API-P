package gateway

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"n-api-p/internal/audit"
)

func TestChatProxyHandlerRejectsUnsupportedMediaTypeBeforeReadingOrDispatch(t *testing.T) {
	for _, mediaType := range []string{"", "text/plain", "multipart/form-data; boundary=synthetic"} {
		t.Run(mediaType, func(t *testing.T) {
			upstream := &fakeChatUpstream{}
			capture := &fakeInitialCapture{}
			handler := newTestChatProxyHandler(t, upstream, capture, &fakeResponseFinalizer{}, &fakeUsageRepository{}, nil)
			body := &readSpy{}
			request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			request.Body = io.NopCloser(body)
			request.Header.Set("Content-Type", mediaType)
			request = request.WithContext(WithChatCaller(request.Context(), validTestChatCaller("media-request")))
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, request)

			if recorder.Code != http.StatusUnsupportedMediaType || !strings.Contains(recorder.Body.String(), `"code":"UNSUPPORTED_CONTENT_TYPE"`) {
				t.Fatalf("response = (%d, %s), want 415 unsupported content", recorder.Code, recorder.Body.String())
			}
			if body.read || upstream.calls != 0 || capture.calls != 0 {
				t.Fatalf("read/upstream/capture = %v/%d/%d, want no body read or dispatch", body.read, upstream.calls, capture.calls)
			}
		})
	}
}

func TestChatProxyHandlerRejectsMultimodalJSONBeforeCaptureOrDispatch(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "image", body: `{"model":"gpt-test","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid/image.png"}}]}]}`},
		{name: "audio", body: `{"model":"gpt-test","messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"AAAA","format":"wav"}}]}]}`},
		{name: "file", body: `{"model":"gpt-test","messages":[{"role":"user","content":[{"type":"file","file":{"filename":"a.txt","file_data":"AAAA"}}]}]}`},
		{name: "base64", body: `{"model":"gpt-test","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]}]}`},
		{name: "audio response mode", body: `{"model":"gpt-test","messages":[{"role":"user","content":"hello"}],"modalities":["text","audio"],"audio":{"voice":"alloy","format":"wav"}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream := &fakeChatUpstream{}
			capture := &fakeInitialCapture{}
			handler := newTestChatProxyHandler(t, upstream, capture, &fakeResponseFinalizer{}, &fakeUsageRepository{}, nil)
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, proxyRequest(t, []byte(test.body), "multimodal-request"))

			if recorder.Code != http.StatusUnsupportedMediaType || !strings.Contains(recorder.Body.String(), `"code":"UNSUPPORTED_CONTENT_TYPE"`) {
				t.Fatalf("response = (%d, %s), want 415 unsupported content", recorder.Code, recorder.Body.String())
			}
			if upstream.calls != 0 || capture.calls != 0 {
				t.Fatalf("upstream/capture = %d/%d, want no dispatch or raw capture", upstream.calls, capture.calls)
			}
		})
	}
}

func TestChatProxyHandlerRejectsUnsupportedPathBeforeDispatch(t *testing.T) {
	upstream := &fakeChatUpstream{}
	capture := &fakeInitialCapture{}
	handler := newTestChatProxyHandler(t, upstream, capture, &fakeResponseFinalizer{}, &fakeUsageRepository{}, nil)
	request := proxyRequest(t, []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hello"}]}`), "unsupported-path")
	request.URL.Path = "/v1/responses"
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound || !strings.Contains(recorder.Body.String(), `"code":"UNSUPPORTED_ENDPOINT"`) {
		t.Fatalf("response = (%d, %s), want structured unsupported endpoint", recorder.Code, recorder.Body.String())
	}
	if upstream.calls != 0 || capture.calls != 0 {
		t.Fatalf("upstream/capture = %d/%d, want no dispatch or capture", upstream.calls, capture.calls)
	}
}

func TestDecodeChatCompletionRequestKeepsBase64LikeTextOpaque(t *testing.T) {
	request, err := DecodeChatCompletionRequest([]byte(`{"model":"gpt-test","messages":[{"role":"user","content":"data:image/png;base64,AAAA"},{"role":"tool","tool_call_id":"call_1","content":"file_data=AAAA"}]}`))
	if err != nil {
		t.Fatalf("DecodeChatCompletionRequest() error = %v", err)
	}
	if !bytes.Contains([]byte(request.Messages[0].Content), []byte("base64")) || request.Messages[1].Content != "file_data=AAAA" {
		t.Fatalf("opaque text was not preserved: %+v", request.Messages)
	}
}

func validTestChatCaller(requestID string) ChatCaller {
	return ChatCaller{RequestID: requestID, KeyID: "key-1", OwnerKind: audit.OwnerKindPersonal, IdentityID: "employee-1", TeamID: "team-1", TrafficOwner: TrafficOwner{Kind: TrafficOwnerEmployee, ID: "employee-1"}}
}

type readSpy struct {
	read bool
}

func (reader *readSpy) Read([]byte) (int, error) {
	reader.read = true
	return 0, io.EOF
}
