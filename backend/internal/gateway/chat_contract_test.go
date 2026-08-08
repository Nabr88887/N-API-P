package gateway

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"n-api-p/internal/httpapi"
)

func TestDecodeChatCompletionRequestAcceptsConfirmedTextualContract(t *testing.T) {
	request, err := DecodeChatCompletionRequest([]byte(`{
  "model": "gpt-4o",
  "messages": [
    {"role": "system", "content": "You are concise."},
    {"role": "developer", "content": "Use plain text."},
    {"role": "user", "content": "Hello"},
    {"role": "assistant", "content": "Hi"},
    {"role": "tool", "tool_call_id": "call_1", "content": "Tool result"}
  ],
  "stream": true,
  "stream_options": {"include_usage": true},
  "temperature": 0.2,
  "top_p": 0.9,
  "n": 1,
  "stop": ["END", "STOP"],
  "max_tokens": 256,
  "max_completion_tokens": 512,
  "presence_penalty": 0.1,
  "frequency_penalty": 0.2,
  "logit_bias": {"42": -3},
  "seed": 7,
  "response_format": {"type": "text"},
  "user": "employee-1"
}`))
	if err != nil {
		t.Fatalf("DecodeChatCompletionRequest() error = %v", err)
	}
	if request.Model != "gpt-4o" || len(request.Messages) != 5 || request.Messages[1].Role != MessageRoleDeveloper || request.Messages[4].Role != MessageRoleTool {
		t.Fatalf("request identity/roles = %+v", request)
	}
	if !request.Stream || request.StreamOptions == nil || !request.StreamOptions.IncludeUsage {
		t.Fatalf("stream options = %+v", request.StreamOptions)
	}
	if request.Stop.Strings == nil || len(request.Stop.Strings) != 2 || request.Stop.Strings[0] != "END" {
		t.Fatalf("stop = %+v", request.Stop)
	}
	if request.ResponseFormat == nil || request.ResponseFormat.Type != ResponseFormatText || request.User != "employee-1" {
		t.Fatalf("response format/user = %+v/%q", request.ResponseFormat, request.User)
	}
}

func TestDecodeChatCompletionRequestAcceptsTypedToolContract(t *testing.T) {
	body := []byte(`{
  "model":"gpt-4o",
  "messages":[
    {"role":"user","content":"Look this up"},
    {"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"q\":\"status\"}"}}]},
    {"role":"tool","tool_call_id":"call_1","content":"https://internal.example/result"}
  ],
  "tools":[{"type":"function","function":{"name":"lookup","description":"Look up a status","parameters":{"type":"object","properties":{"q":{"type":"string"}},"required":["q"],"additionalProperties":false}}}],
  "tool_choice":"auto"
}`)
	request, err := DecodeChatCompletionRequest(body)
	if err != nil {
		t.Fatalf("DecodeChatCompletionRequest() error = %v", err)
	}
	if len(request.Tools) != 1 || request.Tools[0].Type != "function" || request.Tools[0].Function.Name != "lookup" {
		t.Fatalf("tools = %+v", request.Tools)
	}
	if request.Tools[0].Function.Parameters == nil || request.Tools[0].Function.Parameters["type"] == nil {
		t.Fatalf("parameters = %+v", request.Tools[0].Function.Parameters)
	}
	if request.ToolChoice.Mode != "auto" {
		t.Fatalf("tool choice = %+v", request.ToolChoice)
	}
	if len(request.Messages[1].ToolCalls) != 1 || request.Messages[1].ToolCalls[0].Function.Arguments != `{"q":"status"}` {
		t.Fatalf("assistant tool calls = %+v", request.Messages[1].ToolCalls)
	}
	if request.Messages[2].ToolCallID != "call_1" || request.Messages[2].Content != "https://internal.example/result" {
		t.Fatalf("tool result = %+v", request.Messages[2])
	}
}

func TestDecodeChatCompletionRequestAcceptsAllToolChoices(t *testing.T) {
	for _, choice := range []string{`"none"`, `"auto"`, `"required"`, `{"type":"function","function":{"name":"lookup"}}`} {
		body := `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tool_choice":` + choice + `}`
		request, err := DecodeChatCompletionRequest([]byte(body))
		if err != nil {
			t.Fatalf("choice %s: DecodeChatCompletionRequest() error = %v", choice, err)
		}
		if request.ToolChoice.Mode == "" && (request.ToolChoice.Function == nil || request.ToolChoice.Function.Name != "lookup") {
			t.Fatalf("choice %s decoded as %+v", choice, request.ToolChoice)
		}
	}
}

func TestDecodeChatCompletionRequestRejectsMalformedTypedTools(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "unknown tool field", body: `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","future":true,"function":{"name":"lookup","parameters":{"type":"object"}}}]}`},
		{name: "invalid parameters", body: `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup","parameters":[]}}]}`},
		{name: "invalid choice", body: `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tool_choice":"always"}`},
		{name: "tool call arguments must be string", body: `{"model":"gpt-4o","messages":[{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":{"q":"x"}}}]}]}`},
		{name: "tool result requires call id", body: `{"model":"gpt-4o","messages":[{"role":"tool","content":"result"}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeChatCompletionRequest([]byte(test.body))
			assertContractError(t, err)
		})
	}
}

func TestValidateChatCompletionResponseAcceptsAndRejectsTypedToolCalls(t *testing.T) {
	valid := []byte(`{"id":"chatcmpl-1","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"q\":\"x\"}"}}]},"finish_reason":"tool_calls"}]}`)
	if ok, _ := validateChatCompletionResponse(valid); !ok {
		t.Fatal("valid typed tool response was rejected")
	}
	for _, body := range []string{
		`{"id":"chatcmpl-1","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":{"q":"x"}}}]}}]}`,
		`{"id":"chatcmpl-1","model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"custom","function":{"name":"lookup","arguments":"{}"}}]}}]}`,
	} {
		if ok, _ := validateChatCompletionResponse([]byte(body)); ok {
			t.Fatalf("malformed typed tool response accepted: %s", body)
		}
	}
}

func TestDecodeChatCompletionRequestPreservesLongFormattedMessageText(t *testing.T) {
	content := "  " + strings.Repeat("formatted prompt ", 32) + "\n"
	user := "  " + strings.Repeat("caller", 48) + "  "
	body, err := json.Marshal(struct {
		Model    string        `json:"model"`
		Messages []ChatMessage `json:"messages"`
		User     string        `json:"user"`
	}{
		Model: "gpt-4o",
		Messages: []ChatMessage{
			{Role: MessageRoleUser, Content: content},
		},
		User: user,
	})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	request, err := DecodeChatCompletionRequest(body)
	if err != nil {
		t.Fatalf("DecodeChatCompletionRequest() error = %v", err)
	}
	if request.Messages[0].Content != content {
		t.Fatalf("message content was not preserved")
	}
	if request.User != user {
		t.Fatalf("user = %q, want exact caller value", request.User)
	}
}

func TestDecodeChatCompletionRequestRejectsUnknownFields(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "top-level field", body: `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"metadata":{}}`},
		{name: "message field", body: `{"model":"gpt-4o","messages":[{"role":"user","content":"hi","metadata":"no"}]}`},
		{name: "stream option field", body: `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream_options":{"include_usage":true,"future":true}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeChatCompletionRequest([]byte(test.body))
			assertContractError(t, err)
		})
	}
}

func TestDecodeChatCompletionRequestRejectsInvalidTextualInputs(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "missing model", body: `{"messages":[{"role":"user","content":"hi"}]}`},
		{name: "empty messages", body: `{"model":"gpt-4o","messages":[]}`},
		{name: "unsupported role", body: `{"model":"gpt-4o","messages":[{"role":"unknown","content":"hi"}]}`},
		{name: "non-text content", body: `{"model":"gpt-4o","messages":[{"role":"user","content":{"type":"text","text":"hi"}}]}`},
		{name: "wrong parameter type", body: `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"temperature":"0.2"}`},
		{name: "invalid n", body: `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"n":0}`},
		{name: "null stop array entry", body: `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stop":[null]}`},
		{name: "null logit bias value", body: `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"logit_bias":{"42":null}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := DecodeChatCompletionRequest([]byte(test.body))
			assertContractError(t, err)
		})
	}
}

func TestContractErrorMapsToStableCompatibleEnvelope(t *testing.T) {
	_, err := DecodeChatCompletionRequest([]byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"n":0}`))
	var contractErr *ContractError
	if !errors.As(err, &contractErr) {
		t.Fatalf("error = %v, want *ContractError", err)
	}

	status, envelope := httpapi.ErrorResponse(httpapi.CodeInvalidRequest, &contractErr.Param)
	encoded, marshalErr := json.Marshal(envelope)
	if marshalErr != nil {
		t.Fatalf("json.Marshal() error = %v", marshalErr)
	}
	if status != 400 {
		t.Fatalf("status = %d, want 400", status)
	}
	want := `{"error":{"message":"Invalid request.","type":"invalid_request_error","param":"n","code":"INVALID_REQUEST"}}`
	if string(encoded) != want {
		t.Fatalf("encoded response = %s, want %s", encoded, want)
	}
}

func TestDecodeModelListResponseAcceptsCompatibleEnvelope(t *testing.T) {
	response, err := DecodeModelListResponse([]byte(`{
  "object": "list",
  "data": [
    {"id": "gpt-4o", "object": "model", "created": 1700000000, "owned_by": "openai"}
  ]
}`))
	if err != nil {
		t.Fatalf("DecodeModelListResponse() error = %v", err)
	}
	if response.Object != "list" || len(response.Data) != 1 || response.Data[0].ID != "gpt-4o" || response.Data[0].Object != "model" {
		t.Fatalf("model list = %+v", response)
	}
}

func TestDecodeModelListResponseRejectsMalformedEnvelope(t *testing.T) {
	for _, body := range []string{
		`{"object":"list","data":{}}`,
		`{"object":"not-list","data":[]}`,
		`{"object":"list","data":[{"object":"model","created":1700000000,"owned_by":"openai"}]}`,
		`{"object":"list","data":[{"id":"gpt-4o","object":"model","owned_by":"openai"}]}`,
		`{"object":"list","data":[{"id":"gpt-4o","object":"model","created":"now","owned_by":"openai"}]}`,
		`{"object":"list","data":[{"id":"gpt\n4o","object":"model","created":1700000000,"owned_by":"openai"}]}`,
	} {
		if _, err := DecodeModelListResponse([]byte(body)); !errors.Is(err, ErrInvalidModelListResponse) {
			t.Fatalf("DecodeModelListResponse(%s) error = %v, want ErrInvalidModelListResponse", body, err)
		}
	}
}

func assertContractError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("error = nil, want *ContractError")
	}
	var contractErr *ContractError
	if !errors.As(err, &contractErr) {
		t.Fatalf("error = %v, want *ContractError", err)
	}
}
