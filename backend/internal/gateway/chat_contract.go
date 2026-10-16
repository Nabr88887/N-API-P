package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ErrInvalidModelListResponse = errors.New("invalid model list response")

type ContractError struct {
	Param string
}

func (err *ContractError) Error() string {
	return "invalid chat completion request"
}

type MessageRole string

const (
	MessageRoleSystem    MessageRole = "system"
	MessageRoleDeveloper MessageRole = "developer"
	MessageRoleUser      MessageRole = "user"
	MessageRoleAssistant MessageRole = "assistant"
	MessageRoleTool      MessageRole = "tool"
)

type ChatMessage struct {
	Role       MessageRole    `json:"role"`
	Content    string         `json:"content"`
	ToolCallID string         `json:"tool_call_id,omitempty"`
	ToolCalls  []ChatToolCall `json:"tool_calls,omitempty"`
}

func (message *ChatMessage) UnmarshalJSON(data []byte) error {
	var decoded struct {
		Role       MessageRole     `json:"role"`
		Content    json.RawMessage `json:"content"`
		ToolCallID *string         `json:"tool_call_id"`
		ToolCalls  []ChatToolCall  `json:"tool_calls"`
	}
	if err := decodeJSON(data, &decoded, true); err != nil {
		return err
	}
	message.Role = decoded.Role
	message.Content = ""
	message.ToolCalls = decoded.ToolCalls
	if decoded.ToolCallID != nil {
		message.ToolCallID = *decoded.ToolCallID
	}
	contentMissing := len(decoded.Content) == 0 || bytes.Equal(bytes.TrimSpace(decoded.Content), []byte("null"))
	if !contentMissing {
		if err := json.Unmarshal(decoded.Content, &message.Content); err != nil {
			return errors.New("message content must be text")
		}
	} else if message.Role != MessageRoleAssistant || len(message.ToolCalls) == 0 {
		return errors.New("message content must be text")
	}
	return nil
}

type ChatTool struct {
	Type     string                 `json:"type"`
	Function ChatFunctionDefinition `json:"function"`
}

type ChatFunctionDefinition struct {
	Name        string                     `json:"name"`
	Description string                     `json:"description,omitempty"`
	Parameters  map[string]json.RawMessage `json:"parameters"`
}

type ChatToolCall struct {
	ID       string           `json:"id"`
	Type     string           `json:"type"`
	Function ChatFunctionCall `json:"function"`
}

type ChatFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

func (call *ChatFunctionCall) UnmarshalJSON(data []byte) error {
	var decoded struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := decodeJSON(data, &decoded, true); err != nil || len(decoded.Arguments) == 0 || bytes.Equal(bytes.TrimSpace(decoded.Arguments), []byte("null")) {
		return errors.New("invalid function call")
	}
	var arguments string
	if err := json.Unmarshal(decoded.Arguments, &arguments); err != nil {
		return errors.New("tool call arguments must be text")
	}
	*call = ChatFunctionCall{Name: decoded.Name, Arguments: arguments}
	return nil
}

type ToolChoice struct {
	Mode     string              `json:"-"`
	Function *ToolChoiceFunction `json:"-"`
}

type ToolChoiceFunction struct {
	Name string `json:"name"`
}

func (tool *ChatTool) UnmarshalJSON(data []byte) error {
	var decoded struct {
		Type     string                 `json:"type"`
		Function ChatFunctionDefinition `json:"function"`
	}
	if err := decodeJSON(data, &decoded, true); err != nil || decoded.Type != "function" {
		return errors.New("tool type must be function")
	}
	if err := validateFunctionDefinition(decoded.Function); err != nil {
		return err
	}
	*tool = ChatTool{Type: decoded.Type, Function: decoded.Function}
	return nil
}

func (definition *ChatFunctionDefinition) UnmarshalJSON(data []byte) error {
	var decoded struct {
		Name        string                     `json:"name"`
		Description string                     `json:"description"`
		Parameters  map[string]json.RawMessage `json:"parameters"`
	}
	if err := decodeJSON(data, &decoded, true); err != nil {
		return err
	}
	*definition = ChatFunctionDefinition{Name: decoded.Name, Description: decoded.Description, Parameters: decoded.Parameters}
	return nil
}

func (call *ChatToolCall) UnmarshalJSON(data []byte) error {
	var decoded struct {
		ID       string           `json:"id"`
		Type     string           `json:"type"`
		Function ChatFunctionCall `json:"function"`
	}
	if err := decodeJSON(data, &decoded, true); err != nil {
		return err
	}
	if decoded.Type != "function" || !validContractText(decoded.ID, true) || !validContractText(decoded.Function.Name, true) || !validJSONText(decoded.Function.Arguments) {
		return errors.New("invalid tool call")
	}
	*call = ChatToolCall{ID: decoded.ID, Type: decoded.Type, Function: decoded.Function}
	return nil
}

func (choice *ToolChoice) UnmarshalJSON(data []byte) error {
	var mode string
	if json.Unmarshal(data, &mode) == nil {
		if mode != "none" && mode != "auto" && mode != "required" {
			return errors.New("invalid tool choice")
		}
		*choice = ToolChoice{Mode: mode}
		return nil
	}
	var decoded struct {
		Type     string `json:"type"`
		Function struct {
			Name string `json:"name"`
		} `json:"function"`
	}
	if err := decodeJSON(data, &decoded, true); err != nil || decoded.Type != "function" || !validContractText(decoded.Function.Name, true) {
		return errors.New("invalid tool choice")
	}
	*choice = ToolChoice{Function: &ToolChoiceFunction{Name: decoded.Function.Name}}
	return nil
}

func validateFunctionDefinition(definition ChatFunctionDefinition) error {
	if !validContractText(definition.Name, true) || !utf8.ValidString(definition.Description) || definition.Parameters == nil {
		return errors.New("invalid function definition")
	}
	return nil
}

func validJSONText(value string) bool {
	return utf8.ValidString(value)
}

type StreamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

type StopSequence struct {
	String  *string
	Strings []string
}

func (stop *StopSequence) UnmarshalJSON(data []byte) error {
	*stop = StopSequence{}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil
	}
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		stop.String = &single
		return nil
	}
	var encoded []json.RawMessage
	if err := json.Unmarshal(data, &encoded); err != nil || encoded == nil {
		return errors.New("stop must be a string, an array of strings, or null")
	}
	multiple := make([]string, 0, len(encoded))
	for _, entry := range encoded {
		if bytes.Equal(bytes.TrimSpace(entry), []byte("null")) {
			return errors.New("stop array entries must be strings")
		}
		var value string
		if err := json.Unmarshal(entry, &value); err != nil {
			return errors.New("stop array entries must be strings")
		}
		multiple = append(multiple, value)
	}
	stop.Strings = multiple
	return nil
}

func (stop StopSequence) MarshalJSON() ([]byte, error) {
	switch {
	case stop.String != nil && stop.Strings == nil:
		return json.Marshal(*stop.String)
	case stop.String == nil && stop.Strings != nil:
		return json.Marshal(stop.Strings)
	case stop.String == nil:
		return []byte("null"), nil
	default:
		return nil, errors.New("stop contains multiple representations")
	}
}

type ResponseFormatType string

const (
	ResponseFormatText       ResponseFormatType = "text"
	ResponseFormatJSONObject ResponseFormatType = "json_object"
)

type ResponseFormat struct {
	Type ResponseFormatType `json:"type"`
}

type LogitBias map[string]int

func (biases *LogitBias) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		*biases = nil
		return nil
	}

	var encoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &encoded); err != nil || encoded == nil {
		return errors.New("logit_bias must map token IDs to integers")
	}
	decoded := make(LogitBias, len(encoded))
	for tokenID, entry := range encoded {
		if bytes.Equal(bytes.TrimSpace(entry), []byte("null")) {
			return errors.New("logit_bias values must be integers")
		}
		var value int
		if err := json.Unmarshal(entry, &value); err != nil {
			return errors.New("logit_bias values must be integers")
		}
		decoded[tokenID] = value
	}
	*biases = decoded
	return nil
}

type ChatCompletionRequest struct {
	Model               string          `json:"model"`
	Messages            []ChatMessage   `json:"messages"`
	Stream              bool            `json:"stream,omitempty"`
	StreamOptions       *StreamOptions  `json:"stream_options,omitempty"`
	Temperature         *float64        `json:"temperature,omitempty"`
	TopP                *float64        `json:"top_p,omitempty"`
	N                   *int            `json:"n,omitempty"`
	Stop                StopSequence    `json:"stop,omitempty"`
	MaxTokens           *int            `json:"max_tokens,omitempty"`
	MaxCompletionTokens *int            `json:"max_completion_tokens,omitempty"`
	PresencePenalty     *float64        `json:"presence_penalty,omitempty"`
	FrequencyPenalty    *float64        `json:"frequency_penalty,omitempty"`
	LogitBias           LogitBias       `json:"logit_bias,omitempty"`
	Seed                *int64          `json:"seed,omitempty"`
	ResponseFormat      *ResponseFormat `json:"response_format,omitempty"`
	User                string          `json:"user,omitempty"`
	Tools               []ChatTool      `json:"tools,omitempty"`
	ToolChoice          ToolChoice      `json:"tool_choice,omitempty"`
}

func DecodeChatCompletionRequest(data []byte) (ChatCompletionRequest, error) {
	var request ChatCompletionRequest
	if err := decodeJSON(data, &request, true); err != nil {
		return ChatCompletionRequest{}, invalidRequest("")
	}
	if param := request.invalidParam(); param != "" {
		return ChatCompletionRequest{}, invalidRequest(param)
	}
	return request, nil
}

func (request ChatCompletionRequest) invalidParam() string {
	if !validContractText(request.Model, true) {
		return "model"
	}
	if len(request.Messages) == 0 {
		return "messages"
	}
	for index, message := range request.Messages {
		switch message.Role {
		case MessageRoleSystem, MessageRoleDeveloper, MessageRoleUser, MessageRoleAssistant, MessageRoleTool:
		default:
			return fmt.Sprintf("messages[%d].role", index)
		}
		if message.Role == MessageRoleTool {
			if !validContractText(message.ToolCallID, true) || len(message.ToolCalls) != 0 {
				return fmt.Sprintf("messages[%d].tool_call_id", index)
			}
		} else if message.ToolCallID != "" {
			return fmt.Sprintf("messages[%d].tool_call_id", index)
		}
		if message.Role == MessageRoleAssistant {
			if len(message.ToolCalls) == 0 && message.Content == "" {
				return fmt.Sprintf("messages[%d].content", index)
			}
		} else if len(message.ToolCalls) != 0 {
			return fmt.Sprintf("messages[%d].tool_calls", index)
		}
	}
	for index, tool := range request.Tools {
		if err := validateFunctionDefinition(tool.Function); err != nil || tool.Type != "function" {
			return fmt.Sprintf("tools[%d]", index)
		}
	}
	if request.StreamOptions != nil && !request.Stream {
		return "stream_options"
	}
	if request.N != nil && *request.N < 1 {
		return "n"
	}
	if request.MaxTokens != nil && *request.MaxTokens < 1 {
		return "max_tokens"
	}
	if request.MaxCompletionTokens != nil && *request.MaxCompletionTokens < 1 {
		return "max_completion_tokens"
	}
	if request.ResponseFormat != nil && request.ResponseFormat.Type != ResponseFormatText && request.ResponseFormat.Type != ResponseFormatJSONObject {
		return "response_format.type"
	}
	return ""
}

func invalidRequest(param string) error {
	return &ContractError{Param: param}
}

func validContractText(value string, required bool) bool {
	if required && value == "" {
		return false
	}
	if len(value) > 255 || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

type ModelListResponse struct {
	Object string  `json:"object"`
	Data   []Model `json:"data"`
}

type Model struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

func DecodeModelListResponse(data []byte) (ModelListResponse, error) {
	var wire struct {
		Object  string `json:"object"`
		Success *bool  `json:"success,omitempty"`
		Data    []struct {
			ID                     string   `json:"id"`
			Object                 string   `json:"object"`
			Created                *int64   `json:"created"`
			OwnedBy                string   `json:"owned_by"`
			SupportedEndpointTypes []string `json:"supported_endpoint_types,omitempty"`
		} `json:"data"`
	}
	if err := decodeJSON(data, &wire, true); err != nil || wire.Object != "list" || wire.Data == nil || wire.Success != nil && !*wire.Success {
		return ModelListResponse{}, ErrInvalidModelListResponse
	}

	response := ModelListResponse{Object: wire.Object, Data: make([]Model, 0, len(wire.Data))}
	for _, model := range wire.Data {
		if !validContractText(model.ID, true) || model.Object != "model" || model.Created == nil || *model.Created < 0 || !validContractText(model.OwnedBy, true) {
			return ModelListResponse{}, ErrInvalidModelListResponse
		}
		// NewAPI endpoint metadata is validated but never grants gateway capabilities.
		for _, endpointType := range model.SupportedEndpointTypes {
			if !validContractText(endpointType, true) {
				return ModelListResponse{}, ErrInvalidModelListResponse
			}
		}
		response.Data = append(response.Data, Model{
			ID:      model.ID,
			Object:  model.Object,
			Created: *model.Created,
			OwnedBy: model.OwnedBy,
		})
	}
	return response, nil
}

func decodeJSON(data []byte, destination any, rejectUnknown bool) error {
	if !uniqueJSONFields(data) {
		return errors.New("JSON contains duplicate or invalid fields")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if rejectUnknown {
		decoder.DisallowUnknownFields()
	}
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("JSON contains trailing content")
	}
	return nil
}

func uniqueJSONFields(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if !scanUniqueJSONValue(decoder, 0) {
		return false
	}
	_, err := decoder.Token()
	return errors.Is(err, io.EOF)
}

func scanUniqueJSONValue(decoder *json.Decoder, depth int) bool {
	if depth > 128 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, container := token.(json.Delim)
	if !container {
		return true
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return false
			}
			if _, duplicate := seen[key]; duplicate {
				return false
			}
			seen[key] = struct{}{}
			if !scanUniqueJSONValue(decoder, depth+1) {
				return false
			}
		}
		closing, err := decoder.Token()
		return err == nil && closing == json.Delim('}')
	case '[':
		for decoder.More() {
			if !scanUniqueJSONValue(decoder, depth+1) {
				return false
			}
		}
		closing, err := decoder.Token()
		return err == nil && closing == json.Delim(']')
	default:
		return false
	}
}
