package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"

	"n-api-p/internal/usage"
)

var (
	ErrMalformedSSE = errors.New("malformed upstream SSE")
	ErrSSETooLarge  = errors.New("upstream SSE is too large")
	ErrSSETerminal  = errors.New("upstream SSE did not terminate")
)

type SSEEvent struct {
	Raw  []byte
	Data []byte
	Done bool
}

type SSELogicalResponse struct {
	ID            string             `json:"id"`
	Object        string             `json:"object"`
	Model         string             `json:"model"`
	Choices       []SSELogicalChoice `json:"choices"`
	Usage         *usage.TokenUsage  `json:"-"`
	CaptureJSON   []byte             `json:"-"`
	ObservedBytes int64              `json:"-"`
}

type SSELogicalChoice struct {
	Index        int                  `json:"index"`
	Role         string               `json:"-"`
	Content      string               `json:"-"`
	FinishReason string               `json:"finish_reason"`
	ToolCalls    []SSELogicalToolCall `json:"-"`
}

type SSELogicalToolCall struct {
	Index    int
	ID       string
	Type     string
	Function SSELogicalFunction
}

type SSELogicalFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type sseWireChunk struct {
	ID      string `json:"id"`
	Model   string `json:"model"`
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Role      string  `json:"role"`
			Content   *string `json:"content"`
			ToolCalls []struct {
				Index    int    `json:"index"`
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int64 `json:"prompt_tokens"`
		CompletionTokens int64 `json:"completion_tokens"`
		TotalTokens      int64 `json:"total_tokens"`
	} `json:"usage"`
}

// ReadSSEStream validates each complete event before forwarding it and builds
// one logical response from the validated Chat Completions deltas.
func ReadSSEStream(reader io.Reader, limit int64, forward func(SSEEvent) error) (logical SSELogicalResponse, resultErr error) {
	if reader == nil || limit <= 0 {
		return SSELogicalResponse{}, ErrMalformedSSE
	}
	logical = SSELogicalResponse{Object: "chat.completion"}
	choices := make(map[int]*SSELogicalChoice)
	refreshChoices := func() {
		indices := make([]int, 0, len(choices))
		for index := range choices {
			indices = append(indices, index)
		}
		sort.Ints(indices)
		logical.Choices = logical.Choices[:0]
		for _, index := range indices {
			choice := *choices[index]
			choice.ToolCalls = append([]SSELogicalToolCall(nil), choice.ToolCalls...)
			sort.Slice(choice.ToolCalls, func(i, j int) bool {
				return choice.ToolCalls[i].Index < choice.ToolCalls[j].Index
			})
			logical.Choices = append(logical.Choices, choice)
		}
	}
	defer refreshChoices()
	seenTerminal := false
	var frame bytes.Buffer
	frameLimit := limit + 64*1024
	if frameLimit < limit || frameLimit < 0 {
		frameLimit = limit
	}
	flush := func() error {
		if frame.Len() == 0 {
			return nil
		}
		raw := bytes.Clone(frame.Bytes())
		data, err := sseFrameData(raw)
		if err != nil {
			return err
		}
		if !utf8.Valid(data) {
			return ErrMalformedSSE
		}
		if bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]")) {
			if seenTerminal {
				return ErrMalformedSSE
			}
			refreshChoices()
			if err := validateSSELogicalResponse(logical); err != nil {
				return err
			}
			seenTerminal = true
			event := SSEEvent{Raw: raw, Data: []byte("[DONE]"), Done: true}
			if forward != nil {
				if err := forward(event); err != nil {
					return err
				}
			}
			frame.Reset()
			return nil
		}
		if seenTerminal {
			return ErrMalformedSSE
		}
		var chunk sseWireChunk
		if !decodeUpstreamJSON(data, &chunk) || chunk.ID == "" || chunk.Model == "" || chunk.Choices == nil {
			return ErrMalformedSSE
		}
		if logical.ID == "" {
			logical.ID, logical.Model = chunk.ID, chunk.Model
		} else if logical.ID != chunk.ID || logical.Model != chunk.Model {
			return ErrMalformedSSE
		}
		seenChoiceIndices := make(map[int]struct{}, len(chunk.Choices))
		for _, delta := range chunk.Choices {
			if delta.Index < 0 {
				return ErrMalformedSSE
			}
			if _, duplicate := seenChoiceIndices[delta.Index]; duplicate {
				return ErrMalformedSSE
			}
			seenChoiceIndices[delta.Index] = struct{}{}
			choice := choices[delta.Index]
			if choice == nil {
				choice = &SSELogicalChoice{Index: delta.Index}
				choices[delta.Index] = choice
			}
			if delta.Delta.Role != "" {
				if delta.Delta.Role != string(MessageRoleAssistant) || choice.Role != "" && choice.Role != delta.Delta.Role {
					return ErrMalformedSSE
				}
				choice.Role = delta.Delta.Role
			}
			if delta.Delta.Content != nil {
				choice.Content += *delta.Delta.Content
			}
			if delta.FinishReason != nil {
				if choice.FinishReason != "" || !safeStreamFact(*delta.FinishReason) {
					return ErrMalformedSSE
				}
				choice.FinishReason = *delta.FinishReason
			}
			seenToolCallIndices := make(map[int]struct{}, len(delta.Delta.ToolCalls))
			for _, tool := range delta.Delta.ToolCalls {
				if tool.Index < 0 {
					return ErrMalformedSSE
				}
				if _, duplicate := seenToolCallIndices[tool.Index]; duplicate {
					return ErrMalformedSSE
				}
				seenToolCallIndices[tool.Index] = struct{}{}
				var target *SSELogicalToolCall
				for i := range choice.ToolCalls {
					if choice.ToolCalls[i].Index == tool.Index {
						target = &choice.ToolCalls[i]
						break
					}
				}
				if target == nil {
					if !safeStreamFact(tool.ID) || tool.Type != "function" || !safeStreamFact(tool.Function.Name) {
						return ErrMalformedSSE
					}
					choice.ToolCalls = append(choice.ToolCalls, SSELogicalToolCall{Index: tool.Index})
					target = &choice.ToolCalls[len(choice.ToolCalls)-1]
				}
				if tool.ID != "" {
					target.ID += tool.ID
				}
				if tool.Type != "" {
					if tool.Type != "function" || (target.Type != "" && target.Type != tool.Type) {
						return ErrMalformedSSE
					}
					target.Type = tool.Type
				}
				target.Function.Name += tool.Function.Name
				target.Function.Arguments += tool.Function.Arguments
				if !safeStreamFact(target.ID) || target.Type != "function" || !safeStreamFact(target.Function.Name) {
					return ErrMalformedSSE
				}
			}
		}
		if chunk.Usage != nil {
			if chunk.Usage.PromptTokens < 0 || chunk.Usage.CompletionTokens < 0 || chunk.Usage.TotalTokens < 0 || chunk.Usage.TotalTokens != chunk.Usage.PromptTokens+chunk.Usage.CompletionTokens {
				return ErrMalformedSSE
			}
			value := usage.TokenUsage{InputTokens: chunk.Usage.PromptTokens, OutputTokens: chunk.Usage.CompletionTokens, TotalTokens: chunk.Usage.TotalTokens}
			logical.Usage = &value
		}
		refreshChoices()
		encoded, err := json.Marshal(logical)
		if err != nil {
			return ErrMalformedSSE
		}
		logical.ObservedBytes = int64(len(encoded))
		if logical.ObservedBytes > limit {
			logical.ObservedBytes = limit + 1
			logical.CaptureJSON = bytes.Clone(encoded[:limit])
			return ErrSSETooLarge
		}
		logical.CaptureJSON = bytes.Clone(encoded)
		event := SSEEvent{Raw: raw, Data: bytes.Clone(data)}
		if forward != nil {
			if err := forward(event); err != nil {
				return err
			}
		}
		frame.Reset()
		return nil
	}
	buf := bufio.NewReader(reader)
	for {
		line, err := buf.ReadSlice('\n')
		if len(line) > 0 {
			frame.Write(line)
			if int64(frame.Len()) > frameLimit {
				return logical, ErrSSETooLarge
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if len(line) > 0 && bytes.Equal(bytes.TrimRight(line, "\r\n"), nil) {
			if err := flush(); err != nil {
				return logical, err
			}
			if seenTerminal {
				return logical, nil
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return logical, fmt.Errorf("read SSE: %w", err)
			}
			if frame.Len() > 0 {
				if err := flush(); err != nil {
					return logical, err
				}
				if seenTerminal {
					return logical, nil
				}
			}
			break
		}
	}
	return logical, ErrSSETerminal
}

func validateSSELogicalResponse(logical SSELogicalResponse) error {
	if logical.ID == "" || logical.Model == "" || len(logical.Choices) == 0 {
		return ErrMalformedSSE
	}
	for _, choice := range logical.Choices {
		if choice.Role != "assistant" || !safeStreamFact(choice.FinishReason) {
			return ErrMalformedSSE
		}
		seenToolCallIDs := make(map[string]struct{}, len(choice.ToolCalls))
		for _, tool := range choice.ToolCalls {
			if !safeStreamFact(tool.ID) || tool.Type != "function" || !safeStreamFact(tool.Function.Name) || !utf8.ValidString(tool.Function.Arguments) {
				return ErrMalformedSSE
			}
			if _, duplicate := seenToolCallIDs[tool.ID]; duplicate {
				return ErrMalformedSSE
			}
			seenToolCallIDs[tool.ID] = struct{}{}
		}
	}
	return nil
}

func safeStreamFact(value string) bool {
	if value == "" || len(value) > 255 {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func (response SSELogicalResponse) MarshalJSON() ([]byte, error) {
	type wireToolCall struct {
		ID       string             `json:"id,omitempty"`
		Type     string             `json:"type,omitempty"`
		Function SSELogicalFunction `json:"function"`
	}
	type wireMessage struct {
		Role      string         `json:"role,omitempty"`
		Content   string         `json:"content"`
		ToolCalls []wireToolCall `json:"tool_calls,omitempty"`
	}
	type wireChoice struct {
		Index        int         `json:"index"`
		Message      wireMessage `json:"message"`
		FinishReason string      `json:"finish_reason"`
	}
	type wireUsage struct {
		PromptTokens     int64 `json:"prompt_tokens"`
		CompletionTokens int64 `json:"completion_tokens"`
		TotalTokens      int64 `json:"total_tokens"`
	}
	wire := struct {
		ID      string       `json:"id"`
		Object  string       `json:"object"`
		Model   string       `json:"model"`
		Choices []wireChoice `json:"choices"`
		Usage   *wireUsage   `json:"usage,omitempty"`
	}{ID: response.ID, Object: response.Object, Model: response.Model, Choices: make([]wireChoice, 0, len(response.Choices))}
	for _, choice := range response.Choices {
		message := wireMessage{Role: choice.Role, Content: choice.Content}
		for _, tool := range choice.ToolCalls {
			message.ToolCalls = append(message.ToolCalls, wireToolCall{ID: tool.ID, Type: tool.Type, Function: tool.Function})
		}
		wire.Choices = append(wire.Choices, wireChoice{Index: choice.Index, Message: message, FinishReason: choice.FinishReason})
	}
	if response.Usage != nil {
		wire.Usage = &wireUsage{PromptTokens: response.Usage.InputTokens, CompletionTokens: response.Usage.OutputTokens, TotalTokens: response.Usage.TotalTokens}
	}
	return json.Marshal(wire)
}

func sseFrameData(raw []byte) ([]byte, error) {
	lines := bytes.Split(raw, []byte{'\n'})
	var data []string
	for _, line := range lines {
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if len(line) == 0 || line[0] == ':' {
			continue
		}
		if !bytes.HasPrefix(line, []byte("data:")) {
			return nil, ErrMalformedSSE
		}
		value := strings.TrimPrefix(string(line), "data:")
		if strings.HasPrefix(value, " ") {
			value = value[1:]
		}
		data = append(data, value)
	}
	if len(data) == 0 {
		return nil, ErrMalformedSSE
	}
	return []byte(strings.Join(data, "\n")), nil
}
