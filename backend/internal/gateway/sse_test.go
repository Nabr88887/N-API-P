package gateway

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"n-api-p/internal/usage"
)

func TestReadSSEStreamHandlesSplitUTF8AndReconstructsChoicesAndUsage(t *testing.T) {
	stream := "data: {\"id\":\"chatcmpl-sse\",\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"你\"}}]}\n\n" +
		"data: {\"id\":\"chatcmpl-sse\",\"model\":\"gpt-test\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"好\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":3,\"completion_tokens\":2,\"total_tokens\":5}}\n\n" +
		"data: [DONE]\n\n"
	var forwarded bytes.Buffer
	var chunks []SSEEvent
	result, err := ReadSSEStream(&chunkReader{data: []byte(stream), size: 3}, 4096, func(event SSEEvent) error {
		chunks = append(chunks, event)
		forwarded.Write(event.Raw)
		return nil
	})
	if err != nil {
		t.Fatalf("ReadSSEStream() error = %v", err)
	}
	if forwarded.String() != stream || len(chunks) != 3 || !chunks[2].Done {
		t.Fatalf("forwarded/events = %q/%+v, want exact three events and terminal", forwarded.String(), chunks)
	}
	if result.ID != "chatcmpl-sse" || result.Model != "gpt-test" || len(result.Choices) != 1 || result.Choices[0].Content != "你好" || result.Choices[0].FinishReason != "stop" {
		t.Fatalf("reconstruction = %+v", result)
	}
	if result.Usage == nil || *result.Usage != (usage.TokenUsage{InputTokens: 3, OutputTokens: 2, TotalTokens: 5}) {
		t.Fatalf("usage = %+v", result.Usage)
	}
}

func TestReadSSEStreamPreservesToolCallFragmentsAndMultipleChoices(t *testing.T) {
	stream := `data: {"id":"s","model":"m","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"q\":\"a\""}}]}}]}

data: {"id":"s","model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"type":"function","function":{"arguments":"}"}}]},"finish_reason":"tool_calls"}]}

data: {"id":"s","model":"m","choices":[{"index":1,"delta":{"role":"assistant","content":"second"},"finish_reason":"stop"}]}

data: [DONE]

`
	result, err := ReadSSEStream(strings.NewReader(stream), 4096, nil)
	if err != nil {
		t.Fatalf("ReadSSEStream() error = %v", err)
	}
	if len(result.Choices) != 2 || result.Choices[0].ToolCalls[0].Function.Name != "lookup" || result.Choices[0].ToolCalls[0].Function.Arguments != "{\"q\":\"a\"}" || result.Choices[1].Content != "second" {
		t.Fatalf("choices = %+v", result.Choices)
	}
}

func TestReadSSEStreamOrdersToolCallsByIndex(t *testing.T) {
	stream := `data: {"id":"s","model":"m","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":1,"id":"call_1","type":"function","function":{"name":"second","arguments":"{}"}},{"index":0,"id":"call_0","type":"function","function":{"name":"first","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}

data: [DONE]

`
	result, err := ReadSSEStream(strings.NewReader(stream), 4096, nil)
	if err != nil {
		t.Fatalf("ReadSSEStream() error = %v", err)
	}
	if len(result.Choices) != 1 || len(result.Choices[0].ToolCalls) != 2 || result.Choices[0].ToolCalls[0].Index != 0 || result.Choices[0].ToolCalls[0].ID != "call_0" || result.Choices[0].ToolCalls[1].Index != 1 || result.Choices[0].ToolCalls[1].ID != "call_1" {
		t.Fatalf("tool calls = %+v, want index order", result.Choices[0].ToolCalls)
	}
}

func TestReadSSEStreamRejectsMalformedToolCallWithoutForwardingTerminal(t *testing.T) {
	stream := "data: {\"id\":\"s\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n" + "data: [DONE]\n\n"
	var forwarded bytes.Buffer
	_, err := ReadSSEStream(strings.NewReader(stream), 4096, func(event SSEEvent) error {
		forwarded.Write(event.Raw)
		return nil
	})
	if !errors.Is(err, ErrMalformedSSE) {
		t.Fatalf("error = %v, want ErrMalformedSSE", err)
	}
	if forwarded.Len() != 0 {
		t.Fatalf("forwarded malformed tool event = %q", forwarded.String())
	}
}

func TestReadSSEStreamRejectsDuplicateChoiceIndexWithinEvent(t *testing.T) {
	stream := "data: {\"id\":\"s\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"first\"}},{\"index\":0,\"delta\":{\"content\":\"second\"},\"finish_reason\":\"stop\"}]}\n\n" + "data: [DONE]\n\n"
	var forwarded bytes.Buffer
	_, err := ReadSSEStream(strings.NewReader(stream), 4096, func(event SSEEvent) error {
		forwarded.Write(event.Raw)
		return nil
	})
	if !errors.Is(err, ErrMalformedSSE) || forwarded.Len() != 0 {
		t.Fatalf("error/forwarded = %v/%q, want malformed event rejected before forwarding", err, forwarded.String())
	}
}

func TestReadSSEStreamRejectsDuplicateJSONFieldsBeforeForwarding(t *testing.T) {
	stream := "data: {\"id\":\"s\",\"model\":\"m\",\"choices\":[{\"index\":0,\"index\":1,\"delta\":{\"role\":\"assistant\",\"content\":\"ambiguous\"},\"finish_reason\":\"stop\"}]}\n\n" + "data: [DONE]\n\n"
	var forwarded bytes.Buffer
	_, err := ReadSSEStream(strings.NewReader(stream), 4096, func(event SSEEvent) error {
		forwarded.Write(event.Raw)
		return nil
	})
	if !errors.Is(err, ErrMalformedSSE) || forwarded.Len() != 0 {
		t.Fatalf("error/forwarded = %v/%q, want duplicate JSON field rejected before forwarding", err, forwarded.String())
	}
}

func TestReadSSEStreamRejectsDuplicateToolCallIndexWithinDelta(t *testing.T) {
	stream := `data: {"id":"s","model":"m","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{"}},{"index":0,"function":{"arguments":"}"}}]},"finish_reason":"tool_calls"}]}

data: [DONE]

`
	var forwarded bytes.Buffer
	_, err := ReadSSEStream(strings.NewReader(stream), 4096, func(event SSEEvent) error {
		forwarded.Write(event.Raw)
		return nil
	})
	if !errors.Is(err, ErrMalformedSSE) || forwarded.Len() != 0 {
		t.Fatalf("error/forwarded = %v/%q, want duplicate tool index rejected before forwarding", err, forwarded.String())
	}
}

func TestReadSSEStreamRejectsAmbiguousFinishReasonBeforeForwarding(t *testing.T) {
	for _, test := range []struct {
		name   string
		stream string
	}{
		{
			name:   "unsafe finish reason",
			stream: "data: {\"id\":\"s\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"ok\"},\"finish_reason\":\"stop\\nunsafe\"}]}\n\n" + "data: [DONE]\n\n",
		},
		{
			name:   "repeated finish reason",
			stream: "data: {\"id\":\"s\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\n" + "data: {\"id\":\"s\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n" + "data: [DONE]\n\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			var forwarded bytes.Buffer
			_, err := ReadSSEStream(strings.NewReader(test.stream), 4096, func(event SSEEvent) error {
				forwarded.Write(event.Raw)
				return nil
			})
			if !errors.Is(err, ErrMalformedSSE) {
				t.Fatalf("error = %v, want ErrMalformedSSE", err)
			}
			if test.name == "unsafe finish reason" && forwarded.Len() != 0 {
				t.Fatalf("forwarded unsafe finish event = %q", forwarded.String())
			}
		})
	}
}

func TestReadSSEStreamRejectsInvalidRoleBeforeForwarding(t *testing.T) {
	stream := "data: {\"id\":\"s\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"system\",\"content\":\"unsafe\"},\"finish_reason\":\"stop\"}]}\n\n" + "data: [DONE]\n\n"
	var forwarded bytes.Buffer
	_, err := ReadSSEStream(strings.NewReader(stream), 4096, func(event SSEEvent) error {
		forwarded.Write(event.Raw)
		return nil
	})
	if !errors.Is(err, ErrMalformedSSE) || forwarded.Len() != 0 {
		t.Fatalf("error/forwarded = %v/%q, want invalid role rejected before forwarding", err, forwarded.String())
	}
}

func TestReadSSEStreamRejectsUnsafeToolCallFragmentBeforeForwarding(t *testing.T) {
	first := "data: {\"id\":\"s\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{\"}}]}}]}\n\n"
	stream := first + "data: {\"id\":\"s\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"\\nunsafe\",\"function\":{\"arguments\":\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}\n\n" + "data: [DONE]\n\n"
	var forwarded bytes.Buffer
	_, err := ReadSSEStream(strings.NewReader(stream), 4096, func(event SSEEvent) error {
		forwarded.Write(event.Raw)
		return nil
	})
	if !errors.Is(err, ErrMalformedSSE) || forwarded.String() != first {
		t.Fatalf("error/forwarded = %v/%q, want only validated first event", err, forwarded.String())
	}
}

func TestReadSSEStreamRejectsDuplicateFinalToolCallIDsWithoutForwardingTerminal(t *testing.T) {
	first := `data: {"id":"s","model":"m","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"first","arguments":"{}"}},{"index":1,"id":"call_1","type":"function","function":{"name":"second","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}

`
	stream := first + "data: [DONE]\n\n"
	var forwarded bytes.Buffer
	_, err := ReadSSEStream(strings.NewReader(stream), 4096, func(event SSEEvent) error {
		forwarded.Write(event.Raw)
		return nil
	})
	if !errors.Is(err, ErrMalformedSSE) || forwarded.String() != first {
		t.Fatalf("error/forwarded = %v/%q, want duplicate final IDs rejected before terminal", err, forwarded.String())
	}
}

func TestReadSSEStreamRejectsIncompleteLogicalResponseWithoutForwardingTerminal(t *testing.T) {
	first := "data: {\"id\":\"s\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"partial\"}}]}\n\n"
	stream := first + "data: [DONE]\n\n"
	var forwarded bytes.Buffer
	_, err := ReadSSEStream(strings.NewReader(stream), 4096, func(event SSEEvent) error {
		forwarded.Write(event.Raw)
		return nil
	})
	if !errors.Is(err, ErrMalformedSSE) || forwarded.String() != first {
		t.Fatalf("error/forwarded = %v/%q, want incomplete response rejected before terminal", err, forwarded.String())
	}
}

func TestReadSSEStreamRejectsMalformedDataWithoutForwardingIt(t *testing.T) {
	stream := "data: {\"id\":\"ok\",\"model\":\"m\",\"choices\":[]}\n\n" + "data: {not-json}\n\n"
	var forwarded bytes.Buffer
	_, err := ReadSSEStream(strings.NewReader(stream), 4096, func(event SSEEvent) error { forwarded.Write(event.Raw); return nil })
	if !errors.Is(err, ErrMalformedSSE) || forwarded.String() != "data: {\"id\":\"ok\",\"model\":\"m\",\"choices\":[]}\n\n" {
		t.Fatalf("error/forwarded = %v/%q", err, forwarded.String())
	}
}

func TestReadSSEStreamHonorsLimitAndCancellation(t *testing.T) {
	tooLarge := "data: {\"id\":\"x\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"large\"}}]}\n\n"
	if _, err := ReadSSEStream(strings.NewReader(tooLarge), 5, nil); !errors.Is(err, ErrSSETooLarge) {
		t.Fatalf("limit error = %v, want ErrSSETooLarge", err)
	}
	reader := &blockingReader{data: []byte("data: {\"id\":\"x\",\"model\":\"m\",\"choices\":[]}\n\n")}
	_, err := ReadSSEStream(reader, 4096, func(SSEEvent) error { return io.EOF })
	if !errors.Is(err, io.EOF) {
		t.Fatalf("callback error = %v, want io.EOF", err)
	}
}

func TestReadSSEStreamCapturesBoundedLogicalPrefixOnOverflow(t *testing.T) {
	stream := "data: {\"id\":\"x\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"0123456789\"}}]}\n\n"
	result, err := ReadSSEStream(strings.NewReader(stream), 64, nil)
	if !errors.Is(err, ErrSSETooLarge) || len(result.CaptureJSON) != 64 || result.ObservedBytes != 65 {
		t.Fatalf("result/error = %+v/%v, want bounded prefix and observed 65", result, err)
	}
}

func TestReadSSEStreamRequiresTerminalEvent(t *testing.T) {
	stream := "data: {\"id\":\"x\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\n"
	if _, err := ReadSSEStream(strings.NewReader(stream), 4096, nil); !errors.Is(err, ErrSSETerminal) {
		t.Fatalf("terminal error = %v, want ErrSSETerminal", err)
	}
}

func TestReadSSEStreamReturnsImmediatelyAfterTerminalEvent(t *testing.T) {
	stream := "data: {\"id\":\"x\",\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"ok\"},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n"
	reader := &errorAfterDataReader{data: []byte(stream), err: errors.New("read after terminal")}
	result, err := ReadSSEStream(reader, 4096, nil)
	if err != nil {
		t.Fatalf("ReadSSEStream() error = %v, want terminal success without another read", err)
	}
	if len(result.Choices) != 1 || result.Choices[0].Content != "ok" {
		t.Fatalf("result = %+v, want completed logical response", result)
	}
}

type blockingReader struct{ data []byte }

func (r *blockingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

type errorAfterDataReader struct {
	data []byte
	err  error
}

func (r *errorAfterDataReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

type chunkReader struct {
	data []byte
	size int
}

func (r *chunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := r.size
	if n > len(r.data) {
		n = len(r.data)
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}
