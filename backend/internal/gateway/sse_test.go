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
	reader := &blockingReader{data: []byte("data: [DONE]\n\n")}
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

type blockingReader struct{ data []byte }

func (r *blockingReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
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
