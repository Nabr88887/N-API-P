package gateway

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestReadBoundedJSONBodyRejectsDeclaredOverflowWithoutReading(t *testing.T) {
	reader := &readTrackingReader{}
	declaredBytes := DefaultJSONRequestBodyLimit + 1

	body, err := ReadBoundedJSONBody(reader, declaredBytes, DefaultJSONRequestBodyLimit)

	if body != nil {
		t.Fatalf("body = %d bytes, want nil", len(body))
	}
	assertRequestTooLargeError(t, err, declaredBytes)
	if reader.reads != 0 {
		t.Fatalf("reads = %d, want 0", reader.reads)
	}
}

func TestReadBoundedJSONBodyAcceptsExactDeclaredLimit(t *testing.T) {
	want := bytes.Repeat([]byte("a"), int(DefaultJSONRequestBodyLimit))

	got, err := ReadBoundedJSONBody(bytes.NewReader(want), int64(len(want)), DefaultJSONRequestBodyLimit)

	if err != nil {
		t.Fatalf("ReadBoundedJSONBody() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("body length = %d, want %d", len(got), len(want))
	}
}

func TestReadBoundedJSONBodyStopsStreamAtFirstOverflowByte(t *testing.T) {
	source := bytes.NewReader(bytes.Repeat([]byte("a"), int(DefaultJSONRequestBodyLimit+32)))

	body, err := ReadBoundedJSONBody(source, -1, DefaultJSONRequestBodyLimit)

	if body != nil {
		t.Fatalf("body = %d bytes, want nil", len(body))
	}
	assertRequestTooLargeError(t, err, DefaultJSONRequestBodyLimit+1)
	consumed := DefaultJSONRequestBodyLimit + 32 - int64(source.Len())
	if consumed != DefaultJSONRequestBodyLimit+1 {
		t.Fatalf("consumed bytes = %d, want %d", consumed, DefaultJSONRequestBodyLimit+1)
	}
}

func TestReadBoundedJSONBodyAcceptsExactStreamedLimit(t *testing.T) {
	want := bytes.Repeat([]byte("a"), int(DefaultJSONRequestBodyLimit))

	got, err := ReadBoundedJSONBody(bytes.NewReader(want), -1, DefaultJSONRequestBodyLimit)

	if err != nil {
		t.Fatalf("ReadBoundedJSONBody() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("body length = %d, want %d", len(got), len(want))
	}
}

func TestReadBoundedJSONBodyPreservesReadError(t *testing.T) {
	readErr := errors.New("synthetic read failure")

	body, err := ReadBoundedJSONBody(errorReader{err: readErr}, -1, DefaultJSONRequestBodyLimit)

	if body != nil {
		t.Fatalf("body = %d bytes, want nil", len(body))
	}
	if !errors.Is(err, readErr) {
		t.Fatalf("error = %v, want cause %v", err, readErr)
	}
}

func TestReadBoundedJSONBodyRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name   string
		reader io.Reader
		limit  int64
		want   error
	}{
		{name: "nil reader", reader: nil, limit: DefaultJSONRequestBodyLimit, want: ErrNilRequestBody},
		{name: "zero limit", reader: bytes.NewReader(nil), limit: 0, want: ErrInvalidRequestBodyLimit},
		{name: "negative limit", reader: bytes.NewReader(nil), limit: -1, want: ErrInvalidRequestBodyLimit},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body, err := ReadBoundedJSONBody(test.reader, -1, test.limit)
			if body != nil {
				t.Fatalf("body = %d bytes, want nil", len(body))
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func assertRequestTooLargeError(t *testing.T, err error, wantObservedBytes int64) {
	t.Helper()
	if !errors.Is(err, ErrRequestTooLarge) {
		t.Fatalf("error = %v, want ErrRequestTooLarge", err)
	}
	var sizeErr *RequestTooLargeError
	if !errors.As(err, &sizeErr) {
		t.Fatalf("error type = %T, want *RequestTooLargeError", err)
	}
	if sizeErr.ObservedBytes != wantObservedBytes {
		t.Fatalf("observed bytes = %d, want %d", sizeErr.ObservedBytes, wantObservedBytes)
	}
	if err.Error() != "request body is too large" {
		t.Fatalf("error text = %q, want stable content-free message", err.Error())
	}
}

type readTrackingReader struct {
	reads int
}

func (reader *readTrackingReader) Read([]byte) (int, error) {
	reader.reads++
	return 0, io.EOF
}

type errorReader struct {
	err error
}

func (reader errorReader) Read([]byte) (int, error) {
	return 0, reader.err
}
