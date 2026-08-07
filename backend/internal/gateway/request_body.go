package gateway

import (
	"errors"
	"fmt"
	"io"
)

const DefaultJSONRequestBodyLimit int64 = 2 * 1024 * 1024

var (
	ErrRequestTooLarge         = errors.New("request body is too large")
	ErrInvalidRequestBodyLimit = errors.New("request body limit must be positive")
	ErrNilRequestBody          = errors.New("request body reader is nil")
)

type RequestTooLargeError struct {
	ObservedBytes int64
}

func (err *RequestTooLargeError) Error() string {
	return ErrRequestTooLarge.Error()
}

func (err *RequestTooLargeError) Unwrap() error {
	return ErrRequestTooLarge
}

func ReadBoundedJSONBody(reader io.Reader, declaredBytes, limit int64) ([]byte, error) {
	if limit <= 0 {
		return nil, ErrInvalidRequestBodyLimit
	}
	if declaredBytes > limit {
		return nil, &RequestTooLargeError{ObservedBytes: declaredBytes}
	}
	if reader == nil {
		return nil, ErrNilRequestBody
	}

	limited := &io.LimitedReader{R: reader, N: limit}
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read request body: %w", err)
	}
	if int64(len(body)) < limit {
		return body, nil
	}

	var overflowByte [1]byte
	readBytes, err := io.ReadFull(reader, overflowByte[:])
	if readBytes > 0 {
		return nil, &RequestTooLargeError{ObservedBytes: limit + int64(readBytes)}
	}
	if errors.Is(err, io.EOF) {
		return body, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read request body: %w", err)
	}

	return body, nil
}
