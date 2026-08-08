package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

var (
	ErrInvalidNewAPIClient     = errors.New("invalid NewAPI client configuration")
	ErrInvalidNewAPIRequest    = errors.New("invalid NewAPI request")
	ErrUpstreamUnavailable     = errors.New("upstream service unavailable")
	ErrUpstreamTimeout         = errors.New("upstream request timed out")
	ErrInvalidUpstreamResponse = errors.New("invalid upstream response")
)

const (
	defaultConnectTimeout        = 5 * time.Second
	defaultTLSHandshakeTimeout   = 5 * time.Second
	defaultResponseHeaderTimeout = 60 * time.Second
	defaultIdleConnTimeout       = 90 * time.Second
	defaultTotalTimeout          = 10 * time.Minute

	minimumConnectTimeout        = 100 * time.Millisecond
	minimumTLSHandshakeTimeout   = 100 * time.Millisecond
	minimumResponseHeaderTimeout = 1 * time.Second
	minimumIdleConnTimeout       = 1 * time.Second
	minimumTotalTimeout          = 1 * time.Second

	maximumConnectTimeout        = 30 * time.Second
	maximumTLSHandshakeTimeout   = 30 * time.Second
	maximumResponseHeaderTimeout = 5 * time.Minute
	maximumIdleConnTimeout       = 10 * time.Minute
	maximumTotalTimeout          = 30 * time.Minute

	maxUpstreamTokenBytes   = 4096
	maxUpstreamRequestIDLen = 255
	maxUpstreamHeaderBytes  = 64 << 10
)

type NewAPIClientConfig struct {
	BaseURL               *url.URL
	Token                 []byte
	ConnectTimeout        time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	IdleConnTimeout       time.Duration
	TotalTimeout          time.Duration
}

type NewAPIClient struct {
	baseURL      *url.URL
	token        string
	httpClient   *http.Client
	roundTripper http.RoundTripper
}

type NewAPIResponse struct {
	StatusCode  int
	ContentType string
	RequestID   string
	Body        io.ReadCloser
}

func NewClient(config NewAPIClientConfig) (*NewAPIClient, error) {
	baseURL, err := validateClientBaseURL(config.BaseURL)
	if err != nil {
		return nil, err
	}
	token, err := validateClientToken(config.Token)
	if err != nil {
		return nil, err
	}
	timeouts, err := normalizeClientTimeouts(config)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: timeouts.connect}).DialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           100,
		MaxIdleConnsPerHost:    20,
		IdleConnTimeout:        timeouts.idleConn,
		TLSHandshakeTimeout:    timeouts.tlsHandshake,
		ResponseHeaderTimeout:  timeouts.responseHeader,
		ExpectContinueTimeout:  1 * time.Second,
		MaxResponseHeaderBytes: maxUpstreamHeaderBytes,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   timeouts.total,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &NewAPIClient{
		baseURL:      baseURL,
		token:        token,
		httpClient:   httpClient,
		roundTripper: transport,
	}, nil
}

func (client *NewAPIClient) ListModels(ctx context.Context) (*NewAPIResponse, error) {
	return client.do(ctx, http.MethodGet, "v1/models", nil, "application/json")
}

func (client *NewAPIClient) CreateChatCompletion(ctx context.Context, body []byte, stream bool) (*NewAPIResponse, error) {
	if len(body) == 0 {
		return nil, ErrInvalidNewAPIRequest
	}
	expectedResponseType := "application/json"
	if stream {
		expectedResponseType = "text/event-stream"
	}
	return client.do(ctx, http.MethodPost, "v1/chat/completions", bytes.Clone(body), expectedResponseType)
}

func (client *NewAPIClient) do(ctx context.Context, method, path string, body []byte, expectedResponseType string) (*NewAPIResponse, error) {
	if client == nil || client.httpClient == nil || client.baseURL == nil || ctx == nil {
		return nil, ErrInvalidNewAPIRequest
	}
	target := client.baseURL.JoinPath(path)
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), reader)
	if err != nil {
		return nil, ErrInvalidNewAPIRequest
	}
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("Accept", expectedResponseType)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}

	httpClient := *client.httpClient
	httpClient.Transport = client.roundTripper
	response, err := httpClient.Do(request)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if errors.Is(err, context.Canceled) {
			return nil, context.Canceled
		}
		var timeoutError net.Error
		if errors.As(err, &timeoutError) && timeoutError.Timeout() {
			return nil, ErrUpstreamTimeout
		}
		return nil, ErrUpstreamUnavailable
	}
	if response == nil || response.Body == nil {
		return nil, ErrInvalidUpstreamResponse
	}
	if response.StatusCode < 100 || response.StatusCode > 599 {
		return nil, closeInvalidResponse(response)
	}
	if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest {
		return nil, closeInvalidResponse(response)
	}

	contentTypeValues := response.Header.Values("Content-Type")
	contentType, contentTypeOK := "", false
	if len(contentTypeValues) == 1 {
		contentType, contentTypeOK = normalizedMediaType(contentTypeValues[0])
	}
	if response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices && (!contentTypeOK || contentType != expectedResponseType) {
		return nil, closeInvalidResponse(response)
	}

	return &NewAPIResponse{
		StatusCode:  response.StatusCode,
		ContentType: contentType,
		RequestID:   safeUpstreamRequestID(response.Header.Get("X-Request-ID")),
		Body:        response.Body,
	}, nil
}

func validateClientBaseURL(value *url.URL) (*url.URL, error) {
	if value == nil || value.Scheme != "https" || value.Host == "" || value.Hostname() == "" || value.User != nil || value.Fragment != "" || value.RawQuery != "" || value.Opaque != "" || value.RawPath != "" {
		return nil, ErrInvalidNewAPIClient
	}
	copy := *value
	return &copy, nil
}

func validateClientToken(value []byte) (string, error) {
	if len(value) == 0 || len(value) > maxUpstreamTokenBytes {
		return "", ErrInvalidNewAPIClient
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e || unicode.IsControl(rune(character)) {
			return "", ErrInvalidNewAPIClient
		}
	}
	return string(value), nil
}

type clientTimeouts struct {
	connect, tlsHandshake, responseHeader, idleConn, total time.Duration
}

func normalizeClientTimeouts(config NewAPIClientConfig) (clientTimeouts, error) {
	timeouts := clientTimeouts{
		connect:        config.ConnectTimeout,
		tlsHandshake:   config.TLSHandshakeTimeout,
		responseHeader: config.ResponseHeaderTimeout,
		idleConn:       config.IdleConnTimeout,
		total:          config.TotalTimeout,
	}
	if timeouts.connect == 0 {
		timeouts.connect = defaultConnectTimeout
	}
	if timeouts.tlsHandshake == 0 {
		timeouts.tlsHandshake = defaultTLSHandshakeTimeout
	}
	if timeouts.responseHeader == 0 {
		timeouts.responseHeader = defaultResponseHeaderTimeout
	}
	if timeouts.idleConn == 0 {
		timeouts.idleConn = defaultIdleConnTimeout
	}
	if timeouts.total == 0 {
		timeouts.total = defaultTotalTimeout
	}
	if timeouts.connect < minimumConnectTimeout || timeouts.connect > maximumConnectTimeout ||
		timeouts.tlsHandshake < minimumTLSHandshakeTimeout || timeouts.tlsHandshake > maximumTLSHandshakeTimeout ||
		timeouts.responseHeader < minimumResponseHeaderTimeout || timeouts.responseHeader > maximumResponseHeaderTimeout ||
		timeouts.idleConn < minimumIdleConnTimeout || timeouts.idleConn > maximumIdleConnTimeout ||
		timeouts.total < minimumTotalTimeout || timeouts.total > maximumTotalTimeout ||
		timeouts.total < timeouts.responseHeader {
		return clientTimeouts{}, ErrInvalidNewAPIClient
	}
	return timeouts, nil
}

func normalizedMediaType(value string) (string, bool) {
	if strings.TrimSpace(value) == "" {
		return "", false
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return "", false
	}
	return strings.ToLower(mediaType), true
}

func safeUpstreamRequestID(value string) string {
	if len(value) == 0 || len(value) > maxUpstreamRequestIDLen || value != strings.TrimSpace(value) {
		return ""
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return ""
		}
	}
	return value
}

func closeInvalidResponse(response *http.Response) error {
	if err := response.Body.Close(); err != nil {
		return ErrInvalidUpstreamResponse
	}
	return ErrInvalidUpstreamResponse
}
