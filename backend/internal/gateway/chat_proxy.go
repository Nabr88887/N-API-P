package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"n-api-p/internal/audit"
	"n-api-p/internal/httpapi"
	"n-api-p/internal/observability"
	"n-api-p/internal/policy"
	"n-api-p/internal/usage"
)

var (
	ErrInvalidChatProxy       = errors.New("invalid chat proxy configuration")
	ErrUsagePersistenceFailed = errors.New("usage persistence failed")
)

type ChatUpstream interface {
	CreateChatCompletion(context.Context, []byte, bool) (*NewAPIResponse, error)
}

type InitialCapture interface {
	CaptureValidatedRequest(context.Context, audit.InitialCaptureInput) (audit.CaptureReceipt, error)
}

type PostDispatchFailureMarker interface {
	MarkPostDispatchFailure(context.Context, string, string, string, time.Time) error
}

type ModelPolicy interface {
	Authorize(context.Context, string) error
}

type ChatCaller struct {
	RequestID             string
	KeyID                 string
	OwnerKind             audit.OwnerKind
	IdentityID            string
	ServiceAccountID      string
	ResponsibleIdentityID string
	TeamID                string
	TrafficOwner          TrafficOwner
	Price                 *usage.PriceSnapshot
}

type chatCallerContextKey struct{}

func WithChatCaller(ctx context.Context, caller ChatCaller) context.Context {
	return context.WithValue(ctx, chatCallerContextKey{}, caller)
}

func chatCallerFromContext(ctx context.Context) (ChatCaller, bool) {
	if ctx == nil {
		return ChatCaller{}, false
	}
	caller, ok := ctx.Value(chatCallerContextKey{}).(ChatCaller)
	return caller, ok
}

type ChatProxyConfig struct {
	Upstream        ChatUpstream
	Capture         InitialCapture
	Finalizer       ResponseFinalizer
	Usage           usage.Repository
	Policy          ModelPolicy
	Limiter         Limiter
	Now             func() time.Time
	NewID           func() (string, error)
	Retention       time.Duration
	RetentionReader func(context.Context) (time.Duration, error)
	PriceReader     func(context.Context, string) (*usage.PriceSnapshot, error)
	ResponseLimit   int64
	Metrics         *observability.Metrics
	Rejections      RejectionRecorder
}

type ChatProxyHandler struct {
	upstream        ChatUpstream
	capture         InitialCapture
	finalizer       ResponseFinalizer
	usage           usage.Repository
	policy          ModelPolicy
	limiter         Limiter
	now             func() time.Time
	newID           func() (string, error)
	retention       time.Duration
	retentionReader func(context.Context) (time.Duration, error)
	priceReader     func(context.Context, string) (*usage.PriceSnapshot, error)
	responseLimit   int64
	metrics         *observability.Metrics
	rejections      RejectionRecorder
}

func NewChatProxyHandler(config ChatProxyConfig) (*ChatProxyHandler, error) {
	if config.Upstream == nil || config.Capture == nil || config.Finalizer == nil || config.Usage == nil || config.Policy == nil || config.Limiter == nil {
		return nil, ErrInvalidChatProxy
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	newID := config.NewID
	if newID == nil {
		newID = newChatRequestID
	}
	retention := config.Retention
	if retention == 0 {
		retention = 7 * 24 * time.Hour
	}
	if retention < 24*time.Hour || retention > 30*24*time.Hour || config.ResponseLimit < 0 {
		return nil, ErrInvalidChatProxy
	}
	retentionReader := config.RetentionReader
	if retentionReader == nil {
		retentionReader = func(context.Context) (time.Duration, error) { return retention, nil }
	}
	responseLimit := config.ResponseLimit
	if responseLimit == 0 {
		responseLimit = DefaultLogicalResponseLimit
	}
	if responseLimit <= 0 {
		return nil, ErrInvalidChatProxy
	}
	return &ChatProxyHandler{
		upstream: config.Upstream, capture: config.Capture, finalizer: config.Finalizer,
		usage: config.Usage, policy: config.Policy, limiter: config.Limiter, now: now,
		newID: newID, retention: retention, retentionReader: retentionReader, priceReader: config.PriceReader, responseLimit: responseLimit,
		metrics: config.Metrics, rejections: config.Rejections,
	}, nil
}

func (handler *ChatProxyHandler) currentRetention(ctx context.Context) (time.Duration, error) {
	if handler == nil || handler.retentionReader == nil {
		return 0, ErrInvalidChatProxy
	}
	retention, err := handler.retentionReader(ctx)
	if err != nil || retention < 24*time.Hour || retention > 30*24*time.Hour {
		return 0, ErrInvalidChatProxy
	}
	return retention, nil
}

func (handler *ChatProxyHandler) SetMetrics(metrics *observability.Metrics) {
	if handler != nil {
		handler.metrics = metrics
	}
}

func (handler *ChatProxyHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler == nil || request == nil || writer == nil {
		return
	}
	if request.URL == nil || request.URL.Path != "/v1/chat/completions" || request.Method != http.MethodPost {
		writeChatError(writer, httpapi.CodeUnsupportedEndpoint)
		return
	}
	caller, ok := chatCallerFromContext(request.Context())
	if !ok {
		handler.recordRejection(request, RejectionAuthentication, RejectionCodeInvalidAPIKey, nil, "", 0)
		writeChatError(writer, httpapi.CodeInvalidAPIKey)
		return
	}
	if requestID, ok := observability.RequestIDFromContext(request.Context()); ok {
		caller.RequestID = requestID
	}
	if !validChatCaller(caller) {
		handler.recordRejection(request, RejectionAuthentication, RejectionCodeInvalidAPIKey, nil, "", 0)
		writeChatError(writer, httpapi.CodeInvalidAPIKey)
		return
	}
	if !hasJSONMediaType(request) {
		writeChatError(writer, httpapi.CodeUnsupportedContentType)
		return
	}
	body, err := ReadBoundedJSONBody(request.Body, request.ContentLength, DefaultJSONRequestBodyLimit)
	if err != nil {
		if errors.Is(err, ErrRequestTooLarge) {
			handler.recordRejection(request, RejectionRequestSize, RejectionCodeRequestTooLarge, &caller, "", requestObservedBytes(request, DefaultJSONRequestBodyLimit))
			writeChatError(writer, httpapi.CodeRequestTooLarge)
			return
		}
		writeChatError(writer, httpapi.CodeInvalidRequest)
		return
	}
	if hasUnsupportedChatContent(body) {
		writeChatError(writer, httpapi.CodeUnsupportedContentType)
		return
	}
	chatRequest, err := DecodeChatCompletionRequest(body)
	if err != nil {
		var contractErr *ContractError
		if errors.As(err, &contractErr) {
			status, envelope := httpapi.ErrorResponse(httpapi.CodeInvalidRequest, &contractErr.Param)
			writeChatEnvelope(writer, status, envelope)
			return
		}
		writeChatError(writer, httpapi.CodeInvalidRequest)
		return
	}
	if err := handler.policy.Authorize(request.Context(), chatRequest.Model); err != nil {
		switch {
		case errors.Is(err, policy.ErrModelNotAllowed):
			handler.recordRejection(request, RejectionModelPolicy, RejectionCodeModelNotAllowed, &caller, "", 0)
			writeChatError(writer, httpapi.CodeModelNotAllowed)
		case errors.Is(err, policy.ErrInvalidModelID):
			writeChatError(writer, httpapi.CodeInvalidRequest)
		default:
			writeChatError(writer, httpapi.CodeInternalError)
		}
		return
	}
	if handler.priceReader != nil {
		price, priceErr := handler.priceReader(request.Context(), chatRequest.Model)
		if priceErr != nil {
			writeChatError(writer, httpapi.CodeInternalError)
			return
		}
		if price != nil {
			priceCopy := *price
			caller.Price = &priceCopy
		}
	}
	reservation, err := handler.limiter.Acquire(request.Context(), caller.TrafficOwner)
	if err != nil {
		var rateErr *RateLimitError
		if errors.As(err, &rateErr) {
			handler.recordRejection(request, RejectionTrafficLimit, RejectionCodeRateLimited, &caller, rateErr.Rule, 0)
			writer.Header().Set("Retry-After", retryAfterHeader(rateErr.RetryAfter))
			writeChatError(writer, httpapi.CodeRateLimited)
			return
		}
		writeChatError(writer, httpapi.CodeInternalError)
		return
	}
	defer reservation.Release()
	if chatRequest.Stream {
		handler.serveStreaming(writer, request, caller, body, chatRequest)
		return
	}

	createdAt := handler.now().UTC()
	retention, err := handler.currentRetention(request.Context())
	if err != nil {
		writeChatError(writer, httpapi.CodeAuditUnavailable)
		return
	}
	auditID, err := handler.newID()
	if err != nil {
		writeChatError(writer, httpapi.CodeInternalError)
		return
	}
	captureReceipt, err := handler.capture.CaptureValidatedRequest(request.Context(), audit.InitialCaptureInput{
		ID: auditID, RequestID: caller.RequestID, KeyID: caller.KeyID, OwnerKind: caller.OwnerKind,
		IdentityID: caller.IdentityID, ServiceAccountID: caller.ServiceAccountID,
		ResponsibleIdentityID: caller.ResponsibleIdentityID, TeamID: caller.TeamID, ModelID: chatRequest.Model,
		ValidatedRequestJSON: body, CreatedAt: createdAt, ExpiresAt: createdAt.Add(retention),
	})
	if err != nil {
		writeChatError(writer, httpapi.CodeAuditUnavailable)
		return
	}
	if captureReceipt.AuditID == "" || captureReceipt.AuditID != auditID || captureReceipt.RequestID != caller.RequestID {
		writeChatError(writer, httpapi.CodeAuditUnavailable)
		return
	}
	upstreamResponse, err := handler.upstream.CreateChatCompletion(request.Context(), body, false)
	if err != nil {
		if finalErr := handler.finalizeTransportFailure(request.Context(), caller, captureReceipt, chatRequest.Model, createdAt, err); finalErr != nil {
			writeChatError(writer, httpapi.CodeAuditUnavailable)
			return
		}
		writeChatError(writer, upstreamErrorCode(err))
		return
	}
	if upstreamResponse == nil || upstreamResponse.Body == nil {
		if finalErr := handler.finalizeLocalFailure(request.Context(), caller, captureReceipt, chatRequest.Model, createdAt, "UPSTREAM_ERROR"); finalErr != nil {
			writeChatError(writer, httpapi.CodeAuditUnavailable)
			return
		}
		writeChatError(writer, httpapi.CodeUpstreamError)
		return
	}
	defer upstreamResponse.Body.Close()
	bounded, readErr := ReadBoundedLogicalResponse(upstreamResponse.Body, handler.responseLimit)
	if readErr != nil {
		if errors.Is(readErr, ErrUpstreamResponseTooLarge) {
			finalErr := handler.finalize(request.Context(), caller, captureReceipt, chatRequest.Model, createdAt, bounded.Content(), bounded.ObservedBytes(), upstreamResponse, audit.CaptureStatusTruncated, audit.AuditOutcomeLocalError, "UPSTREAM_RESPONSE_TOO_LARGE", nil)
			if finalErr != nil {
				writeChatError(writer, httpapi.CodeAuditUnavailable)
				return
			}
			writeChatError(writer, httpapi.CodeUpstreamResponseTooLarge)
			return
		}
		if finalErr := handler.finalizeLocalFailure(request.Context(), caller, captureReceipt, chatRequest.Model, createdAt, "UPSTREAM_UNAVAILABLE"); finalErr != nil {
			writeChatError(writer, httpapi.CodeAuditUnavailable)
			return
		}
		writeChatError(writer, httpapi.CodeUpstreamUnavailable)
		return
	}

	responseBody := bounded.Content()
	status := upstreamResponse.StatusCode
	outcome := audit.AuditOutcomeSuccess
	responseErrorCode := ""
	responseInvalid := false
	var tokenUsage *usage.TokenUsage
	valid := false
	if status >= 200 && status < 300 {
		valid, tokenUsage = validateChatCompletionResponse(responseBody)
		if !valid {
			outcome = audit.AuditOutcomeUpstreamError
			responseErrorCode = string(httpapi.CodeUpstreamError)
			responseInvalid = true
		}
	} else if status >= 400 && status <= 599 {
		var upstreamCode string
		valid, upstreamCode = validateUpstreamErrorResponse(responseBody)
		outcome = audit.AuditOutcomeUpstreamError
		if !valid {
			responseBody = nil
			responseErrorCode = string(httpapi.CodeUpstreamError)
			responseInvalid = true
		} else {
			responseErrorCode = upstreamCode
		}
	} else {
		responseErrorCode = string(httpapi.CodeUpstreamError)
		outcome = audit.AuditOutcomeUpstreamError
		responseInvalid = true
	}
	if responseInvalid && len(responseBody) == 0 {
		captureStatus := audit.CaptureStatusComplete
		finalOutcome := outcome
		if len(bounded.Content()) == 0 {
			captureStatus = audit.CaptureStatusIncomplete
			finalOutcome = audit.AuditOutcomeLocalError
		}
		finalErr := handler.finalize(request.Context(), caller, captureReceipt, chatRequest.Model, createdAt, bounded.Content(), bounded.ObservedBytes(), upstreamResponse, captureStatus, finalOutcome, responseErrorCode, nil)
		if finalErr != nil {
			writeChatError(writer, httpapi.CodeAuditUnavailable)
			return
		}
		writeChatError(writer, httpapi.CodeUpstreamError)
		return
	}
	finalErr := handler.finalize(request.Context(), caller, captureReceipt, chatRequest.Model, createdAt, bounded.Content(), bounded.ObservedBytes(), upstreamResponse, audit.CaptureStatusComplete, outcome, responseErrorCode, tokenUsage)
	if finalErr != nil {
		writeChatError(writer, httpapi.CodeAuditUnavailable)
		return
	}
	if responseInvalid {
		writeChatError(writer, httpapi.CodeUpstreamError)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	setRequestIDHeader(writer, request, upstreamResponse.RequestID)
	writer.WriteHeader(upstreamResponse.StatusCode)
	_, _ = writer.Write(responseBody)
}

func (handler *ChatProxyHandler) serveStreaming(writer http.ResponseWriter, request *http.Request, caller ChatCaller, body []byte, chatRequest ChatCompletionRequest) {
	streamContext, cancel := context.WithCancel(request.Context())
	defer cancel()
	createdAt := handler.now().UTC()
	retention, err := handler.currentRetention(streamContext)
	if err != nil {
		writeChatError(writer, httpapi.CodeAuditUnavailable)
		return
	}
	auditID, err := handler.newID()
	if err != nil {
		writeChatError(writer, httpapi.CodeInternalError)
		return
	}
	receipt, err := handler.capture.CaptureValidatedRequest(streamContext, audit.InitialCaptureInput{
		ID: auditID, RequestID: caller.RequestID, KeyID: caller.KeyID, OwnerKind: caller.OwnerKind,
		IdentityID: caller.IdentityID, ServiceAccountID: caller.ServiceAccountID, ResponsibleIdentityID: caller.ResponsibleIdentityID,
		TeamID: caller.TeamID, ModelID: chatRequest.Model, ValidatedRequestJSON: body, CreatedAt: createdAt, ExpiresAt: createdAt.Add(retention),
	})
	if err != nil || receipt.AuditID != auditID || receipt.RequestID != caller.RequestID {
		writeChatError(writer, httpapi.CodeAuditUnavailable)
		return
	}
	upstreamResponse, err := handler.upstream.CreateChatCompletion(streamContext, body, true)
	if err != nil {
		if finalErr := handler.finalizeStreamFailure(caller, receipt, chatRequest.Model, createdAt, nil, 0, nil, audit.AuditOutcomeLocalError, string(upstreamErrorCode(err))); finalErr != nil {
			writeChatError(writer, httpapi.CodeAuditUnavailable)
			return
		}
		writeChatError(writer, upstreamErrorCode(err))
		return
	}
	if upstreamResponse == nil || upstreamResponse.Body == nil || upstreamResponse.StatusCode < 200 || upstreamResponse.StatusCode >= 300 {
		if upstreamResponse != nil && upstreamResponse.Body != nil {
			defer upstreamResponse.Body.Close()
			bounded, readErr := ReadBoundedLogicalResponse(upstreamResponse.Body, handler.responseLimit)
			if readErr == nil {
				if valid, code := validateUpstreamErrorResponse(bounded.Content()); valid {
					if finalErr := handler.finalizeStream(caller, receipt, chatRequest.Model, createdAt, bounded.Content(), bounded.ObservedBytes(), upstreamResponse, audit.CaptureStatusComplete, audit.AuditOutcomeUpstreamError, code, nil, ""); finalErr != nil {
						writeChatError(writer, httpapi.CodeAuditUnavailable)
						return
					}
					writer.Header().Set("Content-Type", "application/json")
					setRequestIDHeader(writer, request, upstreamResponse.RequestID)
					writer.WriteHeader(upstreamResponse.StatusCode)
					_, _ = writer.Write(bounded.Content())
					return
				}
			}
		}
		if finalErr := handler.finalizeStreamFailure(caller, receipt, chatRequest.Model, createdAt, nil, 0, upstreamResponse, audit.AuditOutcomeLocalError, string(httpapi.CodeUpstreamError)); finalErr != nil {
			writeChatError(writer, httpapi.CodeAuditUnavailable)
			return
		}
		writeChatError(writer, httpapi.CodeUpstreamError)
		return
	}
	defer upstreamResponse.Body.Close()
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Add("Trailer", "X-N-API-P-Audit-Error")
	setRequestIDHeader(writer, request, upstreamResponse.RequestID)
	flusher, _ := writer.(http.Flusher)
	started := false
	logical, parseErr := ReadSSEStream(upstreamResponse.Body, handler.responseLimit, func(event SSEEvent) error {
		if _, err := writer.Write(event.Raw); err != nil {
			cancel()
			return err
		}
		started = true
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	})
	logicalBody := logical.CaptureJSON
	if parseErr != nil {
		status := audit.CaptureStatusIncomplete
		outcome := audit.AuditOutcomeLocalError
		code := string(httpapi.CodeUpstreamError)
		if errors.Is(parseErr, ErrSSETooLarge) {
			status, code = audit.CaptureStatusTruncated, string(httpapi.CodeUpstreamResponseTooLarge)
		}
		if errors.Is(parseErr, context.Canceled) || errors.Is(parseErr, io.ErrClosedPipe) {
			outcome, code = audit.AuditOutcomeCancelled, "CLIENT_DISCONNECTED"
		}
		finalErr := handler.finalizeStream(caller, receipt, chatRequest.Model, createdAt, logicalBody, logical.ObservedBytes, upstreamResponse, status, outcome, code, logical.Usage, primaryFinishReason(logical))
		if !started {
			if finalErr != nil {
				writeChatError(writer, httpapi.CodeAuditUnavailable)
				return
			}
			if errors.Is(parseErr, ErrSSETooLarge) {
				writeChatError(writer, httpapi.CodeUpstreamResponseTooLarge)
			} else {
				writeChatError(writer, httpapi.CodeUpstreamError)
			}
		} else if finalErr != nil {
			writer.Header().Set("X-N-API-P-Audit-Error", string(httpapi.CodeAuditUnavailable))
		}
		return
	}
	if finalErr := handler.finalizeStream(caller, receipt, chatRequest.Model, createdAt, logicalBody, logical.ObservedBytes, upstreamResponse, audit.CaptureStatusComplete, audit.AuditOutcomeSuccess, "", logical.Usage, primaryFinishReason(logical)); finalErr != nil {
		if started {
			writer.Header().Set("X-N-API-P-Audit-Error", string(httpapi.CodeAuditUnavailable))
			return
		}
		writeChatError(writer, httpapi.CodeAuditUnavailable)
	}
}

func (handler *ChatProxyHandler) finalizeStreamFailure(caller ChatCaller, receipt audit.CaptureReceipt, model string, createdAt time.Time, body []byte, observed int64, response *NewAPIResponse, outcome audit.AuditOutcome, code string) error {
	return handler.finalizeStream(caller, receipt, model, createdAt, body, observed, response, audit.CaptureStatusIncomplete, outcome, code, nil, "")
}

func (handler *ChatProxyHandler) finalizeStream(caller ChatCaller, receipt audit.CaptureReceipt, model string, createdAt time.Time, body []byte, observed int64, response *NewAPIResponse, status audit.CaptureStatus, outcome audit.AuditOutcome, code string, tokenUsage *usage.TokenUsage, finishReason string) error {
	return handler.finalizerAndUsageWithFinish(context.Background(), caller, receipt, model, createdAt, body, observed, status, outcome, code, responseID(response), responseStatus(response), tokenUsage, finishReason)
}

func primaryFinishReason(logical SSELogicalResponse) string {
	if len(logical.Choices) == 0 {
		return ""
	}
	return logical.Choices[0].FinishReason
}

func responseID(response *NewAPIResponse) string {
	if response == nil {
		return ""
	}
	return response.RequestID
}
func responseStatus(response *NewAPIResponse) *int {
	if response == nil {
		return nil
	}
	status := response.StatusCode
	return &status
}

func (handler *ChatProxyHandler) finalizeTransportFailure(ctx context.Context, caller ChatCaller, receipt audit.CaptureReceipt, model string, createdAt time.Time, err error) error {
	if errors.Is(err, context.Canceled) {
		return handler.finalizeLocalFailureWithCode(ctx, caller, receipt, model, createdAt, "CLIENT_DISCONNECTED", audit.AuditOutcomeCancelled)
	}
	code := string(upstreamErrorCode(err))
	if code == string(httpapi.CodeUpstreamError) {
		code = string(httpapi.CodeUpstreamUnavailable)
	}
	return handler.finalizeLocalFailureWithCode(ctx, caller, receipt, model, createdAt, code, audit.AuditOutcomeLocalError)
}

func (handler *ChatProxyHandler) finalizeLocalFailure(ctx context.Context, caller ChatCaller, receipt audit.CaptureReceipt, model string, createdAt time.Time, code string) error {
	return handler.finalizeLocalFailureWithCode(ctx, caller, receipt, model, createdAt, code, audit.AuditOutcomeLocalError)
}

func (handler *ChatProxyHandler) finalizeLocalFailureWithCode(ctx context.Context, caller ChatCaller, receipt audit.CaptureReceipt, model string, createdAt time.Time, code string, outcome audit.AuditOutcome) error {
	return handler.finalize(ctx, caller, receipt, model, createdAt, nil, 0, nil, audit.CaptureStatusIncomplete, outcome, code, nil)
}

func (handler *ChatProxyHandler) finalize(ctx context.Context, caller ChatCaller, receipt audit.CaptureReceipt, model string, createdAt time.Time, body []byte, observed int64, response *NewAPIResponse, status audit.CaptureStatus, outcome audit.AuditOutcome, errorCode string, tokenUsage *usage.TokenUsage) error {
	var upstreamStatus *int
	upstreamRequestID := ""
	if response != nil {
		value := response.StatusCode
		upstreamStatus = &value
		upstreamRequestID = response.RequestID
	}
	if err := handler.finalizerAndUsage(ctx, caller, receipt, model, createdAt, body, observed, status, outcome, errorCode, upstreamRequestID, upstreamStatus, tokenUsage); err != nil {
		return err
	}
	return nil
}

func (handler *ChatProxyHandler) finalizerAndUsage(ctx context.Context, caller ChatCaller, receipt audit.CaptureReceipt, model string, createdAt time.Time, body []byte, observed int64, status audit.CaptureStatus, outcome audit.AuditOutcome, errorCode, upstreamRequestID string, upstreamStatus *int, tokenUsage *usage.TokenUsage) error {
	return handler.finalizerAndUsageWithFinish(ctx, caller, receipt, model, createdAt, body, observed, status, outcome, errorCode, upstreamRequestID, upstreamStatus, tokenUsage, "")
}

func (handler *ChatProxyHandler) finalizerAndUsageWithFinish(ctx context.Context, caller ChatCaller, receipt audit.CaptureReceipt, model string, createdAt time.Time, body []byte, observed int64, status audit.CaptureStatus, outcome audit.AuditOutcome, errorCode, upstreamRequestID string, upstreamStatus *int, tokenUsage *usage.TokenUsage, finishReason string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	persistenceCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, err := handler.finalizer.FinalizeResponse(persistenceCtx, audit.ResponseFinalizationInput{
		AuditID: receipt.AuditID, RequestID: receipt.RequestID, OwnerKind: caller.OwnerKind,
		IdentityID: caller.IdentityID, ServiceAccountID: caller.ServiceAccountID,
		ResponsibleIdentityID: caller.ResponsibleIdentityID, TeamID: caller.TeamID, ModelID: model,
		ResponseJSON: body, CaptureStatus: status, Outcome: outcome, UpstreamRequestID: upstreamRequestID,
		UpstreamHTTPStatus: upstreamStatus, ErrorCode: errorCode, FinishReason: finishReason, ObservedResponseBytes: observed,
		CreatedAt: createdAt, CompletedAt: handler.now().UTC(),
	})
	if err != nil {
		return err
	}
	usageID, err := handler.newID()
	if err != nil {
		handler.observeUsagePersistence("failure")
		return handler.markUsagePersistenceFailure(persistenceCtx, receipt)
	}
	usageOutcome := usage.OutcomeLocalError
	switch outcome {
	case audit.AuditOutcomeSuccess:
		usageOutcome = usage.OutcomeSuccess
	case audit.AuditOutcomeUpstreamError:
		usageOutcome = usage.OutcomeUpstreamError
	case audit.AuditOutcomeCancelled:
		usageOutcome = usage.OutcomeCancelled
	}
	price := caller.Price
	if tokenUsage == nil {
		price = nil
	}
	record, err := usage.NewRecord(usage.RecordInput{
		ID: usageID, AuditID: receipt.AuditID, RequestID: receipt.RequestID, KeyID: caller.KeyID,
		OwnerKind: usage.OwnerKind(caller.OwnerKind), IdentityID: caller.IdentityID,
		ServiceAccountID: caller.ServiceAccountID, ResponsibleIdentityID: caller.ResponsibleIdentityID,
		TeamID: caller.TeamID, ModelID: model, UpstreamRequestID: upstreamRequestID, Outcome: usageOutcome,
		Usage: tokenUsage, Price: price, CreatedAt: createdAt,
	})
	if err != nil {
		handler.observeUsagePersistence("failure")
		return handler.markUsagePersistenceFailure(persistenceCtx, receipt)
	}
	if err := handler.usage.CreateUsageRecord(persistenceCtx, record); err != nil {
		handler.observeUsagePersistence("failure")
		return handler.markUsagePersistenceFailure(persistenceCtx, receipt)
	}
	handler.observeUsagePersistence("success")
	return nil
}

func (handler *ChatProxyHandler) observeUsagePersistence(outcome string) {
	if handler != nil && handler.metrics != nil {
		handler.metrics.ObserveAuditPersistence("usage", outcome)
	}
}

func (handler *ChatProxyHandler) markUsagePersistenceFailure(ctx context.Context, receipt audit.CaptureReceipt) error {
	marker, ok := handler.finalizer.(PostDispatchFailureMarker)
	if !ok {
		return ErrUsagePersistenceFailed
	}
	if err := marker.MarkPostDispatchFailure(ctx, receipt.AuditID, receipt.RequestID, audit.GateReasonUsagePersistence, handler.now().UTC()); err != nil {
		return errors.Join(ErrUsagePersistenceFailed, err)
	}
	return ErrUsagePersistenceFailed
}

func validateChatCompletionResponse(data []byte) (bool, *usage.TokenUsage) {
	var envelope struct {
		ID      string            `json:"id"`
		Model   string            `json:"model"`
		Choices []json.RawMessage `json:"choices"`
		Usage   *struct {
			PromptTokens     int64 `json:"prompt_tokens"`
			CompletionTokens int64 `json:"completion_tokens"`
			TotalTokens      int64 `json:"total_tokens"`
		} `json:"usage"`
	}
	if !decodeUpstreamJSON(data, &envelope) || envelope.ID == "" || envelope.Model == "" || envelope.Choices == nil || len(envelope.Choices) == 0 {
		return false, nil
	}
	for _, choice := range envelope.Choices {
		var fields map[string]json.RawMessage
		if !decodeUpstreamJSON(choice, &fields) {
			return false, nil
		}
		var index int
		if rawIndex, ok := fields["index"]; !ok || json.Unmarshal(rawIndex, &index) != nil || index < 0 {
			return false, nil
		}
		var message struct {
			Role      string          `json:"role"`
			Content   json.RawMessage `json:"content"`
			ToolCalls []ChatToolCall  `json:"tool_calls"`
		}
		if rawMessage, ok := fields["message"]; !ok || !decodeUpstreamJSON(rawMessage, &message) || message.Role == "" {
			return false, nil
		}
		if message.Role != string(MessageRoleAssistant) || !validResponseContent(message.Content) {
			return false, nil
		}
	}
	if envelope.Usage == nil {
		return true, nil
	}
	if envelope.Usage.PromptTokens < 0 || envelope.Usage.CompletionTokens < 0 || envelope.Usage.TotalTokens < 0 || envelope.Usage.TotalTokens != envelope.Usage.PromptTokens+envelope.Usage.CompletionTokens {
		return false, nil
	}
	return true, &usage.TokenUsage{InputTokens: envelope.Usage.PromptTokens, OutputTokens: envelope.Usage.CompletionTokens, TotalTokens: envelope.Usage.TotalTokens}
}

func validResponseContent(content json.RawMessage) bool {
	if len(content) == 0 || bytes.Equal(bytes.TrimSpace(content), []byte("null")) {
		return true
	}
	var text string
	return json.Unmarshal(content, &text) == nil
}

func validateUpstreamErrorResponse(data []byte) (bool, string) {
	var envelope struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		} `json:"error"`
	}
	if !decodeUpstreamJSON(data, &envelope) || envelope.Error.Message == "" || envelope.Error.Type == "" || !safeUpstreamCode(envelope.Error.Code) {
		return false, ""
	}
	return true, envelope.Error.Code
}

func safeUpstreamCode(value string) bool {
	if value == "" || len(value) > 255 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' || character == '-' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func decodeUpstreamJSON(data []byte, destination any) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if decoder.Decode(destination) != nil {
		return false
	}
	var trailing any
	return decoder.Decode(&trailing) == io.EOF
}

func upstreamErrorCode(err error) httpapi.ErrorCode {
	switch {
	case errors.Is(err, ErrUpstreamTimeout):
		return httpapi.CodeUpstreamTimeout
	case errors.Is(err, context.DeadlineExceeded):
		return httpapi.CodeUpstreamTimeout
	case errors.Is(err, ErrUpstreamUnavailable):
		return httpapi.CodeUpstreamUnavailable
	default:
		return httpapi.CodeUpstreamError
	}
}

func retryAfterHeader(value time.Duration) string {
	seconds := int64(value / time.Second)
	if value%time.Second != 0 {
		seconds++
	}
	if seconds < 1 {
		seconds = 1
	}
	return strconv.FormatInt(seconds, 10)
}

func validChatCaller(caller ChatCaller) bool {
	if !safeCallerFact(caller.RequestID) || !safeCallerFact(caller.KeyID) || !safeCallerFact(caller.TeamID) || validateTrafficOwner(caller.TrafficOwner) != nil {
		return false
	}
	switch caller.OwnerKind {
	case audit.OwnerKindPersonal:
		return safeCallerFact(caller.IdentityID) && caller.ServiceAccountID == "" && caller.ResponsibleIdentityID == "" && caller.TrafficOwner.Kind == TrafficOwnerEmployee && caller.TrafficOwner.ID == caller.IdentityID
	case audit.OwnerKindService:
		return caller.IdentityID == "" && safeCallerFact(caller.ServiceAccountID) && safeCallerFact(caller.ResponsibleIdentityID) && caller.TrafficOwner.Kind == TrafficOwnerServiceAccount && caller.TrafficOwner.ID == caller.ServiceAccountID
	default:
		return false
	}
}

func safeCallerFact(value string) bool {
	if value == "" || len(value) > 255 || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func (handler *ChatProxyHandler) recordRejection(request *http.Request, class RejectionClass, code RejectionErrorCode, caller *ChatCaller, rule LimitRule, observedBytes int64) {
	if handler == nil || handler.rejections == nil || request == nil {
		return
	}
	requestID, ok := observability.RequestIDFromContext(request.Context())
	if !ok || requestID == "" {
		return
	}
	var attribution *RejectionAttribution
	if caller != nil {
		attribution = &RejectionAttribution{Owner: caller.TrafficOwner, KeyID: caller.KeyID}
	}
	_ = handler.rejections.Record(request.Context(), Rejection{
		Class: class, Attribution: attribution, Rule: rule, RequestID: requestID,
		ObservedAt: handler.now().UTC(), ObservedBytes: observedBytes, ErrorCode: code,
	})
}

func requestObservedBytes(request *http.Request, limit int64) int64 {
	if request != nil && request.ContentLength > 0 {
		return request.ContentLength
	}
	return limit + 1
}

func writeChatError(writer http.ResponseWriter, code httpapi.ErrorCode) {
	status, envelope := httpapi.ErrorResponse(code, nil)
	writeChatEnvelope(writer, status, envelope)
}

func writeChatEnvelope(writer http.ResponseWriter, status int, envelope httpapi.ErrorEnvelope) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(envelope)
}

func newChatRequestID() (string, error) {
	return observability.NewRequestID()
}

func setRequestIDHeader(writer http.ResponseWriter, request *http.Request, upstreamRequestID string) {
	if request != nil {
		if requestID, ok := observability.RequestIDFromContext(request.Context()); ok {
			writer.Header().Set(observability.RequestIDHeader, requestID)
			return
		}
	}
	if upstreamRequestID != "" {
		writer.Header().Set(observability.RequestIDHeader, upstreamRequestID)
	}
}

var _ ChatUpstream = (*NewAPIClient)(nil)
var _ InitialCapture = (*audit.InitialCaptureService)(nil)
var _ ModelPolicy = (*policy.Resolver)(nil)
