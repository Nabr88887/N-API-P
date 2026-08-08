package gateway

import (
	"errors"
	"net/http"

	"n-api-p/internal/httpapi"
)

var ErrInvalidOpenAIV1Handler = errors.New("invalid OpenAI v1 handler")

type OpenAIV1Handler struct {
	models http.Handler
	chat   http.Handler
}

func NewOpenAIV1Handler(models, chat http.Handler) (*OpenAIV1Handler, error) {
	if models == nil || chat == nil {
		return nil, ErrInvalidOpenAIV1Handler
	}
	return &OpenAIV1Handler{models: models, chat: chat}, nil
}

func (handler *OpenAIV1Handler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler == nil || writer == nil || request == nil || handler.models == nil || handler.chat == nil {
		return
	}
	switch {
	case request.Method == http.MethodGet && request.URL.Path == "/v1/models":
		handler.models.ServeHTTP(writer, request)
	case request.Method == http.MethodPost && request.URL.Path == "/v1/chat/completions":
		handler.chat.ServeHTTP(writer, request)
	default:
		writeChatError(writer, httpapi.CodeUnsupportedEndpoint)
	}
}
