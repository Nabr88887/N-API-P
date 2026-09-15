package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"n-api-p/internal/access"
	"n-api-p/internal/observability"
)

type PasswordResetCodeIssuer interface {
	IssueCode(context.Context, access.PasswordResetIssueInput) (access.PasswordResetCode, error)
}

type PasswordResetCompleter interface {
	Complete(context.Context, access.PasswordResetCompletionInput) error
}

func NewPasswordResetCodeHandler(service PasswordResetCodeIssuer) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := PortalSessionFromContext(request.Context())
		if !ok {
			writeErrorResponse(writer, CodeAuthenticationRequired)
			return
		}
		body := struct {
			Email                  string `json:"email"`
			ManualIdentityVerified bool   `json:"manual_identity_verified"`
			CompromiseResponse     bool   `json:"compromise_response"`
		}{}
		if !decodeStrictJSON(writer, request, &body) {
			return
		}
		targetID := passwordResetTargetIdentityID(request)
		if targetID == "" || strings.TrimSpace(body.Email) == "" {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		issued, err := service.IssueCode(request.Context(), access.PasswordResetIssueInput{
			Actor: session, TargetIdentityID: targetID, TargetEmail: body.Email,
			ManualIdentityVerified: body.ManualIdentityVerified, CompromiseResponse: body.CompromiseResponse,
			RequestID: adminRequestID(request),
		})
		if errors.Is(err, access.ErrForbidden) {
			writeErrorResponse(writer, CodeForbidden)
			return
		}
		if errors.Is(err, access.ErrManualIdentityVerificationRequired) {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		if errors.Is(err, access.ErrReauthenticationRequired) {
			writeErrorResponse(writer, CodeReauthenticationRequired)
			return
		}
		if errors.Is(err, access.ErrPasswordResetRejected) {
			writeErrorResponse(writer, CodeNotFound)
			return
		}
		if err != nil {
			writeErrorResponse(writer, CodeInternalError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(writer).Encode(struct {
			Code      string `json:"code"`
			Email     string `json:"email"`
			ExpiresAt string `json:"expires_at"`
		}{Code: issued.Code, Email: issued.Email, ExpiresAt: issued.ExpiresAt.UTC().Format("2006-01-02T15:04:05.999999999Z07:00")}); err != nil {
			_ = observability.DefaultLogger().Emit(observability.LogEvent{
				Level: observability.LevelError, Event: "http_error_response_write_failed",
			})
		}
	})
}

func NewPasswordResetCompletionHandler(service PasswordResetCompleter) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body := struct {
			Email       string `json:"email"`
			Code        string `json:"code"`
			NewPassword string `json:"new_password"`
		}{}
		if !decodeStrictJSON(writer, request, &body) {
			return
		}
		if body.Email == "" || body.Code == "" || body.NewPassword == "" {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		err := service.Complete(request.Context(), access.PasswordResetCompletionInput{
			Email: body.Email, Code: body.Code, NewPassword: body.NewPassword,
		})
		if errors.Is(err, access.ErrPasswordResetRejected) {
			writeErrorResponse(writer, CodeInvalidCredentials)
			return
		}
		if errors.Is(err, access.ErrPasswordRejected) {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		if err != nil {
			writeErrorResponse(writer, CodeInternalError)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusNoContent)
	})
}

func decodeStrictJSON(writer http.ResponseWriter, request *http.Request, destination any) bool {
	return decodeStrictJSONWithLimit(writer, request, destination, 8<<10)
}

func decodeStrictJSONWithLimit(writer http.ResponseWriter, request *http.Request, destination any, limit int64) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeErrorResponse(writer, CodeInvalidRequest)
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeErrorResponse(writer, CodeInvalidRequest)
		return false
	}
	return true
}

func passwordResetTargetIdentityID(request *http.Request) string {
	if value := strings.TrimSpace(request.PathValue("userID")); value != "" {
		return value
	}
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	for index, part := range parts {
		if part == "users" && index+1 < len(parts) && parts[index+1] != "" {
			return parts[index+1]
		}
	}
	return ""
}
