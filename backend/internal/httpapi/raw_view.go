package httpapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
)

type RawViewInspector interface {
	Inspect(context.Context, audit.RawViewInput) (audit.RawView, error)
}

func NewRawViewHandler(service RawViewInspector) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := PortalSessionFromContext(request.Context())
		if !ok {
			writeErrorResponse(writer, CodeAuthenticationRequired)
			return
		}
		body := struct {
			Reason string `json:"reason"`
		}{}
		if !decodeStrictJSON(writer, request, &body) {
			return
		}
		auditID := rawViewAuditID(request)
		if !validRawViewAuditID(auditID) || service == nil {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		view, err := service.Inspect(request.Context(), audit.RawViewInput{
			Session: session, AuditID: auditID, Reason: body.Reason,
		})
		if err != nil {
			writeRawViewError(writer, err)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		if err := json.NewEncoder(writer).Encode(view); err != nil {
			slog.Warn("write raw audit view response failed", "error", err)
		}
	})
}

func writeRawViewError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, access.ErrSensitiveActionForbidden):
		writeErrorResponse(writer, CodeForbidden)
	case errors.Is(err, access.ErrReauthenticationRequired):
		writeErrorResponse(writer, CodeReauthenticationRequired)
	case errors.Is(err, audit.ErrRawViewReasonRequired):
		writeErrorResponse(writer, CodeInvalidRequest)
	case errors.Is(err, audit.ErrRawViewNotFound):
		writeErrorResponse(writer, CodeNotFound)
	case errors.Is(err, access.ErrSecurityAuditUnavailable):
		writeErrorResponse(writer, CodeAuditUnavailable)
	default:
		writeErrorResponse(writer, CodeInternalError)
	}
}

func rawViewAuditID(request *http.Request) string {
	if value := strings.TrimSpace(request.PathValue("auditID")); value != "" {
		return value
	}
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	for index, part := range parts {
		if part == "audits" && index+1 < len(parts) && parts[index+1] != "" {
			return strings.TrimSpace(parts[index+1])
		}
	}
	return ""
}

func validRawViewAuditID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := strings.ReplaceAll(value, "-", "")
	decoded := make([]byte, 16)
	_, err := hex.Decode(decoded, []byte(compact))
	return err == nil
}
