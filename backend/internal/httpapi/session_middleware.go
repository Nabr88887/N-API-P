package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/observability"
)

const (
	PortalSessionCookieName = "__Host-n-api-p-session"
	CSRFHeaderName          = "X-CSRF-Token"
)

type PortalSessionService interface {
	Authenticate(context.Context, string, string, bool) (access.ActivePortalSession, error)
	Revoke(context.Context, string) error
}

type PortalReauthenticationService interface {
	Reauthenticate(context.Context, access.ReauthenticationInput) (access.PortalSession, error)
}

type PortalSessionMiddleware struct {
	sessions      PortalSessionService
	allowedOrigin string
}

func NewPortalSessionMiddleware(sessions PortalSessionService, allowedOrigin string) (*PortalSessionMiddleware, error) {
	if sessions == nil {
		return nil, errors.New("portal session service is required")
	}
	parsed, err := url.Parse(allowedOrigin)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("portal origin must be an HTTPS origin")
	}
	return &PortalSessionMiddleware{sessions: sessions, allowedOrigin: parsed.String()}, nil
}

func (middleware *PortalSessionMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		cookie, err := request.Cookie(PortalSessionCookieName)
		if err != nil || cookie.Value == "" {
			writeErrorResponse(writer, CodeAuthenticationRequired)
			return
		}

		requireCSRF := stateChangingMethod(request.Method)
		csrfToken := ""
		if requireCSRF {
			if request.Header.Get("Origin") != middleware.allowedOrigin {
				writeErrorResponse(writer, CodeCSRFRejected)
				return
			}
			csrfToken = strings.TrimSpace(request.Header.Get(CSRFHeaderName))
			if csrfToken == "" {
				writeErrorResponse(writer, CodeCSRFRejected)
				return
			}
		}

		session, err := middleware.sessions.Authenticate(request.Context(), cookie.Value, csrfToken, requireCSRF)
		if errors.Is(err, access.ErrSessionInvalid) {
			if requireCSRF {
				writeErrorResponse(writer, CodeCSRFRejected)
			} else {
				writeErrorResponse(writer, CodeAuthenticationRequired)
			}
			return
		}
		if err != nil {
			writeErrorResponse(writer, CodeInternalError)
			return
		}
		request = request.WithContext(context.WithValue(request.Context(), portalSessionContextKey{}, session))
		writer.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(writer, request)
	})
}

func WritePortalSessionCookie(writer http.ResponseWriter, session access.PortalSession) {
	http.SetCookie(writer, &http.Cookie{
		Name: PortalSessionCookieName, Value: session.Token, Path: "/",
		Expires: session.ExpiresAt.UTC(), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func clearPortalSessionCookie(writer http.ResponseWriter) {
	http.SetCookie(writer, &http.Cookie{
		Name: PortalSessionCookieName, Path: "/", MaxAge: -1,
		Expires: time.Unix(1, 0).UTC(), HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

func NewLogoutHandler(sessions PortalSessionService) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := PortalSessionFromContext(request.Context())
		if !ok {
			writeErrorResponse(writer, CodeAuthenticationRequired)
			return
		}
		if err := sessions.Revoke(request.Context(), session.SessionID); errors.Is(err, access.ErrSessionInvalid) {
			writeErrorResponse(writer, CodeAuthenticationRequired)
			return
		} else if err != nil {
			writeErrorResponse(writer, CodeInternalError)
			return
		}
		clearPortalSessionCookie(writer)
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusNoContent)
	})
}

func NewReauthenticationHandler(service PortalReauthenticationService) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := PortalSessionFromContext(request.Context())
		if !ok {
			writeErrorResponse(writer, CodeAuthenticationRequired)
			return
		}
		requestBody := struct {
			Password string `json:"password"`
		}{}
		decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 8<<10))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&requestBody); err != nil || requestBody.Password == "" {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		rotated, err := service.Reauthenticate(request.Context(), access.ReauthenticationInput{
			SessionID: session.SessionID,
			Password:  requestBody.Password,
		})
		if errors.Is(err, access.ErrReauthenticationRejected) {
			writeErrorResponse(writer, CodeInvalidCredentials)
			return
		}
		if err != nil {
			writeErrorResponse(writer, CodeInternalError)
			return
		}
		WritePortalSessionCookie(writer, rotated)
		writer.Header().Set(CSRFHeaderName, rotated.CSRFToken)
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusNoContent)
	})
}

type portalSessionContextKey struct{}

func PortalSessionFromContext(ctx context.Context) (access.ActivePortalSession, bool) {
	session, ok := ctx.Value(portalSessionContextKey{}).(access.ActivePortalSession)
	return session, ok
}

func stateChangingMethod(method string) bool {
	return method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
}

func writeErrorResponse(writer http.ResponseWriter, code ErrorCode) {
	status, response := ErrorResponse(code, nil)
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(response); err != nil {
		if logErr := observability.DefaultLogger().Emit(observability.LogEvent{
			Level: observability.LevelError, Event: "http_error_response_write_failed",
		}); logErr != nil {
			return
		}
	}
}
