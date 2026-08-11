package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/database"
)

type EmployeePersonalKeyService interface {
	Create(context.Context, access.CreatePersonalKeyInput) (access.PersonalKeyIssuance, error)
	ListPage(context.Context, access.PersonalKeyPageRequest) (access.PersonalKeyPage, error)
	Revoke(context.Context, access.RevokePersonalKeyInput) error
}

var (
	ErrEmployeePortalDependencies = errors.New("employee portal services are required")
	ErrEmployeePortalRoute        = errors.New("employee portal route is missing from inventory")
)

type OwnUsageReader interface {
	ListUsageRecords(context.Context, database.UsageListFilter) ([]database.UsageRecord, error)
}

func NewPersonalKeyListHandler(service EmployeePersonalKeyService) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := PortalSessionFromContext(request.Context())
		if !ok || session.IdentityID == "" {
			writeErrorResponse(writer, CodeAuthenticationRequired)
			return
		}
		limit, cursor, err := parseEmployeePage(request)
		if err != nil {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		page, err := service.ListPage(request.Context(), access.PersonalKeyPageRequest{IdentityID: session.IdentityID, Cursor: cursor, Limit: limit})
		if err != nil {
			writeEmployeeError(writer, err)
			return
		}
		data := make([]Key, 0, len(page.Keys))
		for _, key := range page.Keys {
			data = append(data, personalKeyResponse(key))
		}
		var next *employeeCursor
		if page.NextCursor != nil {
			next = &employeeCursor{CreatedAt: page.NextCursor.CreatedAt, ID: page.NextCursor.ID}
		}
		writePagedJSON(writer, http.StatusOK, PagedResponse[Key]{Data: data, Pagination: Pagination{NextCursor: encodeEmployeeCursor(next), HasMore: next != nil}})
	})
}

func NewPersonalKeyCreateHandler(service interface {
	Create(context.Context, access.CreatePersonalKeyInput) (access.PersonalKeyIssuance, error)
}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := PortalSessionFromContext(request.Context())
		if !ok || session.IdentityID == "" {
			writeErrorResponse(writer, CodeAuthenticationRequired)
			return
		}
		var input CreatePersonalKeyRequest
		if err := decodeEmployeeJSON(writer, request, &input); err != nil {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		issuance, err := service.Create(request.Context(), access.CreatePersonalKeyInput{
			IdentityID: session.IdentityID, Name: input.Name,
		})
		if err != nil {
			writeEmployeeError(writer, err)
			return
		}
		value, ok := issuance.Credential.Reveal()
		if !ok || value == "" {
			writeErrorResponse(writer, CodeInternalError)
			return
		}
		writeJSON(writer, http.StatusCreated, KeyIssuance{Key: personalKeyResponse(issuance.Key), Credential: IssuedCredential{Value: value}})
	})
}

func NewPersonalKeyRevokeHandler(service interface {
	Revoke(context.Context, access.RevokePersonalKeyInput) error
}) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := PortalSessionFromContext(request.Context())
		if !ok || session.IdentityID == "" {
			writeErrorResponse(writer, CodeAuthenticationRequired)
			return
		}
		keyID := strings.TrimSpace(strings.TrimPrefix(request.URL.Path, "/api/v1/me/personal-keys/"))
		if keyID == "" || strings.Contains(keyID, "/") || len(keyID) > 128 {
			writeErrorResponse(writer, CodeNotFound)
			return
		}
		if err := service.Revoke(request.Context(), access.RevokePersonalKeyInput{IdentityID: session.IdentityID, KeyID: keyID}); err != nil {
			writeEmployeeError(writer, err)
			return
		}
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusNoContent)
	})
}

func NewOwnUsageHandler(reader OwnUsageReader) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := PortalSessionFromContext(request.Context())
		if !ok || session.IdentityID == "" {
			writeErrorResponse(writer, CodeAuthenticationRequired)
			return
		}
		limit, cursor, err := parseEmployeePage(request)
		if err != nil {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		records, err := reader.ListUsageRecords(request.Context(), database.UsageListFilter{IdentityID: session.IdentityID, Cursor: cursorToUsageCursor(cursor), Limit: limit + 1})
		if err != nil {
			writeErrorResponse(writer, CodeInternalError)
			return
		}
		hasMore := len(records) > limit
		if hasMore {
			records = records[:limit]
		}
		data := make([]UsageRecord, 0, len(records))
		for _, record := range records {
			data = append(data, usageResponse(record))
		}
		var next *employeeCursor
		if hasMore && len(records) > 0 {
			last := records[len(records)-1]
			next = &employeeCursor{CreatedAt: last.CreatedAt, ID: last.ID}
		}
		writePagedJSON(writer, http.StatusOK, PagedResponse[UsageRecord]{Data: data, Pagination: Pagination{NextCursor: encodeEmployeeCursor(next), HasMore: next != nil}})
	})
}

type PortalAuthenticator interface {
	Login(context.Context, access.LoginInput) (access.PortalSession, error)
}

func NewLoginHandler(authenticator PortalAuthenticator) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var input CreateSessionRequest
		if err := decodeEmployeeJSON(writer, request, &input); err != nil {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		session, err := authenticator.Login(request.Context(), access.LoginInput{Email: input.Email, Password: input.Password})
		if errors.Is(err, access.ErrInvalidCredentials) {
			writeErrorResponse(writer, CodeInvalidCredentials)
			return
		}
		if err != nil {
			writeErrorResponse(writer, CodeInternalError)
			return
		}
		if session.Token == "" || session.CSRFToken == "" {
			writeErrorResponse(writer, CodeInternalError)
			return
		}
		WritePortalSessionCookie(writer, session)
		writer.Header().Set(CSRFHeaderName, session.CSRFToken)
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusNoContent)
	})
}

func NewEmployeePortalRouter(sessions PortalSessionService, allowedOrigin string, keys EmployeePersonalKeyService, usage OwnUsageReader) (http.Handler, error) {
	if keys == nil || usage == nil {
		return nil, ErrEmployeePortalDependencies
	}
	middleware, err := NewPortalSessionMiddleware(sessions, allowedOrigin)
	if err != nil {
		return nil, err
	}
	guard := NewAuthorizationGuard()
	mux := http.NewServeMux()
	listRoute := routeByNameValue(RouteName("portal.personal_keys.list"))
	createRoute := routeByNameValue(RouteName("portal.personal_keys.create"))
	revokeRoute := routeByNameValue(RouteName("portal.personal_keys.revoke"))
	usageRoute := routeByNameValue(RouteName("portal.usage.own"))
	for _, route := range []Route{listRoute, createRoute, revokeRoute, usageRoute} {
		if route.Pattern == "" || route.Auth != AuthPortalSession {
			return nil, ErrEmployeePortalRoute
		}
	}
	mux.Handle("GET /api/v1/me/personal-keys", guard.Wrap(listRoute, NewPersonalKeyListHandler(keys)))
	mux.Handle("POST /api/v1/me/personal-keys", guard.Wrap(createRoute, NewPersonalKeyCreateHandler(keys)))
	mux.Handle("DELETE /api/v1/me/personal-keys/{keyID}", guard.Wrap(revokeRoute, NewPersonalKeyRevokeHandler(keys)))
	mux.Handle("GET /api/v1/me/usage", guard.Wrap(usageRoute, NewOwnUsageHandler(usage)))
	return middleware.Wrap(mux), nil
}

func routeByNameValue(name RouteName) Route {
	for _, route := range Routes() {
		if route.Name == name {
			return route
		}
	}
	return Route{Name: name}
}

type employeeCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
}

func parseEmployeePage(request *http.Request) (int, *access.PersonalKeyCursor, error) {
	limit, err := parsePageLimit(request)
	if err != nil {
		return 0, nil, err
	}
	cursor, err := decodeEmployeeCursor(request.URL.Query().Get("cursor"))
	if err != nil {
		return 0, nil, err
	}
	return limit, cursor, nil
}

func parsePageLimit(request *http.Request) (int, error) {
	limit := AdminAPIPageSizeDefault
	if raw := request.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return 0, ErrInvalidPageRequest
		}
		limit = parsed
	}
	page := PageRequest{Cursor: request.URL.Query().Get("cursor"), Limit: limit}
	if err := page.Validate(); err != nil || page.EffectiveLimit() < 1 {
		return 0, ErrInvalidPageRequest
	}
	return page.EffectiveLimit(), nil
}

func encodeEmployeeCursor(cursor *employeeCursor) string {
	if cursor == nil {
		return ""
	}
	value, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(value)
}

func decodeEmployeeCursor(value string) (*access.PersonalKeyCursor, error) {
	if value == "" {
		return nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) > AdminAPICursorMaxBytes {
		return nil, ErrInvalidPageRequest
	}
	var cursor employeeCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil || cursor.CreatedAt.IsZero() {
		return nil, ErrInvalidPageRequest
	}
	if !validCursorID(cursor.ID) {
		return nil, ErrInvalidPageRequest
	}
	return &access.PersonalKeyCursor{CreatedAt: cursor.CreatedAt.UTC(), ID: cursor.ID}, nil
}

func validCursorID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index, character := range value {
		if index == 8 || index == 13 || index == 18 || index == 23 {
			if character != '-' {
				return false
			}
			continue
		}
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}

func cursorToUsageCursor(cursor *access.PersonalKeyCursor) *database.UsageCursor {
	if cursor == nil {
		return nil
	}
	return &database.UsageCursor{CreatedAt: cursor.CreatedAt, ID: cursor.ID}
}

func personalKeyResponse(key access.PersonalKey) Key {
	return Key{ID: key.ID, Kind: KeyKindPersonal, OwnerAccountID: key.IdentityID, Name: key.Name, Prefix: key.Prefix, Status: KeyStatus(key.Status), CreatedAt: key.CreatedAt, LastUsedAt: key.LastUsedAt, RevokedAt: key.RevokedAt}
}

func usageResponse(record database.UsageRecord) UsageRecord {
	response := UsageRecord{ID: record.ID, AuditID: record.AuditID, RequestID: record.RequestID, KeyID: record.KeyID, OwnerAccountID: record.IdentityID, TeamID: record.TeamID, ModelID: record.ModelID, Outcome: UsageOutcome(record.Outcome), UsageReported: record.UsageReported, CreatedAt: record.CreatedAt}
	if record.ServiceAccountID.Valid {
		response.ServiceAccountID = record.ServiceAccountID.String
	}
	if record.UsageReported && record.InputTokens.Valid && record.OutputTokens.Valid && record.TotalTokens.Valid {
		response.Usage = &TokenUsage{InputTokens: record.InputTokens.Int64, OutputTokens: record.OutputTokens.Int64, TotalTokens: record.TotalTokens.Int64}
	}
	if record.PriceVersion.Valid {
		response.PriceVersion = record.PriceVersion.String
	}
	if record.CalculatedAmount.Valid {
		response.CalculatedAmount = record.CalculatedAmount.String
	}
	return response
}

func decodeEmployeeJSON(writer http.ResponseWriter, request *http.Request, target any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 8<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("trailing request data")
	}
	return nil
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(value); err != nil {
		slog.Warn("write employee API response failed", "error", err)
	}
}

func writePagedJSON[T any](writer http.ResponseWriter, status int, value PagedResponse[T]) {
	writeJSON(writer, status, value)
}

func writeEmployeeError(writer http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, access.ErrInvalidPersonalKeyName), errors.Is(err, access.ErrInvalidPersonalKeyPage):
		writeErrorResponse(writer, CodeInvalidRequest)
	case errors.Is(err, access.ErrPersonalKeyNameConflict):
		writeErrorResponse(writer, CodeConflict)
	case errors.Is(err, access.ErrPersonalKeyLimitReached):
		writeErrorResponse(writer, CodeKeyLimitReached)
	case errors.Is(err, access.ErrPersonalKeyNotFound):
		writeErrorResponse(writer, CodeNotFound)
	case errors.Is(err, access.ErrForbidden):
		writeErrorResponse(writer, CodeForbidden)
	default:
		writeErrorResponse(writer, CodeInternalError)
	}
}
