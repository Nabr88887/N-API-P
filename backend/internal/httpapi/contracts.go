package httpapi

import "net/http"

type ErrorType string

const (
	TypeInvalidRequest     ErrorType = "invalid_request_error"
	TypeAuthentication     ErrorType = "authentication_error"
	TypePermission         ErrorType = "permission_error"
	TypeRateLimit          ErrorType = "rate_limit_error"
	TypeInternal           ErrorType = "internal_error"
	TypeUpstream           ErrorType = "upstream_error"
	TypeServiceUnavailable ErrorType = "service_unavailable_error"
)

type ErrorCode string

const (
	CodeInvalidRequest           ErrorCode = "INVALID_REQUEST"
	CodeAuthenticationRequired   ErrorCode = "AUTHENTICATION_REQUIRED"
	CodeInvalidCredentials       ErrorCode = "INVALID_CREDENTIALS"
	CodeInvalidAPIKey            ErrorCode = "INVALID_API_KEY"
	CodeForbidden                ErrorCode = "FORBIDDEN"
	CodeCSRFRejected             ErrorCode = "CSRF_REJECTED"
	CodeReauthenticationRequired ErrorCode = "REAUTHENTICATION_REQUIRED"
	CodeModelNotAllowed          ErrorCode = "MODEL_NOT_ALLOWED"
	CodeNotFound                 ErrorCode = "NOT_FOUND"
	CodeUnsupportedEndpoint      ErrorCode = "UNSUPPORTED_ENDPOINT"
	CodeConflict                 ErrorCode = "CONFLICT"
	CodeKeyLimitReached          ErrorCode = "KEY_LIMIT_REACHED"
	CodeRequestTooLarge          ErrorCode = "REQUEST_TOO_LARGE"
	CodeUnsupportedContentType   ErrorCode = "UNSUPPORTED_CONTENT_TYPE"
	CodeRateLimited              ErrorCode = "RATE_LIMITED"
	CodeInternalError            ErrorCode = "INTERNAL_ERROR"
	CodeUpstreamError            ErrorCode = "UPSTREAM_ERROR"
	CodeUpstreamUnavailable      ErrorCode = "UPSTREAM_UNAVAILABLE"
	CodeUpstreamResponseTooLarge ErrorCode = "UPSTREAM_RESPONSE_TOO_LARGE"
	CodeAuditUnavailable         ErrorCode = "AUDIT_UNAVAILABLE"
	CodeUpstreamTimeout          ErrorCode = "UPSTREAM_TIMEOUT"
)

type ErrorObject struct {
	Message string    `json:"message"`
	Type    ErrorType `json:"type"`
	Param   *string   `json:"param"`
	Code    ErrorCode `json:"code"`
}

type ErrorEnvelope struct {
	Error ErrorObject `json:"error"`
}

type errorDefinition struct {
	status  int
	typeID  ErrorType
	message string
}

var errorDefinitions = map[ErrorCode]errorDefinition{
	CodeInvalidRequest:           {http.StatusBadRequest, TypeInvalidRequest, "Invalid request."},
	CodeAuthenticationRequired:   {http.StatusUnauthorized, TypeAuthentication, "Authentication required."},
	CodeInvalidCredentials:       {http.StatusUnauthorized, TypeAuthentication, "Invalid credentials."},
	CodeInvalidAPIKey:            {http.StatusUnauthorized, TypeAuthentication, "Invalid API key."},
	CodeForbidden:                {http.StatusForbidden, TypePermission, "Access forbidden."},
	CodeCSRFRejected:             {http.StatusForbidden, TypePermission, "Request origin or CSRF token rejected."},
	CodeReauthenticationRequired: {http.StatusForbidden, TypePermission, "Recent password reauthentication required."},
	CodeModelNotAllowed:          {http.StatusForbidden, TypePermission, "Requested model is not allowed."},
	CodeNotFound:                 {http.StatusNotFound, TypeInvalidRequest, "Resource not found."},
	CodeUnsupportedEndpoint:      {http.StatusNotFound, TypeInvalidRequest, "Endpoint not supported."},
	CodeConflict:                 {http.StatusConflict, TypeInvalidRequest, "Resource state conflicts with the request."},
	CodeKeyLimitReached:          {http.StatusConflict, TypeInvalidRequest, "Active key limit reached."},
	CodeRequestTooLarge:          {http.StatusRequestEntityTooLarge, TypeInvalidRequest, "Request body is too large."},
	CodeUnsupportedContentType:   {http.StatusUnsupportedMediaType, TypeInvalidRequest, "Unsupported content type."},
	CodeRateLimited:              {http.StatusTooManyRequests, TypeRateLimit, "Rate limit exceeded."},
	CodeInternalError:            {http.StatusInternalServerError, TypeInternal, "Internal server error."},
	CodeUpstreamError:            {http.StatusBadGateway, TypeUpstream, "Upstream response was invalid."},
	CodeUpstreamUnavailable:      {http.StatusBadGateway, TypeUpstream, "Upstream service is unavailable."},
	CodeUpstreamResponseTooLarge: {http.StatusBadGateway, TypeUpstream, "Upstream response is too large."},
	CodeAuditUnavailable:         {http.StatusServiceUnavailable, TypeServiceUnavailable, "Audit persistence is unavailable."},
	CodeUpstreamTimeout:          {http.StatusGatewayTimeout, TypeUpstream, "Upstream request timed out."},
}

func ErrorResponse(code ErrorCode, param *string) (int, ErrorEnvelope) {
	definition, ok := errorDefinitions[code]
	if !ok {
		code = CodeInternalError
		definition = errorDefinitions[code]
		param = nil
	}

	return definition.status, ErrorEnvelope{
		Error: ErrorObject{
			Message: definition.message,
			Type:    definition.typeID,
			Param:   safeErrorParam(param),
			Code:    code,
		},
	}
}

func safeErrorParam(param *string) *string {
	if param == nil || len(*param) == 0 || len(*param) > 128 {
		return nil
	}

	for _, character := range []byte(*param) {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '_' || character == '.' ||
			character == '[' || character == ']' {
			continue
		}
		return nil
	}

	value := *param
	return &value
}

type Method string

const (
	MethodGet    Method = http.MethodGet
	MethodPost   Method = http.MethodPost
	MethodPut    Method = http.MethodPut
	MethodPatch  Method = http.MethodPatch
	MethodDelete Method = http.MethodDelete
)

type Surface string

const (
	SurfaceDataPlane  Surface = "data_plane"
	SurfacePortal     Surface = "portal"
	SurfaceOperations Surface = "operations"
)

type AuthMode string

const (
	AuthAnonymous        AuthMode = "anonymous"
	AuthPortalSession    AuthMode = "portal_session"
	AuthDownstreamKey    AuthMode = "downstream_key"
	AuthOperatorBoundary AuthMode = "operator_boundary"
)

type Role string

const (
	RoleEmployee            Role = "employee"
	RoleTeamAdministrator   Role = "team_administrator"
	RoleSystemAdministrator Role = "system_administrator"
)

type RouteName string

type Route struct {
	Name    RouteName
	Method  Method
	Pattern string
	Surface Surface
	Auth    AuthMode
	Roles   []Role
}

var routeInventory = buildRouteInventory()

func Routes() []Route {
	routes := make([]Route, len(routeInventory))
	for index, route := range routeInventory {
		routes[index] = route
		routes[index].Roles = append([]Role(nil), route.Roles...)
	}
	return routes
}

func buildRouteInventory() []Route {
	allPortalRoles := []Role{RoleEmployee, RoleTeamAdministrator, RoleSystemAdministrator}
	teamRoles := []Role{RoleTeamAdministrator, RoleSystemAdministrator}
	systemRole := []Role{RoleSystemAdministrator}

	return []Route{
		route("data.models.list", MethodGet, "/v1/models", SurfaceDataPlane, AuthDownstreamKey, nil),
		route("data.chat.create", MethodPost, "/v1/chat/completions", SurfaceDataPlane, AuthDownstreamKey, nil),
		route("operations.live", MethodGet, "/health/live", SurfaceOperations, AuthOperatorBoundary, nil),
		route("operations.ready", MethodGet, "/health/ready", SurfaceOperations, AuthOperatorBoundary, nil),
		route("operations.metrics", MethodGet, "/metrics", SurfaceOperations, AuthOperatorBoundary, nil),

		route("portal.activation.create", MethodPost, "/api/v1/activations", SurfacePortal, AuthAnonymous, nil),
		route("portal.session.create", MethodPost, "/api/v1/sessions", SurfacePortal, AuthAnonymous, nil),
		route("portal.password_reset.complete", MethodPost, "/api/v1/password-reset-completions", SurfacePortal, AuthAnonymous, nil),
		route("portal.me.get", MethodGet, "/api/v1/me", SurfacePortal, AuthPortalSession, allPortalRoles),
		route("portal.session.delete_current", MethodDelete, "/api/v1/sessions/current", SurfacePortal, AuthPortalSession, allPortalRoles),
		route("portal.session.reauthenticate", MethodPost, "/api/v1/sessions/current/reauthentications", SurfacePortal, AuthPortalSession, allPortalRoles),
		route("portal.personal_keys.list", MethodGet, "/api/v1/me/personal-keys", SurfacePortal, AuthPortalSession, allPortalRoles),
		route("portal.personal_keys.create", MethodPost, "/api/v1/me/personal-keys", SurfacePortal, AuthPortalSession, allPortalRoles),
		route("portal.personal_keys.revoke", MethodDelete, "/api/v1/me/personal-keys/{keyID}", SurfacePortal, AuthPortalSession, allPortalRoles),
		route("portal.usage.own", MethodGet, "/api/v1/me/usage", SurfacePortal, AuthPortalSession, allPortalRoles),
		route("portal.team.members.list", MethodGet, "/api/v1/teams/{teamID}/members", SurfacePortal, AuthPortalSession, teamRoles),
		route("portal.team.usage.list", MethodGet, "/api/v1/teams/{teamID}/usage", SurfacePortal, AuthPortalSession, teamRoles),

		route("admin.invitations.list", MethodGet, "/api/v1/invitations", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.invitations.create", MethodPost, "/api/v1/invitations", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.users.list", MethodGet, "/api/v1/users", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.users.get", MethodGet, "/api/v1/users/{userID}", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.users.update", MethodPatch, "/api/v1/users/{userID}", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.users.issue_password_reset", MethodPost, "/api/v1/users/{userID}/password-reset-codes", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.teams.list", MethodGet, "/api/v1/teams", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.teams.create", MethodPost, "/api/v1/teams", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.teams.get", MethodGet, "/api/v1/teams/{teamID}", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.teams.update", MethodPatch, "/api/v1/teams/{teamID}", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.teams.delete", MethodDelete, "/api/v1/teams/{teamID}", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.team_members.add", MethodPut, "/api/v1/teams/{teamID}/members/{userID}", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.team_members.remove", MethodDelete, "/api/v1/teams/{teamID}/members/{userID}", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.service_accounts.list", MethodGet, "/api/v1/service-accounts", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.service_accounts.create", MethodPost, "/api/v1/service-accounts", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.service_accounts.get", MethodGet, "/api/v1/service-accounts/{serviceAccountID}", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.service_accounts.update", MethodPatch, "/api/v1/service-accounts/{serviceAccountID}", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.service_accounts.delete", MethodDelete, "/api/v1/service-accounts/{serviceAccountID}", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.service_keys.list", MethodGet, "/api/v1/service-accounts/{serviceAccountID}/keys", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.service_keys.create", MethodPost, "/api/v1/service-accounts/{serviceAccountID}/keys", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.service_keys.revoke", MethodDelete, "/api/v1/service-accounts/{serviceAccountID}/keys/{keyID}", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.service_keys.rotate", MethodPost, "/api/v1/service-accounts/{serviceAccountID}/keys/{keyID}/rotations", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.model_allowlist.get", MethodGet, "/api/v1/model-allowlist", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.model_allowlist.replace", MethodPut, "/api/v1/model-allowlist", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.retention_policy.get", MethodGet, "/api/v1/retention-policy", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.retention_policy.replace", MethodPut, "/api/v1/retention-policy", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.audits.list", MethodGet, "/api/v1/audits", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.audits.get", MethodGet, "/api/v1/audits/{auditID}", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.audits.view_raw", MethodPost, "/api/v1/audits/{auditID}/raw-views", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.security_events.list", MethodGet, "/api/v1/security-events", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.operations.health", MethodGet, "/api/v1/operations/health", SurfacePortal, AuthPortalSession, systemRole),
		route("admin.operations.events", MethodGet, "/api/v1/operations/events", SurfacePortal, AuthPortalSession, systemRole),
	}
}

func route(
	name RouteName,
	method Method,
	pattern string,
	surface Surface,
	auth AuthMode,
	roles []Role,
) Route {
	return Route{
		Name:    name,
		Method:  method,
		Pattern: pattern,
		Surface: surface,
		Auth:    auth,
		Roles:   append([]Role(nil), roles...),
	}
}
