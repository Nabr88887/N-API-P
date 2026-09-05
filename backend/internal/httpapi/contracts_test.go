package httpapi

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestErrorResponseUsesStableOpenAICompatibleEnvelope(t *testing.T) {
	status, response := ErrorResponse(CodeInvalidRequest, nil)
	if status != 400 {
		t.Fatalf("status = %d, want 400", status)
	}

	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	want := `{"error":{"message":"Invalid request.","type":"invalid_request_error","param":null,"code":"INVALID_REQUEST"}}`
	if string(encoded) != want {
		t.Fatalf("encoded response = %s, want %s", encoded, want)
	}
}

func TestErrorDefinitionsExposeOnlyApprovedSafeSemantics(t *testing.T) {
	tests := []struct {
		code      ErrorCode
		status    int
		errorType ErrorType
		message   string
	}{
		{CodeInvalidRequest, 400, TypeInvalidRequest, "Invalid request."},
		{CodeAuthenticationRequired, 401, TypeAuthentication, "Authentication required."},
		{CodeInvalidCredentials, 401, TypeAuthentication, "Invalid credentials."},
		{CodeInvalidAPIKey, 401, TypeAuthentication, "Invalid API key."},
		{CodeForbidden, 403, TypePermission, "Access forbidden."},
		{CodeCSRFRejected, 403, TypePermission, "Request origin or CSRF token rejected."},
		{CodeReauthenticationRequired, 403, TypePermission, "Recent password reauthentication required."},
		{CodeModelNotAllowed, 403, TypePermission, "Requested model is not allowed."},
		{CodeNotFound, 404, TypeInvalidRequest, "Resource not found."},
		{CodeUnsupportedEndpoint, 404, TypeInvalidRequest, "Endpoint not supported."},
		{CodeConflict, 409, TypeInvalidRequest, "Resource state conflicts with the request."},
		{CodeKeyLimitReached, 409, TypeInvalidRequest, "Active key limit reached."},
		{CodeRequestTooLarge, 413, TypeInvalidRequest, "Request body is too large."},
		{CodeUnsupportedContentType, 415, TypeInvalidRequest, "Unsupported content type."},
		{CodeRateLimited, 429, TypeRateLimit, "Rate limit exceeded."},
		{CodeInternalError, 500, TypeInternal, "Internal server error."},
		{CodeUpstreamError, 502, TypeUpstream, "Upstream response was invalid."},
		{CodeUpstreamUnavailable, 502, TypeUpstream, "Upstream service is unavailable."},
		{CodeUpstreamResponseTooLarge, 502, TypeUpstream, "Upstream response is too large."},
		{CodeAuditUnavailable, 503, TypeServiceUnavailable, "Audit persistence is unavailable."},
		{CodeUpstreamTimeout, 504, TypeUpstream, "Upstream request timed out."},
		{CodeInvestigationScopeTooBroad, 409, TypeInvalidRequest, "More than 100 retained audit records matched this scope; narrow the time range."},
		{CodeInvestigationNoCandidates, 400, TypeInvalidRequest, "No retained audit records matched this employee and time range."},
	}

	for _, tt := range tests {
		t.Run(string(tt.code), func(t *testing.T) {
			status, response := ErrorResponse(tt.code, stringPointer("fieldName"))
			if status != tt.status {
				t.Fatalf("status = %d, want %d", status, tt.status)
			}
			if response.Error.Code != tt.code {
				t.Fatalf("code = %q, want %q", response.Error.Code, tt.code)
			}
			if response.Error.Type != tt.errorType {
				t.Fatalf("type = %q, want %q", response.Error.Type, tt.errorType)
			}
			if response.Error.Message != tt.message {
				t.Fatalf("message = %q, want %q", response.Error.Message, tt.message)
			}
			if response.Error.Param == nil || *response.Error.Param != "fieldName" {
				t.Fatalf("param = %v, want fieldName", response.Error.Param)
			}
		})
	}
}

func TestUnknownErrorCodeFailsClosedWithoutEchoingInput(t *testing.T) {
	status, response := ErrorResponse(ErrorCode("SECRET_DATABASE_FAILURE"), stringPointer("C:\\secret\\path"))

	if status != 500 {
		t.Fatalf("status = %d, want 500", status)
	}
	if response.Error.Code != CodeInternalError {
		t.Fatalf("code = %q, want %q", response.Error.Code, CodeInternalError)
	}
	if response.Error.Message != "Internal server error." {
		t.Fatalf("message = %q, want safe fallback", response.Error.Message)
	}
	if response.Error.Param != nil {
		t.Fatalf("param = %v, want nil", response.Error.Param)
	}
}

func TestErrorResponseDropsUnsafeParameterNames(t *testing.T) {
	unsafeParameters := []string{
		"C:\\secret\\path",
		"field\r\ninjected-header",
		"field/value",
		"",
	}

	for _, unsafeParameter := range unsafeParameters {
		_, response := ErrorResponse(CodeInvalidRequest, stringPointer(unsafeParameter))
		if response.Error.Param != nil {
			t.Errorf("param %q was retained, want nil", unsafeParameter)
		}
	}

	_, response := ErrorResponse(CodeInvalidRequest, stringPointer("messages[0].content"))
	if response.Error.Param == nil || *response.Error.Param != "messages[0].content" {
		t.Fatalf("safe param = %v, want messages[0].content", response.Error.Param)
	}
}

func TestRoutesMatchApprovedInventory(t *testing.T) {
	expected := expectedRoutes()
	actual := Routes()

	if len(actual) != len(expected) {
		t.Fatalf("route count = %d, want %d", len(actual), len(expected))
	}

	seenNames := make(map[RouteName]struct{}, len(actual))
	for _, route := range actual {
		key := routeKey(route.Method, route.Pattern)
		want, ok := expected[key]
		if !ok {
			t.Errorf("unexpected route %s", key)
			continue
		}
		if !reflect.DeepEqual(route, want) {
			t.Errorf("route %s = %#v, want %#v", key, route, want)
		}
		if _, exists := seenNames[route.Name]; exists {
			t.Errorf("duplicate route name %q", route.Name)
		}
		seenNames[route.Name] = struct{}{}
		delete(expected, key)
	}

	for key := range expected {
		t.Errorf("missing route %s", key)
	}
}

func TestRoutesReturnsIndependentCopies(t *testing.T) {
	first := Routes()
	first[0].Pattern = "/changed"
	if len(first[0].Roles) > 0 {
		first[0].Roles[0] = RoleSystemAdministrator
	}

	second := Routes()
	if second[0].Pattern == "/changed" {
		t.Fatal("Routes() exposes mutable inventory storage")
	}
}

func expectedRoutes() map[string]Route {
	allPortalRoles := []Role{RoleEmployee, RoleTeamAdministrator, RoleSystemAdministrator}
	teamRoles := []Role{RoleTeamAdministrator, RoleSystemAdministrator}
	systemRole := []Role{RoleSystemAdministrator}

	routes := []Route{
		approvedRoute("data.models.list", MethodGet, "/v1/models", SurfaceDataPlane, AuthDownstreamKey, nil),
		approvedRoute("data.chat.create", MethodPost, "/v1/chat/completions", SurfaceDataPlane, AuthDownstreamKey, nil),
		approvedRoute("operations.live", MethodGet, "/health/live", SurfaceOperations, AuthOperatorBoundary, nil),
		approvedRoute("operations.ready", MethodGet, "/health/ready", SurfaceOperations, AuthOperatorBoundary, nil),
		approvedRoute("operations.metrics", MethodGet, "/metrics", SurfaceOperations, AuthOperatorBoundary, nil),

		approvedRoute("portal.activation.create", MethodPost, "/api/v1/activations", SurfacePortal, AuthAnonymous, nil),
		approvedRoute("portal.session.create", MethodPost, "/api/v1/sessions", SurfacePortal, AuthAnonymous, nil),
		approvedRoute("portal.password_reset.complete", MethodPost, "/api/v1/password-reset-completions", SurfacePortal, AuthAnonymous, nil),
		approvedRoute("portal.me.get", MethodGet, "/api/v1/me", SurfacePortal, AuthPortalSession, allPortalRoles),
		approvedRoute("portal.session.delete_current", MethodDelete, "/api/v1/sessions/current", SurfacePortal, AuthPortalSession, allPortalRoles),
		approvedRoute("portal.session.reauthenticate", MethodPost, "/api/v1/sessions/current/reauthentications", SurfacePortal, AuthPortalSession, allPortalRoles),
		approvedRoute("portal.personal_keys.list", MethodGet, "/api/v1/me/personal-keys", SurfacePortal, AuthPortalSession, allPortalRoles),
		approvedRoute("portal.personal_keys.create", MethodPost, "/api/v1/me/personal-keys", SurfacePortal, AuthPortalSession, allPortalRoles),
		approvedRoute("portal.personal_keys.revoke", MethodDelete, "/api/v1/me/personal-keys/{keyID}", SurfacePortal, AuthPortalSession, allPortalRoles),
		approvedRoute("portal.usage.own", MethodGet, "/api/v1/me/usage", SurfacePortal, AuthPortalSession, allPortalRoles),
		approvedRoute("portal.team.members.list", MethodGet, "/api/v1/teams/{teamID}/members", SurfacePortal, AuthPortalSession, teamRoles),
		approvedRoute("portal.team.usage.list", MethodGet, "/api/v1/teams/{teamID}/usage", SurfacePortal, AuthPortalSession, teamRoles),

		approvedRoute("admin.invitations.list", MethodGet, "/api/v1/invitations", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.invitations.create", MethodPost, "/api/v1/invitations", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.users.list", MethodGet, "/api/v1/users", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.users.get", MethodGet, "/api/v1/users/{userID}", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.users.update", MethodPatch, "/api/v1/users/{userID}", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.users.issue_password_reset", MethodPost, "/api/v1/users/{userID}/password-reset-codes", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.teams.list", MethodGet, "/api/v1/teams", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.teams.create", MethodPost, "/api/v1/teams", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.teams.get", MethodGet, "/api/v1/teams/{teamID}", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.teams.update", MethodPatch, "/api/v1/teams/{teamID}", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.teams.delete", MethodDelete, "/api/v1/teams/{teamID}", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.team_members.add", MethodPut, "/api/v1/teams/{teamID}/members/{userID}", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.team_members.remove", MethodDelete, "/api/v1/teams/{teamID}/members/{userID}", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.service_accounts.list", MethodGet, "/api/v1/service-accounts", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.service_accounts.create", MethodPost, "/api/v1/service-accounts", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.service_accounts.get", MethodGet, "/api/v1/service-accounts/{serviceAccountID}", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.service_accounts.update", MethodPatch, "/api/v1/service-accounts/{serviceAccountID}", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.service_accounts.delete", MethodDelete, "/api/v1/service-accounts/{serviceAccountID}", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.service_keys.list", MethodGet, "/api/v1/service-accounts/{serviceAccountID}/keys", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.service_keys.create", MethodPost, "/api/v1/service-accounts/{serviceAccountID}/keys", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.service_keys.revoke", MethodDelete, "/api/v1/service-accounts/{serviceAccountID}/keys/{keyID}", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.service_keys.rotate", MethodPost, "/api/v1/service-accounts/{serviceAccountID}/keys/{keyID}/rotations", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.model_allowlist.get", MethodGet, "/api/v1/model-allowlist", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.model_allowlist.replace", MethodPut, "/api/v1/model-allowlist", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.retention_policy.get", MethodGet, "/api/v1/retention-policy", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.retention_policy.replace", MethodPut, "/api/v1/retention-policy", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.audits.list", MethodGet, "/api/v1/audits", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.audits.get", MethodGet, "/api/v1/audits/{auditID}", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.audits.view_raw", MethodPost, "/api/v1/audits/{auditID}/raw-views", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.investigations.create", MethodPost, "/api/v1/investigation-cases", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.investigations.list", MethodGet, "/api/v1/investigation-cases", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.investigations.candidates", MethodGet, "/api/v1/investigation-cases/{caseID}/audits", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.investigations.raw_view", MethodPost, "/api/v1/investigation-cases/{caseID}/audits/{auditID}/raw-views", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.investigations.grant", MethodPost, "/api/v1/investigation-cases/{caseID}/access-grants", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.investigations.close", MethodPost, "/api/v1/investigation-cases/{caseID}/closures", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.security_events.list", MethodGet, "/api/v1/security-events", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.operations.health", MethodGet, "/api/v1/operations/health", SurfacePortal, AuthPortalSession, systemRole),
		approvedRoute("admin.operations.events", MethodGet, "/api/v1/operations/events", SurfacePortal, AuthPortalSession, systemRole),
	}

	expected := make(map[string]Route, len(routes))
	for _, route := range routes {
		expected[routeKey(route.Method, route.Pattern)] = route
	}
	return expected
}

func approvedRoute(
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
		Roles:   roles,
	}
}

func routeKey(method Method, pattern string) string {
	return string(method) + " " + pattern
}

func stringPointer(value string) *string {
	return &value
}
