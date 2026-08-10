package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestAdminPageRequestValidatesCursorAndBoundedLimit(t *testing.T) {
	for name, request := range map[string]PageRequest{
		"default": {},
		"minimum": {Limit: 1},
		"maximum": {Limit: AdminAPIPageSizeMax},
	} {
		t.Run(name, func(t *testing.T) {
			if err := request.Validate(); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}

	for _, limit := range []int{-1, AdminAPIPageSizeMax + 1} {
		if err := (PageRequest{Limit: limit}).Validate(); err == nil {
			t.Fatalf("Validate(limit=%d) = nil, want an error", limit)
		}
	}
	if err := (PageRequest{Cursor: strings.Repeat("x", AdminAPICursorMaxBytes+1)}).Validate(); err == nil {
		t.Fatal("Validate() accepted an oversized cursor")
	}
	if got := (PageRequest{}).EffectiveLimit(); got != AdminAPIPageSizeDefault {
		t.Fatalf("default EffectiveLimit() = %d, want %d", got, AdminAPIPageSizeDefault)
	}
}

func TestAdminPagedResponseUsesStableTypedShape(t *testing.T) {
	createdAt := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	response := PagedResponse[Account]{
		Data:       []Account{{ID: "account-1", Email: "employee@example.test", Role: RoleEmployee, Status: AccountStatusActive, CreatedAt: createdAt}},
		Pagination: Pagination{NextCursor: "opaque-next", HasMore: true},
	}

	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	want := `{"data":[{"id":"account-1","email":"employee@example.test","role":"employee","status":"active","created_at":"2026-08-10T12:00:00Z"}],"pagination":{"next_cursor":"opaque-next","has_more":true}}`
	if string(encoded) != want {
		t.Fatalf("encoded response = %s, want %s", encoded, want)
	}
}

func TestAdminContractsKeepCredentialsOutOfResourceResponses(t *testing.T) {
	key := Key{ID: "key-1", Kind: KeyKindPersonal, Name: "laptop", Prefix: "nk_live_", Status: KeyStatusActive}
	encoded, err := json.Marshal(key)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	for _, forbidden := range []string{"password", "token", "secret", "hash", "verification"} {
		if strings.Contains(strings.ToLower(string(encoded)), forbidden) {
			t.Fatalf("key response contains forbidden field %q: %s", forbidden, encoded)
		}
	}

	issuance := KeyIssuance{Key: key, Credential: IssuedCredential{Value: "synthetic-one-time-value"}}
	encoded, err = json.Marshal(issuance)
	if err != nil {
		t.Fatalf("json.Marshal(issuance) error = %v", err)
	}
	if !strings.Contains(string(encoded), `"credential":{"value":"synthetic-one-time-value"}`) {
		t.Fatalf("issuance response did not expose its explicit one-time credential: %s", encoded)
	}
}

func TestAdminContractsCoverMetadataWithoutRawAuditContent(t *testing.T) {
	response := PagedResponse[AuditMetadata]{
		Data: []AuditMetadata{{ID: "audit-1", RequestID: "request-1", ModelID: "model-a", CaptureStatus: AuditCaptureStatusComplete}},
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	for _, forbidden := range []string{"prompt", "response_content", "ciphertext", "raw_content"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("audit metadata response contains raw-content field %q: %s", forbidden, encoded)
		}
	}
}

func TestAdminContractsFollowExistingAPIV1FieldConvention(t *testing.T) {
	request := IssuePasswordResetRequest{
		Email:                  "employee@example.test",
		ManualIdentityVerified: true,
		CompromiseResponse:     true,
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	want := `{"email":"employee@example.test","manual_identity_verified":true,"compromise_response":true}`
	if string(encoded) != want {
		t.Fatalf("encoded request = %s, want %s", encoded, want)
	}
}

func TestAdminContractsRetainServerSideRouteAuthorization(t *testing.T) {
	anonymous := map[RouteName]bool{
		"portal.activation.create":       true,
		"portal.session.create":          true,
		"portal.password_reset.complete": true,
	}
	for _, route := range Routes() {
		if !strings.HasPrefix(route.Pattern, "/api/v1/") || anonymous[route.Name] {
			continue
		}
		if route.Auth != AuthPortalSession || len(route.Roles) == 0 {
			t.Errorf("route %q lacks server-side portal authorization metadata: %+v", route.Name, route)
		}
	}
}
