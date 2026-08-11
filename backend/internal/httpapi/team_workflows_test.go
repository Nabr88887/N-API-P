package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/database"
)

const (
	testTeamID      = "20000000-0000-0000-0000-000000000001"
	testTeamAdminID = "30000000-0000-0000-0000-000000000001"
)

func TestTeamMembersUsesAssignedTeamScopeAndBoundedPagination(t *testing.T) {
	joinedAt := time.Date(2026, 8, 11, 4, 0, 0, 0, time.UTC)
	reader := &fakeTeamPortalReader{memberPage: database.TeamMemberPage{Members: []database.TeamMemberRecord{
		{AccountID: "40000000-0000-0000-0000-000000000001", Email: "member@example.internal", Role: "employee", Status: "active", JoinedAt: joinedAt},
		{AccountID: "40000000-0000-0000-0000-000000000002", Email: "next@example.internal", Role: "employee", Status: "active", JoinedAt: joinedAt.Add(-time.Minute)},
	}}}
	handler := withEmployeeSession(NewTeamMembersHandler(reader), access.ActivePortalSession{IdentityID: testTeamAdminID, Role: access.RoleTeamAdministrator})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/teams/"+testTeamID+"/members?limit=1", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if reader.memberFilter.TeamID != testTeamID || reader.memberFilter.ViewerIdentityID != testTeamAdminID || reader.memberFilter.ViewerRole != string(access.RoleTeamAdministrator) || reader.memberFilter.Limit != 2 {
		t.Fatalf("member filter = %#v, want assigned-team scope and lookahead limit", reader.memberFilter)
	}
	var response PagedResponse[TeamMember]
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode member page: %v", err)
	}
	if len(response.Data) != 1 || response.Data[0].Email != "member@example.internal" || response.Data[0].Status != AccountStatusActive || !response.Pagination.HasMore || response.Pagination.NextCursor == "" {
		t.Fatalf("member page = %#v, want one member and opaque next page", response)
	}
	reader.memberPage = database.TeamMemberPage{}
	secondPage := httptest.NewRecorder()
	handler.ServeHTTP(secondPage, httptest.NewRequest(http.MethodGet, "/api/v1/teams/"+testTeamID+"/members?limit=1&cursor="+response.Pagination.NextCursor, nil))
	if secondPage.Code != http.StatusOK || reader.memberFilter.Cursor == nil || reader.memberFilter.Cursor.AccountID != response.Data[0].AccountID {
		t.Fatalf("second member request = (%d, %#v), want decoded opaque cursor", secondPage.Code, reader.memberFilter.Cursor)
	}
	assertTeamResponseHasNoSensitiveFields(t, recorder.Body.Bytes())
}

func TestTeamUsageReturnsWholeTeamAggregateAndContentFreeRecords(t *testing.T) {
	createdAt := time.Date(2026, 8, 11, 5, 0, 0, 0, time.UTC)
	memberID := "40000000-0000-0000-0000-000000000001"
	reader := &fakeTeamPortalReader{usagePage: database.TeamUsagePage{
		Records:   []database.UsageRecord{{ID: "50000000-0000-0000-0000-000000000001", AuditID: "51000000-0000-0000-0000-000000000001", RequestID: "52000000-0000-0000-0000-000000000001", KeyID: "53000000-0000-0000-0000-000000000001", IdentityID: memberID, TeamID: testTeamID, ModelID: "gpt-test", Outcome: "success", UsageReported: true, CreatedAt: createdAt}},
		Aggregate: database.TeamUsageAggregate{RequestCount: 7, ReportedUsageCount: 6, InputTokens: 80, OutputTokens: 20, TotalTokens: 100},
	}}
	handler := withEmployeeSession(NewTeamUsageHandler(reader), access.ActivePortalSession{IdentityID: testTeamAdminID, Role: access.RoleTeamAdministrator})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/teams/"+testTeamID+"/usage?limit=50&account_id="+memberID, nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	if reader.usageFilter.TeamID != testTeamID || reader.usageFilter.ViewerIdentityID != testTeamAdminID || reader.usageFilter.AccountID != memberID || reader.usageFilter.Limit != 51 {
		t.Fatalf("usage filter = %#v, want assigned-team scope and lookahead limit", reader.usageFilter)
	}
	var response TeamUsageResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode team usage: %v", err)
	}
	if len(response.Data) != 1 || response.Aggregate.RequestCount != 7 || response.Aggregate.TotalTokens != 100 {
		t.Fatalf("team usage response = %#v, want repository aggregate independent of current page", response)
	}
	assertTeamResponseHasNoSensitiveFields(t, recorder.Body.Bytes())
}

func TestTeamViewsHideUnassignedTeamsAsNotFound(t *testing.T) {
	reader := &fakeTeamPortalReader{memberErr: database.ErrTeamViewNotFound, usageErr: database.ErrTeamViewNotFound}
	session := access.ActivePortalSession{IdentityID: testTeamAdminID, Role: access.RoleTeamAdministrator}
	for name, test := range map[string]struct {
		handler http.Handler
		path    string
	}{
		"members": {NewTeamMembersHandler(reader), "/api/v1/teams/" + testTeamID + "/members"},
		"usage":   {NewTeamUsageHandler(reader), "/api/v1/teams/" + testTeamID + "/usage"},
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			withEmployeeSession(test.handler, session).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))
			assertHTTPError(t, recorder, http.StatusNotFound, CodeNotFound)
		})
	}
}

func TestTeamViewGuardRejectsEmployeeBeforeRepository(t *testing.T) {
	reader := &fakeTeamPortalReader{}
	route := routeByNameValue(RouteName("portal.team.members.list"))
	handler := NewAuthorizationGuard().Wrap(route, NewTeamMembersHandler(reader))
	handler = withEmployeeSession(handler, access.ActivePortalSession{IdentityID: "employee-1", Role: access.RoleEmployee})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/teams/"+testTeamID+"/members", nil))

	assertHTTPError(t, recorder, http.StatusForbidden, CodeForbidden)
	if reader.memberCalls != 0 {
		t.Fatal("team repository was called for an employee")
	}
}

func TestTeamViewsRejectMalformedTeamAndPagination(t *testing.T) {
	reader := &fakeTeamPortalReader{}
	session := access.ActivePortalSession{IdentityID: testTeamAdminID, Role: access.RoleTeamAdministrator}
	for name, test := range map[string]struct {
		handler http.Handler
		path    string
	}{
		"invalid team":          {NewTeamMembersHandler(reader), "/api/v1/teams/not-a-uuid/members"},
		"invalid limit":         {NewTeamUsageHandler(reader), "/api/v1/teams/" + testTeamID + "/usage?limit=101"},
		"invalid member filter": {NewTeamUsageHandler(reader), "/api/v1/teams/" + testTeamID + "/usage?account_id=not-a-uuid"},
	} {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			withEmployeeSession(test.handler, session).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, test.path, nil))
			assertHTTPError(t, recorder, http.StatusBadRequest, CodeInvalidRequest)
		})
	}
}

func assertTeamResponseHasNoSensitiveFields(t *testing.T, body []byte) {
	t.Helper()
	lower := strings.ToLower(string(body))
	for _, forbidden := range []string{"prompt", "response_content", "raw_content", "ciphertext", "credential", "verification_hash", "password"} {
		if bytes.Contains([]byte(lower), []byte(forbidden)) {
			t.Fatalf("team response contains forbidden field %q: %s", forbidden, body)
		}
	}
}

type fakeTeamPortalReader struct {
	memberCalls  int
	memberFilter database.TeamMemberListFilter
	memberPage   database.TeamMemberPage
	memberErr    error
	usageFilter  database.TeamUsageListFilter
	usagePage    database.TeamUsagePage
	usageErr     error
}

func (fake *fakeTeamPortalReader) ListTeamMembers(_ context.Context, filter database.TeamMemberListFilter) (database.TeamMemberPage, error) {
	fake.memberCalls++
	fake.memberFilter = filter
	return fake.memberPage, fake.memberErr
}

func (fake *fakeTeamPortalReader) ListTeamUsage(_ context.Context, filter database.TeamUsageListFilter) (database.TeamUsagePage, error) {
	fake.usageFilter = filter
	return fake.usagePage, fake.usageErr
}
