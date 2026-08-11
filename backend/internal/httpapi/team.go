package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"n-api-p/internal/access"
	"n-api-p/internal/database"
)

var (
	ErrTeamPortalDependencies = errors.New("team portal reader is required")
	ErrTeamPortalRoute        = errors.New("team portal route is missing from inventory")
)

type TeamPortalReader interface {
	ListTeamMembers(context.Context, database.TeamMemberListFilter) (database.TeamMemberPage, error)
	ListTeamUsage(context.Context, database.TeamUsageListFilter) (database.TeamUsagePage, error)
}

func NewTeamMembersHandler(reader TeamPortalReader) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := teamViewSession(request)
		if !ok {
			writeErrorResponse(writer, CodeForbidden)
			return
		}
		teamID, err := teamIDFromRequest(request, "/members")
		if err != nil {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		limit, cursor, err := parseTeamMemberPage(request)
		if err != nil {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		page, err := reader.ListTeamMembers(request.Context(), database.TeamMemberListFilter{
			TeamID: teamID, ViewerIdentityID: session.IdentityID, ViewerRole: string(session.Role), Cursor: cursor, Limit: limit + 1,
		})
		if err != nil {
			writeTeamViewError(writer, err)
			return
		}
		hasMore := len(page.Members) > limit
		if hasMore {
			page.Members = page.Members[:limit]
		}
		data := make([]TeamMember, 0, len(page.Members))
		for _, member := range page.Members {
			data = append(data, TeamMember{AccountID: member.AccountID, Email: member.Email, Role: Role(member.Role), Status: AccountStatus(member.Status), JoinedAt: member.JoinedAt})
		}
		nextCursor := ""
		if hasMore && len(page.Members) > 0 {
			nextCursor = encodeTeamMemberCursor(&database.TeamMemberCursor{AccountID: page.Members[len(page.Members)-1].AccountID})
		}
		writePagedJSON(writer, http.StatusOK, PagedResponse[TeamMember]{Data: data, Pagination: Pagination{NextCursor: nextCursor, HasMore: nextCursor != ""}})
	})
}

func NewTeamUsageHandler(reader TeamPortalReader) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		session, ok := teamViewSession(request)
		if !ok {
			writeErrorResponse(writer, CodeForbidden)
			return
		}
		teamID, err := teamIDFromRequest(request, "/usage")
		if err != nil {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		limit, cursor, err := parseEmployeePage(request)
		if err != nil {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		accountID := strings.TrimSpace(request.URL.Query().Get("account_id"))
		if accountID != "" && !validCursorID(accountID) {
			writeErrorResponse(writer, CodeInvalidRequest)
			return
		}
		page, err := reader.ListTeamUsage(request.Context(), database.TeamUsageListFilter{
			TeamID: teamID, ViewerIdentityID: session.IdentityID, ViewerRole: string(session.Role), AccountID: accountID, Cursor: cursorToUsageCursor(cursor), Limit: limit + 1,
		})
		if err != nil {
			writeTeamViewError(writer, err)
			return
		}
		hasMore := len(page.Records) > limit
		if hasMore {
			page.Records = page.Records[:limit]
		}
		data := make([]UsageRecord, 0, len(page.Records))
		for _, record := range page.Records {
			data = append(data, usageResponse(record))
		}
		nextCursor := ""
		if hasMore && len(page.Records) > 0 {
			last := page.Records[len(page.Records)-1]
			nextCursor = encodeEmployeeCursor(&employeeCursor{CreatedAt: last.CreatedAt, ID: last.ID})
		}
		writeJSON(writer, http.StatusOK, TeamUsageResponse{
			Data:       data,
			Pagination: Pagination{NextCursor: nextCursor, HasMore: nextCursor != ""},
			Aggregate: TeamUsageAggregate{
				RequestCount: page.Aggregate.RequestCount, ReportedUsageCount: page.Aggregate.ReportedUsageCount,
				InputTokens: page.Aggregate.InputTokens, OutputTokens: page.Aggregate.OutputTokens, TotalTokens: page.Aggregate.TotalTokens,
			},
		})
	})
}

func NewTeamPortalRouter(sessions PortalSessionService, allowedOrigin string, reader TeamPortalReader) (http.Handler, error) {
	if reader == nil {
		return nil, ErrTeamPortalDependencies
	}
	middleware, err := NewPortalSessionMiddleware(sessions, allowedOrigin)
	if err != nil {
		return nil, err
	}
	memberRoute := routeByNameValue(RouteName("portal.team.members.list"))
	usageRoute := routeByNameValue(RouteName("portal.team.usage.list"))
	for _, route := range []Route{memberRoute, usageRoute} {
		if route.Pattern == "" || route.Auth != AuthPortalSession {
			return nil, ErrTeamPortalRoute
		}
	}
	guard := NewAuthorizationGuard()
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/teams/{teamID}/members", guard.Wrap(memberRoute, NewTeamMembersHandler(reader)))
	mux.Handle("GET /api/v1/teams/{teamID}/usage", guard.Wrap(usageRoute, NewTeamUsageHandler(reader)))
	return middleware.Wrap(mux), nil
}

func teamViewSession(request *http.Request) (access.ActivePortalSession, bool) {
	session, ok := PortalSessionFromContext(request.Context())
	if !ok || session.IdentityID == "" {
		return access.ActivePortalSession{}, false
	}
	if session.Role != access.RoleTeamAdministrator && session.Role != access.RoleSystemAdministrator {
		return access.ActivePortalSession{}, false
	}
	return session, true
}

func teamIDFromRequest(request *http.Request, suffix string) (string, error) {
	teamID := request.PathValue("teamID")
	if teamID == "" {
		teamID = strings.TrimPrefix(request.URL.Path, "/api/v1/teams/")
		teamID = strings.TrimSuffix(teamID, suffix)
	}
	if !validCursorID(teamID) {
		return "", ErrInvalidPageRequest
	}
	return teamID, nil
}

func parseTeamMemberPage(request *http.Request) (int, *database.TeamMemberCursor, error) {
	limit, err := parsePageLimit(request)
	if err != nil {
		return 0, nil, err
	}
	cursor, err := decodeTeamMemberCursor(request.URL.Query().Get("cursor"))
	return limit, cursor, err
}

func encodeTeamMemberCursor(cursor *database.TeamMemberCursor) string {
	if cursor == nil {
		return ""
	}
	value, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(value)
}

func decodeTeamMemberCursor(value string) (*database.TeamMemberCursor, error) {
	if value == "" {
		return nil, nil
	}
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) > AdminAPICursorMaxBytes {
		return nil, ErrInvalidPageRequest
	}
	var cursor database.TeamMemberCursor
	if err := json.Unmarshal(decoded, &cursor); err != nil || !validCursorID(cursor.AccountID) {
		return nil, ErrInvalidPageRequest
	}
	return &cursor, nil
}

func writeTeamViewError(writer http.ResponseWriter, err error) {
	if errors.Is(err, database.ErrTeamViewNotFound) {
		writeErrorResponse(writer, CodeNotFound)
		return
	}
	if errors.Is(err, database.ErrInvalidPageSize) {
		writeErrorResponse(writer, CodeInvalidRequest)
		return
	}
	writeErrorResponse(writer, CodeInternalError)
}
