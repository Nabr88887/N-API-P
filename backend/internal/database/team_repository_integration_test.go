//go:build integration

package database

import (
	"context"
	"errors"
	"testing"

	"n-api-p/internal/usage"
)

func TestRepositoryTeamViewsEnforceAssignmentPaginationAndMemberAggregate(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	const teamAdminID = "82000000-0000-0000-0000-000000000002"
	mustExec(t, db, `INSERT INTO identities (id, email, role, status) VALUES ($1, 'team-admin@example.internal', 'team_administrator', 'active')`, teamAdminID)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id, created_at) VALUES ($1, $2, $3)`, teamAdminID, fixture.teamID, fixture.now)

	repository := NewRepository(db)
	firstMembers, err := repository.ListTeamMembers(context.Background(), TeamMemberListFilter{
		TeamID: fixture.teamID, ViewerIdentityID: teamAdminID, ViewerRole: "team_administrator", Limit: 1,
	})
	if err != nil || len(firstMembers.Members) != 1 {
		t.Fatalf("first member page = (%#v, %v), want one assigned-team member", firstMembers, err)
	}
	secondMembers, err := repository.ListTeamMembers(context.Background(), TeamMemberListFilter{
		TeamID: fixture.teamID, ViewerIdentityID: teamAdminID, ViewerRole: "team_administrator",
		Cursor: &TeamMemberCursor{AccountID: firstMembers.Members[0].AccountID}, Limit: 1,
	})
	if err != nil || len(secondMembers.Members) != 1 || secondMembers.Members[0].AccountID == firstMembers.Members[0].AccountID {
		t.Fatalf("second member page = (%#v, %v), want a distinct cursor page", secondMembers, err)
	}

	finalizeUsageAudit(t, db, fixture.auditID, "complete", "success", "upstream-team-usage", fixture.now)
	record, err := usage.NewRecord(usage.RecordInput{
		ID: fixtureUsageID(9), AuditID: fixture.auditID, RequestID: fixture.requestID, KeyID: fixture.keyID,
		OwnerKind: usage.OwnerKindPersonal, IdentityID: fixture.identityID, TeamID: fixture.teamID,
		ModelID: "gpt-test", UpstreamRequestID: "upstream-team-usage", Outcome: usage.OutcomeSuccess,
		Usage: &usage.TokenUsage{InputTokens: 30, OutputTokens: 12, TotalTokens: 42}, CreatedAt: fixture.now,
	})
	if err != nil {
		t.Fatalf("usage.NewRecord() error = %v", err)
	}
	if err := repository.CreateUsageRecord(context.Background(), record); err != nil {
		t.Fatalf("CreateUsageRecord() error = %v", err)
	}
	teamUsage, err := repository.ListTeamUsage(context.Background(), TeamUsageListFilter{
		TeamID: fixture.teamID, ViewerIdentityID: teamAdminID, ViewerRole: "team_administrator",
		AccountID: fixture.identityID, Limit: 10,
	})
	if err != nil || len(teamUsage.Records) != 1 {
		t.Fatalf("team usage = (%#v, %v), want one member record", teamUsage, err)
	}
	if teamUsage.Aggregate.RequestCount != 1 || teamUsage.Aggregate.ReportedUsageCount != 1 || teamUsage.Aggregate.TotalTokens != 42 {
		t.Fatalf("team aggregate = %#v, want complete member totals", teamUsage.Aggregate)
	}

	const otherTeamID = "81000000-0000-0000-0000-000000000002"
	mustExec(t, db, `INSERT INTO teams (id, name, status) VALUES ($1, 'Other team', 'active')`, otherTeamID)
	if _, err := repository.ListTeamMembers(context.Background(), TeamMemberListFilter{
		TeamID: otherTeamID, ViewerIdentityID: teamAdminID, ViewerRole: "team_administrator", Limit: 10,
	}); !errors.Is(err, ErrTeamViewNotFound) {
		t.Fatalf("cross-team member view error = %v, want ErrTeamViewNotFound", err)
	}
	if _, err := repository.ListTeamUsage(context.Background(), TeamUsageListFilter{
		TeamID: otherTeamID, ViewerIdentityID: teamAdminID, ViewerRole: "team_administrator", Limit: 10,
	}); !errors.Is(err, ErrTeamViewNotFound) {
		t.Fatalf("cross-team usage view error = %v, want ErrTeamViewNotFound", err)
	}
	if _, err := repository.ListTeamMembers(context.Background(), TeamMemberListFilter{
		TeamID: otherTeamID, ViewerIdentityID: fixture.identityID, ViewerRole: "system_administrator", Limit: 10,
	}); err != nil {
		t.Fatalf("system-administrator team view error = %v", err)
	}
}
