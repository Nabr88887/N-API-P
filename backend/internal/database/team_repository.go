package database

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var ErrTeamViewNotFound = errors.New("team view not found")

type TeamMemberCursor struct {
	AccountID string
}

type TeamMemberListFilter struct {
	TeamID           string
	ViewerIdentityID string
	ViewerRole       string
	Cursor           *TeamMemberCursor
	Limit            int
}

type TeamMemberRecord struct {
	AccountID string
	Email     string
	Role      string
	Status    string
	JoinedAt  time.Time
}

type TeamMemberPage struct {
	Members []TeamMemberRecord
}

type TeamUsageListFilter struct {
	TeamID           string
	ViewerIdentityID string
	ViewerRole       string
	AccountID        string
	Cursor           *UsageCursor
	Limit            int
}

type TeamUsageAggregate struct {
	RequestCount       int64
	ReportedUsageCount int64
	InputTokens        int64
	OutputTokens       int64
	TotalTokens        int64
}

type TeamUsagePage struct {
	Records   []UsageRecord
	Aggregate TeamUsageAggregate
}

const teamViewAccessSQL = `
SELECT EXISTS (
    SELECT 1
    FROM teams AS team
    WHERE team.id = $1::uuid
      AND (
          $3 = 'system_administrator'
          OR EXISTS (
              SELECT 1
              FROM memberships AS viewer_membership
              WHERE viewer_membership.team_id = team.id
                AND viewer_membership.identity_id = $2::uuid
          )
      )
)`

const listTeamMembersSQL = `
SELECT identity.id::text, identity.email, identity.role, identity.status,
       membership.created_at
FROM memberships AS membership
JOIN identities AS identity ON identity.id = membership.identity_id
WHERE membership.team_id = $1::uuid
  AND (
      $3 = 'system_administrator'
      OR EXISTS (
          SELECT 1
          FROM memberships AS viewer_membership
          WHERE viewer_membership.team_id = membership.team_id
            AND viewer_membership.identity_id = $2::uuid
      )
  )
  AND ($4::uuid IS NULL OR membership.identity_id > $4::uuid)
ORDER BY membership.identity_id ASC
LIMIT $5`

func (r *Repository) ListTeamMembers(ctx context.Context, filter TeamMemberListFilter) (page TeamMemberPage, err error) {
	if err := validateTeamViewFilter(r, filter.TeamID, filter.ViewerIdentityID, filter.ViewerRole, filter.Limit); err != nil {
		return TeamMemberPage{}, err
	}
	if err := r.ensureTeamViewAccess(ctx, filter.TeamID, filter.ViewerIdentityID, filter.ViewerRole); err != nil {
		return TeamMemberPage{}, err
	}
	var cursorID any
	if filter.Cursor != nil {
		cursorID = filter.Cursor.AccountID
	}
	rows, err := r.db.QueryContext(ctx, listTeamMembersSQL, filter.TeamID, filter.ViewerIdentityID, filter.ViewerRole, cursorID, filter.Limit)
	if err != nil {
		return TeamMemberPage{}, fmt.Errorf("query team members: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close team member rows: %w", closeErr))
		}
	}()
	for rows.Next() {
		var member TeamMemberRecord
		if err := rows.Scan(&member.AccountID, &member.Email, &member.Role, &member.Status, &member.JoinedAt); err != nil {
			return TeamMemberPage{}, fmt.Errorf("scan team member: %w", err)
		}
		page.Members = append(page.Members, member)
	}
	if err := rows.Err(); err != nil {
		return TeamMemberPage{}, fmt.Errorf("iterate team members: %w", err)
	}
	return page, nil
}

const listTeamUsageSQL = `
SELECT id::text, audit_id::text, request_id::text, key_id::text,
       identity_id::text, service_account_id::text, team_id::text, model_id,
       outcome, usage_reported, input_tokens, output_tokens, total_tokens,
       price_version, calculated_amount::text, created_at
FROM usage_records AS usage
WHERE usage.team_id = $1::uuid
  AND (
      $3 = 'system_administrator'
      OR EXISTS (
          SELECT 1
          FROM memberships AS viewer_membership
          WHERE viewer_membership.team_id = usage.team_id
            AND viewer_membership.identity_id = $2::uuid
      )
  )
  AND ($4::uuid IS NULL OR usage.identity_id = $4::uuid)
  AND ($5::timestamptz IS NULL OR (usage.created_at, usage.id) < ($5, $6::uuid))
ORDER BY usage.created_at DESC, usage.id DESC
LIMIT $7`

const aggregateTeamUsageSQL = `
SELECT COUNT(*),
       COUNT(*) FILTER (WHERE usage.usage_reported),
       COALESCE(SUM(usage.input_tokens), 0),
       COALESCE(SUM(usage.output_tokens), 0),
       COALESCE(SUM(usage.total_tokens), 0)
FROM usage_records AS usage
WHERE usage.team_id = $1::uuid
  AND (
      $3 = 'system_administrator'
      OR EXISTS (
          SELECT 1
          FROM memberships AS viewer_membership
          WHERE viewer_membership.team_id = usage.team_id
            AND viewer_membership.identity_id = $2::uuid
      )
  )
  AND ($4::uuid IS NULL OR usage.identity_id = $4::uuid)`

func (r *Repository) ListTeamUsage(ctx context.Context, filter TeamUsageListFilter) (page TeamUsagePage, err error) {
	if err := validateTeamViewFilter(r, filter.TeamID, filter.ViewerIdentityID, filter.ViewerRole, filter.Limit); err != nil {
		return TeamUsagePage{}, err
	}
	if err := r.ensureTeamViewAccess(ctx, filter.TeamID, filter.ViewerIdentityID, filter.ViewerRole); err != nil {
		return TeamUsagePage{}, err
	}
	var cursorTime any
	var cursorID any
	var accountID any
	if filter.AccountID != "" {
		accountID = filter.AccountID
	}
	if filter.Cursor != nil {
		cursorTime = filter.Cursor.CreatedAt
		cursorID = filter.Cursor.ID
	}
	rows, err := r.db.QueryContext(ctx, listTeamUsageSQL, filter.TeamID, filter.ViewerIdentityID, filter.ViewerRole, accountID, cursorTime, cursorID, filter.Limit)
	if err != nil {
		return TeamUsagePage{}, fmt.Errorf("query team usage: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close team usage rows: %w", closeErr))
		}
	}()
	for rows.Next() {
		var record UsageRecord
		if err := scanUsageRecord(rows, &record); err != nil {
			return TeamUsagePage{}, fmt.Errorf("scan team usage record: %w", err)
		}
		page.Records = append(page.Records, record)
	}
	if err := rows.Err(); err != nil {
		return TeamUsagePage{}, fmt.Errorf("iterate team usage records: %w", err)
	}
	if err := rows.Close(); err != nil {
		return TeamUsagePage{}, fmt.Errorf("close team usage rows before aggregate: %w", err)
	}
	if err := r.db.QueryRowContext(ctx, aggregateTeamUsageSQL, filter.TeamID, filter.ViewerIdentityID, filter.ViewerRole, accountID).Scan(
		&page.Aggregate.RequestCount,
		&page.Aggregate.ReportedUsageCount,
		&page.Aggregate.InputTokens,
		&page.Aggregate.OutputTokens,
		&page.Aggregate.TotalTokens,
	); err != nil {
		return TeamUsagePage{}, fmt.Errorf("aggregate team usage: %w", err)
	}
	return page, nil
}

func validateTeamViewFilter(r *Repository, teamID, viewerIdentityID, viewerRole string, limit int) error {
	if r == nil || r.db == nil || teamID == "" || viewerIdentityID == "" || limit < 1 || limit > MaxPageSize+1 {
		return ErrInvalidPageSize
	}
	if viewerRole != "team_administrator" && viewerRole != "system_administrator" {
		return ErrTeamViewNotFound
	}
	return nil
}

func (r *Repository) ensureTeamViewAccess(ctx context.Context, teamID, viewerIdentityID, viewerRole string) error {
	var allowed bool
	if err := r.db.QueryRowContext(ctx, teamViewAccessSQL, teamID, viewerIdentityID, viewerRole).Scan(&allowed); err != nil {
		return fmt.Errorf("check team view access: %w", err)
	}
	if !allowed {
		return ErrTeamViewNotFound
	}
	return nil
}
