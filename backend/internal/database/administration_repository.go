package database

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"n-api-p/internal/access"
)

type administrationCursor struct {
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
}

const listAdministrationAccountsSQL = `
SELECT i.id::text, i.email, i.role, i.status, i.created_at, i.updated_at, i.disabled_at,
       COALESCE(json_agg(m.team_id::text ORDER BY m.team_id) FILTER (WHERE m.team_id IS NOT NULL), '[]'::json)
FROM identities AS i
LEFT JOIN memberships AS m ON m.identity_id = i.id
WHERE ($1::text IS NULL OR i.status = $1)
  AND ($2::text IS NULL OR i.role = $2)
  AND ($3::timestamptz IS NULL OR (i.created_at, i.id) < ($3, $4::uuid))
GROUP BY i.id, i.email, i.role, i.status, i.created_at, i.updated_at, i.disabled_at
ORDER BY i.created_at DESC, i.id DESC
LIMIT $5`

const listAdministrationInvitationsSQL = `
SELECT c.identity_id::text, c.email, m.team_id::text, i.status, c.expires_at, c.created_at, c.id::text
FROM one_time_codes AS c
JOIN identities AS i ON i.id = c.identity_id
JOIN LATERAL (
    SELECT team_id
    FROM memberships
    WHERE identity_id = c.identity_id
    ORDER BY created_at, team_id
    LIMIT 1
) AS m ON true
WHERE c.purpose = 'activation'
  AND ($1::text IS NULL OR i.status = $1)
  AND ($2::timestamptz IS NULL OR (c.created_at, c.id) < ($2, $3::uuid))
ORDER BY c.created_at DESC, c.id DESC
LIMIT $4`

const listAdministrationTeamsSQL = `
SELECT t.id::text, t.name, t.status, COUNT(m.identity_id)::int, t.created_at, t.updated_at, t.disabled_at
FROM teams AS t
LEFT JOIN memberships AS m ON m.team_id = t.id
WHERE ($1::text IS NULL OR t.status = $1)
  AND ($2::timestamptz IS NULL OR (t.created_at, t.id) < ($2, $3::uuid))
GROUP BY t.id, t.name, t.status, t.created_at, t.updated_at, t.disabled_at
ORDER BY t.created_at DESC, t.id DESC
LIMIT $4`

const listAdministrationServiceAccountsSQL = `
SELECT sa.id::text, sa.team_id::text, sa.responsible_identity_id::text,
       sa.name, sa.status, sa.created_at, sa.updated_at, sa.disabled_at
FROM service_accounts AS sa
WHERE ($1::uuid IS NULL OR sa.team_id = $1)
  AND ($2::text IS NULL OR sa.status = $2)
  AND ($3::timestamptz IS NULL OR (sa.created_at, sa.id) < ($3, $4::uuid))
ORDER BY sa.created_at DESC, sa.id DESC
LIMIT $5`

const lockAdministrationTargetIdentitySQL = `
SELECT id::text
FROM identities
WHERE id = $1
FOR UPDATE`

const updateAdministrationRoleSQL = `
UPDATE identities
SET role = $1,
    updated_at = $2
WHERE id = $3`

const insertAdministrationMembershipSQL = `
INSERT INTO memberships (identity_id, team_id, created_at)
VALUES ($1, $2, $3)`

const deleteAdministrationMembershipSQL = `
DELETE FROM memberships
WHERE identity_id = $1
  AND team_id = $2`

const lockAdministrationTeamSQL = `
SELECT id::text
FROM teams
WHERE id = $1
FOR SHARE`

const getAdministrationAccountSQL = `
SELECT i.id::text, i.email, i.role, i.status, i.created_at, i.updated_at, i.disabled_at,
       COALESCE(json_agg(m.team_id::text ORDER BY m.team_id) FILTER (WHERE m.team_id IS NOT NULL), '[]'::json)
FROM identities AS i
LEFT JOIN memberships AS m ON m.identity_id = i.id
WHERE i.id = $1
GROUP BY i.id, i.email, i.role, i.status, i.created_at, i.updated_at, i.disabled_at`

const getAdministrationTeamSQL = `
SELECT t.id::text, t.name, t.status, COUNT(m.identity_id)::int, t.created_at, t.updated_at, t.disabled_at
FROM teams AS t
LEFT JOIN memberships AS m ON m.team_id = t.id
WHERE t.id = $1
GROUP BY t.id, t.name, t.status, t.created_at, t.updated_at, t.disabled_at`

const getAdministrationServiceAccountSQL = `
SELECT id::text, team_id::text, responsible_identity_id::text,
       name, status, created_at, updated_at, disabled_at
FROM service_accounts
WHERE id = $1`

const insertAdministrationTeamSQL = `
INSERT INTO teams (id, name, status, created_at, updated_at)
VALUES ($1, $2, 'active', $3, $3)
RETURNING id::text, name, status, created_at, updated_at, disabled_at`

const updateAdministrationTeamSQL = `
UPDATE teams
SET name = $1,
    updated_at = $2
WHERE id = $3
RETURNING id::text, name, status, created_at, updated_at, disabled_at`

const countAdministrationTeamMembersSQL = `
SELECT COUNT(*)::int
FROM memberships
WHERE team_id = $1`

func (r *Repository) ListAdministrationInvitations(ctx context.Context, filter access.AdministrationInvitationFilter) (page access.AdministrationInvitationPage, err error) {
	cursor, err := decodeAdministrationCursor(filter.Cursor)
	if err != nil || r == nil || r.db == nil {
		return access.AdministrationInvitationPage{}, access.ErrInvalidAdministrationRequest
	}
	var cursorTime, cursorID any
	if cursor != nil {
		cursorTime, cursorID = cursor.CreatedAt.UTC(), cursor.ID
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return access.AdministrationInvitationPage{}, fmt.Errorf("begin administration invitation list transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				err = errors.Join(err, fmt.Errorf("roll back administration invitation list transaction: %w", rollbackErr))
			}
		}
	}()
	if err := requireActiveSystemAdministrator(ctx, tx, filter.ActorIdentityID); err != nil {
		return access.AdministrationInvitationPage{}, err
	}
	rows, err := tx.QueryContext(ctx, listAdministrationInvitationsSQL, optionalAdministrationStatus(filter.Status), cursorTime, cursorID, filter.Limit+1)
	if err != nil {
		return access.AdministrationInvitationPage{}, fmt.Errorf("query administration invitations: %w", err)
	}
	var cursorIDs []string
	for rows.Next() {
		var invitation access.AdministrationInvitation
		var cursorID string
		if err := rows.Scan(&invitation.IdentityID, &invitation.Email, &invitation.TeamID, &invitation.Status, &invitation.ExpiresAt, &invitation.CreatedAt, &cursorID); err != nil {
			rows.Close()
			return access.AdministrationInvitationPage{}, fmt.Errorf("scan administration invitation: %w", err)
		}
		page.Invitations = append(page.Invitations, invitation)
		cursorIDs = append(cursorIDs, cursorID)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return access.AdministrationInvitationPage{}, fmt.Errorf("iterate administration invitations: %w", err)
	}
	if err := rows.Close(); err != nil {
		return access.AdministrationInvitationPage{}, fmt.Errorf("close administration invitation rows: %w", err)
	}
	if len(page.Invitations) > filter.Limit {
		last := page.Invitations[filter.Limit-1]
		page.Invitations = page.Invitations[:filter.Limit]
		page.NextCursor = encodeAdministrationCursor(administrationCursor{CreatedAt: last.CreatedAt, ID: cursorIDs[filter.Limit-1]})
	}
	if err := tx.Commit(); err != nil {
		return access.AdministrationInvitationPage{}, fmt.Errorf("commit administration invitation list transaction: %w", err)
	}
	committed = true
	return page, nil
}

func (r *Repository) ListAdministrationAccounts(ctx context.Context, filter access.AdministrationAccountFilter) (page access.AdministrationAccountPage, err error) {
	cursor, err := decodeAdministrationCursor(filter.Cursor)
	if err != nil {
		return access.AdministrationAccountPage{}, access.ErrInvalidAdministrationRequest
	}
	if r == nil || r.db == nil {
		return access.AdministrationAccountPage{}, access.ErrInvalidAdministrationRequest
	}
	var cursorTime, cursorID any
	if cursor != nil {
		cursorTime, cursorID = cursor.CreatedAt.UTC(), cursor.ID
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return access.AdministrationAccountPage{}, fmt.Errorf("begin administration account list transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				err = errors.Join(err, fmt.Errorf("roll back administration account list transaction: %w", rollbackErr))
			}
		}
	}()
	if err := requireActiveSystemAdministrator(ctx, tx, filter.ActorIdentityID); err != nil {
		return access.AdministrationAccountPage{}, err
	}
	rows, err := tx.QueryContext(ctx, listAdministrationAccountsSQL,
		optionalAdministrationStatus(filter.Status), optionalAdministrationRole(filter.Role), cursorTime, cursorID, filter.Limit+1)
	if err != nil {
		return access.AdministrationAccountPage{}, fmt.Errorf("query administration accounts: %w", err)
	}
	for rows.Next() {
		var account access.AdministrationAccount
		var disabledAt sql.NullTime
		var teamIDs []byte
		if err := rows.Scan(&account.ID, &account.Email, &account.Role, &account.Status, &account.CreatedAt, &account.UpdatedAt, &disabledAt, &teamIDs); err != nil {
			return access.AdministrationAccountPage{}, fmt.Errorf("scan administration account: %w", err)
		}
		if err := json.Unmarshal(teamIDs, &account.TeamIDs); err != nil {
			return access.AdministrationAccountPage{}, fmt.Errorf("decode administration account teams: %w", err)
		}
		if disabledAt.Valid {
			value := disabledAt.Time
			account.DisabledAt = &value
		}
		page.Accounts = append(page.Accounts, account)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return access.AdministrationAccountPage{}, fmt.Errorf("iterate administration accounts: %w", err)
	}
	if err := rows.Close(); err != nil {
		return access.AdministrationAccountPage{}, fmt.Errorf("close administration account rows: %w", err)
	}
	if len(page.Accounts) > filter.Limit {
		last := page.Accounts[filter.Limit-1]
		page.Accounts = page.Accounts[:filter.Limit]
		page.NextCursor = encodeAdministrationCursor(administrationCursor{CreatedAt: last.CreatedAt, ID: last.ID})
	}
	if err := tx.Commit(); err != nil {
		return access.AdministrationAccountPage{}, fmt.Errorf("commit administration account list transaction: %w", err)
	}
	committed = true
	return page, nil
}

func (r *Repository) ListAdministrationTeams(ctx context.Context, filter access.AdministrationTeamFilter) (page access.AdministrationTeamPage, err error) {
	cursor, err := decodeAdministrationCursor(filter.Cursor)
	if err != nil {
		return access.AdministrationTeamPage{}, access.ErrInvalidAdministrationRequest
	}
	if r == nil || r.db == nil {
		return access.AdministrationTeamPage{}, access.ErrInvalidAdministrationRequest
	}
	var cursorTime, cursorID any
	if cursor != nil {
		cursorTime, cursorID = cursor.CreatedAt.UTC(), cursor.ID
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return access.AdministrationTeamPage{}, fmt.Errorf("begin administration team list transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				err = errors.Join(err, fmt.Errorf("roll back administration team list transaction: %w", rollbackErr))
			}
		}
	}()
	if err := requireActiveSystemAdministrator(ctx, tx, filter.ActorIdentityID); err != nil {
		return access.AdministrationTeamPage{}, err
	}
	rows, err := tx.QueryContext(ctx, listAdministrationTeamsSQL,
		optionalAdministrationTeamStatus(filter.Status), cursorTime, cursorID, filter.Limit+1)
	if err != nil {
		return access.AdministrationTeamPage{}, fmt.Errorf("query administration teams: %w", err)
	}
	for rows.Next() {
		var team access.AdministrationTeam
		var disabledAt sql.NullTime
		if err := rows.Scan(&team.ID, &team.Name, &team.Status, &team.MemberCount, &team.CreatedAt, &team.UpdatedAt, &disabledAt); err != nil {
			return access.AdministrationTeamPage{}, fmt.Errorf("scan administration team: %w", err)
		}
		if disabledAt.Valid {
			value := disabledAt.Time
			team.DisabledAt = &value
		}
		page.Teams = append(page.Teams, team)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return access.AdministrationTeamPage{}, fmt.Errorf("iterate administration teams: %w", err)
	}
	if err := rows.Close(); err != nil {
		return access.AdministrationTeamPage{}, fmt.Errorf("close administration team rows: %w", err)
	}
	if len(page.Teams) > filter.Limit {
		last := page.Teams[filter.Limit-1]
		page.Teams = page.Teams[:filter.Limit]
		page.NextCursor = encodeAdministrationCursor(administrationCursor{CreatedAt: last.CreatedAt, ID: last.ID})
	}
	if err := tx.Commit(); err != nil {
		return access.AdministrationTeamPage{}, fmt.Errorf("commit administration team list transaction: %w", err)
	}
	committed = true
	return page, nil
}

func (r *Repository) ListAdministrationServiceAccounts(ctx context.Context, filter access.AdministrationServiceAccountFilter) (page access.AdministrationServiceAccountPage, err error) {
	cursor, err := decodeAdministrationCursor(filter.Cursor)
	if err != nil || r == nil || r.db == nil {
		return access.AdministrationServiceAccountPage{}, access.ErrInvalidAdministrationRequest
	}
	var cursorTime, cursorID any
	if cursor != nil {
		cursorTime, cursorID = cursor.CreatedAt.UTC(), cursor.ID
	}
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return access.AdministrationServiceAccountPage{}, fmt.Errorf("begin administration service account list transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				err = errors.Join(err, fmt.Errorf("roll back administration service account list transaction: %w", rollbackErr))
			}
		}
	}()
	if err := requireActiveSystemAdministrator(ctx, tx, filter.ActorIdentityID); err != nil {
		return access.AdministrationServiceAccountPage{}, err
	}
	rows, err := tx.QueryContext(ctx, listAdministrationServiceAccountsSQL,
		optionalAdministrationString(filter.TeamID), optionalAdministrationServiceStatus(filter.Status), cursorTime, cursorID, filter.Limit+1)
	if err != nil {
		return access.AdministrationServiceAccountPage{}, fmt.Errorf("query administration service accounts: %w", err)
	}
	for rows.Next() {
		var account access.ServiceAccount
		var disabledAt sql.NullTime
		if err := rows.Scan(&account.ID, &account.TeamID, &account.ResponsibleIdentityID, &account.Name, &account.Status, &account.CreatedAt, &account.UpdatedAt, &disabledAt); err != nil {
			rows.Close()
			return access.AdministrationServiceAccountPage{}, fmt.Errorf("scan administration service account: %w", err)
		}
		if disabledAt.Valid {
			value := disabledAt.Time
			account.DisabledAt = &value
		}
		page.ServiceAccounts = append(page.ServiceAccounts, account)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return access.AdministrationServiceAccountPage{}, fmt.Errorf("iterate administration service accounts: %w", err)
	}
	if err := rows.Close(); err != nil {
		return access.AdministrationServiceAccountPage{}, fmt.Errorf("close administration service account rows: %w", err)
	}
	if len(page.ServiceAccounts) > filter.Limit {
		last := page.ServiceAccounts[filter.Limit-1]
		page.ServiceAccounts = page.ServiceAccounts[:filter.Limit]
		page.NextCursor = encodeAdministrationCursor(administrationCursor{CreatedAt: last.CreatedAt, ID: last.ID})
	}
	if err := tx.Commit(); err != nil {
		return access.AdministrationServiceAccountPage{}, fmt.Errorf("commit administration service account list transaction: %w", err)
	}
	committed = true
	return page, nil
}

func (r *Repository) GetAdministrationAccount(ctx context.Context, actorIdentityID, identityID string) (account access.AdministrationAccount, err error) {
	if !validAdministrationUUID(actorIdentityID) || !validAdministrationUUID(identityID) || r == nil || r.db == nil {
		return access.AdministrationAccount{}, access.ErrInvalidAdministrationRequest
	}
	err = r.withAdministrationRead(ctx, actorIdentityID, "get administration account", func(tx *sql.Tx) error {
		var disabledAt sql.NullTime
		var teamIDs []byte
		if err := tx.QueryRowContext(ctx, getAdministrationAccountSQL, identityID).Scan(
			&account.ID, &account.Email, &account.Role, &account.Status, &account.CreatedAt, &account.UpdatedAt, &disabledAt, &teamIDs,
		); errors.Is(err, sql.ErrNoRows) {
			return access.ErrAdministrationNotFound
		} else if err != nil {
			return fmt.Errorf("query administration account: %w", err)
		}
		if err := json.Unmarshal(teamIDs, &account.TeamIDs); err != nil {
			return fmt.Errorf("decode administration account teams: %w", err)
		}
		if disabledAt.Valid {
			value := disabledAt.Time
			account.DisabledAt = &value
		}
		return nil
	})
	return account, err
}

func (r *Repository) GetAdministrationTeam(ctx context.Context, actorIdentityID, teamID string) (team access.AdministrationTeam, err error) {
	if !validAdministrationUUID(actorIdentityID) || !validAdministrationUUID(teamID) || r == nil || r.db == nil {
		return access.AdministrationTeam{}, access.ErrInvalidAdministrationRequest
	}
	err = r.withAdministrationRead(ctx, actorIdentityID, "get administration team", func(tx *sql.Tx) error {
		var disabledAt sql.NullTime
		if err := tx.QueryRowContext(ctx, getAdministrationTeamSQL, teamID).Scan(
			&team.ID, &team.Name, &team.Status, &team.MemberCount, &team.CreatedAt, &team.UpdatedAt, &disabledAt,
		); errors.Is(err, sql.ErrNoRows) {
			return access.ErrAdministrationNotFound
		} else if err != nil {
			return fmt.Errorf("query administration team: %w", err)
		}
		if disabledAt.Valid {
			value := disabledAt.Time
			team.DisabledAt = &value
		}
		return nil
	})
	return team, err
}

func (r *Repository) GetAdministrationServiceAccount(ctx context.Context, actorIdentityID, serviceAccountID string) (account access.ServiceAccount, err error) {
	if !validAdministrationUUID(actorIdentityID) || !validAdministrationUUID(serviceAccountID) || r == nil || r.db == nil {
		return access.ServiceAccount{}, access.ErrInvalidAdministrationRequest
	}
	err = r.withAdministrationRead(ctx, actorIdentityID, "get administration service account", func(tx *sql.Tx) error {
		var disabledAt sql.NullTime
		if err := tx.QueryRowContext(ctx, getAdministrationServiceAccountSQL, serviceAccountID).Scan(
			&account.ID, &account.TeamID, &account.ResponsibleIdentityID, &account.Name, &account.Status,
			&account.CreatedAt, &account.UpdatedAt, &disabledAt,
		); errors.Is(err, sql.ErrNoRows) {
			return access.ErrAdministrationNotFound
		} else if err != nil {
			return fmt.Errorf("query administration service account: %w", err)
		}
		if disabledAt.Valid {
			value := disabledAt.Time
			account.DisabledAt = &value
		}
		return nil
	})
	return account, err
}

func (r *Repository) ChangeAdministrationTeam(ctx context.Context, change access.TeamChange) (team access.AdministrationTeam, err error) {
	if !validAdministrationUUID(change.EventID) || !validAdministrationUUID(change.TeamID) || !validAdministrationUUID(change.ActorIdentityID) || !validAdministrationUUID(change.RequestID) || strings.TrimSpace(change.Name) == "" {
		return access.AdministrationTeam{}, access.ErrInvalidAdministrationRequest
	}
	err = r.withTransaction(ctx, "change administration team", func(tx *sql.Tx) error {
		if err := requireActiveSystemAdministrator(ctx, tx, change.ActorIdentityID); err != nil {
			return err
		}
		var disabledAt sql.NullTime
		var row *sql.Row
		switch change.Operation {
		case access.TeamCreated:
			row = tx.QueryRowContext(ctx, insertAdministrationTeamSQL, change.TeamID, change.Name, change.ChangedAt.UTC())
		case access.TeamUpdated:
			row = tx.QueryRowContext(ctx, updateAdministrationTeamSQL, change.Name, change.ChangedAt.UTC(), change.TeamID)
		default:
			return access.ErrInvalidAdministrationRequest
		}
		if err := row.Scan(&team.ID, &team.Name, &team.Status, &team.CreatedAt, &team.UpdatedAt, &disabledAt); isUniqueViolation(err) {
			return access.ErrAdministrationConflict
		} else if errors.Is(err, sql.ErrNoRows) {
			return access.ErrAdministrationNotFound
		} else if err != nil {
			return fmt.Errorf("write administration team: %w", err)
		}
		if disabledAt.Valid {
			value := disabledAt.Time
			team.DisabledAt = &value
		}
		if err := tx.QueryRowContext(ctx, countAdministrationTeamMembersSQL, change.TeamID).Scan(&team.MemberCount); err != nil {
			return fmt.Errorf("count administration team members: %w", err)
		}
		return appendSecurityEventTx(ctx, tx, access.SecurityEvent{
			ID: change.EventID, EventType: string(change.Operation), ActorIdentityID: change.ActorIdentityID,
			RequestID: change.RequestID, Outcome: access.SecurityEventSuccess, Reason: change.TeamID,
			DetailCode: "team_metadata", OccurredAt: change.ChangedAt.UTC(),
		})
	})
	return team, err
}

func (r *Repository) withAdministrationRead(ctx context.Context, actorIdentityID, operation string, run func(*sql.Tx) error) (err error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return fmt.Errorf("begin %s transaction: %w", operation, err)
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				err = errors.Join(err, fmt.Errorf("roll back %s transaction: %w", operation, rollbackErr))
			}
		}
	}()
	if err := requireActiveSystemAdministrator(ctx, tx, actorIdentityID); err != nil {
		return err
	}
	if err := run(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit %s transaction: %w", operation, err)
	}
	committed = true
	return nil
}

func (r *Repository) ChangeIdentityRole(ctx context.Context, change access.RoleChange) error {
	if !validAdministrationUUID(change.EventID) || !validAdministrationUUID(change.IdentityID) || !validAdministrationUUID(change.ActorIdentityID) || !validAdministrationUUID(change.RequestID) {
		return access.ErrInvalidAdministrationRequest
	}
	return r.withTransaction(ctx, "change identity role", func(tx *sql.Tx) error {
		if err := requireActiveSystemAdministrator(ctx, tx, change.ActorIdentityID); err != nil {
			return err
		}
		var targetID string
		if err := tx.QueryRowContext(ctx, lockAdministrationTargetIdentitySQL, change.IdentityID).Scan(&targetID); errors.Is(err, sql.ErrNoRows) {
			return access.ErrAdministrationNotFound
		} else if err != nil {
			return fmt.Errorf("lock role target: %w", err)
		}
		if _, err := tx.ExecContext(ctx, updateAdministrationRoleSQL, change.Role, change.ChangedAt.UTC(), change.IdentityID); err != nil {
			return fmt.Errorf("update identity role: %w", err)
		}
		if change.Role != access.RoleEmployee {
			if _, err := tx.ExecContext(ctx, revokeResponsibleServiceAccountKeysSQL, change.ChangedAt.UTC(), change.IdentityID, change.ActorIdentityID, change.RequestID); err != nil {
				return fmt.Errorf("revoke service keys after role change: %w", err)
			}
		}
		return appendSecurityEventTx(ctx, tx, access.SecurityEvent{
			ID: change.EventID, EventType: "role_change", ActorIdentityID: change.ActorIdentityID,
			TargetIdentityID: change.IdentityID, RequestID: change.RequestID, Outcome: access.SecurityEventSuccess,
			DetailCode: string(change.Role), OccurredAt: change.ChangedAt.UTC(),
		})
	})
}

func (r *Repository) ChangeMembership(ctx context.Context, change access.MembershipChange) error {
	if !validAdministrationUUID(change.EventID) || !validAdministrationUUID(change.IdentityID) || !validAdministrationUUID(change.TeamID) || !validAdministrationUUID(change.ActorIdentityID) || !validAdministrationUUID(change.RequestID) {
		return access.ErrInvalidAdministrationRequest
	}
	return r.withTransaction(ctx, "change membership", func(tx *sql.Tx) error {
		if err := requireActiveSystemAdministrator(ctx, tx, change.ActorIdentityID); err != nil {
			return err
		}
		var targetID string
		if err := tx.QueryRowContext(ctx, lockAdministrationTargetIdentitySQL, change.IdentityID).Scan(&targetID); errors.Is(err, sql.ErrNoRows) {
			return access.ErrAdministrationNotFound
		} else if err != nil {
			return fmt.Errorf("lock membership identity: %w", err)
		}
		var teamID string
		if err := tx.QueryRowContext(ctx, lockAdministrationTeamSQL, change.TeamID).Scan(&teamID); errors.Is(err, sql.ErrNoRows) {
			return access.ErrAdministrationNotFound
		} else if err != nil {
			return fmt.Errorf("lock membership team: %w", err)
		}
		var err error
		switch change.Operation {
		case access.MembershipAdded:
			_, err = tx.ExecContext(ctx, insertAdministrationMembershipSQL, change.IdentityID, change.TeamID, change.ChangedAt.UTC())
			if isUniqueViolation(err) {
				return access.ErrAdministrationConflict
			}
		case access.MembershipRemoved:
			var result sql.Result
			result, err = tx.ExecContext(ctx, deleteAdministrationMembershipSQL, change.IdentityID, change.TeamID)
			if isForeignKeyViolation(err) {
				return access.ErrAdministrationConflict
			}
			if err == nil {
				if affected, countErr := result.RowsAffected(); countErr != nil {
					return fmt.Errorf("count removed membership: %w", countErr)
				} else if affected != 1 {
					return access.ErrAdministrationNotFound
				}
			}
		default:
			return access.ErrInvalidAdministrationRequest
		}
		if err != nil {
			return fmt.Errorf("change membership row: %w", err)
		}
		return appendSecurityEventTx(ctx, tx, access.SecurityEvent{
			ID: change.EventID, EventType: "team_change", ActorIdentityID: change.ActorIdentityID,
			TargetIdentityID: change.IdentityID, RequestID: change.RequestID, Outcome: access.SecurityEventSuccess,
			Reason: change.TeamID, DetailCode: string(change.Operation), OccurredAt: change.ChangedAt.UTC(),
		})
	})
}

func encodeAdministrationCursor(cursor administrationCursor) string {
	payload, _ := json.Marshal(cursor)
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodeAdministrationCursor(value string) (*administrationCursor, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if len(value) > 512 {
		return nil, access.ErrInvalidAdministrationRequest
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, access.ErrInvalidAdministrationRequest
	}
	var cursor administrationCursor
	if err := json.Unmarshal(payload, &cursor); err != nil || cursor.CreatedAt.IsZero() || !validAdministrationUUID(cursor.ID) {
		return nil, access.ErrInvalidAdministrationRequest
	}
	return &cursor, nil
}

func validAdministrationUUID(value string) bool {
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

func optionalAdministrationStatus(value *access.IdentityStatus) any {
	if value == nil {
		return nil
	}
	return string(*value)
}

func optionalAdministrationRole(value *access.Role) any {
	if value == nil {
		return nil
	}
	return string(*value)
}

func optionalAdministrationTeamStatus(value *string) any {
	if value == nil {
		return nil
	}
	return strings.TrimSpace(*value)
}

func optionalAdministrationString(value *string) any {
	if value == nil {
		return nil
	}
	return strings.TrimSpace(*value)
}

func optionalAdministrationServiceStatus(value *access.ServiceAccountStatus) any {
	if value == nil {
		return nil
	}
	return string(*value)
}

func isUniqueViolation(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "23505"
}

func isForeignKeyViolation(err error) bool {
	var postgresError *pgconn.PgError
	return errors.As(err, &postgresError) && postgresError.Code == "23503"
}

var _ access.AdministrationRepository = (*Repository)(nil)
