package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"n-api-p/internal/access"
)

func TestElevatedAuditAccessIssuesGrantBoundToSessionAndClampedToSessionExpiry(t *testing.T) {
	now := time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC)
	session := elevatedAuditTestSession(now, now.Add(12*time.Hour))
	repository := &elevatedAuditRepositoryFake{}
	service := newTestElevatedAuditAccessService(repository, now)

	grant, err := service.Issue(context.Background(), IssueElevatedAuditGrantInput{
		Session: session, Purpose: "  review synthetic policy alert  ", RequestID: elevatedAuditUUID(1),
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if grant.ID == "" || grant.ActorIdentityID != session.IdentityID || grant.SessionID != session.SessionID {
		t.Fatalf("grant binding = %+v, want actor/session binding", grant)
	}
	if grant.Purpose != "review synthetic policy alert" {
		t.Fatalf("grant purpose = %q, want normalized purpose", grant.Purpose)
	}
	if !grant.ExpiresAt.Equal(session.AbsoluteExpiresAt) {
		t.Fatalf("grant expiry = %v, want session absolute expiry %v", grant.ExpiresAt, session.AbsoluteExpiresAt)
	}
	if len(repository.createdEvents) != 1 || repository.createdEvents[0].EventType != "audit_grant_issued" || repository.createdEvents[0].Reason != grant.Purpose {
		t.Fatalf("grant event = %+v, want content-free issuance event", repository.createdEvents)
	}
}

func TestElevatedAuditAccessClampsGrantToTwentyFourHours(t *testing.T) {
	now := time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC)
	session := elevatedAuditTestSession(now, now.Add(72*time.Hour))
	repository := &elevatedAuditRepositoryFake{}
	service := newTestElevatedAuditAccessService(repository, now)

	grant, err := service.Issue(context.Background(), IssueElevatedAuditGrantInput{
		Session: session, Purpose: "review", RequestID: elevatedAuditUUID(2),
	})
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if !grant.ExpiresAt.Equal(now.Add(24 * time.Hour)) {
		t.Fatalf("grant expiry = %v, want 24-hour expiry", grant.ExpiresAt)
	}
}

func TestElevatedAuditAccessRejectsLowerRolesAndMissingSecurityCheck(t *testing.T) {
	now := time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		role    access.Role
		reauth  *time.Time
		wantErr error
	}{
		{name: "employee", role: access.RoleEmployee, reauth: timePointer(now.Add(time.Minute)), wantErr: ErrElevatedAuditForbidden},
		{name: "team administrator", role: access.RoleTeamAdministrator, reauth: timePointer(now.Add(time.Minute)), wantErr: ErrElevatedAuditForbidden},
		{name: "missing security check", role: access.RoleSystemAdministrator, wantErr: access.ErrReauthenticationRequired},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &elevatedAuditRepositoryFake{}
			service := newTestElevatedAuditAccessService(repository, now)
			session := elevatedAuditTestSession(now, now.Add(time.Hour))
			session.Role = test.role
			session.ReauthenticatedUntil = test.reauth
			_, err := service.Issue(context.Background(), IssueElevatedAuditGrantInput{
				Session: session, Purpose: "review", RequestID: elevatedAuditUUID(3),
			})
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Issue() error = %v, want %v", err, test.wantErr)
			}
			if repository.createdGrant.ID != "" || len(repository.createdEvents) != 0 {
				t.Fatalf("repository mutated after rejected issue: grant=%+v events=%+v", repository.createdGrant, repository.createdEvents)
			}
		})
	}
}

func TestElevatedAuditAccessRequiresBoundActiveGrantAndRevocationInvalidatesIt(t *testing.T) {
	now := time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC)
	session := elevatedAuditTestSession(now, now.Add(time.Hour))
	repository := &elevatedAuditRepositoryFake{
		activeGrant: ElevatedAuditGrant{
			ID: "grant-1", ActorIdentityID: session.IdentityID, SessionID: session.SessionID,
			Purpose: "review", IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute),
		},
	}
	service := newTestElevatedAuditAccessService(repository, now)

	grant, err := service.Current(context.Background(), session)
	if err != nil || grant.ID != "grant-1" {
		t.Fatalf("Current() = %+v, %v; want active bound grant", grant, err)
	}

	if err := service.Revoke(context.Background(), RevokeElevatedAuditGrantInput{Session: session, RequestID: elevatedAuditUUID(4)}); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if repository.revokedGrantID != "grant-1" || len(repository.createdEvents) != 1 || repository.createdEvents[0].EventType != "audit_grant_revoked" {
		t.Fatalf("revocation = grant %q events=%+v", repository.revokedGrantID, repository.createdEvents)
	}
	repository.activeGrant = ElevatedAuditGrant{}
	if _, err := service.Current(context.Background(), session); !errors.Is(err, ErrElevatedAuditGrantNotFound) {
		t.Fatalf("Current() after revoke error = %v, want not found", err)
	}
}

func TestElevatedAuditAccessFailsClosedWhenGrantEventCannotPersist(t *testing.T) {
	now := time.Date(2026, 9, 10, 10, 0, 0, 0, time.UTC)
	repository := &elevatedAuditRepositoryFake{createErr: access.ErrSecurityAuditUnavailable}
	service := newTestElevatedAuditAccessService(repository, now)
	_, err := service.Issue(context.Background(), IssueElevatedAuditGrantInput{
		Session: elevatedAuditTestSession(now, now.Add(time.Hour)), Purpose: "review", RequestID: elevatedAuditUUID(5),
	})
	if !errors.Is(err, access.ErrSecurityAuditUnavailable) {
		t.Fatalf("Issue() error = %v, want security audit failure", err)
	}
	if repository.createdGrant.ID != "" {
		t.Fatalf("grant persisted despite event failure: %+v", repository.createdGrant)
	}
}

func newTestElevatedAuditAccessService(repository *elevatedAuditRepositoryFake, now time.Time) *ElevatedAuditAccessService {
	service, err := NewElevatedAuditAccessService(repository)
	if err != nil {
		panic(err)
	}
	service.now = func() time.Time { return now }
	service.newID = func() (string, error) { return elevatedAuditUUID(99), nil }
	return service
}

func timePointer(value time.Time) *time.Time { return &value }

func elevatedAuditTestSession(now, absoluteExpiry time.Time) access.ActivePortalSession {
	return access.ActivePortalSession{
		SessionID: "session-1", IdentityID: "admin-1", Role: access.RoleSystemAdministrator,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: absoluteExpiry,
		ReauthenticatedUntil: timePointer(now.Add(time.Minute)),
	}
}

func elevatedAuditUUID(value int) string {
	return "91000000-0000-0000-0000-" + fiveDigitUUIDSuffix(value)
}

type elevatedAuditRepositoryFake struct {
	activeGrant    ElevatedAuditGrant
	createdGrant   ElevatedAuditGrant
	createdEvents  []access.SecurityEvent
	revokedGrantID string
	createErr      error
	findErr        error
	revokeErr      error
}

func (repository *elevatedAuditRepositoryFake) CreateElevatedAuditGrant(_ context.Context, grant ElevatedAuditGrant, event access.SecurityEvent) error {
	if repository.createErr != nil {
		return repository.createErr
	}
	repository.createdGrant = grant
	repository.activeGrant = grant
	repository.createdEvents = append(repository.createdEvents, event)
	return nil
}

func (repository *elevatedAuditRepositoryFake) FindElevatedAuditGrant(_ context.Context, lookup ElevatedAuditGrantLookup) (ElevatedAuditGrant, error) {
	if repository.findErr != nil {
		return ElevatedAuditGrant{}, repository.findErr
	}
	if repository.activeGrant.ID == "" || repository.activeGrant.ActorIdentityID != lookup.ActorIdentityID || repository.activeGrant.SessionID != lookup.SessionID || !repository.activeGrant.ExpiresAt.After(lookup.At) {
		return ElevatedAuditGrant{}, ErrElevatedAuditGrantNotFound
	}
	return repository.activeGrant, nil
}

func (repository *elevatedAuditRepositoryFake) RevokeElevatedAuditGrant(_ context.Context, grantID, actorIdentityID, sessionID string, _ time.Time, event access.SecurityEvent) error {
	if repository.revokeErr != nil {
		return repository.revokeErr
	}
	if repository.activeGrant.ID != grantID || repository.activeGrant.ActorIdentityID != actorIdentityID || repository.activeGrant.SessionID != sessionID {
		return ErrElevatedAuditGrantNotFound
	}
	repository.revokedGrantID = grantID
	repository.createdEvents = append(repository.createdEvents, event)
	return nil
}
