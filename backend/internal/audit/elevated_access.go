package audit

import (
	"context"
	"errors"
	"strings"
	"time"

	"n-api-p/internal/access"
)

const (
	elevatedAuditGrantLifetime = 24 * time.Hour
	maxElevatedAuditPurpose    = 500
)

var (
	ErrInvalidElevatedAuditAccess = errors.New("invalid elevated audit access request")
	ErrElevatedAuditForbidden     = errors.New("elevated audit access forbidden")
	ErrElevatedAuditGrantNotFound = errors.New("elevated audit grant not found")
	ErrElevatedAuditGrantExpired  = errors.New("elevated audit grant expired")
	ErrElevatedAuditGrantRevoked  = errors.New("elevated audit grant revoked")
)

type ElevatedAuditGrant struct {
	ID              string
	ActorIdentityID string
	SessionID       string
	Purpose         string
	IssuedAt        time.Time
	ExpiresAt       time.Time
	RevokedAt       *time.Time
}

type IssueElevatedAuditGrantInput struct {
	Session   access.ActivePortalSession
	Purpose   string
	RequestID string
}

type ElevatedAuditGrantLookup struct {
	ActorIdentityID string
	SessionID       string
	At              time.Time
}

type RevokeElevatedAuditGrantInput struct {
	Session   access.ActivePortalSession
	RequestID string
}

type ElevatedAuditGrantRepository interface {
	CreateElevatedAuditGrant(context.Context, ElevatedAuditGrant, access.SecurityEvent) error
	FindElevatedAuditGrant(context.Context, ElevatedAuditGrantLookup) (ElevatedAuditGrant, error)
	RevokeElevatedAuditGrant(context.Context, string, string, string, time.Time, access.SecurityEvent) error
}

type ElevatedAuditAccessService struct {
	repository ElevatedAuditGrantRepository
	now        func() time.Time
	newID      func() (string, error)
}

func NewElevatedAuditAccessService(repository ElevatedAuditGrantRepository) (*ElevatedAuditAccessService, error) {
	if repository == nil {
		return nil, ErrInvalidElevatedAuditAccess
	}
	return &ElevatedAuditAccessService{repository: repository, now: time.Now, newID: investigationID}, nil
}

func (service *ElevatedAuditAccessService) Issue(ctx context.Context, input IssueElevatedAuditGrantInput) (ElevatedAuditGrant, error) {
	if service == nil || service.repository == nil || service.now == nil || service.newID == nil {
		return ElevatedAuditGrant{}, ErrInvalidElevatedAuditAccess
	}
	now := service.now().UTC()
	if !validElevatedAuditSession(input.Session, now) {
		return ElevatedAuditGrant{}, ErrElevatedAuditForbidden
	}
	if input.Session.ReauthenticatedUntil == nil || !input.Session.ReauthenticatedUntil.After(now) {
		return ElevatedAuditGrant{}, access.ErrReauthenticationRequired
	}
	purpose := strings.TrimSpace(input.Purpose)
	requestID := strings.TrimSpace(input.RequestID)
	if purpose == "" || len([]rune(purpose)) > maxElevatedAuditPurpose || !validMetadataID(requestID) {
		return ElevatedAuditGrant{}, ErrInvalidElevatedAuditAccess
	}
	grantID, err := service.newID()
	if err != nil {
		return ElevatedAuditGrant{}, access.ErrSecurityAuditUnavailable
	}
	eventID, err := service.newID()
	if err != nil {
		return ElevatedAuditGrant{}, access.ErrSecurityAuditUnavailable
	}
	expiresAt := now.Add(elevatedAuditGrantLifetime)
	if expiresAt.After(input.Session.AbsoluteExpiresAt) {
		expiresAt = input.Session.AbsoluteExpiresAt
	}
	grant := ElevatedAuditGrant{
		ID: grantID, ActorIdentityID: input.Session.IdentityID, SessionID: input.Session.SessionID,
		Purpose: purpose, IssuedAt: now, ExpiresAt: expiresAt,
	}
	event := access.SecurityEvent{
		ID: eventID, EventType: "audit_grant_issued", ActorIdentityID: input.Session.IdentityID,
		SessionID: input.Session.SessionID, GrantID: grant.ID, RequestID: requestID,
		Outcome: access.SecurityEventSuccess, Reason: purpose, DetailCode: "issued", OccurredAt: now,
	}
	if err := service.repository.CreateElevatedAuditGrant(ctx, grant, event); err != nil {
		return ElevatedAuditGrant{}, err
	}
	return grant, nil
}

func (service *ElevatedAuditAccessService) Current(ctx context.Context, session access.ActivePortalSession) (ElevatedAuditGrant, error) {
	if service == nil || service.repository == nil || service.now == nil || !validElevatedAuditSession(session, service.now().UTC()) {
		return ElevatedAuditGrant{}, ErrElevatedAuditForbidden
	}
	grant, err := service.repository.FindElevatedAuditGrant(ctx, ElevatedAuditGrantLookup{
		ActorIdentityID: session.IdentityID, SessionID: session.SessionID, At: service.now().UTC(),
	})
	if errors.Is(err, ErrElevatedAuditGrantNotFound) {
		return ElevatedAuditGrant{}, ErrElevatedAuditGrantNotFound
	}
	if err != nil {
		return ElevatedAuditGrant{}, err
	}
	if grant.ActorIdentityID != session.IdentityID || grant.SessionID != session.SessionID || !grant.ExpiresAt.After(service.now().UTC()) || grant.RevokedAt != nil {
		return ElevatedAuditGrant{}, ErrElevatedAuditGrantNotFound
	}
	return grant, nil
}

func (service *ElevatedAuditAccessService) Revoke(ctx context.Context, input RevokeElevatedAuditGrantInput) error {
	if service == nil || service.repository == nil || service.now == nil || service.newID == nil {
		return ErrInvalidElevatedAuditAccess
	}
	now := service.now().UTC()
	if !validElevatedAuditSession(input.Session, now) {
		return ErrElevatedAuditForbidden
	}
	requestID := strings.TrimSpace(input.RequestID)
	if !validMetadataID(requestID) {
		return ErrInvalidElevatedAuditAccess
	}
	grant, err := service.Current(ctx, input.Session)
	if err != nil {
		return err
	}
	eventID, err := service.newID()
	if err != nil {
		return access.ErrSecurityAuditUnavailable
	}
	event := access.SecurityEvent{
		ID: eventID, EventType: "audit_grant_revoked", ActorIdentityID: input.Session.IdentityID,
		SessionID: input.Session.SessionID, GrantID: grant.ID, RequestID: requestID,
		Outcome: access.SecurityEventSuccess, Reason: grant.Purpose, DetailCode: "revoked", OccurredAt: now,
	}
	return service.repository.RevokeElevatedAuditGrant(ctx, grant.ID, input.Session.IdentityID, input.Session.SessionID, now, event)
}

func validElevatedAuditSession(session access.ActivePortalSession, now time.Time) bool {
	return strings.TrimSpace(session.IdentityID) != "" && strings.TrimSpace(session.SessionID) != "" &&
		session.Role == access.RoleSystemAdministrator && session.IdleExpiresAt.After(now) && session.AbsoluteExpiresAt.After(now)
}
