package access

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestSessionServiceHashesCredentialsAndRequestsBoundedTouch(t *testing.T) {
	repository := &memorySessionRepository{session: ActivePortalSession{
		SessionID: "session-1", IdentityID: "identity-1", Role: RoleEmployee,
		IdleExpiresAt: fixedNow.Add(20 * time.Minute), AbsoluteExpiresAt: fixedNow.Add(2 * time.Hour),
	}}
	service := NewSessionService(repository)
	service.now = func() time.Time { return fixedNow }

	session, err := service.Authenticate(context.Background(), "session-token", "csrf-token", true)
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if session.SessionID != "session-1" || session.IdentityID != "identity-1" || session.Role != RoleEmployee {
		t.Fatalf("Authenticate() session = %+v", session)
	}
	wantTokenHash := sha256.Sum256([]byte("session-token"))
	wantCSRFHash := sha256.Sum256([]byte("csrf-token"))
	use := repository.lastUse
	if !bytes.Equal(use.TokenHash, wantTokenHash[:]) || !bytes.Equal(use.CSRFTokenHash, wantCSRFHash[:]) {
		t.Fatal("repository did not receive session and CSRF hashes")
	}
	if !use.UsedAt.Equal(fixedNow) || !use.IdleExpiresAt.Equal(fixedNow.Add(sessionIdleLifetime)) {
		t.Fatalf("session use times = (%v, %v)", use.UsedAt, use.IdleExpiresAt)
	}
}

func TestSessionServiceAllowsSafeRequestsWithoutCSRF(t *testing.T) {
	repository := &memorySessionRepository{session: ActivePortalSession{SessionID: "session-1"}}
	service := NewSessionService(repository)
	service.now = func() time.Time { return fixedNow }

	if _, err := service.Authenticate(context.Background(), "session-token", "", false); err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if repository.lastUse.CSRFTokenHash != nil {
		t.Fatal("safe request unexpectedly supplied a CSRF hash")
	}
}

func TestSessionServiceRejectsMissingCredentialsAndMapsRepositoryFailures(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		csrf        string
		requireCSRF bool
		repository  *memorySessionRepository
		want        error
	}{
		{name: "missing token", requireCSRF: false, repository: &memorySessionRepository{}, want: ErrSessionInvalid},
		{name: "missing csrf", token: "token", requireCSRF: true, repository: &memorySessionRepository{}, want: ErrSessionInvalid},
		{name: "invalid session", token: "token", repository: &memorySessionRepository{err: ErrSessionInvalid}, want: ErrSessionInvalid},
		{name: "repository failure", token: "token", repository: &memorySessionRepository{err: errors.New("synthetic database failure")}, want: ErrSessionUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := NewSessionService(test.repository)
			_, err := service.Authenticate(context.Background(), test.token, test.csrf, test.requireCSRF)
			if !errors.Is(err, test.want) {
				t.Fatalf("Authenticate() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestSessionServiceRevokesOnlyServerSideSessionID(t *testing.T) {
	repository := &memorySessionRepository{}
	service := NewSessionService(repository)
	service.now = func() time.Time { return fixedNow }

	if err := service.Revoke(context.Background(), "session-1"); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}
	if repository.lastRevocation.SessionID != "session-1" || !repository.lastRevocation.RevokedAt.Equal(fixedNow) {
		t.Fatalf("revocation = %+v", repository.lastRevocation)
	}
}

type memorySessionRepository struct {
	session        ActivePortalSession
	lastUse        PortalSessionUse
	lastRevocation PortalSessionRevocation
	err            error
}

func (repository *memorySessionRepository) UsePortalSession(_ context.Context, use PortalSessionUse) (ActivePortalSession, error) {
	repository.lastUse = use
	return repository.session, repository.err
}

func (repository *memorySessionRepository) RevokePortalSession(_ context.Context, revocation PortalSessionRevocation) error {
	repository.lastRevocation = revocation
	return repository.err
}
