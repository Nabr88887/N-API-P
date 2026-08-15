package access

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestPasswordResetIssueRequiresSystemAdministratorManualVerificationAndRecentReauthenticationForCompromise(t *testing.T) {
	tests := []struct {
		name       string
		actor      ActivePortalSession
		manual     bool
		compromise bool
		want       error
	}{
		{name: "employee", actor: ActivePortalSession{IdentityID: "employee-1", Role: RoleEmployee}, manual: true, want: ErrForbidden},
		{name: "team administrator", actor: ActivePortalSession{IdentityID: "team-admin-1", Role: RoleTeamAdministrator}, manual: true, want: ErrForbidden},
		{name: "manual verification required", actor: ActivePortalSession{IdentityID: "admin-1", Role: RoleSystemAdministrator}, want: ErrManualIdentityVerificationRequired},
		{name: "compromise requires recent reauthentication", actor: ActivePortalSession{IdentityID: "admin-1", Role: RoleSystemAdministrator}, manual: true, compromise: true, want: ErrReauthenticationRequired},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &memoryPasswordResetRepository{}
			service := newTestPasswordResetService(repository)
			_, err := service.IssueCode(context.Background(), PasswordResetIssueInput{
				Actor: test.actor, TargetIdentityID: "employee-1", ManualIdentityVerified: test.manual,
				CompromiseResponse: test.compromise,
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("IssueCode() error = %v, want %v", err, test.want)
			}
			if repository.issued.CodeHash != nil {
				t.Fatal("rejected issuance persisted a code")
			}
		})
	}
}

func TestPasswordResetIssueBindsEmailStoresOnlyHashAndExpiresInThirtyMinutes(t *testing.T) {
	repository := &memoryPasswordResetRepository{}
	service := newTestPasswordResetService(repository)
	service.random = bytes.NewReader(bytes.Repeat([]byte{0x2a}, passwordResetRandomBytes))
	service.newID = func() (string, error) { return "code-1", nil }

	issued, err := service.IssueCode(context.Background(), PasswordResetIssueInput{
		Actor:            ActivePortalSession{IdentityID: "admin-1", Role: RoleSystemAdministrator},
		TargetIdentityID: "employee-1", ManualIdentityVerified: true,
		TargetEmail: " Employee@Example.Internal ",
	})
	if err != nil {
		t.Fatalf("IssueCode() error = %v", err)
	}
	if issued.Code == "" || issued.Code == repository.issued.Email || issued.Code == repository.issued.TargetIdentityID {
		t.Fatal("issued reset code is empty or mixed with identity data")
	}
	if repository.issued.Email != "employee@example.internal" || repository.issued.TargetIdentityID != "employee-1" {
		t.Fatalf("issued record binding = %+v", repository.issued)
	}
	if !repository.issued.ExpiresAt.Equal(fixedNow.Add(passwordResetLifetime)) {
		t.Fatalf("expiry = %v, want %v", repository.issued.ExpiresAt, fixedNow.Add(passwordResetLifetime))
	}
	wantHash := sha256.Sum256([]byte(issued.Code))
	if !bytes.Equal(repository.issued.CodeHash, wantHash[:]) || bytes.Contains(repository.issued.CodeHash, []byte(issued.Code)) {
		t.Fatal("repository received reset code plaintext or an incorrect hash")
	}
}

func TestPasswordResetCompromiseResponseAuditsSensitiveAction(t *testing.T) {
	events := &memorySecurityEventWriter{}
	repository := &memoryPasswordResetRepository{}
	service := newTestPasswordResetService(repository)
	service.sensitiveActions = NewSensitiveActionGuard(events)
	grantUntil := fixedNow.Add(time.Minute)

	_, err := service.IssueCode(context.Background(), PasswordResetIssueInput{
		Actor: ActivePortalSession{
			IdentityID:           "admin-1",
			Role:                 RoleSystemAdministrator,
			ReauthenticatedUntil: &grantUntil,
		},
		TargetIdentityID:       "employee-1",
		TargetEmail:            "employee@example.internal",
		ManualIdentityVerified: true,
		CompromiseResponse:     true,
	})
	if err != nil {
		t.Fatalf("IssueCode() error = %v", err)
	}
	if len(events.events) != 1 {
		t.Fatalf("security events = %d, want 1", len(events.events))
	}
	event := events.events[0]
	if event.EventType != string(SensitiveActionCredentialCompromiseRecovery) ||
		event.ActorIdentityID != "admin-1" || event.TargetIdentityID != "employee-1" ||
		event.Outcome != SecurityEventSuccess {
		t.Fatalf("compromise recovery event = %+v", event)
	}
}

func TestPasswordResetCompromiseResponseAuditsMissingReauthentication(t *testing.T) {
	events := &memorySecurityEventWriter{}
	repository := &memoryPasswordResetRepository{}
	service := newTestPasswordResetService(repository)
	service.sensitiveActions = NewSensitiveActionGuard(events)

	_, err := service.IssueCode(context.Background(), PasswordResetIssueInput{
		Actor:                  ActivePortalSession{IdentityID: "admin-1", Role: RoleSystemAdministrator},
		TargetIdentityID:       "employee-1",
		TargetEmail:            "employee@example.internal",
		ManualIdentityVerified: true,
		CompromiseResponse:     true,
	})
	if !errors.Is(err, ErrReauthenticationRequired) {
		t.Fatalf("IssueCode() error = %v, want ErrReauthenticationRequired", err)
	}
	if len(events.events) != 1 {
		t.Fatalf("security events = %d, want 1", len(events.events))
	}
	event := events.events[0]
	if event.EventType != string(SensitiveActionCredentialCompromiseRecovery) ||
		event.ActorIdentityID != "admin-1" || event.TargetIdentityID != "employee-1" ||
		event.Outcome != SecurityEventDenied || event.DetailCode != "reauthentication_required" {
		t.Fatalf("denied compromise recovery event = %+v", event)
	}
}

func TestPasswordResetCompromiseResponseFailsClosedWhenAuditIsUnavailable(t *testing.T) {
	repository := &memoryPasswordResetRepository{}
	service := newTestPasswordResetService(repository)
	service.sensitiveActions = NewSensitiveActionGuard(&memorySecurityEventWriter{err: errors.New("audit unavailable")})
	grantUntil := fixedNow.Add(time.Minute)

	_, err := service.IssueCode(context.Background(), PasswordResetIssueInput{
		Actor: ActivePortalSession{
			IdentityID:           "admin-1",
			Role:                 RoleSystemAdministrator,
			ReauthenticatedUntil: &grantUntil,
		},
		TargetIdentityID:       "employee-1",
		TargetEmail:            "employee@example.internal",
		ManualIdentityVerified: true,
		CompromiseResponse:     true,
	})
	if !errors.Is(err, ErrPasswordResetUnavailable) {
		t.Fatalf("IssueCode() error = %v, want ErrPasswordResetUnavailable", err)
	}
	if repository.issued.CodeHash != nil {
		t.Fatal("audit failure persisted a password reset code")
	}
}

func TestPasswordResetCompletionPreservesKeysForRoutineAndRevokesThemForCompromise(t *testing.T) {
	tests := []struct {
		name       string
		compromise bool
	}{
		{name: "routine", compromise: false},
		{name: "compromise", compromise: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &memoryPasswordResetRepository{candidate: PasswordResetCandidate{
				CodeID: "code-1", IdentityID: "employee-1", Email: "employee@example.internal",
				RevokePersonalKeysOnUse: test.compromise,
			}}
			service := newTestPasswordResetService(repository)
			err := service.Complete(context.Background(), PasswordResetCompletionInput{
				Email: " employee@example.internal ", Code: "reset-code", NewPassword: "new-password",
			})
			if err != nil {
				t.Fatalf("Complete() error = %v", err)
			}
			if repository.completion.IdentityID != "employee-1" || repository.completion.CodeID != "code-1" {
				t.Fatalf("completion binding = %+v", repository.completion)
			}
			if repository.completion.RevokePersonalKeysOnUse != test.compromise {
				t.Fatalf("revoke personal keys = %v, want %v", repository.completion.RevokePersonalKeysOnUse, test.compromise)
			}
			if repository.completion.PasswordHash != "hashed:new-password" || repository.completion.PasswordHash == "new-password" {
				t.Fatalf("completion persisted plaintext password or wrong hash: %q", repository.completion.PasswordHash)
			}
			if event := repository.completion.Event; event.EventType != "password_reset_completed" ||
				event.TargetIdentityID != "employee-1" || event.Outcome != SecurityEventSuccess ||
				event.RequestID == "" || !event.OccurredAt.Equal(fixedNow) {
				t.Fatalf("password reset completion event = %+v", event)
			}
		})
	}
}

func TestPasswordResetCompletionRejectsInvalidExpiredOrReusedCodeBeforePasswordWork(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
	}{
		{name: "invalid", err: ErrPasswordResetRejected},
		{name: "expired", err: ErrPasswordResetRejected},
		{name: "reused", err: ErrPasswordResetRejected},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &memoryPasswordResetRepository{prepareErr: test.err}
			passwords := &recordingPasswordInitializer{}
			service := newTestPasswordResetService(repository)
			service.passwords = passwords
			err := service.Complete(context.Background(), PasswordResetCompletionInput{
				Email: "employee@example.internal", Code: "reset-code", NewPassword: "new-password",
			})
			if !errors.Is(err, ErrPasswordResetRejected) {
				t.Fatalf("Complete() error = %v, want ErrPasswordResetRejected", err)
			}
			if passwords.calls != 0 {
				t.Fatalf("password initializer calls = %d, want 0 for rejected code", passwords.calls)
			}
		})
	}
}

func newTestPasswordResetService(repository PasswordResetRepository) *PasswordResetService {
	service := NewPasswordResetService(repository, &recordingPasswordInitializer{}, NewSensitiveActionGuard(&memorySecurityEventWriter{}))
	service.now = func() time.Time { return fixedNow }
	service.newID = func() (string, error) { return "code-1", nil }
	return service
}

type memoryPasswordResetRepository struct {
	issued      PasswordResetCodeRecord
	issuedErr   error
	candidate   PasswordResetCandidate
	prepareErr  error
	completion  PasswordResetCompletionRecord
	completeErr error
}

func (repository *memoryPasswordResetRepository) IssuePasswordResetCode(_ context.Context, record PasswordResetCodeRecord) error {
	repository.issued = record
	return repository.issuedErr
}

func (repository *memoryPasswordResetRepository) PreparePasswordReset(_ context.Context, _ PasswordResetLookup) (PasswordResetCandidate, error) {
	return repository.candidate, repository.prepareErr
}

func (repository *memoryPasswordResetRepository) CompletePasswordReset(_ context.Context, record PasswordResetCompletionRecord) error {
	repository.completion = record
	return repository.completeErr
}

type recordingPasswordInitializer struct {
	calls int
}

func (initializer *recordingPasswordInitializer) Initialize(plaintext string) (string, error) {
	initializer.calls++
	return "hashed:" + plaintext, nil
}
