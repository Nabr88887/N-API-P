package access

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestReauthenticationRotatesSessionAndIssuesFiveMinuteGrant(t *testing.T) {
	repository := &memoryReauthenticationRepository{candidate: ReauthenticationCandidate{
		SessionID: "old-session", IdentityID: "identity-1", Role: RoleSystemAdministrator,
		PasswordHash: "stored-password", IdleExpiresAt: fixedNow.Add(10 * time.Minute), AbsoluteExpiresAt: fixedNow.Add(2 * time.Hour),
	}}
	service := NewReauthenticationService(repository, reauthenticationPasswordVerifier{})
	service.now = func() time.Time { return fixedNow }
	service.random = bytes.NewReader(bytes.Repeat([]byte{0x42}, sessionRandomBytes*2))
	service.newID = func() (string, error) { return "new-session", nil }

	session, err := service.Reauthenticate(context.Background(), ReauthenticationInput{SessionID: "old-session", Password: "current-password"})
	if err != nil {
		t.Fatalf("Reauthenticate() error = %v", err)
	}
	if session.ID != "new-session" || session.IdentityID != "identity-1" || session.Token == "" || session.CSRFToken == "" {
		t.Fatalf("rotated session = %+v", session)
	}
	if !session.ExpiresAt.Equal(fixedNow.Add(2 * time.Hour)) {
		t.Fatalf("cookie expiry = %v, want preserved absolute expiry", session.ExpiresAt)
	}
	rotation := repository.rotation
	if rotation.ExistingSessionID != "old-session" || rotation.IdentityID != "identity-1" || rotation.NewSession.ID != "new-session" {
		t.Fatalf("rotation = %+v", rotation)
	}
	if !rotation.ReauthenticatedUntil.Equal(fixedNow.Add(reauthenticationLifetime)) {
		t.Fatalf("grant expiry = %v, want %v", rotation.ReauthenticatedUntil, fixedNow.Add(reauthenticationLifetime))
	}
	wantTokenHash := sha256.Sum256([]byte(session.Token))
	if !bytes.Equal(rotation.NewSession.TokenHash, wantTokenHash[:]) {
		t.Fatal("rotation did not receive token hash")
	}
	if bytes.Contains(rotation.NewSession.TokenHash, []byte(session.Token)) {
		t.Fatal("rotation token hash contains plaintext token")
	}
}

func TestReauthenticationRejectsWrongPasswordWithoutRotation(t *testing.T) {
	repository := &memoryReauthenticationRepository{candidate: ReauthenticationCandidate{
		SessionID: "old-session", IdentityID: "identity-1", PasswordHash: "stored-password",
	}}
	service := NewReauthenticationService(repository, reauthenticationPasswordVerifier{valid: false})
	service.now = func() time.Time { return fixedNow }

	_, err := service.Reauthenticate(context.Background(), ReauthenticationInput{SessionID: "old-session", Password: "wrong-password"})
	if !errors.Is(err, ErrReauthenticationRejected) {
		t.Fatalf("Reauthenticate() error = %v, want ErrReauthenticationRejected", err)
	}
	if repository.rotation.ExistingSessionID != "" {
		t.Fatal("wrong password rotated a session")
	}
}

func TestSensitiveActionGuardAuditsDeniedAndSuccessfulAttempts(t *testing.T) {
	events := &memorySecurityEventWriter{}
	guard := NewSensitiveActionGuard(events)
	guard.now = func() time.Time { return fixedNow }

	deniedSession := ActivePortalSession{SessionID: "session-1", IdentityID: "employee-1", Role: RoleEmployee}
	err := guard.Authorize(context.Background(), SensitiveActionRequest{
		Session: deniedSession, Action: SensitiveActionRetentionPolicy, RequestID: "request-denied",
	})
	if !errors.Is(err, ErrSensitiveActionForbidden) {
		t.Fatalf("denied authorization error = %v, want ErrSensitiveActionForbidden", err)
	}

	grantUntil := fixedNow.Add(time.Minute)
	allowedSession := ActivePortalSession{
		SessionID: "session-2", IdentityID: "admin-1", Role: RoleSystemAdministrator,
		ReauthenticatedUntil: &grantUntil,
	}
	err = guard.Authorize(context.Background(), SensitiveActionRequest{
		Session: allowedSession, Action: SensitiveActionRawView, RequestID: "request-success", TargetAuditID: "audit-1",
	})
	if err != nil {
		t.Fatalf("allowed authorization error = %v", err)
	}
	if len(events.events) != 2 {
		t.Fatalf("security events = %d, want 2", len(events.events))
	}
	if events.events[0].EventType != string(SensitiveActionRetentionPolicy) || events.events[0].Outcome != SecurityEventDenied || events.events[0].DetailCode != "forbidden" {
		t.Fatalf("denied event = %+v", events.events[0])
	}
	if events.events[1].EventType != string(SensitiveActionRawView) || events.events[1].Outcome != SecurityEventSuccess || events.events[1].TargetAuditID != "audit-1" {
		t.Fatalf("success event = %+v", events.events[1])
	}
}

func TestSensitiveActionGuardRejectsStaleGrantAndAuditFailure(t *testing.T) {
	events := &memorySecurityEventWriter{}
	guard := NewSensitiveActionGuard(events)
	stale := fixedNow.Add(-time.Second)
	err := guard.AuthorizeAt(context.Background(), SensitiveActionRequest{
		Session: ActivePortalSession{SessionID: "session-1", IdentityID: "admin-1", Role: RoleSystemAdministrator, ReauthenticatedUntil: &stale},
		Action:  SensitiveActionRawView, RequestID: "request-stale",
	}, fixedNow)
	if !errors.Is(err, ErrReauthenticationRequired) {
		t.Fatalf("stale grant error = %v, want ErrReauthenticationRequired", err)
	}
	if events.events[0].DetailCode != "reauthentication_required" {
		t.Fatalf("stale event = %+v", events.events[0])
	}

	failingWriter := &memorySecurityEventWriter{err: errors.New("audit unavailable")}
	guard = NewSensitiveActionGuard(failingWriter)
	err = guard.AuthorizeAt(context.Background(), SensitiveActionRequest{
		Session: ActivePortalSession{SessionID: "session-2", IdentityID: "admin-1", Role: RoleSystemAdministrator, ReauthenticatedUntil: timePointer(fixedNow.Add(time.Minute))},
		Action:  SensitiveActionRawView, RequestID: "request-audit-failure",
	}, fixedNow)
	if !errors.Is(err, ErrSecurityAuditUnavailable) {
		t.Fatalf("audit failure error = %v, want ErrSecurityAuditUnavailable", err)
	}
}

func TestRequireRecentActorReauthenticationFailsClosedWhenDeniedAuditIsUnavailable(t *testing.T) {
	events := &memorySecurityEventWriter{err: errors.New("audit unavailable")}
	err := requireRecentActorReauthentication(context.Background(), events, Actor{
		IdentityID: "admin-1", Role: RoleSystemAdministrator,
	}, SecurityEvent{
		ID: "event-1", EventType: "role_change", TargetIdentityID: "employee-1", RequestID: "request-1", OccurredAt: fixedNow,
	}, fixedNow)

	if !errors.Is(err, ErrSecurityAuditUnavailable) {
		t.Fatalf("denied audit failure error = %v, want ErrSecurityAuditUnavailable", err)
	}
	if len(events.events) != 1 || events.events[0].Outcome != SecurityEventDenied || events.events[0].DetailCode != "reauthentication_required" {
		t.Fatalf("attempted denied security event = %#v", events.events)
	}
}

func TestSensitiveActionGuardExecutesBeforeAuditingFinalOutcome(t *testing.T) {
	events := &memorySecurityEventWriter{}
	guard := NewSensitiveActionGuard(events)
	grantUntil := fixedNow.Add(time.Minute)
	request := SensitiveActionRequest{
		Session: ActivePortalSession{
			SessionID: "session-1", IdentityID: "admin-1", Role: RoleSystemAdministrator,
			ReauthenticatedUntil: &grantUntil,
		},
		Action: SensitiveActionRawView, RequestID: "request-1", Reason: "investigation",
	}
	executed := false
	err := guard.ExecuteAt(context.Background(), request, fixedNow, func() (SensitiveActionExecution, error) {
		if len(events.events) != 0 {
			t.Fatal("success event was appended before the sensitive operation completed")
		}
		executed = true
		return SensitiveActionExecution{
			TargetAuditID: "audit-1", Outcome: SecurityEventSuccess, DetailCode: "raw_viewed",
		}, nil
	})
	if err != nil {
		t.Fatalf("ExecuteAt() error = %v", err)
	}
	if !executed || len(events.events) != 1 {
		t.Fatalf("execution/events = (%v, %d), want (true, 1)", executed, len(events.events))
	}
	event := events.events[0]
	if event.Outcome != SecurityEventSuccess || event.DetailCode != "raw_viewed" || event.TargetAuditID != "audit-1" || event.Reason != "investigation" {
		t.Fatalf("success event = %+v", event)
	}

	operationErr := errors.New("authenticated decryption failed")
	err = guard.ExecuteAt(context.Background(), request, fixedNow, func() (SensitiveActionExecution, error) {
		return SensitiveActionExecution{
			TargetAuditID: "audit-1", Outcome: SecurityEventFailure, DetailCode: "decryption_failed",
		}, operationErr
	})
	if !errors.Is(err, operationErr) {
		t.Fatalf("failed ExecuteAt() error = %v, want operation error", err)
	}
	event = events.events[1]
	if event.Outcome != SecurityEventFailure || event.DetailCode != "decryption_failed" || event.TargetAuditID != "audit-1" {
		t.Fatalf("failure event = %+v", event)
	}
}

func TestSensitiveActionGuardDoesNotExecuteDeniedOperation(t *testing.T) {
	events := &memorySecurityEventWriter{}
	guard := NewSensitiveActionGuard(events)
	executed := false
	err := guard.ExecuteAt(context.Background(), SensitiveActionRequest{
		Session: ActivePortalSession{IdentityID: "employee-1", Role: RoleEmployee},
		Action:  SensitiveActionRawView, RequestID: "request-1",
	}, fixedNow, func() (SensitiveActionExecution, error) {
		executed = true
		return SensitiveActionExecution{}, nil
	})
	if !errors.Is(err, ErrSensitiveActionForbidden) {
		t.Fatalf("ExecuteAt() error = %v, want ErrSensitiveActionForbidden", err)
	}
	if executed || len(events.events) != 1 || events.events[0].Outcome != SecurityEventDenied {
		t.Fatalf("denied execution/events = (%v, %+v)", executed, events.events)
	}
}

func TestSensitiveActionGuardAuditsInvalidExecutionBoundary(t *testing.T) {
	events := &memorySecurityEventWriter{}
	guard := NewSensitiveActionGuard(events)
	grantUntil := fixedNow.Add(time.Minute)
	request := SensitiveActionRequest{
		Session: ActivePortalSession{IdentityID: "admin-1", Role: RoleSystemAdministrator, ReauthenticatedUntil: &grantUntil},
		Action:  SensitiveActionRawView, RequestID: "request-invalid",
	}
	if err := guard.ExecuteAt(context.Background(), request, fixedNow, nil); !errors.Is(err, ErrSensitiveActionForbidden) {
		t.Fatalf("nil execution error = %v, want ErrSensitiveActionForbidden", err)
	}
	if len(events.events) != 1 || events.events[0].Outcome != SecurityEventFailure || events.events[0].DetailCode != "operation_invalid" {
		t.Fatalf("invalid execution event = %+v", events.events)
	}

	events.events = nil
	if err := guard.ExecuteAt(context.Background(), request, fixedNow, func() (SensitiveActionExecution, error) {
		return SensitiveActionExecution{}, nil
	}); !errors.Is(err, ErrSensitiveActionForbidden) {
		t.Fatalf("invalid outcome error = %v, want ErrSensitiveActionForbidden", err)
	}
	if len(events.events) != 1 || events.events[0].Outcome != SecurityEventFailure || events.events[0].DetailCode != "operation_failed" {
		t.Fatalf("invalid outcome event = %+v", events.events)
	}
}

type memoryReauthenticationRepository struct {
	candidate ReauthenticationCandidate
	err       error
	rotation  PortalSessionRotation
}

func (repository *memoryReauthenticationRepository) FindReauthenticationCandidate(_ context.Context, _ ReauthenticationLookup) (ReauthenticationCandidate, error) {
	return repository.candidate, repository.err
}

func (repository *memoryReauthenticationRepository) RotatePortalSession(_ context.Context, rotation PortalSessionRotation) error {
	repository.rotation = rotation
	return repository.err
}

type reauthenticationPasswordVerifier struct {
	valid bool
}

func (verifier reauthenticationPasswordVerifier) Verify(plaintext, encodedHash string) (bool, error) {
	if verifier.valid || (plaintext == "current-password" && encodedHash == "stored-password") {
		return true, nil
	}
	return false, nil
}

type memorySecurityEventWriter struct {
	events []SecurityEvent
	err    error
}

func (writer *memorySecurityEventWriter) AppendSecurityEvent(_ context.Context, event SecurityEvent) error {
	writer.events = append(writer.events, event)
	return writer.err
}
