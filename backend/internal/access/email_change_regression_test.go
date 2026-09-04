package access

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestIdentityServiceBuildsAuditedEmailChange(t *testing.T) {
	repository := &emailChangeRepositoryFake{}
	service := NewIdentityService(repository)
	service.now = func() time.Time { return time.Date(2026, 9, 2, 8, 0, 0, 0, time.UTC) }
	service.newID = func() (string, error) { return "72000000-0000-0000-0000-000000000001", nil }
	err := service.ChangeEmail(context.Background(), ChangeEmailInput{
		Actor:      Actor{IdentityID: "20000000-0000-0000-0000-000000000001", Role: RoleSystemAdministrator, ReauthenticatedUntil: timePointer(time.Date(2026, 9, 2, 8, 1, 0, 0, time.UTC))},
		IdentityID: "10000000-0000-0000-0000-000000000001", Email: " NEW@EXAMPLE.INTERNAL ",
		RequestID: "30000000-0000-0000-0000-000000000001",
	})
	if err != nil {
		t.Fatalf("ChangeEmail() error = %v", err)
	}
	event := repository.record.Event
	if repository.record.Email != "new@example.internal" || event.EventType != "email_change" || event.ActorIdentityID != "20000000-0000-0000-0000-000000000001" || event.TargetIdentityID != "10000000-0000-0000-0000-000000000001" || event.RequestID != "30000000-0000-0000-0000-000000000001" || event.Outcome != SecurityEventSuccess || event.DetailCode != "email_changed" || !event.OccurredAt.Equal(repository.record.ChangedAt) {
		t.Fatalf("email change record = %+v", repository.record)
	}
}

func TestIdentityServiceRequiresRecentReauthenticationForEmailChange(t *testing.T) {
	repository := &emailChangeRepositoryFake{}
	service := NewIdentityService(repository)
	service.now = func() time.Time { return time.Date(2026, 9, 2, 8, 0, 0, 0, time.UTC) }
	service.newID = func() (string, error) { return "72000000-0000-0000-0000-000000000002", nil }

	err := service.ChangeEmail(context.Background(), ChangeEmailInput{
		Actor:      Actor{IdentityID: "20000000-0000-0000-0000-000000000001", Role: RoleSystemAdministrator},
		IdentityID: "10000000-0000-0000-0000-000000000001", Email: "new@example.internal",
		RequestID: "30000000-0000-0000-0000-000000000002",
	})

	if !errors.Is(err, ErrReauthenticationRequired) {
		t.Fatalf("ChangeEmail() error = %v, want ErrReauthenticationRequired", err)
	}
	if repository.record != (EmailChangeRecord{}) {
		t.Fatalf("email change reached repository: %#v", repository.record)
	}
	if len(repository.events) != 1 || repository.events[0].EventType != "email_change" || repository.events[0].Outcome != SecurityEventDenied || repository.events[0].DetailCode != "reauthentication_required" {
		t.Fatalf("denied security events = %#v", repository.events)
	}
}

type emailChangeRepositoryFake struct {
	record EmailChangeRecord
	events []SecurityEvent
}

func (fake *emailChangeRepositoryFake) ChangeIdentityEmail(_ context.Context, record EmailChangeRecord) error {
	fake.record = record
	return nil
}

func (fake *emailChangeRepositoryFake) AppendSecurityEvent(_ context.Context, event SecurityEvent) error {
	fake.events = append(fake.events, event)
	return nil
}
