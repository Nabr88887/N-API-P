package access

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetentionPolicyServiceReadsSevenDayDefaultAndDeploymentCeiling(t *testing.T) {
	repository := &retentionPolicyRepositoryFake{policy: RetentionPolicy{Days: 7, MaximumDays: 30}}
	service, err := NewRetentionPolicyService(repository, 30)
	if err != nil {
		t.Fatalf("NewRetentionPolicyService() error = %v", err)
	}

	policy, err := service.Get(context.Background(), ActivePortalSession{IdentityID: "admin-1", Role: RoleSystemAdministrator})
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if policy.Days != 7 || policy.MaximumDays != 30 {
		t.Fatalf("policy = %+v, want seven-day default and 30-day ceiling", policy)
	}
}

func TestRetentionPolicyServiceRejectsNonSystemAdminStaleReauthAndMissingConfirmation(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		session ActivePortalSession
		input   RetentionPolicyChangeInput
		want    error
		code    string
	}{
		{
			name:    "team administrator",
			session: ActivePortalSession{IdentityID: "team-admin-1", Role: RoleTeamAdministrator},
			input:   RetentionPolicyChangeInput{Days: 10, Confirmed: true, RequestID: "request-team"},
			want:    ErrForbidden,
			code:    "forbidden",
		},
		{
			name:    "stale reauthentication",
			session: ActivePortalSession{IdentityID: "admin-1", Role: RoleSystemAdministrator, ReauthenticatedUntil: timePtr(now)},
			input:   RetentionPolicyChangeInput{Days: 10, Confirmed: true, RequestID: "request-stale"},
			want:    ErrReauthenticationRequired,
			code:    "reauthentication_required",
		},
		{
			name:    "missing confirmation",
			session: ActivePortalSession{IdentityID: "admin-1", Role: RoleSystemAdministrator, ReauthenticatedUntil: timePtr(now.Add(5 * time.Minute))},
			input:   RetentionPolicyChangeInput{Days: 10, RequestID: "request-confirm"},
			want:    ErrRetentionConfirmationRequired,
			code:    "confirmation_required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repository := &retentionPolicyRepositoryFake{policy: RetentionPolicy{Days: 7, MaximumDays: 30}}
			service, err := NewRetentionPolicyService(repository, 30)
			if err != nil {
				t.Fatalf("NewRetentionPolicyService() error = %v", err)
			}
			service.now = func() time.Time { return now }

			_, err = service.Change(context.Background(), tt.session, tt.input)
			if !errors.Is(err, tt.want) {
				t.Fatalf("Change() error = %v, want %v", err, tt.want)
			}
			if repository.changed {
				t.Fatal("policy changed after rejected request")
			}
			if len(repository.events) != 1 || repository.events[0].Outcome != SecurityEventDenied || repository.events[0].DetailCode != tt.code {
				t.Fatalf("denied audit events = %+v, want one %s denial", repository.events, tt.code)
			}
		})
	}
}

func TestRetentionPolicyServiceRejectsDaysOutsideOneToThirty(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	repository := &retentionPolicyRepositoryFake{policy: RetentionPolicy{Days: 7, MaximumDays: 30}}
	service, err := NewRetentionPolicyService(repository, 30)
	if err != nil {
		t.Fatalf("NewRetentionPolicyService() error = %v", err)
	}
	service.now = func() time.Time { return now }
	session := ActivePortalSession{IdentityID: "admin-1", Role: RoleSystemAdministrator, ReauthenticatedUntil: timePtr(now.Add(time.Minute))}

	for _, days := range []int{0, 31} {
		_, err := service.Change(context.Background(), session, RetentionPolicyChangeInput{Days: days, Confirmed: true, RequestID: "request-range"})
		if !errors.Is(err, ErrInvalidRetentionPolicy) {
			t.Fatalf("Change(%d) error = %v, want ErrInvalidRetentionPolicy", days, err)
		}
	}
	if repository.changed {
		t.Fatal("policy changed after out-of-range request")
	}
}

func TestRetentionPolicyServiceAcceptsInclusiveOneAndThirtyDayBounds(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	session := ActivePortalSession{IdentityID: "admin-1", Role: RoleSystemAdministrator, ReauthenticatedUntil: timePtr(now.Add(time.Minute))}
	for _, days := range []int{1, 30} {
		repository := &retentionPolicyRepositoryFake{policy: RetentionPolicy{Days: 7, MaximumDays: 30}}
		service, err := NewRetentionPolicyService(repository, 30)
		if err != nil {
			t.Fatalf("NewRetentionPolicyService() error = %v", err)
		}
		service.now = func() time.Time { return now }

		policy, err := service.Change(context.Background(), session, RetentionPolicyChangeInput{Days: days, Confirmed: true, RequestID: "request-bound"})
		if err != nil {
			t.Fatalf("Change(%d) error = %v", days, err)
		}
		if policy.Days != days {
			t.Fatalf("Change(%d) policy days = %d", days, policy.Days)
		}
	}
}

func TestRetentionPolicyServicePassesAtomicSuccessMutationAndAuditsIt(t *testing.T) {
	now := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	repository := &retentionPolicyRepositoryFake{policy: RetentionPolicy{Days: 7, MaximumDays: 30}}
	service, err := NewRetentionPolicyService(repository, 30)
	if err != nil {
		t.Fatalf("NewRetentionPolicyService() error = %v", err)
	}
	service.now = func() time.Time { return now }
	session := ActivePortalSession{IdentityID: "admin-1", Role: RoleSystemAdministrator, ReauthenticatedUntil: timePtr(now.Add(time.Minute))}

	policy, err := service.Change(context.Background(), session, RetentionPolicyChangeInput{Days: 3, Confirmed: true, RequestID: "request-success"})
	if err != nil {
		t.Fatalf("Change() error = %v", err)
	}
	if policy.Days != 3 {
		t.Fatalf("policy days = %d, want 3", policy.Days)
	}
	if !repository.changed || repository.change.Event.Outcome != SecurityEventSuccess || repository.change.Event.EventType != string(SensitiveActionRetentionPolicy) {
		t.Fatalf("atomic mutation = %+v, want successful retention event", repository.change)
	}
	if repository.change.Event.RequestID != "request-success" || repository.change.Event.ActorIdentityID != "admin-1" {
		t.Fatalf("audit event = %+v, want request and actor correlation", repository.change.Event)
	}
}

type retentionPolicyRepositoryFake struct {
	policy  RetentionPolicy
	changed bool
	change  RetentionPolicyChange
	events  []SecurityEvent
	err     error
}

func (repository *retentionPolicyRepositoryFake) ReadRetentionPolicy(context.Context) (RetentionPolicy, error) {
	return repository.policy, repository.err
}

func (repository *retentionPolicyRepositoryFake) ChangeRetentionPolicy(_ context.Context, change RetentionPolicyChange) (RetentionPolicy, error) {
	if repository.err != nil {
		return RetentionPolicy{}, repository.err
	}
	repository.changed = true
	repository.change = change
	repository.policy.Days = change.Days
	return repository.policy, nil
}

func (repository *retentionPolicyRepositoryFake) AppendSecurityEvent(_ context.Context, event SecurityEvent) error {
	if repository.err != nil {
		return repository.err
	}
	repository.events = append(repository.events, event)
	return nil
}

func timePtr(value time.Time) *time.Time { return &value }
