package access

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestModelAllowlistServiceGetAllowsOnlySystemAdministrators(t *testing.T) {
	repository := &modelAllowlistRepositoryFake{entries: []ModelAllowlistEntry{{ModelID: "gpt-4o", Status: ModelStatusAllowed}}}
	service, err := NewModelAllowlistService(repository)
	if err != nil {
		t.Fatalf("NewModelAllowlistService() error = %v", err)
	}
	for _, session := range []ActivePortalSession{
		{},
		{IdentityID: "employee-1", Role: RoleEmployee},
		{IdentityID: "team-admin-1", Role: RoleTeamAdministrator},
	} {
		if _, err := service.Get(context.Background(), session); !errors.Is(err, ErrForbidden) {
			t.Fatalf("Get(%+v) error = %v, want ErrForbidden", session, err)
		}
	}
	entries, err := service.Get(context.Background(), ActivePortalSession{IdentityID: "admin-1", Role: RoleSystemAdministrator})
	if err != nil {
		t.Fatalf("Get(system administrator) error = %v", err)
	}
	if len(entries) != 1 || entries[0].ModelID != "gpt-4o" {
		t.Fatalf("Get(system administrator) entries = %+v", entries)
	}
}

func TestModelAllowlistServiceDeniesAnonymousAndNonSystemAdministrators(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		session ActivePortalSession
		want    error
		code    string
	}{
		{name: "anonymous", want: ErrForbidden, code: "forbidden"},
		{name: "employee", session: ActivePortalSession{IdentityID: "employee-1", Role: RoleEmployee}, want: ErrForbidden, code: "forbidden"},
		{name: "team administrator", session: ActivePortalSession{IdentityID: "team-admin-1", Role: RoleTeamAdministrator}, want: ErrForbidden, code: "forbidden"},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &modelAllowlistRepositoryFake{}
			service, err := NewModelAllowlistService(repository)
			if err != nil {
				t.Fatalf("NewModelAllowlistService() error = %v", err)
			}
			service.now = func() time.Time { return now }
			_, err = service.Replace(context.Background(), test.session, ModelAllowlistChangeInput{
				Entries: []ModelAllowlistEntry{{ModelID: "gpt-4o", Status: ModelStatusAllowed}}, Confirmed: true, RequestID: "request-" + test.name,
			})
			if !errors.Is(err, test.want) {
				t.Fatalf("Replace() error = %v, want %v", err, test.want)
			}
			if repository.changed {
				t.Fatal("model policy changed after denied request")
			}
			if len(repository.events) != 1 || repository.events[0].Outcome != SecurityEventDenied || repository.events[0].DetailCode != test.code {
				t.Fatalf("events = %+v, want one denied %s event", repository.events, test.code)
			}
		})
	}
}

func TestModelAllowlistServiceRequiresFreshReauthenticationAndConfirmation(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name    string
		session ActivePortalSession
		input   ModelAllowlistChangeInput
		want    error
		code    string
	}{
		{name: "stale reauthentication", session: ActivePortalSession{IdentityID: "admin-1", Role: RoleSystemAdministrator, ReauthenticatedUntil: timePtr(now)}, input: ModelAllowlistChangeInput{Confirmed: true, RequestID: "request-stale"}, want: ErrReauthenticationRequired, code: "reauthentication_required"},
		{name: "missing confirmation", session: ActivePortalSession{IdentityID: "admin-1", Role: RoleSystemAdministrator, ReauthenticatedUntil: timePtr(now.Add(time.Minute))}, input: ModelAllowlistChangeInput{RequestID: "request-confirm"}, want: ErrModelAllowlistConfirmationRequired, code: "confirmation_required"},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &modelAllowlistRepositoryFake{}
			service, err := NewModelAllowlistService(repository)
			if err != nil {
				t.Fatalf("NewModelAllowlistService() error = %v", err)
			}
			service.now = func() time.Time { return now }
			_, err = service.Replace(context.Background(), test.session, test.input)
			if !errors.Is(err, test.want) {
				t.Fatalf("Replace() error = %v, want %v", err, test.want)
			}
			if repository.changed || len(repository.events) != 1 || repository.events[0].DetailCode != test.code {
				t.Fatalf("repository = %+v, want denied audited request", repository)
			}
		})
	}
}

func TestModelAllowlistServiceAuditsAuthorizedReplacement(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	repository := &modelAllowlistRepositoryFake{entries: []ModelAllowlistEntry{{ModelID: "gpt-4o", Status: ModelStatusAllowed}}}
	service, err := NewModelAllowlistService(repository)
	if err != nil {
		t.Fatalf("NewModelAllowlistService() error = %v", err)
	}
	service.now = func() time.Time { return now }
	service.newID = func() (string, error) { return "event-1", nil }
	session := ActivePortalSession{IdentityID: "admin-1", Role: RoleSystemAdministrator, ReauthenticatedUntil: timePtr(now.Add(time.Minute))}

	entries, err := service.Replace(context.Background(), session, ModelAllowlistChangeInput{
		Entries:   []ModelAllowlistEntry{{ModelID: "gpt-4.1", Status: ModelStatusAllowed}, {ModelID: "gpt-4o", Status: ModelStatusDisabled}},
		Confirmed: true, RequestID: "request-success",
	})
	if err != nil {
		t.Fatalf("Replace() error = %v", err)
	}
	if len(entries) != 2 || entries[0].ModelID != "gpt-4.1" || entries[1].Status != ModelStatusDisabled {
		t.Fatalf("entries = %+v, want replacement", entries)
	}
	if !repository.changed || repository.change.Event.EventType != string(SensitiveActionModelAllowlist) || repository.change.Event.Outcome != SecurityEventSuccess {
		t.Fatalf("change = %+v, want audited success", repository.change)
	}
	if repository.change.Event.ActorIdentityID != "admin-1" || repository.change.Event.RequestID != "request-success" || repository.change.Event.ID != "event-1" {
		t.Fatalf("event = %+v, want actor/request correlation", repository.change.Event)
	}
}

func TestModelAllowlistServiceRejectsInvalidEntriesAndDuplicateModelIDs(t *testing.T) {
	service, err := NewModelAllowlistService(&modelAllowlistRepositoryFake{})
	if err != nil {
		t.Fatalf("NewModelAllowlistService() error = %v", err)
	}
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	session := ActivePortalSession{IdentityID: "admin-1", Role: RoleSystemAdministrator, ReauthenticatedUntil: timePtr(now.Add(time.Minute))}
	for _, entries := range [][]ModelAllowlistEntry{
		{{ModelID: "", Status: ModelStatusAllowed}},
		{{ModelID: "gpt-4o", Status: ModelStatus("unknown")}},
		{{ModelID: "gpt-4o", Status: ModelStatusAllowed}, {ModelID: " gpt-4o ", Status: ModelStatusDisabled}},
		{{ModelID: "gpt-priced", Status: ModelStatusAllowed, InputUnitPrice: "0.001"}},
		{{ModelID: "gpt-priced", Status: ModelStatusAllowed, InputUnitPrice: "not-a-number", OutputUnitPrice: "0.002", PriceVersion: "v1"}},
		{{ModelID: "gpt-priced", Status: ModelStatusAllowed, InputUnitPrice: "-0.001", OutputUnitPrice: "0.002", PriceVersion: "v1"}},
		{{ModelID: "gpt-priced", Status: ModelStatusAllowed, InputUnitPrice: "1000000000000", OutputUnitPrice: "0.002", PriceVersion: "v1"}},
		{{ModelID: "gpt-priced", Status: ModelStatusAllowed, InputUnitPrice: "0.0000000000001", OutputUnitPrice: "0.002", PriceVersion: "v1"}},
		{{ModelID: "gpt-priced", Status: ModelStatusAllowed, InputUnitPrice: "0.001", OutputUnitPrice: "0.002", PriceVersion: " version\n"}},
	} {
		_, err := service.Replace(context.Background(), session, ModelAllowlistChangeInput{Entries: entries, Confirmed: true, RequestID: "request-invalid"})
		if !errors.Is(err, ErrInvalidModelAllowlist) {
			t.Fatalf("Replace(%+v) error = %v, want ErrInvalidModelAllowlist", entries, err)
		}
	}
}

func TestModelAllowlistServiceRejectsMoreThanMaximumEntries(t *testing.T) {
	repository := &modelAllowlistRepositoryFake{}
	service, err := NewModelAllowlistService(repository)
	if err != nil {
		t.Fatalf("NewModelAllowlistService() error = %v", err)
	}
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	service.now = func() time.Time { return now }
	session := ActivePortalSession{IdentityID: "admin-1", Role: RoleSystemAdministrator, ReauthenticatedUntil: timePtr(now.Add(time.Minute))}
	entries := make([]ModelAllowlistEntry, MaxModelAllowlistEntries+1)
	for index := range entries {
		entries[index] = ModelAllowlistEntry{ModelID: fmt.Sprintf("model-%03d", index), Status: ModelStatusAllowed}
	}

	_, err = service.Replace(context.Background(), session, ModelAllowlistChangeInput{
		Entries: entries, Confirmed: true, RequestID: "request-too-many-models",
	})
	if !errors.Is(err, ErrInvalidModelAllowlist) {
		t.Fatalf("Replace() error = %v, want ErrInvalidModelAllowlist", err)
	}
	if repository.changed || len(repository.events) != 1 || repository.events[0].DetailCode != "invalid_model_allowlist" {
		t.Fatalf("repository = %+v, want denied audited request", repository)
	}
}

type modelAllowlistRepositoryFake struct {
	entries []ModelAllowlistEntry
	changed bool
	change  ModelAllowlistChange
	events  []SecurityEvent
	err     error
}

func (r *modelAllowlistRepositoryFake) ReadModelAllowlist(context.Context) ([]ModelAllowlistEntry, error) {
	return append([]ModelAllowlistEntry(nil), r.entries...), r.err
}

func (r *modelAllowlistRepositoryFake) ReplaceModelAllowlist(_ context.Context, change ModelAllowlistChange) ([]ModelAllowlistEntry, error) {
	if r.err != nil {
		return nil, r.err
	}
	r.changed = true
	r.change = change
	r.entries = append([]ModelAllowlistEntry(nil), change.Entries...)
	return append([]ModelAllowlistEntry(nil), r.entries...), nil
}

func (r *modelAllowlistRepositoryFake) AppendSecurityEvent(_ context.Context, event SecurityEvent) error {
	if r.err != nil {
		return r.err
	}
	r.events = append(r.events, event)
	return nil
}
