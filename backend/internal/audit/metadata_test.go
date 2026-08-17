package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"n-api-p/internal/access"
)

func TestMetadataServiceListsOnlyForSystemAdministratorsWithBoundedPagination(t *testing.T) {
	repository := &recordingMetadataRepository{page: MetadataPage{
		Records:    []Metadata{{ID: "84000000-0000-0000-0000-000000000001", ModelID: "gpt-test"}},
		NextCursor: "next-page",
	}}
	service, err := NewMetadataService(repository)
	if err != nil {
		t.Fatalf("NewMetadataService() error = %v", err)
	}

	page, err := service.List(context.Background(), MetadataListInput{
		Session: access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator},
		Filter:  MetadataFilter{Limit: 50, Cursor: "opaque-cursor"},
	})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(page.Records) != 1 || page.NextCursor != "next-page" || repository.filter.Cursor != "opaque-cursor" || repository.filter.Limit != 50 {
		t.Fatalf("page/filter = %+v / %+v", page, repository.filter)
	}

	for _, session := range []access.ActivePortalSession{
		{IdentityID: "employee-1", Role: access.RoleEmployee},
		{IdentityID: "team-admin-1", Role: access.RoleTeamAdministrator},
	} {
		_, err := service.List(context.Background(), MetadataListInput{Session: session, Filter: MetadataFilter{Limit: 50}})
		if !errors.Is(err, access.ErrForbidden) {
			t.Fatalf("List() error = %v, want ErrForbidden", err)
		}
	}
	if repository.listCalls != 1 {
		t.Fatalf("repository list calls = %d, want 1", repository.listCalls)
	}
}

func TestMetadataServiceGetsOneRecordAndRejectsInvalidRequests(t *testing.T) {
	repository := &recordingMetadataRepository{record: Metadata{ID: "84000000-0000-0000-0000-000000000001", CreatedAt: time.Now().UTC()}}
	service, err := NewMetadataService(repository)
	if err != nil {
		t.Fatalf("NewMetadataService() error = %v", err)
	}
	admin := access.ActivePortalSession{IdentityID: "admin-1", Role: access.RoleSystemAdministrator}

	record, err := service.Get(context.Background(), MetadataGetInput{Session: admin, AuditID: repository.record.ID})
	if err != nil || record.ID != repository.record.ID {
		t.Fatalf("Get() = (%+v, %v)", record, err)
	}
	for _, filter := range []MetadataFilter{{Limit: 0}, {Limit: MaxMetadataPageSize + 1}, {Limit: 50, Cursor: string(make([]byte, 513))}} {
		if _, err := service.List(context.Background(), MetadataListInput{Session: admin, Filter: filter}); !errors.Is(err, ErrInvalidMetadataRequest) {
			t.Fatalf("List(%+v) error = %v, want ErrInvalidMetadataRequest", filter, err)
		}
	}
	if _, err := service.Get(context.Background(), MetadataGetInput{Session: admin, AuditID: " "}); !errors.Is(err, ErrInvalidMetadataRequest) {
		t.Fatalf("Get(blank) error = %v, want ErrInvalidMetadataRequest", err)
	}
}

type recordingMetadataRepository struct {
	page      MetadataPage
	record    Metadata
	filter    MetadataFilter
	listCalls int
}

func (repository *recordingMetadataRepository) ListAuditMetadata(_ context.Context, filter MetadataFilter) (MetadataPage, error) {
	repository.filter = filter
	repository.listCalls++
	return repository.page, nil
}

func (repository *recordingMetadataRepository) GetAuditMetadata(context.Context, string) (Metadata, error) {
	return repository.record, nil
}
