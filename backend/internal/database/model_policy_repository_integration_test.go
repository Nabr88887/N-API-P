//go:build integration

package database

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"n-api-p/internal/access"
)

func TestRepositoryModelAllowlistUsesOneGlobalSetAndAuditsReplacement(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)
	mustExec(t, db, `INSERT INTO model_allowlist (model_id, status, updated_by_identity_id) VALUES ($1, $2, $3)`, "gpt-4.1", "disabled", fixture.identityID)

	allowed, err := repository.ListAllowedModelIDs(context.Background())
	if err != nil {
		t.Fatalf("ListAllowedModelIDs() error = %v", err)
	}
	if len(allowed) != 1 || allowed[0] != "gpt-test" {
		t.Fatalf("allowed model IDs = %v, want [gpt-test]", allowed)
	}

	changedAt := fixture.now.Add(time.Hour)
	entries, err := repository.ReplaceModelAllowlist(context.Background(), access.ModelAllowlistChange{
		Entries:   []access.ModelAllowlistEntry{{ModelID: "gpt-4.1", Status: access.ModelStatusAllowed}, {ModelID: "gpt-test", Status: access.ModelStatusDisabled}},
		ChangedAt: changedAt,
		Event:     access.SecurityEvent{ID: "86000000-0000-0000-0000-000000000010", EventType: string(access.SensitiveActionModelAllowlist), ActorIdentityID: fixture.identityID, RequestID: "88000000-0000-0000-0000-000000000010", Outcome: access.SecurityEventSuccess, OccurredAt: changedAt},
	})
	if err != nil {
		t.Fatalf("ReplaceModelAllowlist() error = %v", err)
	}
	if len(entries) != 2 || entries[0].ModelID != "gpt-4.1" || entries[0].Status != access.ModelStatusAllowed || entries[1].Status != access.ModelStatusDisabled {
		t.Fatalf("replacement entries = %+v", entries)
	}
	var eventType, detailCode string
	if err := db.QueryRow(`SELECT event_type, detail_code FROM security_events WHERE id = $1`, "86000000-0000-0000-0000-000000000010").Scan(&eventType, &detailCode); err != nil {
		t.Fatalf("read model policy event: %v", err)
	}
	if eventType != string(access.SensitiveActionModelAllowlist) || detailCode != "replaced_2_models" {
		t.Fatalf("event = %s/%s, want model policy replacement", eventType, detailCode)
	}
}

func TestRepositoryModelAllowlistReplacementRemovesOmittedModels(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)
	changedAt := fixture.now.Add(time.Hour)

	entries, err := repository.ReplaceModelAllowlist(context.Background(), access.ModelAllowlistChange{
		Entries:   []access.ModelAllowlistEntry{{ModelID: "gpt-new", Status: access.ModelStatusAllowed}},
		ChangedAt: changedAt,
		Event: access.SecurityEvent{
			ID: "86000000-0000-0000-0000-000000000015", EventType: string(access.SensitiveActionModelAllowlist),
			ActorIdentityID: fixture.identityID, RequestID: "88000000-0000-0000-0000-000000000015",
			Outcome: access.SecurityEventSuccess, OccurredAt: changedAt,
		},
	})
	if err != nil {
		t.Fatalf("ReplaceModelAllowlist() error = %v", err)
	}
	if len(entries) != 1 || entries[0].ModelID != "gpt-new" {
		t.Fatalf("replacement entries = %+v, want only gpt-new", entries)
	}
	var omittedExists bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM model_allowlist WHERE model_id = $1)`, "gpt-test").Scan(&omittedExists); err != nil {
		t.Fatalf("check omitted model: %v", err)
	}
	if omittedExists {
		t.Fatal("omitted model still exists after full replacement")
	}
}

func TestRepositoryModelAllowlistPersistsPriceSnapshotFields(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)
	changedAt := fixture.now.Add(time.Hour)

	entries, err := repository.ReplaceModelAllowlist(context.Background(), access.ModelAllowlistChange{
		Entries: []access.ModelAllowlistEntry{{
			ModelID: "gpt-priced", Status: access.ModelStatusAllowed,
			InputUnitPrice: "0.001", OutputUnitPrice: "0.002", PriceVersion: "v1",
		}},
		ChangedAt: changedAt,
		Event: access.SecurityEvent{
			ID: "86000000-0000-0000-0000-000000000013", EventType: string(access.SensitiveActionModelAllowlist),
			ActorIdentityID: fixture.identityID, RequestID: "88000000-0000-0000-0000-000000000013",
			Outcome: access.SecurityEventSuccess, OccurredAt: changedAt,
		},
	})
	if err != nil {
		t.Fatalf("ReplaceModelAllowlist() error = %v", err)
	}
	entry := findModelAllowlistEntry(t, entries, "gpt-priced")
	if !equalDecimal(entry.InputUnitPrice, "0.001") || !equalDecimal(entry.OutputUnitPrice, "0.002") || entry.PriceVersion != "v1" {
		t.Fatalf("replacement price snapshot = %+v", entries)
	}
}

func TestRepositoryModelAllowlistPreservesExistingPriceSnapshotWhenOmitted(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)
	mustExec(t, db, `INSERT INTO model_allowlist (model_id, status, input_unit_price, output_unit_price, price_version, updated_by_identity_id) VALUES ($1, $2, $3, $4, $5, $6)`, "gpt-priced", "disabled", "0.001", "0.002", "v1", fixture.identityID)
	changedAt := fixture.now.Add(time.Hour)

	entries, err := repository.ReplaceModelAllowlist(context.Background(), access.ModelAllowlistChange{
		Entries: []access.ModelAllowlistEntry{{ModelID: "gpt-priced", Status: access.ModelStatusAllowed}}, ChangedAt: changedAt,
		Event: access.SecurityEvent{
			ID: "86000000-0000-0000-0000-000000000014", EventType: string(access.SensitiveActionModelAllowlist),
			ActorIdentityID: fixture.identityID, RequestID: "88000000-0000-0000-0000-000000000014",
			Outcome: access.SecurityEventSuccess, OccurredAt: changedAt,
		},
	})
	if err != nil {
		t.Fatalf("ReplaceModelAllowlist() error = %v", err)
	}
	entry := findModelAllowlistEntry(t, entries, "gpt-priced")
	if !equalDecimal(entry.InputUnitPrice, "0.001") || !equalDecimal(entry.OutputUnitPrice, "0.002") || entry.PriceVersion != "v1" {
		t.Fatalf("preserved price snapshot = %+v", entries)
	}
}

func findModelAllowlistEntry(t *testing.T, entries []access.ModelAllowlistEntry, modelID string) access.ModelAllowlistEntry {
	t.Helper()
	for _, entry := range entries {
		if entry.ModelID == modelID {
			return entry
		}
	}
	t.Fatalf("model allowlist entry %q not found in %+v", modelID, entries)
	return access.ModelAllowlistEntry{}
}

func equalDecimal(got, want string) bool {
	gotValue, ok := new(big.Rat).SetString(got)
	if !ok {
		return false
	}
	wantValue, ok := new(big.Rat).SetString(want)
	return ok && gotValue.Cmp(wantValue) == 0
}

func TestRepositoryModelAllowlistRequiresActiveSystemAdministrator(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)
	mustExec(t, db, `UPDATE identities SET role = 'team_administrator' WHERE id = $1`, fixture.identityID)
	changedAt := fixture.now.Add(time.Hour)
	_, err := repository.ReplaceModelAllowlist(context.Background(), access.ModelAllowlistChange{
		Entries: []access.ModelAllowlistEntry{{ModelID: "gpt-new", Status: access.ModelStatusAllowed}}, ChangedAt: changedAt,
		Event: access.SecurityEvent{ID: "86000000-0000-0000-0000-000000000011", EventType: string(access.SensitiveActionModelAllowlist), ActorIdentityID: fixture.identityID, RequestID: "88000000-0000-0000-0000-000000000011", Outcome: access.SecurityEventSuccess, OccurredAt: changedAt},
	})
	if !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("ReplaceModelAllowlist() error = %v, want ErrForbidden", err)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM model_allowlist WHERE model_id = $1`, "gpt-test").Scan(&status); err != nil {
		t.Fatalf("read unchanged model policy: %v", err)
	}
	if status != "allowed" {
		t.Fatalf("model status = %s, want allowed", status)
	}
}

func TestRepositoryModelAllowlistRollsBackWhenAuditInsertFails(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)
	mustExec(t, db, `CREATE FUNCTION reject_model_policy_event() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic model policy audit failure'; END $$`)
	mustExec(t, db, `CREATE TRIGGER reject_model_policy_event BEFORE INSERT ON security_events FOR EACH ROW EXECUTE FUNCTION reject_model_policy_event()`)
	changedAt := fixture.now.Add(time.Hour)
	_, err := repository.ReplaceModelAllowlist(context.Background(), access.ModelAllowlistChange{
		Entries: []access.ModelAllowlistEntry{{ModelID: "gpt-new", Status: access.ModelStatusAllowed}}, ChangedAt: changedAt,
		Event: access.SecurityEvent{ID: "86000000-0000-0000-0000-000000000012", EventType: string(access.SensitiveActionModelAllowlist), ActorIdentityID: fixture.identityID, RequestID: "88000000-0000-0000-0000-000000000012", Outcome: access.SecurityEventSuccess, OccurredAt: changedAt},
	})
	if err == nil {
		t.Fatal("ReplaceModelAllowlist() succeeded despite audit insert failure")
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM model_allowlist WHERE model_id = $1`, "gpt-test").Scan(&status); err != nil {
		t.Fatalf("read rolled-back model policy: %v", err)
	}
	if status != "allowed" {
		t.Fatalf("rolled-back model status = %s, want allowed", status)
	}
	var exists bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM model_allowlist WHERE model_id = $1)`, "gpt-new").Scan(&exists); err != nil {
		t.Fatalf("check rolled-back model: %v", err)
	}
	if exists {
		t.Fatal("rolled-back model entry still exists")
	}
}

func TestRepositoryModelAllowlistSerializesConcurrentFullReplacements(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)
	mustExec(t, db, `DELETE FROM model_allowlist`)
	mustExec(t, db, `CREATE FUNCTION delay_model_policy_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.2); RETURN NEW; END $$`)
	mustExec(t, db, `CREATE TRIGGER delay_model_policy_insert BEFORE INSERT ON model_allowlist FOR EACH ROW EXECUTE FUNCTION delay_model_policy_insert()`)

	start := make(chan struct{})
	errorsByReplacement := make(chan error, 2)
	var wait sync.WaitGroup
	for index, modelID := range []string{"gpt-a", "gpt-b"} {
		wait.Add(1)
		go func(index int, modelID string) {
			defer wait.Done()
			<-start
			changedAt := fixture.now.Add(time.Duration(index+1) * time.Hour)
			_, err := repository.ReplaceModelAllowlist(context.Background(), access.ModelAllowlistChange{
				Entries: []access.ModelAllowlistEntry{{ModelID: modelID, Status: access.ModelStatusAllowed}}, ChangedAt: changedAt,
				Event: access.SecurityEvent{
					ID: fmt.Sprintf("86000000-0000-0000-0000-%012d", index+20), EventType: string(access.SensitiveActionModelAllowlist),
					ActorIdentityID: fixture.identityID, RequestID: fmt.Sprintf("88000000-0000-0000-0000-%012d", index+20),
					Outcome: access.SecurityEventSuccess, OccurredAt: changedAt,
				},
			})
			errorsByReplacement <- err
		}(index, modelID)
	}
	close(start)
	wait.Wait()
	close(errorsByReplacement)
	for err := range errorsByReplacement {
		if err != nil {
			t.Fatalf("concurrent ReplaceModelAllowlist() error = %v", err)
		}
	}
	allowed, err := repository.ListAllowedModelIDs(context.Background())
	if err != nil {
		t.Fatalf("ListAllowedModelIDs() error = %v", err)
	}
	if len(allowed) != 1 || (allowed[0] != "gpt-a" && allowed[0] != "gpt-b") {
		t.Fatalf("allowed model IDs = %v, want exactly one complete replacement", allowed)
	}
}
