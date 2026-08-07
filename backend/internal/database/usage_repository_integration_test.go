//go:build integration

package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"n-api-p/internal/usage"
	"testing"
	"time"
)

func TestRepositoryCreateUsageRecordFreezesRequestTimeFactsAndPrice(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	repository := NewRepository(db)
	record, err := usage.NewRecord(usage.RecordInput{
		ID: fixtureUsageID(1), AuditID: fixture.auditID, RequestID: fixture.requestID, KeyID: fixture.keyID,
		OwnerKind: usage.OwnerKindPersonal, IdentityID: fixture.identityID, TeamID: fixture.teamID,
		ModelID: "gpt-test", UpstreamRequestID: "upstream-usage-1", Outcome: usage.OutcomeSuccess,
		Usage:     &usage.TokenUsage{InputTokens: 100, OutputTokens: 200, TotalTokens: 300},
		Price:     &usage.PriceSnapshot{Version: "price-v1", InputUnitPrice: "0.001", OutputUnitPrice: "0.003"},
		CreatedAt: fixture.now,
	})
	if err != nil {
		t.Fatalf("usage.NewRecord() error = %v", err)
	}
	if err := repository.CreateUsageRecord(context.Background(), record); err != nil {
		t.Fatalf("CreateUsageRecord() error = %v", err)
	}

	newTeamID := "81000000-0000-0000-0000-000000000002"
	mustExec(t, db, `INSERT INTO teams (id, name, status) VALUES ($1, $2, $3)`, newTeamID, "New team", "active")
	mustExec(t, db, `DELETE FROM memberships WHERE identity_id = $1 AND team_id = $2`, fixture.identityID, fixture.teamID)
	mustExec(t, db, `INSERT INTO memberships (identity_id, team_id) VALUES ($1, $2)`, fixture.identityID, newTeamID)
	mustExec(t, db, `UPDATE api_keys SET status = 'revoked', revoked_at = $1 WHERE id = $2`, fixture.now.Add(time.Hour), fixture.keyID)

	var keyID, ownerKind, identityID, teamID, modelID, upstreamRequestID, outcome, priceVersion, inputPrice, outputPrice, calculatedAmount string
	var usageReported bool
	var inputTokens, outputTokens, totalTokens sql.NullInt64
	if err := db.QueryRow(`
SELECT key_id::text, owner_kind, identity_id::text, team_id::text, model_id, upstream_request_id, outcome,
       usage_reported, input_tokens, output_tokens, total_tokens, price_version,
       input_unit_price::text, output_unit_price::text, calculated_amount::text
FROM usage_records WHERE id = $1`, record.ID).Scan(
		&keyID, &ownerKind, &identityID, &teamID, &modelID, &upstreamRequestID, &outcome,
		&usageReported, &inputTokens, &outputTokens, &totalTokens, &priceVersion, &inputPrice, &outputPrice, &calculatedAmount,
	); err != nil {
		t.Fatalf("read usage record: %v", err)
	}
	if keyID != fixture.keyID || ownerKind != "personal" || identityID != fixture.identityID || teamID != fixture.teamID || modelID != "gpt-test" || upstreamRequestID != "upstream-usage-1" || outcome != "success" {
		t.Fatalf("frozen attribution = (%s, %s, %s, %s, %s, %s, %s)", keyID, ownerKind, identityID, teamID, modelID, upstreamRequestID, outcome)
	}
	if !usageReported || !inputTokens.Valid || inputTokens.Int64 != 100 || !outputTokens.Valid || outputTokens.Int64 != 200 || !totalTokens.Valid || totalTokens.Int64 != 300 {
		t.Fatalf("persisted usage = (%t, %+v, %+v, %+v)", usageReported, inputTokens, outputTokens, totalTokens)
	}
	if priceVersion != "price-v1" || inputPrice != "0.001000000000" || outputPrice != "0.003000000000" || calculatedAmount != "0.700000000000" {
		t.Fatalf("persisted price snapshot = (%q, %q, %q, %q)", priceVersion, inputPrice, outputPrice, calculatedAmount)
	}
}

func TestRepositoryCreateUsageRecordKeepsMissingUsageUnknown(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	secondAuditID := "84000000-0000-0000-0000-000000000002"
	secondRequestID := "87000000-0000-0000-0000-000000000002"
	insertPendingAudit(t, db, secondAuditID, secondRequestID, fixture, fixture.now.Add(time.Minute))
	record, err := usage.NewRecord(usage.RecordInput{
		ID: fixtureUsageID(2), AuditID: secondAuditID, RequestID: secondRequestID, KeyID: fixture.keyID,
		OwnerKind: usage.OwnerKindPersonal, IdentityID: fixture.identityID, TeamID: fixture.teamID,
		ModelID: "gpt-test", Outcome: usage.OutcomeUpstreamError, CreatedAt: fixture.now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("usage.NewRecord() error = %v", err)
	}
	if err := NewRepository(db).CreateUsageRecord(context.Background(), record); err != nil {
		t.Fatalf("CreateUsageRecord() error = %v", err)
	}

	var usageReported bool
	var inputTokens, outputTokens, totalTokens, priceVersion, calculatedAmount sql.NullString
	if err := db.QueryRow(`SELECT usage_reported, input_tokens::text, output_tokens::text, total_tokens::text, price_version, calculated_amount::text FROM usage_records WHERE id = $1`, record.ID).Scan(&usageReported, &inputTokens, &outputTokens, &totalTokens, &priceVersion, &calculatedAmount); err != nil {
		t.Fatalf("read unknown usage record: %v", err)
	}
	if usageReported || inputTokens.Valid || outputTokens.Valid || totalTokens.Valid || priceVersion.Valid || calculatedAmount.Valid {
		t.Fatalf("missing usage was not persisted as unknown = (%t, %+v, %+v, %+v, %+v, %+v)", usageReported, inputTokens, outputTokens, totalTokens, priceVersion, calculatedAmount)
	}
}

func TestRepositoryCreateUsageRecordIsAppendOnlyPerAuditAndRequest(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	record, err := usage.NewRecord(usage.RecordInput{
		ID: fixtureUsageID(3), AuditID: fixture.auditID, RequestID: fixture.requestID, KeyID: fixture.keyID,
		OwnerKind: usage.OwnerKindPersonal, IdentityID: fixture.identityID, TeamID: fixture.teamID,
		ModelID: "gpt-test", Outcome: usage.OutcomeCancelled, CreatedAt: fixture.now,
	})
	if err != nil {
		t.Fatalf("usage.NewRecord() error = %v", err)
	}
	repository := NewRepository(db)
	if err := repository.CreateUsageRecord(context.Background(), record); err != nil {
		t.Fatalf("first CreateUsageRecord() error = %v", err)
	}
	if err := repository.CreateUsageRecord(context.Background(), record); !errors.Is(err, usage.ErrUsageAlreadyRecorded) {
		t.Fatalf("duplicate CreateUsageRecord() error = %v, want ErrUsageAlreadyRecorded", err)
	}
}

func TestRepositoryCreateUsageRecordRejectsFactsThatDoNotMatchAudit(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	otherKeyID := "83000000-0000-0000-0000-000000000002"
	mustExec(t, db, `INSERT INTO api_keys (id, identity_id, kind, name, prefix, verification_hash, status, created_at) VALUES ($1, $2, 'personal', 'other-key', 'nap_other', $3, 'active', $4)`, otherKeyID, fixture.identityID, []byte("other-key-hash"), fixture.now)
	record, err := usage.NewRecord(usage.RecordInput{
		ID: fixtureUsageID(4), AuditID: fixture.auditID, RequestID: fixture.requestID, KeyID: otherKeyID,
		OwnerKind: usage.OwnerKindPersonal, IdentityID: fixture.identityID, TeamID: fixture.teamID,
		ModelID: "gpt-test", Outcome: usage.OutcomeSuccess, CreatedAt: fixture.now,
	})
	if err != nil {
		t.Fatalf("usage.NewRecord() error = %v", err)
	}

	if err := NewRepository(db).CreateUsageRecord(context.Background(), record); !errors.Is(err, usage.ErrInvalidRecord) {
		t.Fatalf("CreateUsageRecord() mismatched audit facts error = %v, want ErrInvalidRecord", err)
	}
}

func TestRepositoryCreateUsageRecordPersistsServiceOwnerSnapshot(t *testing.T) {
	db, _ := migrateRepositorySchema(t)
	fixture := insertAuditPolicyFixture(t, db)
	const (
		serviceAccountID = "88000000-0000-0000-0000-000000000001"
		groupKeyID       = "83000000-0000-0000-0000-000000000003"
		auditID          = "84000000-0000-0000-0000-000000000003"
		requestID        = "87000000-0000-0000-0000-000000000003"
	)
	mustExec(t, db, `INSERT INTO service_accounts (id, team_id, responsible_identity_id, name, status, created_at) VALUES ($1, $2, $3, 'usage-service', 'active', $4)`, serviceAccountID, fixture.teamID, fixture.identityID, fixture.now)
	mustExec(t, db, `INSERT INTO api_keys (id, service_account_id, kind, name, prefix, verification_hash, status, created_at) VALUES ($1, $2, 'service', 'usage-group-key', 'nap_group', $3, 'active', $4)`, groupKeyID, serviceAccountID, []byte("group-key-hash"), fixture.now)
	mustExec(t, db, `INSERT INTO audit_records (id, request_id, key_id, owner_kind, service_account_id, responsible_identity_id, team_id, model_id, capture_status, outcome, observed_request_bytes, observed_response_bytes, created_at, updated_at) VALUES ($1, $2, $3, 'service', $4, $5, $6, 'gpt-test', 'pending', 'pending', 128, 0, $7, $7)`, auditID, requestID, groupKeyID, serviceAccountID, fixture.identityID, fixture.teamID, fixture.now)
	record, err := usage.NewRecord(usage.RecordInput{
		ID: fixtureUsageID(5), AuditID: auditID, RequestID: requestID, KeyID: groupKeyID,
		OwnerKind: usage.OwnerKindService, ServiceAccountID: serviceAccountID,
		ResponsibleIdentityID: fixture.identityID, TeamID: fixture.teamID,
		ModelID: "gpt-test", Outcome: usage.OutcomeSuccess, CreatedAt: fixture.now,
	})
	if err != nil {
		t.Fatalf("usage.NewRecord() error = %v", err)
	}
	if err := NewRepository(db).CreateUsageRecord(context.Background(), record); err != nil {
		t.Fatalf("CreateUsageRecord() error = %v", err)
	}

	var ownerKind string
	var identityID, persistedServiceID, responsibleIdentityID sql.NullString
	if err := db.QueryRow(`SELECT owner_kind, identity_id::text, service_account_id::text, responsible_identity_id::text FROM usage_records WHERE id = $1`, record.ID).Scan(&ownerKind, &identityID, &persistedServiceID, &responsibleIdentityID); err != nil {
		t.Fatalf("read service usage attribution: %v", err)
	}
	if ownerKind != "service" || identityID.Valid || !persistedServiceID.Valid || persistedServiceID.String != serviceAccountID || !responsibleIdentityID.Valid || responsibleIdentityID.String != fixture.identityID {
		t.Fatalf("service usage attribution = (%q, %+v, %+v, %+v)", ownerKind, identityID, persistedServiceID, responsibleIdentityID)
	}
}

func fixtureUsageID(number int) string {
	return fmt.Sprintf("85000000-0000-0000-0000-%012d", number)
}
