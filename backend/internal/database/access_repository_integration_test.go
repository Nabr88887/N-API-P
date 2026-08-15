//go:build integration

package database

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"n-api-p/internal/access"
)

const (
	accessTeamID     = "11000000-0000-0000-0000-000000000001"
	accessAdminID    = "21000000-0000-0000-0000-000000000001"
	accessEmployeeID = "21000000-0000-0000-0000-000000000002"
)

var accessNow = time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC)

func TestAccessRepositoryCreatesInvitationAtomically(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	repository := NewRepository(db)

	record := accessInvitationRecord("22000000-0000-0000-0000-000000000001", "32000000-0000-0000-0000-000000000001", "new@example.internal")
	if err := repository.CreateInvitation(context.Background(), record); err != nil {
		t.Fatalf("CreateInvitation() error = %v", err)
	}
	assertCountWhere(t, db, "identities", "id", record.IdentityID, 1)
	assertCountWhere(t, db, "memberships", "identity_id", record.IdentityID, 1)
	assertCountWhere(t, db, "one_time_codes", "id", record.ActivationID, 1)

	mustExec(t, db, `CREATE FUNCTION reject_access_membership() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic membership failure'; END $$`)
	mustExec(t, db, `CREATE TRIGGER reject_access_membership BEFORE INSERT ON memberships FOR EACH ROW EXECUTE FUNCTION reject_access_membership()`)
	failing := accessInvitationRecord("22000000-0000-0000-0000-000000000002", "32000000-0000-0000-0000-000000000002", "rollback@example.internal")
	if err := repository.CreateInvitation(context.Background(), failing); err == nil {
		t.Fatal("CreateInvitation() with injected second-write failure succeeded")
	}
	assertCountWhere(t, db, "identities", "id", failing.IdentityID, 0)
	assertCountWhere(t, db, "one_time_codes", "id", failing.ActivationID, 0)
}

func TestAccessRepositoryRejectsUntrustedAdministratorAndConcurrentDuplicateEmail(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	repository := NewRepository(db)

	untrusted := accessInvitationRecord("22000000-0000-0000-0000-000000000010", "32000000-0000-0000-0000-000000000010", "untrusted@example.internal")
	untrusted.IssuedByIdentityID = accessEmployeeID
	if err := repository.CreateInvitation(context.Background(), untrusted); !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("untrusted CreateInvitation() error = %v, want ErrForbidden", err)
	}
	assertCountWhere(t, db, "identities", "id", untrusted.IdentityID, 0)

	mustExec(t, db, `UPDATE identities SET status = 'disabled', disabled_at = $1 WHERE id = $2`, accessNow, accessAdminID)
	disabledAdministrator := accessInvitationRecord("22000000-0000-0000-0000-000000000013", "32000000-0000-0000-0000-000000000013", "disabled-admin@example.internal")
	if err := repository.CreateInvitation(context.Background(), disabledAdministrator); !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("disabled administrator CreateInvitation() error = %v, want ErrForbidden", err)
	}
	mustExec(t, db, `UPDATE identities SET status = 'active', disabled_at = NULL WHERE id = $1`, accessAdminID)

	mustExec(t, db, `UPDATE teams SET status = 'disabled', disabled_at = $1 WHERE id = $2`, accessNow, accessTeamID)
	disabledTeam := accessInvitationRecord("22000000-0000-0000-0000-000000000014", "32000000-0000-0000-0000-000000000014", "disabled-team@example.internal")
	if err := repository.CreateInvitation(context.Background(), disabledTeam); !errors.Is(err, access.ErrInvalidInvitation) {
		t.Fatalf("disabled team CreateInvitation() error = %v, want ErrInvalidInvitation", err)
	}
	mustExec(t, db, `UPDATE teams SET status = 'active', disabled_at = NULL WHERE id = $1`, accessTeamID)

	records := []access.InvitationRecord{
		accessInvitationRecord("22000000-0000-0000-0000-000000000011", "32000000-0000-0000-0000-000000000011", "duplicate@example.internal"),
		accessInvitationRecord("22000000-0000-0000-0000-000000000012", "32000000-0000-0000-0000-000000000012", "duplicate@example.internal"),
	}
	errorsByCall := runConcurrent(2, func(index int) error {
		return repository.CreateInvitation(context.Background(), records[index])
	})
	assertOneSuccessOneError(t, errorsByCall, access.ErrEmailAlreadyExists)
	assertCountWhere(t, db, "identities", "email", "duplicate@example.internal", 1)
}

func TestAccessRepositoryPrevalidatesAndConsumesActivationOnce(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	repository := NewRepository(db)
	record := accessInvitationRecord("22000000-0000-0000-0000-000000000020", "32000000-0000-0000-0000-000000000020", "activate@example.internal")
	if err := repository.CreateInvitation(context.Background(), record); err != nil {
		t.Fatalf("CreateInvitation() error = %v", err)
	}
	siblingID := "32000000-0000-0000-0000-000000000021"
	mustExec(t, db, `INSERT INTO one_time_codes (id, identity_id, email, purpose, code_hash, expires_at, created_at, issued_by_identity_id) VALUES ($1, $2, $3, 'activation', $4, $5, $6, $7)`, siblingID, record.IdentityID, record.Email, []byte("sibling-hash"), record.ExpiresAt, record.CreatedAt, accessAdminID)

	lookup := access.ActivationLookup{Email: record.Email, ActivationHash: record.ActivationHash, CheckedAt: accessNow}
	candidate, err := repository.PrepareActivation(context.Background(), lookup)
	if err != nil {
		t.Fatalf("PrepareActivation() error = %v", err)
	}
	activation := activationRecord(candidate, record.Email, record.ActivationHash, "encoded-password-hash", "62000000-0000-0000-0000-000000000020", accessNow)
	errorsByCall := runConcurrent(2, func(int) error {
		return repository.ActivateIdentity(context.Background(), activation)
	})
	assertOneSuccessOneError(t, errorsByCall, access.ErrActivationRejected)

	assertIdentityActivation(t, db, record.IdentityID, "encoded-password-hash")
	assertCodeTimeSet(t, db, record.ActivationID, "used_at")
	assertCodeTimeSet(t, db, siblingID, "revoked_at")

	if _, err := repository.PrepareActivation(context.Background(), lookup); err != access.ErrActivationRejected {
		t.Fatalf("reused PrepareActivation() error = %v, want ErrActivationRejected", err)
	}
}

func TestAccessRepositoryConsumesOnlyOneOfConcurrentSiblingActivations(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	repository := NewRepository(db)
	record := accessInvitationRecord("22000000-0000-0000-0000-000000000022", "32000000-0000-0000-0000-000000000022", "siblings@example.internal")
	if err := repository.CreateInvitation(context.Background(), record); err != nil {
		t.Fatalf("CreateInvitation() error = %v", err)
	}
	siblingID := "32000000-0000-0000-0000-000000000023"
	siblingHash := []byte("sibling-hash")
	mustExec(t, db, `INSERT INTO one_time_codes (id, identity_id, email, purpose, code_hash, expires_at, created_at, issued_by_identity_id) VALUES ($1, $2, $3, 'activation', $4, $5, $6, $7)`, siblingID, record.IdentityID, record.Email, siblingHash, record.ExpiresAt, record.CreatedAt, accessAdminID)
	mustExec(t, db, `CREATE FUNCTION delay_access_activation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.status = 'active' AND OLD.status = 'pending' THEN PERFORM pg_sleep(0.1); END IF; RETURN NEW; END $$`)
	mustExec(t, db, `CREATE TRIGGER delay_access_activation BEFORE UPDATE ON identities FOR EACH ROW EXECUTE FUNCTION delay_access_activation()`)

	firstCandidate, err := repository.PrepareActivation(context.Background(), access.ActivationLookup{Email: record.Email, ActivationHash: record.ActivationHash, CheckedAt: accessNow})
	if err != nil {
		t.Fatalf("PrepareActivation() first error = %v", err)
	}
	siblingCandidate, err := repository.PrepareActivation(context.Background(), access.ActivationLookup{Email: record.Email, ActivationHash: siblingHash, CheckedAt: accessNow})
	if err != nil {
		t.Fatalf("PrepareActivation() sibling error = %v", err)
	}
	activations := []access.ActivationRecord{
		activationRecord(firstCandidate, record.Email, record.ActivationHash, "first-password-hash", "62000000-0000-0000-0000-000000000022", accessNow),
		activationRecord(siblingCandidate, record.Email, siblingHash, "sibling-password-hash", "62000000-0000-0000-0000-000000000023", accessNow),
	}
	errorsByCall := runConcurrent(2, func(index int) error {
		return repository.ActivateIdentity(context.Background(), activations[index])
	})
	assertOneSuccessOneError(t, errorsByCall, access.ErrActivationRejected)
	assertOneUsedOneRevokedCode(t, db, record.IdentityID)
}

func TestAccessRepositorySerializesActivationAndEmailChange(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	repository := NewRepository(db)
	record := accessInvitationRecord("22000000-0000-0000-0000-000000000024", "32000000-0000-0000-0000-000000000024", "race@example.internal")
	if err := repository.CreateInvitation(context.Background(), record); err != nil {
		t.Fatalf("CreateInvitation() error = %v", err)
	}
	candidate, err := repository.PrepareActivation(context.Background(), access.ActivationLookup{Email: record.Email, ActivationHash: record.ActivationHash, CheckedAt: accessNow})
	if err != nil {
		t.Fatalf("PrepareActivation() error = %v", err)
	}

	errorsByCall := runConcurrent(2, func(index int) error {
		if index == 0 {
			return repository.ActivateIdentity(context.Background(), activationRecord(candidate, record.Email, record.ActivationHash, "encoded-password-hash", "62000000-0000-0000-0000-000000000024", accessNow))
		}
		return repository.ChangeIdentityEmail(context.Background(), access.EmailChangeRecord{
			IdentityID: record.IdentityID, Email: "changed@example.internal", ChangedByIdentityID: accessAdminID, ChangedAt: accessNow,
		})
	})
	if errorsByCall[1] != nil {
		t.Fatalf("concurrent ChangeIdentityEmail() error = %v", errorsByCall[1])
	}
	if errorsByCall[0] != nil && !errors.Is(errorsByCall[0], access.ErrActivationRejected) {
		t.Fatalf("concurrent ActivateIdentity() error = %v, want nil or ErrActivationRejected", errorsByCall[0])
	}
	assertActivationEmailChangeOutcome(t, db, record.IdentityID, record.ActivationID, errorsByCall[0])
}

func TestAccessRepositoryRollsBackActivationWhenCompletionEventFails(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	repository := NewRepository(db)
	record := accessInvitationRecord("22000000-0000-0000-0000-000000000025", "32000000-0000-0000-0000-000000000025", "audit-rollback@example.internal")
	if err := repository.CreateInvitation(context.Background(), record); err != nil {
		t.Fatalf("CreateInvitation() error = %v", err)
	}
	candidate, err := repository.PrepareActivation(context.Background(), access.ActivationLookup{Email: record.Email, ActivationHash: record.ActivationHash, CheckedAt: accessNow})
	if err != nil {
		t.Fatalf("PrepareActivation() error = %v", err)
	}
	activation := activationRecord(candidate, record.Email, record.ActivationHash, "rolled-back-password", "not-a-uuid", accessNow)
	if err := repository.ActivateIdentity(context.Background(), activation); err == nil {
		t.Fatal("ActivateIdentity() with invalid security event succeeded")
	}
	var status string
	var codeUsed bool
	if err := db.QueryRow(`SELECT status FROM identities WHERE id = $1`, record.IdentityID).Scan(&status); err != nil {
		t.Fatalf("query rolled-back activation identity: %v", err)
	}
	if err := db.QueryRow(`SELECT used_at IS NOT NULL FROM one_time_codes WHERE id = $1`, record.ActivationID).Scan(&codeUsed); err != nil {
		t.Fatalf("query rolled-back activation code: %v", err)
	}
	if status != "pending" || codeUsed {
		t.Fatalf("activation event failure left status/code = %q/%t, want pending/unused", status, codeUsed)
	}
}

func TestAccessRepositoryChangesEmailInPlaceAndRevokesOldCodes(t *testing.T) {
	db, _ := migrateWorkforceSchema(t)
	seedAccessOwners(t, db)
	repository := NewRepository(db)
	record := accessInvitationRecord("22000000-0000-0000-0000-000000000030", "32000000-0000-0000-0000-000000000030", "old@example.internal")
	if err := repository.CreateInvitation(context.Background(), record); err != nil {
		t.Fatalf("CreateInvitation() error = %v", err)
	}
	mustExec(t, db, `INSERT INTO api_keys (id, identity_id, kind, name, prefix, verification_hash, status) VALUES ($1, $2, 'personal', 'owned', 'nap_owned', $3, 'active')`, "42000000-0000-0000-0000-000000000030", record.IdentityID, []byte("owned-hash"))

	err := repository.ChangeIdentityEmail(context.Background(), access.EmailChangeRecord{
		IdentityID: record.IdentityID, Email: "new@example.internal", ChangedByIdentityID: accessAdminID, ChangedAt: accessNow,
	})
	if err != nil {
		t.Fatalf("ChangeIdentityEmail() error = %v", err)
	}
	assertIdentityEmailAndKeyOwner(t, db, record.IdentityID, "new@example.internal")
	assertCodeTimeSet(t, db, record.ActivationID, "revoked_at")

	err = repository.ChangeIdentityEmail(context.Background(), access.EmailChangeRecord{
		IdentityID: record.IdentityID, Email: "other@example.internal", ChangedByIdentityID: accessEmployeeID, ChangedAt: accessNow,
	})
	if !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("untrusted ChangeIdentityEmail() error = %v, want ErrForbidden", err)
	}

	err = repository.ChangeIdentityEmail(context.Background(), access.EmailChangeRecord{
		IdentityID: record.IdentityID, Email: "employee@example.internal", ChangedByIdentityID: accessAdminID, ChangedAt: accessNow,
	})
	if !errors.Is(err, access.ErrEmailAlreadyExists) {
		t.Fatalf("duplicate ChangeIdentityEmail() error = %v, want ErrEmailAlreadyExists", err)
	}

	err = repository.ChangeIdentityEmail(context.Background(), access.EmailChangeRecord{
		IdentityID: "22000000-0000-0000-0000-000000000099", Email: "missing@example.internal", ChangedByIdentityID: accessAdminID, ChangedAt: accessNow,
	})
	if !errors.Is(err, access.ErrIdentityNotFound) {
		t.Fatalf("missing ChangeIdentityEmail() error = %v, want ErrIdentityNotFound", err)
	}
}

func seedAccessOwners(t *testing.T, db *sql.DB) {
	t.Helper()
	mustExec(t, db, `INSERT INTO teams (id, name, status) VALUES ($1, 'Access', 'active')`, accessTeamID)
	mustExec(t, db, `INSERT INTO identities (id, email, role, status) VALUES ($1, 'admin@example.internal', 'system_administrator', 'active')`, accessAdminID)
	mustExec(t, db, `INSERT INTO identities (id, email, role, status) VALUES ($1, 'employee@example.internal', 'employee', 'active')`, accessEmployeeID)
}

func accessInvitationRecord(identityID, activationID, email string) access.InvitationRecord {
	return access.InvitationRecord{
		IdentityID: identityID, ActivationID: activationID, Email: email, Role: access.RoleEmployee,
		Status: access.IdentityStatusPending, TeamID: accessTeamID, ActivationHash: []byte("activation-hash-" + identityID),
		ExpiresAt: accessNow.Add(time.Hour), IssuedByIdentityID: accessAdminID, CreatedAt: accessNow.Add(-time.Hour),
		Event: access.SecurityEvent{ID: activationID, EventType: "invitation_issued", ActorIdentityID: accessAdminID, TargetIdentityID: identityID, RequestID: activationID, Outcome: access.SecurityEventSuccess, DetailCode: "pending_employee", OccurredAt: accessNow.Add(-time.Hour)},
	}
}

func activationRecord(candidate access.ActivationCandidate, email string, hash []byte, passwordHash, eventID string, activatedAt time.Time) access.ActivationRecord {
	return access.ActivationRecord{
		Candidate: candidate, Email: email, ActivationHash: hash, PasswordHash: passwordHash, ActivatedAt: activatedAt,
		Event: access.SecurityEvent{ID: eventID, EventType: "activation_completed", TargetIdentityID: candidate.IdentityID, RequestID: eventID, Outcome: access.SecurityEventSuccess, DetailCode: "account_activated", OccurredAt: activatedAt},
	}
}

func runConcurrent(count int, call func(int) error) []error {
	errorsByCall := make([]error, count)
	start := make(chan struct{})
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			<-start
			errorsByCall[index] = call(index)
		}(index)
	}
	close(start)
	wait.Wait()
	return errorsByCall
}

func assertOneSuccessOneError(t *testing.T, got []error, want error) {
	t.Helper()
	successes := 0
	wantErrors := 0
	for _, err := range got {
		if err == nil {
			successes++
		} else if errors.Is(err, want) {
			wantErrors++
		} else {
			t.Fatalf("unexpected concurrent error: %v", err)
		}
	}
	if successes != 1 || wantErrors != 1 {
		t.Fatalf("concurrent results = %v, want one success and one %v", got, want)
	}
}

func assertCountWhere(t *testing.T, db queryRower, table, column, value string, want int) {
	t.Helper()
	var got int
	query := `SELECT count(*) FROM ` + table + ` WHERE ` + column + ` = $1`
	if err := db.QueryRow(query, value).Scan(&got); err != nil {
		t.Fatalf("count %s by %s: %v", table, column, err)
	}
	if got != want {
		t.Fatalf("%s count by %s = %d, want %d", table, column, got, want)
	}
}

func assertIdentityActivation(t *testing.T, db queryRower, identityID, passwordHash string) {
	t.Helper()
	var status, gotHash string
	if err := db.QueryRow(`SELECT status, password_hash FROM identities WHERE id = $1`, identityID).Scan(&status, &gotHash); err != nil {
		t.Fatalf("query activated identity: %v", err)
	}
	if status != "active" || gotHash != passwordHash {
		t.Fatalf("activated identity = (%q, %q), want active and supplied hash", status, gotHash)
	}
}

func assertCodeTimeSet(t *testing.T, db queryRower, codeID, column string) {
	t.Helper()
	var set bool
	query := `SELECT ` + column + ` IS NOT NULL FROM one_time_codes WHERE id = $1`
	if err := db.QueryRow(query, codeID).Scan(&set); err != nil {
		t.Fatalf("query code %s: %v", column, err)
	}
	if !set {
		t.Fatalf("code %s is NULL", column)
	}
}

func assertIdentityEmailAndKeyOwner(t *testing.T, db queryRower, identityID, email string) {
	t.Helper()
	var gotEmail, keyOwner string
	if err := db.QueryRow(`SELECT i.email, k.identity_id::text FROM identities i JOIN api_keys k ON k.identity_id = i.id WHERE i.id = $1`, identityID).Scan(&gotEmail, &keyOwner); err != nil {
		t.Fatalf("query identity ownership: %v", err)
	}
	if gotEmail != email || keyOwner != identityID {
		t.Fatalf("identity ownership = (%q, %q), want (%q, %q)", gotEmail, keyOwner, email, identityID)
	}
}

func assertOneUsedOneRevokedCode(t *testing.T, db queryRower, identityID string) {
	t.Helper()
	var used int
	var revoked int
	if err := db.QueryRow(`SELECT count(*) FILTER (WHERE used_at IS NOT NULL), count(*) FILTER (WHERE revoked_at IS NOT NULL) FROM one_time_codes WHERE identity_id = $1`, identityID).Scan(&used, &revoked); err != nil {
		t.Fatalf("query sibling activation outcomes: %v", err)
	}
	if used != 1 || revoked != 1 {
		t.Fatalf("sibling activation outcomes = used %d, revoked %d; want one each", used, revoked)
	}
}

func assertActivationEmailChangeOutcome(t *testing.T, db queryRower, identityID, codeID string, activationErr error) {
	t.Helper()
	var email string
	var status string
	var used bool
	var revoked bool
	if err := db.QueryRow(`SELECT i.email, i.status, c.used_at IS NOT NULL, c.revoked_at IS NOT NULL FROM identities AS i JOIN one_time_codes AS c ON c.identity_id = i.id WHERE i.id = $1 AND c.id = $2`, identityID, codeID).Scan(&email, &status, &used, &revoked); err != nil {
		t.Fatalf("query activation/email-change outcome: %v", err)
	}
	if email != "changed@example.internal" {
		t.Fatalf("concurrent identity email = %q, want changed@example.internal", email)
	}
	if activationErr == nil {
		if status != "active" || !used || revoked {
			t.Fatalf("activation-first outcome = status %q, used %t, revoked %t", status, used, revoked)
		}
		return
	}
	if status != "pending" || used || !revoked {
		t.Fatalf("email-change-first outcome = status %q, used %t, revoked %t", status, used, revoked)
	}
}

type queryRower interface {
	QueryRow(query string, args ...any) *sql.Row
}

var _ access.InvitationRepository = (*Repository)(nil)
var _ access.ActivationRepository = (*Repository)(nil)
var _ access.IdentityRepository = (*Repository)(nil)
