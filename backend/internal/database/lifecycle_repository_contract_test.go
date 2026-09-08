package database

import (
	"strings"
	"testing"
)

func TestMetadataPurgeQueriesAreBounded(t *testing.T) {
	queries := map[string]string{
		"usage":                purgeExpiredUsageSQL,
		"audit":                purgeExpiredAuditMetadataSQL,
		"service account":      purgeExpiredServiceAccountsSQL,
		"key":                  purgeExpiredRevokedKeysSQL,
		"identity":             purgeExpiredDisabledIdentitiesSQL,
		"identity session":     purgeExpiredIdentitySessionsSQL,
		"identity code":        purgeExpiredIdentityCodesSQL,
		"model-policy updater": clearExpiredModelPolicyUpdatersSQL,
		"identity membership":  purgeExpiredIdentityMembershipsSQL,
		"investigation cases":  purgeExpiredInvestigationCasesSQL,
	}
	for name, query := range queries {
		t.Run(name, func(t *testing.T) {
			if !strings.Contains(query, "LIMIT $2") {
				t.Fatalf("%s purge is not bounded by LIMIT $2", name)
			}
		})
	}
	if !strings.Contains(purgeExpiredSecurityEventsSQL, "n_api_p_purge_security_events") ||
		!strings.Contains(purgeExpiredOperationalEventsSQL, "n_api_p_purge_security_events") {
		t.Fatal("security-event purges do not use the controlled database function")
	}
	if !strings.Contains(purgeExpiredInvestigationCasesSQL, "cases.status = 'closed'") ||
		!strings.Contains(purgeExpiredInvestigationCasesSQL, "cases.closed_at <= $1") {
		t.Fatal("investigation case purge must only remove closed cases past the closure cutoff")
	}
}

func TestRawContentPurgeQueryIsBoundedAndLockSafe(t *testing.T) {
	for _, required := range []string{
		"ORDER BY expires_at, audit_id, content_kind",
		"FOR UPDATE SKIP LOCKED",
		"LIMIT $2",
	} {
		if !strings.Contains(deleteExpiredRawContentSQL, required) {
			t.Fatalf("raw-content purge query missing %q", required)
		}
	}
	for _, required := range []string{
		"min(expires_at)",
		"oldest_expired_at < $1 - INTERVAL '1 hour'",
		"oldest_expired_at + INTERVAL '1 hour'",
	} {
		if !strings.Contains(markLifecycleCleanupSQL, required) {
			t.Fatalf("raw-content cleanup state query missing %q", required)
		}
	}
	if strings.Contains(markLifecycleCleanupSQL, "THEN deletion_overdue_since") {
		t.Fatal("raw-content cleanup must recompute overdue state from the remaining oldest row")
	}
}
