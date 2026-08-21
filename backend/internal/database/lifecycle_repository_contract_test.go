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
}
