package database

import (
	"strings"
	"testing"

	"n-api-p/internal/access"
)

var _ access.AdministrationRepository = (*Repository)(nil)

func TestAdministrationRepositoryUsesStableBoundedQueries(t *testing.T) {
	for name, query := range map[string]string{
		"accounts":         listAdministrationAccountsSQL,
		"teams":            listAdministrationTeamsSQL,
		"service accounts": listAdministrationServiceAccountsSQL,
	} {
		if query == "" || !containsAll(query, "ORDER BY", "LIMIT", "::uuid") {
			t.Fatalf("%s administration query is missing stable bounded pagination: %q", name, query)
		}
	}
}

func containsAll(value string, parts ...string) bool {
	for _, part := range parts {
		if !strings.Contains(value, part) {
			return false
		}
	}
	return true
}
