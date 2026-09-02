package database

import (
	"strings"
	"testing"

	"n-api-p/internal/access"
)

var _ access.ServiceAccountRepository = (*Repository)(nil)

func TestServiceAccountKeyListQueryIsStableAndBounded(t *testing.T) {
	for _, fragment := range []string{
		"(k.created_at, k.id) < ($2, $3::uuid)",
		"ORDER BY k.created_at DESC, k.id DESC",
		"LIMIT $4",
	} {
		if !strings.Contains(listServiceAccountKeysSQL, fragment) {
			t.Fatalf("service key list query missing %q", fragment)
		}
	}
}
