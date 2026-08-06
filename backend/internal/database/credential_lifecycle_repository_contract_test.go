package database

import (
	"os"
	"strings"
	"testing"
)

func TestCredentialLifecyclePersistenceUsesOnlySafeEventFields(t *testing.T) {
	paths := []string{
		"personal_key_repository.go",
		"service_account_repository.go",
		"offboarding_repository.go",
		"access_repository.go",
	}
	var source strings.Builder
	for _, path := range paths {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read repository source %q: %v", path, err)
		}
		source.Write(contents)
	}
	text := source.String()
	for _, required := range []string{
		"appendCredentialLifecycleEvent",
		"target_service_account_id",
		"target_key_id",
		"request_id",
		"detail_code",
		"gen_random_uuid()",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("credential lifecycle persistence is missing %q", required)
		}
	}
	if strings.Contains(text, "INSERT INTO security_events (\n    id, event_type, actor_identity_id, target_identity_id, target_service_account_id, target_key_id, request_id, outcome, detail_code, occurred_at, verification_hash") {
		t.Fatal("credential lifecycle event insert includes verification_hash")
	}
}
