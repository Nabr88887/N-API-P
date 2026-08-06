package access

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestCredentialLifecycleEventContainsOnlyAllowlistedSafeFields(t *testing.T) {
	secret := "nap_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x5c}, apiKeyRandomBytes))
	hash := sha256.Sum256([]byte(secret))
	event := CredentialLifecycleEvent{
		Action:                 CredentialLifecycleServiceKeyCreated,
		ActorIdentityID:        "admin-1",
		TargetIdentityID:       "employee-1",
		TargetServiceAccountID: "service-1",
		TargetKeyID:            "key-1",
		KeyPrefix:              secret[:apiKeyPrefixLength],
		RequestID:              "request-1",
		Outcome:                SecurityEventSuccess,
		OccurredAt:             time.Date(2026, time.August, 4, 16, 0, 0, 0, time.UTC),
	}

	jsonValue, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var logBuffer bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuffer, nil)).Info("credential lifecycle", "event", event)
	snapshot := fmt.Sprintf("%+v %#v", event, event)
	output := string(jsonValue) + logBuffer.String() + snapshot

	for _, safe := range []string{
		string(event.Action), event.ActorIdentityID, event.TargetIdentityID,
		event.TargetServiceAccountID, event.TargetKeyID, event.KeyPrefix,
		event.RequestID, string(event.Outcome), event.OccurredAt.Format(time.RFC3339),
	} {
		if !strings.Contains(output, safe) {
			t.Fatalf("allowlisted lifecycle field %q missing from output", safe)
		}
	}
	for _, forbidden := range []string{secret, base64.RawStdEncoding.EncodeToString(hash[:]), hex.EncodeToString(hash[:])} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("credential material %q appeared in lifecycle output", forbidden)
		}
	}
}

func TestCredentialLifecycleEventValidationRejectsUnknownOrIncompleteEvents(t *testing.T) {
	valid := CredentialLifecycleEvent{
		Action:           CredentialLifecyclePersonalKeyCreated,
		ActorIdentityID:  "employee-1",
		TargetIdentityID: "employee-1",
		TargetKeyID:      "key-1",
		KeyPrefix:        "nap_safe0001",
		RequestID:        "request-1",
		Outcome:          SecurityEventSuccess,
		OccurredAt:       time.Date(2026, time.August, 4, 16, 0, 0, 0, time.UTC),
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid lifecycle event error = %v", err)
	}

	tests := map[string]func(*CredentialLifecycleEvent){
		"unknown action": func(event *CredentialLifecycleEvent) { event.Action = "arbitrary" },
		"missing actor":  func(event *CredentialLifecycleEvent) { event.ActorIdentityID = "" },
		"missing key":    func(event *CredentialLifecycleEvent) { event.TargetKeyID = "" },
		"target mismatch": func(event *CredentialLifecycleEvent) {
			event.TargetIdentityID = ""
			event.TargetServiceAccountID = "service-1"
		},
		"unsafe prefix":   func(event *CredentialLifecycleEvent) { event.KeyPrefix = "complete-or-malformed-key" },
		"missing request": func(event *CredentialLifecycleEvent) { event.RequestID = "" },
		"non-success":     func(event *CredentialLifecycleEvent) { event.Outcome = SecurityEventFailure },
		"missing time":    func(event *CredentialLifecycleEvent) { event.OccurredAt = time.Time{} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			event := valid
			mutate(&event)
			if err := event.Validate(); err == nil {
				t.Fatal("invalid lifecycle event was accepted")
			}
		})
	}
}

func TestVerificationHashesAreRedactedFromRepositoryOutput(t *testing.T) {
	hash := bytes.Repeat([]byte{0x17}, sha256.Size)
	values := []any{
		PersonalKeyRecord{ID: "key-1", IdentityID: "employee-1", Name: "IDE", Prefix: "nap_safe0001", VerificationHash: hash, CreatedAt: personalKeyTestTime},
		PersonalKeyAuthenticationCandidate{KeyID: "key-1", IdentityID: "employee-1", VerificationHash: hash},
		ServiceAccountKeyRecord{ID: "key-2", ServiceAccountID: "service-1", Kind: ServiceAccountKeyKind, Name: "agent", Prefix: "nap_safe0002", VerificationHash: hash, CreatedByIdentityID: "admin-1", CreatedAt: personalKeyTestTime},
		ServiceAccountKeyAuthenticationCandidate{KeyID: "key-2", ServiceAccountID: "service-1", VerificationHash: hash},
	}
	var logBuffer bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuffer, nil))
	var output strings.Builder
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("json.Marshal(%T) error = %v", value, err)
		}
		output.Write(encoded)
		output.WriteString(fmt.Sprintf("%+v %#v", value, value))
		logger.Info("repository value", "value", value)
	}
	output.WriteString(logBuffer.String())
	for _, forbidden := range []string{
		base64.RawStdEncoding.EncodeToString(hash),
		hex.EncodeToString(hash),
		fmt.Sprint(hash),
	} {
		if strings.Contains(output.String(), forbidden) {
			t.Fatalf("verification hash %q appeared in repository output", forbidden)
		}
	}
	if !strings.Contains(output.String(), "nap_safe0001") || !strings.Contains(output.String(), "nap_safe0002") {
		t.Fatal("safe key prefixes were omitted from repository output")
	}
}

func TestCredentialLifecycleContextCompletesAnAuthoritativeKeyEvent(t *testing.T) {
	context := CredentialLifecycleContext{
		Action:                 CredentialLifecycleServiceKeyRevoked,
		ActorIdentityID:        "admin-1",
		TargetServiceAccountID: "service-1",
		RequestID:              "request-1",
		Outcome:                SecurityEventSuccess,
		OccurredAt:             time.Date(2026, time.August, 4, 16, 0, 0, 0, time.UTC),
	}
	event, err := context.ForKey("key-1", "nap_safe0001")
	if err != nil {
		t.Fatalf("ForKey() error = %v", err)
	}
	if event.Action != context.Action || event.ActorIdentityID != context.ActorIdentityID ||
		event.TargetServiceAccountID != context.TargetServiceAccountID || event.TargetKeyID != "key-1" ||
		event.KeyPrefix != "nap_safe0001" || event.RequestID != context.RequestID ||
		event.Outcome != context.Outcome || !event.OccurredAt.Equal(context.OccurredAt) {
		t.Fatalf("completed lifecycle event = %#v", event)
	}
}
