package config

import (
	"strings"
	"testing"
)

func TestLoadUsesDocumentedDefaults(t *testing.T) {
	cfg, err := Load(mapLookup(validEnvironment()))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.ListenAddress != ":8080" {
		t.Fatalf("ListenAddress = %q, want %q", cfg.ListenAddress, ":8080")
	}
	if cfg.RawRetentionDefaultDays != 7 {
		t.Fatalf("RawRetentionDefaultDays = %d, want 7", cfg.RawRetentionDefaultDays)
	}
	if cfg.RawRetentionMaxDays != 30 {
		t.Fatalf("RawRetentionMaxDays = %d, want 30", cfg.RawRetentionMaxDays)
	}
	if got := cfg.NewAPIBaseURL.String(); got != "https://newapi.internal" {
		t.Fatalf("NewAPIBaseURL = %q, want %q", got, "https://newapi.internal")
	}
}

func TestLoadRejectsMissingRequiredConfiguration(t *testing.T) {
	values := validEnvironment()
	delete(values, "N_API_P_DATABASE_URL")

	_, err := Load(mapLookup(values))
	if err == nil {
		t.Fatal("Load() error = nil, want missing configuration error")
	}
	if !strings.Contains(err.Error(), "N_API_P_DATABASE_URL") {
		t.Fatalf("Load() error = %q, want variable name", err)
	}
}

func TestLoadRejectsUnsupportedDatabaseSchemeWithoutEchoingValue(t *testing.T) {
	values := validEnvironment()
	values["N_API_P_DATABASE_URL"] = "mysql://admin:do-not-echo@db.internal/n_api_p"

	_, err := Load(mapLookup(values))
	if err == nil {
		t.Fatal("Load() error = nil, want database scheme error")
	}
	if strings.Contains(err.Error(), "do-not-echo") {
		t.Fatalf("Load() error exposes configuration value: %q", err)
	}
}

func TestLoadRejectsInsecureNewAPIURLWithoutEchoingValue(t *testing.T) {
	values := validEnvironment()
	values["N_API_P_NEWAPI_BASE_URL"] = "http://newapi.internal/private"

	_, err := Load(mapLookup(values))
	if err == nil {
		t.Fatal("Load() error = nil, want HTTPS validation error")
	}
	if strings.Contains(err.Error(), "http://") {
		t.Fatalf("Load() error exposes configuration value: %q", err)
	}
}

func TestLoadRejectsRelativeOrSharedSecretPaths(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]string)
	}{
		{
			name: "relative upstream token path",
			mutate: func(values map[string]string) {
				values["N_API_P_NEWAPI_TOKEN_FILE"] = "secrets/newapi-token"
			},
		},
		{
			name: "shared secret path",
			mutate: func(values map[string]string) {
				values["N_API_P_AUDIT_KEY_FILE"] = values["N_API_P_NEWAPI_TOKEN_FILE"]
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values := validEnvironment()
			tt.mutate(values)

			if _, err := Load(mapLookup(values)); err == nil {
				t.Fatal("Load() error = nil, want secret path validation error")
			}
		})
	}
}

func TestLoadRejectsRetentionOutsideDeploymentCeiling(t *testing.T) {
	values := validEnvironment()
	values["N_API_P_RAW_RETENTION_DEFAULT_DAYS"] = "8"
	values["N_API_P_RAW_RETENTION_MAX_DAYS"] = "7"

	_, err := Load(mapLookup(values))
	if err == nil {
		t.Fatal("Load() error = nil, want retention range error")
	}
}

func validEnvironment() map[string]string {
	return map[string]string{
		"N_API_P_DATABASE_URL":      "postgres://app:test-only@db.internal/n_api_p",
		"N_API_P_NEWAPI_BASE_URL":   "https://newapi.internal",
		"N_API_P_NEWAPI_TOKEN_FILE": "/run/secrets/newapi-token",
		"N_API_P_AUDIT_KEY_FILE":    "/run/secrets/audit-master-key",
	}
}

func mapLookup(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
