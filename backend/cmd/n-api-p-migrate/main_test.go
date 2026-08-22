package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"n-api-p/internal/observability"
)

func TestRunEmitsOnlyStablePreflightFailureEvent(t *testing.T) {
	var output bytes.Buffer
	logger := observability.NewJSONLoggerWithClock(&output, func() time.Time {
		return time.Date(2026, 8, 22, 8, 0, 0, 0, time.UTC)
	})
	values := map[string]string{
		"N_API_P_DATABASE_URL":                      "not-a-url-with-supersecret",
		"N_API_P_MIGRATION_EXPECTED_SOURCE_VERSION": "6",
		"N_API_P_MIGRATION_RECOVERY_MANIFEST_PATH":  "/private/recovery-manifest.json",
	}

	exitCode := run(func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}, func() time.Time {
		return time.Date(2026, 8, 22, 8, 0, 0, 0, time.UTC)
	}, logger)

	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
	logLine := output.String()
	for _, forbidden := range []string{"supersecret", "/private/", "not-a-url"} {
		if strings.Contains(logLine, forbidden) {
			t.Fatalf("log output leaked %q: %s", forbidden, logLine)
		}
	}
	for _, required := range []string{`"event":"migration_preflight_rejected"`, `"error_code":"migration_configuration_rejected"`} {
		if !strings.Contains(logLine, required) {
			t.Fatalf("log output = %s, want %s", logLine, required)
		}
	}
}
