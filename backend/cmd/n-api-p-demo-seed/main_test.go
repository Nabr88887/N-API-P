package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateDemoDatabaseURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{name: "compose demo URL", url: "postgres://n_api_p_demo:LocalDemoPassword@db:5432/n_api_p_demo?sslmode=disable", want: true},
		{name: "wrong host", url: "postgres://n_api_p_demo:LocalDemoPassword@production-db:5432/n_api_p_demo?sslmode=disable", want: false},
		{name: "wrong database", url: "postgres://n_api_p_demo:LocalDemoPassword@db:5432/production?sslmode=disable", want: false},
		{name: "tls database", url: "postgres://n_api_p_demo:LocalDemoPassword@db:5432/n_api_p_demo?sslmode=verify-full", want: false},
		{name: "userinfo missing", url: "postgres://db:5432/n_api_p_demo?sslmode=disable", want: false},
		{name: "empty password", url: "postgres://n_api_p_demo:@db:5432/n_api_p_demo?sslmode=disable", want: false},
		{name: "extra query parameter", url: "postgres://n_api_p_demo:LocalDemoPassword@db:5432/n_api_p_demo?sslmode=disable&connect_timeout=5", want: false},
		{name: "postgresql alias", url: "postgresql://n_api_p_demo:LocalDemoPassword@db:5432/n_api_p_demo?sslmode=disable", want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validateDemoDatabaseURL(test.url); got != test.want {
				t.Fatalf("validateDemoDatabaseURL(%q) = %t, want %t", test.url, got, test.want)
			}
		})
	}
}

func TestWriteCredentialsUsesLocalOnlyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "demo-credentials.txt")
	if err := writeCredentials(path, "LocalDemo-test-password"); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "email=demo-admin@example.invalid\npassword=LocalDemo-test-password\n" {
		t.Fatalf("credentials content = %q", content)
	}
}

func TestDemoPasswordIsRandomAndLongEnough(t *testing.T) {
	first, err := newDemoPassword()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newDemoPassword()
	if err != nil {
		t.Fatal(err)
	}
	if first == second || len(first) < 20 || len(second) < 20 {
		t.Fatalf("demo passwords are not distinct and bounded: %d/%d", len(first), len(second))
	}
}
