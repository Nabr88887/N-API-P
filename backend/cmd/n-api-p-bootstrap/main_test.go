package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func TestBootstrapCommandRejectsMalformedInputWithoutCallingDatabase(t *testing.T) {
	for _, input := range []string{"", `{}`, `{"email":"a","password":"b","extra":true}`, `{"email":"a","password":"b"} {}`, strings.Repeat("x", 2049)} {
		var output bytes.Buffer
		err := run(context.Background(), strings.NewReader(input), &output, func(context.Context, string, string) error {
			t.Fatal("malformed input reached database")
			return nil
		})
		if err == nil || output.Len() != 0 {
			t.Fatal("malformed input was accepted or echoed")
		}
	}
}

func TestBootstrapCommandNeverEchoesCredentialsOrDatabaseErrors(t *testing.T) {
	const input = `{"email":"admin@example.invalid","password":"synthetic-password-123"}`
	for _, failure := range []error{nil, errors.New("private-dsn-and-password")} {
		var output bytes.Buffer
		err := run(context.Background(), strings.NewReader(input), &output, func(_ context.Context, email, password string) error {
			if email != "admin@example.invalid" || password != "synthetic-password-123" {
				t.Fatal("input was not preserved")
			}
			return failure
		})
		if (err != nil) != (failure != nil) {
			t.Fatal("incorrect command outcome")
		}
		combined := output.String()
		if err != nil {
			combined += err.Error()
		}
		for _, secret := range []string{"admin@example.invalid", "synthetic-password-123", "private-dsn-and-password"} {
			if strings.Contains(combined, secret) {
				t.Fatal("sensitive input reached output")
			}
		}
	}
}
