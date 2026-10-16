package database

import (
	"context"
	"errors"
	"strings"
	"testing"

	"n-api-p/internal/access"
)

func TestBootstrapRejectsInvalidInputBeforeDatabaseAccess(t *testing.T) {
	for _, email := range []string{"", "admin", "Admin <admin@example.invalid>", "a@example.invalid\nother", strings.Repeat("a", 255) + "@example.invalid"} {
		t.Run(email, func(t *testing.T) {
			err := NewRepository(nil).BootstrapAdministrator(context.Background(), email, "synthetic-password-123")
			if !errors.Is(err, ErrInvalidBootstrapInput) {
				t.Fatalf("invalid email error = %v", err)
			}
		})
	}
	if err := NewRepository(nil).BootstrapAdministrator(context.Background(), "admin@example.invalid", "short"); !errors.Is(err, access.ErrPasswordRejected) {
		t.Fatalf("weak password error = %v", err)
	}
}
