package policy

import (
	"context"
	"errors"
	"testing"
)

func TestResolverAuthorizesSameGlobalAllowlistForEmployeeAndServiceAccount(t *testing.T) {
	resolver, err := NewResolver(&allowlistReaderFake{allowed: []string{"gpt-4o"}})
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	for _, caller := range []string{"employee", "service_account"} {
		if err := resolver.Authorize(context.Background(), "gpt-4o"); err != nil {
			t.Fatalf("Authorize(%s) error = %v, want nil", caller, err)
		}
		if err := resolver.Authorize(context.Background(), "gpt-3.5"); !errors.Is(err, ErrModelNotAllowed) {
			t.Fatalf("Authorize(%s, disallowed) error = %v, want ErrModelNotAllowed", caller, err)
		}
	}
}

func TestResolverFiltersUpstreamModelsByActiveGlobalAllowlist(t *testing.T) {
	resolver, err := NewResolver(&allowlistReaderFake{allowed: []string{"gpt-4o", "gpt-4.1"}})
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	models, err := resolver.FilterModelIDs(context.Background(), []string{"gpt-3.5", "gpt-4.1", "gpt-4o"})
	if err != nil {
		t.Fatalf("FilterModelIDs() error = %v", err)
	}
	if got, want := models, []string{"gpt-4.1", "gpt-4o"}; !equalStrings(got, want) {
		t.Fatalf("filtered models = %v, want %v", got, want)
	}
}

func TestResolverRejectsInvalidModelIDsAndPropagatesPolicyFailure(t *testing.T) {
	resolver, err := NewResolver(&allowlistReaderFake{allowed: []string{"gpt-4o"}})
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	for _, modelID := range []string{"", " gpt-4o ", "gpt\n4o"} {
		if err := resolver.Authorize(context.Background(), modelID); !errors.Is(err, ErrInvalidModelID) {
			t.Fatalf("Authorize(%q) error = %v, want ErrInvalidModelID", modelID, err)
		}
	}
	readerErr := errors.New("policy store unavailable")
	resolver, err = NewResolver(&allowlistReaderFake{err: readerErr})
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	if err := resolver.Authorize(context.Background(), "gpt-4o"); !errors.Is(err, ErrPolicyUnavailable) {
		t.Fatalf("Authorize() error = %v, want ErrPolicyUnavailable", err)
	}
}

type allowlistReaderFake struct {
	allowed []string
	err     error
}

func (r *allowlistReaderFake) ListAllowedModelIDs(context.Context) ([]string, error) {
	if r.err != nil {
		return nil, r.err
	}
	return append([]string(nil), r.allowed...), nil
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
