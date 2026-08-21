package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"n-api-p/internal/access"
	"n-api-p/internal/audit"
	"n-api-p/internal/observability"
)

func TestBearerAuthenticationAttributesPersonalAndServiceCredentials(t *testing.T) {
	tests := []struct {
		name     string
		personal access.AuthenticatedPersonalKey
		service  access.AuthenticatedServiceAccountKey
		want     ChatCaller
	}{
		{
			name: "personal",
			personal: access.AuthenticatedPersonalKey{
				KeyID: "30000000-0000-0000-0000-000000000001", IdentityID: "20000000-0000-0000-0000-000000000001",
			},
			want: ChatCaller{
				RequestID: "10000000-0000-0000-0000-000000000001", KeyID: "30000000-0000-0000-0000-000000000001",
				OwnerKind: audit.OwnerKindPersonal, IdentityID: "20000000-0000-0000-0000-000000000001",
				TeamID:       "40000000-0000-0000-0000-000000000001",
				TrafficOwner: TrafficOwner{Kind: TrafficOwnerEmployee, ID: "20000000-0000-0000-0000-000000000001"},
			},
		},
		{
			name: "service",
			service: access.AuthenticatedServiceAccountKey{
				KeyID: "30000000-0000-0000-0000-000000000002", ServiceAccountID: "50000000-0000-0000-0000-000000000001",
				TeamID: "40000000-0000-0000-0000-000000000002", ResponsibleIdentityID: "20000000-0000-0000-0000-000000000002",
			},
			want: ChatCaller{
				RequestID: "10000000-0000-0000-0000-000000000001", KeyID: "30000000-0000-0000-0000-000000000002",
				OwnerKind: audit.OwnerKindService, ServiceAccountID: "50000000-0000-0000-0000-000000000001",
				TeamID: "40000000-0000-0000-0000-000000000002", ResponsibleIdentityID: "20000000-0000-0000-0000-000000000002",
				TrafficOwner: TrafficOwner{Kind: TrafficOwnerServiceAccount, ID: "50000000-0000-0000-0000-000000000001"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			personal := &fakePersonalBearerAuthenticator{result: test.personal}
			service := &fakeServiceBearerAuthenticator{result: test.service}
			middleware := mustBearerMiddleware(t, BearerAuthenticationConfig{
				Personal: personal, Service: service,
				PersonalTeams: fakePersonalTeamResolver("40000000-0000-0000-0000-000000000001"),
				Rejections:    &fakeRejectionRecorder{}, Now: func() time.Time { return rejectionTestTime },
			})
			var got ChatCaller
			next := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				got, _ = chatCallerFromContext(request.Context())
				writer.WriteHeader(http.StatusNoContent)
			})
			request := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
			request.Header.Set("Authorization", "Bearer nap_synthetic-credential")
			request = request.WithContext(observability.WithRequestID(request.Context(), test.want.RequestID))
			recorder := httptest.NewRecorder()
			middleware.Wrap(next).ServeHTTP(recorder, request)

			if recorder.Code != http.StatusNoContent || got != test.want {
				t.Fatalf("response/caller = (%d, %+v), want 204/%+v", recorder.Code, got, test.want)
			}
			wantServiceCalls := 0
			if test.name == "service" {
				wantServiceCalls = 1
			}
			if personal.calls != 1 || service.calls != wantServiceCalls {
				t.Fatalf("personal/service authentication calls = %d/%d, want 1/%d", personal.calls, service.calls, wantServiceCalls)
			}
		})
	}
}

func TestBearerAuthenticationRejectsMalformedOrInvalidCredentialsAndRecordsNoSecret(t *testing.T) {
	tests := []struct {
		name    string
		headers []string
	}{
		{name: "missing"},
		{name: "basic", headers: []string{"Basic credential"}},
		{name: "empty bearer", headers: []string{"Bearer "}},
		{name: "extra field", headers: []string{"Bearer credential extra"}},
		{name: "duplicate", headers: []string{"Bearer first", "Bearer second"}},
		{name: "unknown", headers: []string{"Bearer nap_unknown"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rejections := &fakeRejectionRecorder{}
			middleware := mustBearerMiddleware(t, BearerAuthenticationConfig{
				Personal: &fakePersonalBearerAuthenticator{}, Service: &fakeServiceBearerAuthenticator{},
				PersonalTeams: fakePersonalTeamResolver("team-1"), Rejections: rejections,
				Now: func() time.Time { return rejectionTestTime },
			})
			called := false
			request := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
			for _, value := range test.headers {
				request.Header.Add("Authorization", value)
			}
			request = request.WithContext(observability.WithRequestID(request.Context(), "10000000-0000-0000-0000-000000000001"))
			recorder := httptest.NewRecorder()
			middleware.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(recorder, request)
			if recorder.Code != http.StatusUnauthorized || called || len(rejections.values) != 1 {
				t.Fatalf("status/called/rejections = %d/%t/%+v", recorder.Code, called, rejections.values)
			}
			got := rejections.values[0]
			if got.Class != RejectionAuthentication || got.Attribution != nil || got.ErrorCode != RejectionCodeInvalidAPIKey {
				t.Fatalf("rejection = %+v, want anonymous invalid-key metadata", got)
			}
		})
	}
}

func mustBearerMiddleware(t *testing.T, config BearerAuthenticationConfig) *BearerAuthenticationMiddleware {
	t.Helper()
	middleware, err := NewBearerAuthenticationMiddleware(config)
	if err != nil {
		t.Fatalf("NewBearerAuthenticationMiddleware() error = %v", err)
	}
	return middleware
}

type fakePersonalBearerAuthenticator struct {
	result access.AuthenticatedPersonalKey
	err    error
	calls  int
}

func (fake *fakePersonalBearerAuthenticator) Authenticate(context.Context, string) (access.AuthenticatedPersonalKey, error) {
	fake.calls++
	if fake.err != nil {
		return access.AuthenticatedPersonalKey{}, fake.err
	}
	if fake.result.KeyID == "" {
		return access.AuthenticatedPersonalKey{}, access.ErrInvalidAPIKey
	}
	return fake.result, nil
}

type fakeServiceBearerAuthenticator struct {
	result access.AuthenticatedServiceAccountKey
	err    error
	calls  int
}

func (fake *fakeServiceBearerAuthenticator) Authenticate(context.Context, string) (access.AuthenticatedServiceAccountKey, error) {
	fake.calls++
	if fake.err != nil {
		return access.AuthenticatedServiceAccountKey{}, fake.err
	}
	if fake.result.KeyID == "" {
		return access.AuthenticatedServiceAccountKey{}, access.ErrInvalidAPIKey
	}
	return fake.result, nil
}

type fakePersonalTeamResolver string

func (resolver fakePersonalTeamResolver) ResolvePersonalTeamID(context.Context, string) (string, error) {
	if resolver == "" {
		return "", errors.New("synthetic team lookup failure")
	}
	return string(resolver), nil
}

type fakeRejectionRecorder struct{ values []Rejection }

func (fake *fakeRejectionRecorder) Record(_ context.Context, value Rejection) error {
	fake.values = append(fake.values, value)
	return nil
}
