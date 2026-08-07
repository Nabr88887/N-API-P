package gateway

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"n-api-p/internal/access"
)

var rejectionTestTime = time.Date(2026, time.August, 7, 15, 0, 0, 0, time.UTC)

func TestSecurityEventRejectionRecorderWritesOnlyContentFreeMetadata(t *testing.T) {
	tests := []struct {
		name                 string
		rejection            Rejection
		wantEventType        string
		wantActorIdentityID  string
		wantServiceAccountID string
		wantKeyID            string
		wantReason           string
	}{
		{
			name: "pre-authentication",
			rejection: Rejection{
				Class: RejectionAuthentication, RequestID: "10000000-0000-0000-0000-000000000001",
				ObservedAt: rejectionTestTime, ErrorCode: RejectionCodeInvalidAPIKey,
			},
			wantEventType: "gateway_authentication_rejected",
		},
		{
			name: "employee model policy",
			rejection: Rejection{
				Class: RejectionModelPolicy, RequestID: "10000000-0000-0000-0000-000000000002",
				ObservedAt: rejectionTestTime, ErrorCode: RejectionCodeModelNotAllowed,
				Attribution: &RejectionAttribution{
					Owner: TrafficOwner{Kind: TrafficOwnerEmployee, ID: "20000000-0000-0000-0000-000000000001"},
					KeyID: "30000000-0000-0000-0000-000000000001",
				},
			},
			wantEventType:       "gateway_model_policy_rejected",
			wantActorIdentityID: "20000000-0000-0000-0000-000000000001",
			wantKeyID:           "30000000-0000-0000-0000-000000000001",
		},
		{
			name: "attributed request size",
			rejection: Rejection{
				Class: RejectionRequestSize, RequestID: "10000000-0000-0000-0000-000000000003",
				ObservedAt: rejectionTestTime, ObservedBytes: 2*1024*1024 + 1, ErrorCode: RejectionCodeRequestTooLarge,
				Attribution: &RejectionAttribution{
					Owner: TrafficOwner{Kind: TrafficOwnerServiceAccount, ID: "40000000-0000-0000-0000-000000000001"},
					KeyID: "30000000-0000-0000-0000-000000000002",
				},
			},
			wantEventType:        "gateway_request_size_rejected",
			wantServiceAccountID: "40000000-0000-0000-0000-000000000001",
			wantKeyID:            "30000000-0000-0000-0000-000000000002",
			wantReason:           "observed_bytes_2097153",
		},
		{
			name: "employee traffic limit",
			rejection: Rejection{
				Class: RejectionTrafficLimit, RequestID: "10000000-0000-0000-0000-000000000004",
				ObservedAt: rejectionTestTime, ErrorCode: RejectionCodeRateLimited,
				Rule: LimitRuleEmployeeRPM,
				Attribution: &RejectionAttribution{
					Owner: TrafficOwner{Kind: TrafficOwnerEmployee, ID: "20000000-0000-0000-0000-000000000002"},
					KeyID: "30000000-0000-0000-0000-000000000003",
				},
			},
			wantEventType:       "gateway_traffic_limit_rejected",
			wantActorIdentityID: "20000000-0000-0000-0000-000000000002",
			wantKeyID:           "30000000-0000-0000-0000-000000000003",
			wantReason:          string(LimitRuleEmployeeRPM),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writer := &rejectionEventWriterFake{}
			recorder := mustNewRejectionRecorder(t, writer)
			if err := recorder.Record(context.Background(), test.rejection); err != nil {
				t.Fatalf("Record() error = %v", err)
			}
			if len(writer.events) != 1 {
				t.Fatalf("security events = %d, want 1", len(writer.events))
			}

			event := writer.events[0]
			if event.ID != "50000000-0000-0000-0000-000000000001" || event.EventType != test.wantEventType ||
				event.ActorIdentityID != test.wantActorIdentityID || event.TargetIdentityID != "" ||
				event.TargetServiceAccountID != test.wantServiceAccountID || event.TargetKeyID != test.wantKeyID ||
				event.TargetAuditID != "" || event.RequestID != test.rejection.RequestID ||
				event.Outcome != access.SecurityEventDenied || event.Reason != test.wantReason ||
				event.DetailCode != string(test.rejection.ErrorCode) || !event.OccurredAt.Equal(rejectionTestTime) {
				t.Fatalf("security event = %+v, want content-free rejection metadata", event)
			}
		})
	}
}

func TestSecurityEventRejectionRecorderAcceptsAnonymousRequestSizeRejection(t *testing.T) {
	writer := &rejectionEventWriterFake{}
	recorder := mustNewRejectionRecorder(t, writer)
	err := recorder.Record(context.Background(), Rejection{
		Class: RejectionRequestSize, RequestID: "10000000-0000-0000-0000-000000000005",
		ObservedAt: rejectionTestTime, ObservedBytes: 2*1024*1024 + 1, ErrorCode: RejectionCodeRequestTooLarge,
	})
	if err != nil {
		t.Fatalf("Record() error = %v", err)
	}
	if len(writer.events) != 1 || writer.events[0].ActorIdentityID != "" || writer.events[0].TargetServiceAccountID != "" || writer.events[0].TargetKeyID != "" {
		t.Fatalf("anonymous size event = %+v, want no attribution", writer.events)
	}
}

func TestSecurityEventRejectionRecorderRejectsUnsafeOrInconsistentMetadata(t *testing.T) {
	validAttribution := &RejectionAttribution{
		Owner: TrafficOwner{Kind: TrafficOwnerEmployee, ID: "20000000-0000-0000-0000-000000000001"},
		KeyID: "30000000-0000-0000-0000-000000000001",
	}
	valid := Rejection{
		Class: RejectionTrafficLimit, RequestID: "10000000-0000-0000-0000-000000000001",
		ObservedAt: rejectionTestTime, ErrorCode: RejectionCodeRateLimited,
		Rule: LimitRuleEmployeeConcurrency, Attribution: validAttribution,
	}
	tests := []struct {
		name   string
		mutate func(*Rejection)
	}{
		{name: "unknown class", mutate: func(input *Rejection) { input.Class = RejectionClass("unknown") }},
		{name: "wrong error code", mutate: func(input *Rejection) { input.ErrorCode = RejectionCodeModelNotAllowed }},
		{name: "missing request ID", mutate: func(input *Rejection) { input.RequestID = "" }},
		{name: "unsafe request ID", mutate: func(input *Rejection) { input.RequestID = "request\n1" }},
		{name: "missing observed time", mutate: func(input *Rejection) { input.ObservedAt = time.Time{} }},
		{name: "missing attribution", mutate: func(input *Rejection) { input.Attribution = nil }},
		{name: "missing key", mutate: func(input *Rejection) { input.Attribution.KeyID = "" }},
		{name: "invalid owner", mutate: func(input *Rejection) { input.Attribution.Owner.ID = " owner " }},
		{name: "unknown rule", mutate: func(input *Rejection) { input.Rule = LimitRule("unknown") }},
		{name: "authentication attribution", mutate: func(input *Rejection) {
			input.Class, input.ErrorCode, input.Rule = RejectionAuthentication, RejectionCodeInvalidAPIKey, ""
		}},
		{name: "model missing attribution", mutate: func(input *Rejection) {
			input.Class, input.ErrorCode, input.Rule, input.Attribution = RejectionModelPolicy, RejectionCodeModelNotAllowed, "", nil
		}},
		{name: "non-traffic rule", mutate: func(input *Rejection) {
			input.Class, input.ErrorCode = RejectionRequestSize, RejectionCodeRequestTooLarge
		}},
		{name: "size missing observed bytes", mutate: func(input *Rejection) {
			input.Class, input.ErrorCode, input.Rule = RejectionRequestSize, RejectionCodeRequestTooLarge, ""
		}},
		{name: "non-size observed bytes", mutate: func(input *Rejection) { input.ObservedBytes = 1 }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := valid
			if valid.Attribution != nil {
				attribution := *valid.Attribution
				input.Attribution = &attribution
			}
			test.mutate(&input)
			writer := &rejectionEventWriterFake{}
			recorder := mustNewRejectionRecorder(t, writer)
			if err := recorder.Record(context.Background(), input); !errors.Is(err, ErrInvalidRejection) {
				t.Fatalf("Record() error = %v, want ErrInvalidRejection", err)
			}
			if len(writer.events) != 0 {
				t.Fatalf("security events = %+v, want none", writer.events)
			}
		})
	}
}

func TestSecurityEventRejectionRecorderReturnsUnavailableWithoutLeakingMetadata(t *testing.T) {
	cause := errors.New("synthetic persistence failure")
	writer := &rejectionEventWriterFake{err: cause}
	recorder := mustNewRejectionRecorder(t, writer)
	ownerID := "20000000-0000-0000-0000-000000000001"
	err := recorder.Record(context.Background(), Rejection{
		Class: RejectionModelPolicy, RequestID: "10000000-0000-0000-0000-000000000001",
		ObservedAt: rejectionTestTime, ErrorCode: RejectionCodeModelNotAllowed,
		Attribution: &RejectionAttribution{
			Owner: TrafficOwner{Kind: TrafficOwnerEmployee, ID: ownerID},
			KeyID: "30000000-0000-0000-0000-000000000001",
		},
	})
	if !errors.Is(err, ErrRejectionRecorderUnavailable) || !errors.Is(err, cause) || strings.Contains(err.Error(), ownerID) {
		t.Fatalf("Record() error = %v, want content-free unavailable error", err)
	}
}

func TestSecurityEventRejectionRecorderPreservesEventIDFailure(t *testing.T) {
	writer := &rejectionEventWriterFake{}
	recorder := mustNewRejectionRecorder(t, writer)
	cause := errors.New("synthetic entropy failure")
	recorder.newID = func() (string, error) { return "", cause }
	err := recorder.Record(context.Background(), Rejection{
		Class: RejectionAuthentication, RequestID: "10000000-0000-0000-0000-000000000001",
		ObservedAt: rejectionTestTime, ErrorCode: RejectionCodeInvalidAPIKey,
	})
	if !errors.Is(err, ErrRejectionRecorderUnavailable) || !errors.Is(err, cause) || len(writer.events) != 0 {
		t.Fatalf("Record() = (%v, %+v), want both unavailable/cause and no event", err, writer.events)
	}
}

func TestSecurityEventRejectionRecorderHonorsCanceledContext(t *testing.T) {
	writer := &rejectionEventWriterFake{}
	recorder := mustNewRejectionRecorder(t, writer)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := recorder.Record(ctx, Rejection{
		Class: RejectionAuthentication, RequestID: "10000000-0000-0000-0000-000000000001",
		ObservedAt: rejectionTestTime, ErrorCode: RejectionCodeInvalidAPIKey,
	})
	if !errors.Is(err, context.Canceled) || len(writer.events) != 0 {
		t.Fatalf("Record(canceled) = (%v, %+v), want context.Canceled and no event", err, writer.events)
	}
}

func TestRejectionRecordingBoundaryHasNoContentOrUpstreamSurface(t *testing.T) {
	banned := []string{"body", "prompt", "tool", "credential", "authorization", "header", "raw", "upstream", "newapi"}
	for _, value := range []any{Rejection{}, RejectionAttribution{}, SecurityEventRejectionRecorder{}} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			fieldName := strings.ToLower(typeOf.Field(index).Name)
			for _, fragment := range banned {
				if strings.Contains(fieldName, fragment) {
					t.Fatalf("%s field %q exposes forbidden rejection surface %q", typeOf.Name(), fieldName, fragment)
				}
			}
		}
	}
}

func mustNewRejectionRecorder(t *testing.T, writer access.SecurityEventWriter) *SecurityEventRejectionRecorder {
	t.Helper()
	recorder, err := NewSecurityEventRejectionRecorder(writer)
	if err != nil {
		t.Fatalf("NewSecurityEventRejectionRecorder() error = %v", err)
	}
	recorder.newID = func() (string, error) {
		return "50000000-0000-0000-0000-000000000001", nil
	}
	return recorder
}

type rejectionEventWriterFake struct {
	events []access.SecurityEvent
	err    error
}

func (writer *rejectionEventWriterFake) AppendSecurityEvent(_ context.Context, event access.SecurityEvent) error {
	if writer.err != nil {
		return writer.err
	}
	writer.events = append(writer.events, event)
	return nil
}
