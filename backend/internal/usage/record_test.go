package usage

import (
	"errors"
	"testing"
	"time"
)

var usageRecordTestTime = time.Date(2026, time.August, 7, 12, 0, 0, 0, time.UTC)

func TestNewRecordFreezesPersonalRequestTimeAttribution(t *testing.T) {
	upstreamUsage := &TokenUsage{InputTokens: 120, OutputTokens: 30, TotalTokens: 150}
	input := RecordInput{
		ID: "usage-1", AuditID: "audit-1", RequestID: "request-1", KeyID: "key-original",
		OwnerKind: OwnerKindPersonal, IdentityID: "employee-original", TeamID: "team-original",
		ModelID: "gpt-test", UpstreamRequestID: "upstream-1", Outcome: OutcomeSuccess,
		Usage: upstreamUsage, CreatedAt: usageRecordTestTime,
	}

	record, err := NewRecord(input)
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}

	input.KeyID = "key-rotated"
	input.IdentityID = "employee-changed"
	input.TeamID = "team-changed"
	upstreamUsage.InputTokens = 999
	if record.KeyID != "key-original" || record.IdentityID != "employee-original" || record.TeamID != "team-original" {
		t.Fatalf("request-time attribution changed = %+v", record)
	}
	if record.Usage == nil || record.Usage.InputTokens != 120 || record.Usage.OutputTokens != 30 || record.Usage.TotalTokens != 150 {
		t.Fatalf("upstream usage changed = %+v", record.Usage)
	}
}

func TestNewRecordFreezesServiceAccountAttribution(t *testing.T) {
	record, err := NewRecord(RecordInput{
		ID: "usage-2", AuditID: "audit-2", RequestID: "request-2", KeyID: "group-key-1",
		OwnerKind: OwnerKindService, ServiceAccountID: "service-1", ResponsibleIdentityID: "employee-1",
		TeamID: "team-1", ModelID: "gpt-test", Outcome: OutcomeUpstreamError,
		CreatedAt: usageRecordTestTime,
	})
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}
	if record.IdentityID != "" || record.ServiceAccountID != "service-1" || record.ResponsibleIdentityID != "employee-1" || record.TeamID != "team-1" {
		t.Fatalf("service attribution = %+v", record)
	}
}

func TestNewRecordPreservesMissingUpstreamUsageAsUnknown(t *testing.T) {
	record, err := NewRecord(validPersonalRecordInput())
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}
	if record.UsageReported || record.Usage != nil {
		t.Fatalf("missing usage was estimated = %+v", record)
	}
	if record.Price != nil || record.CalculatedAmount != "" {
		t.Fatalf("unknown usage has price result = %+v", record)
	}
}

func TestNewRecordBindsActivePriceSnapshotAndExactAmount(t *testing.T) {
	input := validPersonalRecordInput()
	input.Usage = &TokenUsage{InputTokens: 100, OutputTokens: 200, TotalTokens: 300}
	input.Price = &PriceSnapshot{Version: "price-v1", InputUnitPrice: "0.001", OutputUnitPrice: "0.003"}

	record, err := NewRecord(input)
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}
	input.Price.Version = "price-v2"
	input.Price.InputUnitPrice = "9"
	if record.Price == nil || record.Price.Version != "price-v1" || record.Price.InputUnitPrice != "0.001" || record.Price.OutputUnitPrice != "0.003" {
		t.Fatalf("price snapshot changed = %+v", record.Price)
	}
	if record.CalculatedAmount != "0.700000000000" {
		t.Fatalf("calculated amount = %q, want 0.700000000000", record.CalculatedAmount)
	}
}

func TestNewRecordRejectsInvalidAttributionUsageAndPrice(t *testing.T) {
	tests := map[string]RecordInput{
		"personal without identity": func() RecordInput {
			input := validPersonalRecordInput()
			input.IdentityID = ""
			return input
		}(),
		"personal with service owner": func() RecordInput {
			input := validPersonalRecordInput()
			input.ServiceAccountID = "service-1"
			return input
		}(),
		"service without responsible identity": func() RecordInput {
			input := validPersonalRecordInput()
			input.OwnerKind = OwnerKindService
			input.IdentityID = ""
			input.ServiceAccountID = "service-1"
			return input
		}(),
		"unknown outcome": func() RecordInput {
			input := validPersonalRecordInput()
			input.Outcome = Outcome("unknown")
			return input
		}(),
		"negative usage": func() RecordInput {
			input := validPersonalRecordInput()
			input.Usage = &TokenUsage{InputTokens: -1, OutputTokens: 1, TotalTokens: 0}
			return input
		}(),
		"incorrect token total": func() RecordInput {
			input := validPersonalRecordInput()
			input.Usage = &TokenUsage{InputTokens: 1, OutputTokens: 2, TotalTokens: 4}
			return input
		}(),
		"price without usage": func() RecordInput {
			input := validPersonalRecordInput()
			input.Price = &PriceSnapshot{Version: "v1", InputUnitPrice: "0.1", OutputUnitPrice: "0.2"}
			return input
		}(),
		"partial price": func() RecordInput {
			input := validPersonalRecordInput()
			input.Usage = &TokenUsage{}
			input.Price = &PriceSnapshot{Version: "v1", InputUnitPrice: "0.1"}
			return input
		}(),
		"invalid price": func() RecordInput {
			input := validPersonalRecordInput()
			input.Usage = &TokenUsage{}
			input.Price = &PriceSnapshot{Version: "v1", InputUnitPrice: "not-a-number", OutputUnitPrice: "0.2"}
			return input
		}(),
		"amount exceeds numeric column": func() RecordInput {
			input := validPersonalRecordInput()
			input.Usage = &TokenUsage{InputTokens: 2, OutputTokens: 0, TotalTokens: 2}
			input.Price = &PriceSnapshot{Version: "v1", InputUnitPrice: "999999999999.999999999999", OutputUnitPrice: "0"}
			return input
		}(),
	}

	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := NewRecord(input); !errors.Is(err, ErrInvalidRecord) {
				t.Fatalf("NewRecord() error = %v, want ErrInvalidRecord", err)
			}
		})
	}
}

func validPersonalRecordInput() RecordInput {
	return RecordInput{
		ID: "usage-1", AuditID: "audit-1", RequestID: "request-1", KeyID: "key-1",
		OwnerKind: OwnerKindPersonal, IdentityID: "employee-1", TeamID: "team-1",
		ModelID: "gpt-test", Outcome: OutcomeSuccess, CreatedAt: usageRecordTestTime,
	}
}
