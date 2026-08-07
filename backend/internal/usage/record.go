package usage

import (
	"context"
	"errors"
	"math"
	"math/big"
	"strings"
	"time"
	"unicode"
)

const (
	decimalScaleDigits    = 12
	maxDecimalFieldLength = 25
	maxPriceVersionLength = 255
	maxFactFieldLength    = 255
)

var (
	ErrInvalidRecord        = errors.New("invalid usage record")
	ErrUsageAlreadyRecorded = errors.New("usage already recorded")
	decimalScale            = new(big.Int).Exp(big.NewInt(10), big.NewInt(decimalScaleDigits), nil)
	maxScaledAmount         = new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil)
)

type OwnerKind string

const (
	OwnerKindPersonal OwnerKind = "personal"
	OwnerKindService  OwnerKind = "service"
)

type Outcome string

const (
	OutcomeSuccess       Outcome = "success"
	OutcomeUpstreamError Outcome = "upstream_error"
	OutcomeCancelled     Outcome = "cancelled"
	OutcomeLocalError    Outcome = "local_error"
)

type TokenUsage struct {
	InputTokens  int64
	OutputTokens int64
	TotalTokens  int64
}

type PriceSnapshot struct {
	Version         string
	InputUnitPrice  string
	OutputUnitPrice string
}

type RecordInput struct {
	ID                    string
	AuditID               string
	RequestID             string
	KeyID                 string
	OwnerKind             OwnerKind
	IdentityID            string
	ServiceAccountID      string
	ResponsibleIdentityID string
	TeamID                string
	ModelID               string
	UpstreamRequestID     string
	Outcome               Outcome
	Usage                 *TokenUsage
	Price                 *PriceSnapshot
	CreatedAt             time.Time
}

type Record struct {
	ID                    string
	AuditID               string
	RequestID             string
	KeyID                 string
	OwnerKind             OwnerKind
	IdentityID            string
	ServiceAccountID      string
	ResponsibleIdentityID string
	TeamID                string
	ModelID               string
	UpstreamRequestID     string
	Outcome               Outcome
	UsageReported         bool
	Usage                 *TokenUsage
	Price                 *PriceSnapshot
	CalculatedAmount      string
	CreatedAt             time.Time
}

type Repository interface {
	CreateUsageRecord(context.Context, Record) error
}

func NewRecord(input RecordInput) (Record, error) {
	record := Record{
		ID: input.ID, AuditID: input.AuditID, RequestID: input.RequestID, KeyID: input.KeyID,
		OwnerKind: input.OwnerKind, IdentityID: input.IdentityID,
		ServiceAccountID: input.ServiceAccountID, ResponsibleIdentityID: input.ResponsibleIdentityID,
		TeamID: input.TeamID, ModelID: input.ModelID, UpstreamRequestID: input.UpstreamRequestID,
		Outcome: input.Outcome, CreatedAt: input.CreatedAt.UTC(),
	}
	if input.Usage != nil {
		usageCopy := *input.Usage
		record.UsageReported = true
		record.Usage = &usageCopy
	}
	if input.Price != nil {
		priceCopy := *input.Price
		record.Price = &priceCopy
	}
	if err := record.validateAndCalculate(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (record Record) Validate() error {
	validated := record
	validated.CalculatedAmount = ""
	if err := validated.validateAndCalculate(); err != nil || validated.CalculatedAmount != record.CalculatedAmount {
		return ErrInvalidRecord
	}
	return nil
}

func (record *Record) validateAndCalculate() error {
	if record == nil || !validFactField(record.ID) || !validFactField(record.AuditID) ||
		!validFactField(record.RequestID) || !validFactField(record.KeyID) ||
		!validFactField(record.TeamID) || !validFactField(record.ModelID) || record.CreatedAt.IsZero() {
		return ErrInvalidRecord
	}
	if record.UpstreamRequestID != "" && !validFactField(record.UpstreamRequestID) {
		return ErrInvalidRecord
	}
	switch record.OwnerKind {
	case OwnerKindPersonal:
		if !validFactField(record.IdentityID) || record.ServiceAccountID != "" || record.ResponsibleIdentityID != "" {
			return ErrInvalidRecord
		}
	case OwnerKindService:
		if record.IdentityID != "" || !validFactField(record.ServiceAccountID) || !validFactField(record.ResponsibleIdentityID) {
			return ErrInvalidRecord
		}
	default:
		return ErrInvalidRecord
	}
	switch record.Outcome {
	case OutcomeSuccess, OutcomeUpstreamError, OutcomeCancelled, OutcomeLocalError:
	default:
		return ErrInvalidRecord
	}
	if record.UsageReported != (record.Usage != nil) {
		return ErrInvalidRecord
	}
	if record.Usage != nil {
		if record.Usage.InputTokens < 0 || record.Usage.OutputTokens < 0 || record.Usage.TotalTokens < 0 ||
			record.Usage.InputTokens > math.MaxInt64-record.Usage.OutputTokens ||
			record.Usage.TotalTokens != record.Usage.InputTokens+record.Usage.OutputTokens {
			return ErrInvalidRecord
		}
	}
	if record.Price == nil {
		if record.CalculatedAmount != "" {
			return ErrInvalidRecord
		}
		return nil
	}
	if record.Usage == nil || !validPriceVersion(record.Price.Version) {
		return ErrInvalidRecord
	}
	inputPrice, ok := parseScaledDecimal(record.Price.InputUnitPrice)
	if !ok {
		return ErrInvalidRecord
	}
	outputPrice, ok := parseScaledDecimal(record.Price.OutputUnitPrice)
	if !ok {
		return ErrInvalidRecord
	}
	amount := new(big.Int).Mul(inputPrice, big.NewInt(record.Usage.InputTokens))
	amount.Add(amount, new(big.Int).Mul(outputPrice, big.NewInt(record.Usage.OutputTokens)))
	if amount.Sign() < 0 || amount.Cmp(maxScaledAmount) >= 0 {
		return ErrInvalidRecord
	}
	record.CalculatedAmount = formatScaledDecimal(amount)
	return nil
}

func validFactField(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > maxFactFieldLength {
		return false
	}
	for _, char := range value {
		if unicode.IsControl(char) {
			return false
		}
	}
	return true
}

func validPriceVersion(version string) bool {
	return len(version) <= maxPriceVersionLength && validFactField(version)
}

func parseScaledDecimal(value string) (*big.Int, bool) {
	if value == "" || len(value) > maxDecimalFieldLength {
		return nil, false
	}
	integerPart, fractionalPart, hasFraction := strings.Cut(value, ".")
	if integerPart == "" || (hasFraction && fractionalPart == "") || strings.Contains(fractionalPart, ".") || len(fractionalPart) > decimalScaleDigits {
		return nil, false
	}
	for _, part := range []string{integerPart, fractionalPart} {
		for _, char := range part {
			if char < '0' || char > '9' {
				return nil, false
			}
		}
	}
	if len(strings.TrimLeft(integerPart, "0")) > decimalScaleDigits {
		return nil, false
	}
	integer := new(big.Int)
	if _, ok := integer.SetString(integerPart, 10); !ok {
		return nil, false
	}
	integer.Mul(integer, decimalScale)
	if fractionalPart != "" {
		fraction := new(big.Int)
		if _, ok := fraction.SetString(fractionalPart+strings.Repeat("0", decimalScaleDigits-len(fractionalPart)), 10); !ok {
			return nil, false
		}
		integer.Add(integer, fraction)
	}
	return integer, true
}

func formatScaledDecimal(value *big.Int) string {
	digits := value.String()
	if len(digits) <= decimalScaleDigits {
		digits = strings.Repeat("0", decimalScaleDigits+1-len(digits)) + digits
	}
	return digits[:len(digits)-decimalScaleDigits] + "." + digits[len(digits)-decimalScaleDigits:]
}
