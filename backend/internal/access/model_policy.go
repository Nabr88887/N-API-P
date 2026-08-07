package access

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
)

var (
	ErrInvalidModelAllowlist              = errors.New("invalid model allowlist")
	ErrModelAllowlistUnavailable          = errors.New("model allowlist unavailable")
	ErrModelAllowlistConfirmationRequired = errors.New("model allowlist confirmation required")
)

const (
	MaxModelAllowlistEntries      = 100
	maxModelPriceLength           = 25
	maxModelPriceIntegerDigits    = 12
	maxModelPriceFractionalDigits = 12
	maxModelPriceVersionLength    = 255
)

type ModelStatus string

const (
	ModelStatusAllowed  ModelStatus = "allowed"
	ModelStatusDisabled ModelStatus = "disabled"
)

type ModelAllowlistEntry struct {
	ModelID             string
	Status              ModelStatus
	InputUnitPrice      string
	OutputUnitPrice     string
	PriceVersion        string
	UpdatedAt           time.Time
	UpdatedByIdentityID string
}

type ModelAllowlistChangeInput struct {
	Entries   []ModelAllowlistEntry
	Confirmed bool
	RequestID string
}

type ModelAllowlistChange struct {
	Entries   []ModelAllowlistEntry
	ChangedAt time.Time
	Event     SecurityEvent
}

func (change ModelAllowlistChange) Validate() error {
	if change.ChangedAt.IsZero() || change.Event.ID == "" || change.Event.EventType != string(SensitiveActionModelAllowlist) || change.Event.ActorIdentityID == "" || change.Event.RequestID == "" || change.Event.Outcome != SecurityEventSuccess || !change.Event.OccurredAt.Equal(change.ChangedAt) {
		return ErrInvalidModelAllowlist
	}
	_, err := normalizeModelAllowlist(change.Entries)
	return err
}

type ModelAllowlistRepository interface {
	ReadModelAllowlist(context.Context) ([]ModelAllowlistEntry, error)
	ReplaceModelAllowlist(context.Context, ModelAllowlistChange) ([]ModelAllowlistEntry, error)
	AppendSecurityEvent(context.Context, SecurityEvent) error
}

type ModelAllowlistService struct {
	repository ModelAllowlistRepository
	now        func() time.Time
	newID      func() (string, error)
}

func NewModelAllowlistService(repository ModelAllowlistRepository) (*ModelAllowlistService, error) {
	if repository == nil {
		return nil, ErrInvalidModelAllowlist
	}
	return &ModelAllowlistService{repository: repository, now: time.Now, newID: newIdentityID}, nil
}

func (service *ModelAllowlistService) Get(ctx context.Context, session ActivePortalSession) ([]ModelAllowlistEntry, error) {
	if service == nil || service.repository == nil || session.IdentityID == "" || session.Role != RoleSystemAdministrator {
		return nil, ErrForbidden
	}
	entries, err := service.repository.ReadModelAllowlist(ctx)
	if err != nil {
		return nil, ErrModelAllowlistUnavailable
	}
	normalized, err := normalizeModelAllowlist(entries)
	if err != nil {
		return nil, ErrModelAllowlistUnavailable
	}
	return normalized, nil
}

func (service *ModelAllowlistService) Replace(ctx context.Context, session ActivePortalSession, input ModelAllowlistChangeInput) ([]ModelAllowlistEntry, error) {
	if service == nil || service.repository == nil || service.newID == nil || strings.TrimSpace(input.RequestID) == "" {
		return nil, ErrInvalidModelAllowlist
	}
	now := service.now().UTC()
	eventID, err := service.newID()
	if err != nil {
		return nil, ErrSecurityAuditUnavailable
	}
	event := SecurityEvent{ID: eventID, EventType: string(SensitiveActionModelAllowlist), ActorIdentityID: session.IdentityID, RequestID: input.RequestID, Outcome: SecurityEventSuccess, DetailCode: "authorized", OccurredAt: now}
	var denial error
	switch {
	case session.IdentityID == "" || session.Role != RoleSystemAdministrator:
		event.Outcome, event.DetailCode, denial = SecurityEventDenied, "forbidden", ErrForbidden
	case session.ReauthenticatedUntil == nil || !session.ReauthenticatedUntil.After(now):
		event.Outcome, event.DetailCode, denial = SecurityEventDenied, "reauthentication_required", ErrReauthenticationRequired
	case !input.Confirmed:
		event.Outcome, event.DetailCode, denial = SecurityEventDenied, "confirmation_required", ErrModelAllowlistConfirmationRequired
	default:
		input.Entries, denial = normalizeModelAllowlist(input.Entries)
		if denial != nil {
			event.Outcome, event.DetailCode = SecurityEventDenied, "invalid_model_allowlist"
		}
	}
	if denial != nil {
		if err := service.repository.AppendSecurityEvent(ctx, event); err != nil {
			return nil, ErrSecurityAuditUnavailable
		}
		return nil, denial
	}
	entries, err := service.repository.ReplaceModelAllowlist(ctx, ModelAllowlistChange{Entries: input.Entries, ChangedAt: now, Event: event})
	if err != nil {
		switch {
		case errors.Is(err, ErrForbidden):
			return nil, ErrForbidden
		case errors.Is(err, ErrInvalidModelAllowlist):
			return nil, ErrInvalidModelAllowlist
		default:
			return nil, ErrModelAllowlistUnavailable
		}
	}
	entries, err = normalizeModelAllowlist(entries)
	if err != nil {
		return nil, ErrModelAllowlistUnavailable
	}
	return entries, nil
}

func normalizeModelAllowlist(entries []ModelAllowlistEntry) ([]ModelAllowlistEntry, error) {
	if len(entries) > MaxModelAllowlistEntries {
		return nil, ErrInvalidModelAllowlist
	}
	result := make([]ModelAllowlistEntry, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		modelID := strings.TrimSpace(entry.ModelID)
		if modelID == "" || len(modelID) > 255 {
			return nil, ErrInvalidModelAllowlist
		}
		for _, r := range modelID {
			if unicode.IsControl(r) {
				return nil, ErrInvalidModelAllowlist
			}
		}
		if entry.Status != ModelStatusAllowed && entry.Status != ModelStatusDisabled {
			return nil, ErrInvalidModelAllowlist
		}
		if err := validatePriceSnapshot(entry); err != nil {
			return nil, err
		}
		if _, exists := seen[modelID]; exists {
			return nil, ErrInvalidModelAllowlist
		}
		seen[modelID] = struct{}{}
		entry.ModelID = modelID
		result = append(result, entry)
	}
	return result, nil
}

func validatePriceSnapshot(entry ModelAllowlistEntry) error {
	provided := entry.InputUnitPrice != "" || entry.OutputUnitPrice != "" || entry.PriceVersion != ""
	complete := entry.InputUnitPrice != "" && entry.OutputUnitPrice != "" && entry.PriceVersion != ""
	if provided && !complete {
		return ErrInvalidModelAllowlist
	}
	if !provided {
		return nil
	}
	for _, price := range []string{entry.InputUnitPrice, entry.OutputUnitPrice} {
		if !validModelPrice(price) {
			return ErrInvalidModelAllowlist
		}
	}
	if entry.PriceVersion != strings.TrimSpace(entry.PriceVersion) || len(entry.PriceVersion) > maxModelPriceVersionLength {
		return ErrInvalidModelAllowlist
	}
	for _, r := range entry.PriceVersion {
		if unicode.IsControl(r) {
			return ErrInvalidModelAllowlist
		}
	}
	return nil
}

func validModelPrice(price string) bool {
	if price == "" || len(price) > maxModelPriceLength {
		return false
	}
	integerPart, fractionalPart, hasFraction := strings.Cut(price, ".")
	if integerPart == "" || (hasFraction && fractionalPart == "") || strings.Contains(fractionalPart, ".") {
		return false
	}
	for _, part := range []string{integerPart, fractionalPart} {
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	return len(strings.TrimLeft(integerPart, "0")) <= maxModelPriceIntegerDigits && len(fractionalPart) <= maxModelPriceFractionalDigits
}
