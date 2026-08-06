package access

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

var ErrInvalidCredentialLifecycleEvent = errors.New("invalid credential lifecycle event")

type CredentialLifecycleAction string

const (
	CredentialLifecyclePersonalKeyCreated            CredentialLifecycleAction = "personal_key_created"
	CredentialLifecyclePersonalKeyRevoked            CredentialLifecycleAction = "personal_key_revoked"
	CredentialLifecycleServiceKeyCreated             CredentialLifecycleAction = "service_key_created"
	CredentialLifecycleServiceKeyRotationRevoked     CredentialLifecycleAction = "service_key_rotation_revoked"
	CredentialLifecycleServiceKeyRotationCreated     CredentialLifecycleAction = "service_key_rotation_created"
	CredentialLifecycleServiceKeyRevoked             CredentialLifecycleAction = "service_key_revoked"
	CredentialLifecyclePersonalKeyOffboardingRevoked CredentialLifecycleAction = "personal_key_offboarding_revoked"
	CredentialLifecycleServiceKeyOffboardingRevoked  CredentialLifecycleAction = "service_key_offboarding_revoked"
)

// CredentialLifecycleEvent is deliberately closed over non-secret fields.
// KeyPrefix is the bounded recognizable prefix, never a complete credential.
type CredentialLifecycleEvent struct {
	Action                 CredentialLifecycleAction
	ActorIdentityID        string
	TargetIdentityID       string
	TargetServiceAccountID string
	TargetKeyID            string
	KeyPrefix              string
	RequestID              string
	Outcome                SecurityEventOutcome
	OccurredAt             time.Time
}

type CredentialLifecycleContext struct {
	Action                 CredentialLifecycleAction
	ActorIdentityID        string
	TargetIdentityID       string
	TargetServiceAccountID string
	RequestID              string
	Outcome                SecurityEventOutcome
	OccurredAt             time.Time
}

func newCredentialLifecycleContext(
	action CredentialLifecycleAction,
	actorIdentityID string,
	targetIdentityID string,
	targetServiceAccountID string,
	requestID string,
	occurredAt time.Time,
) (CredentialLifecycleContext, error) {
	requestID, err := credentialLifecycleRequestID(requestID)
	if err != nil {
		return CredentialLifecycleContext{}, err
	}
	context := CredentialLifecycleContext{
		Action:                 action,
		ActorIdentityID:        strings.TrimSpace(actorIdentityID),
		TargetIdentityID:       strings.TrimSpace(targetIdentityID),
		TargetServiceAccountID: strings.TrimSpace(targetServiceAccountID),
		RequestID:              requestID,
		Outcome:                SecurityEventSuccess,
		OccurredAt:             occurredAt,
	}
	if err := context.Validate(); err != nil {
		return CredentialLifecycleContext{}, err
	}
	return context, nil
}

func credentialLifecycleRequestID(requestID string) (string, error) {
	requestID = strings.TrimSpace(requestID)
	if requestID != "" {
		return requestID, nil
	}
	return newIdentityID()
}

func (eventContext CredentialLifecycleContext) Validate() error {
	if !knownCredentialLifecycleAction(eventContext.Action) ||
		strings.TrimSpace(eventContext.ActorIdentityID) == "" ||
		strings.TrimSpace(eventContext.RequestID) == "" ||
		eventContext.Outcome != SecurityEventSuccess || eventContext.OccurredAt.IsZero() ||
		!credentialLifecycleTargetMatches(eventContext.Action, eventContext.TargetIdentityID, eventContext.TargetServiceAccountID) {
		return ErrInvalidCredentialLifecycleEvent
	}
	return nil
}

func (eventContext CredentialLifecycleContext) ForKey(keyID, keyPrefix string) (CredentialLifecycleEvent, error) {
	if err := eventContext.Validate(); err != nil {
		return CredentialLifecycleEvent{}, err
	}
	event := CredentialLifecycleEvent{
		Action:                 eventContext.Action,
		ActorIdentityID:        eventContext.ActorIdentityID,
		TargetIdentityID:       eventContext.TargetIdentityID,
		TargetServiceAccountID: eventContext.TargetServiceAccountID,
		TargetKeyID:            strings.TrimSpace(keyID),
		KeyPrefix:              strings.TrimSpace(keyPrefix),
		RequestID:              eventContext.RequestID,
		Outcome:                eventContext.Outcome,
		OccurredAt:             eventContext.OccurredAt,
	}
	if err := event.Validate(); err != nil {
		return CredentialLifecycleEvent{}, err
	}
	return event, nil
}

func (event CredentialLifecycleEvent) Validate() error {
	if !knownCredentialLifecycleAction(event.Action) ||
		strings.TrimSpace(event.ActorIdentityID) == "" ||
		!credentialLifecycleTargetMatches(event.Action, event.TargetIdentityID, event.TargetServiceAccountID) ||
		strings.TrimSpace(event.TargetKeyID) == "" ||
		len(event.KeyPrefix) != apiKeyPrefixLength || !strings.HasPrefix(event.KeyPrefix, apiKeyPrefix) ||
		strings.TrimSpace(event.RequestID) == "" || event.Outcome != SecurityEventSuccess || event.OccurredAt.IsZero() {
		return ErrInvalidCredentialLifecycleEvent
	}
	return nil
}

func credentialLifecycleTargetMatches(action CredentialLifecycleAction, targetIdentityID, targetServiceAccountID string) bool {
	targetIdentityID = strings.TrimSpace(targetIdentityID)
	targetServiceAccountID = strings.TrimSpace(targetServiceAccountID)
	switch action {
	case CredentialLifecyclePersonalKeyCreated,
		CredentialLifecyclePersonalKeyRevoked,
		CredentialLifecyclePersonalKeyOffboardingRevoked:
		return targetIdentityID != "" && targetServiceAccountID == ""
	case CredentialLifecycleServiceKeyCreated,
		CredentialLifecycleServiceKeyRotationRevoked,
		CredentialLifecycleServiceKeyRotationCreated,
		CredentialLifecycleServiceKeyRevoked,
		CredentialLifecycleServiceKeyOffboardingRevoked:
		return targetIdentityID == "" && targetServiceAccountID != ""
	default:
		return false
	}
}

func knownCredentialLifecycleAction(action CredentialLifecycleAction) bool {
	switch action {
	case CredentialLifecyclePersonalKeyCreated,
		CredentialLifecyclePersonalKeyRevoked,
		CredentialLifecycleServiceKeyCreated,
		CredentialLifecycleServiceKeyRotationRevoked,
		CredentialLifecycleServiceKeyRotationCreated,
		CredentialLifecycleServiceKeyRevoked,
		CredentialLifecyclePersonalKeyOffboardingRevoked,
		CredentialLifecycleServiceKeyOffboardingRevoked:
		return true
	default:
		return false
	}
}

func (event CredentialLifecycleEvent) String() string {
	return fmt.Sprintf(
		"CredentialLifecycleEvent{action=%s actor=%s target_identity=%s target_service_account=%s target_key=%s key_prefix=%s request=%s outcome=%s occurred_at=%s}",
		event.Action, event.ActorIdentityID, event.TargetIdentityID, event.TargetServiceAccountID,
		event.TargetKeyID, event.KeyPrefix, event.RequestID, event.Outcome, event.OccurredAt.Format(time.RFC3339Nano),
	)
}

func (event CredentialLifecycleEvent) GoString() string {
	return event.String()
}

func (event CredentialLifecycleEvent) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("action", string(event.Action)),
		slog.String("actor_identity_id", event.ActorIdentityID),
		slog.String("target_identity_id", event.TargetIdentityID),
		slog.String("target_service_account_id", event.TargetServiceAccountID),
		slog.String("target_key_id", event.TargetKeyID),
		slog.String("key_prefix", event.KeyPrefix),
		slog.String("request_id", event.RequestID),
		slog.String("outcome", string(event.Outcome)),
		slog.Time("occurred_at", event.OccurredAt),
	)
}
