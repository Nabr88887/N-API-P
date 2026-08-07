package gateway

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	"n-api-p/internal/access"
)

const maxRejectionMetadataLength = 255

var (
	ErrInvalidRejection             = errors.New("invalid rejection metadata")
	ErrRejectionRecorderUnavailable = errors.New("rejection recorder unavailable")
)

type RejectionClass string

const (
	RejectionAuthentication RejectionClass = "authentication"
	RejectionModelPolicy    RejectionClass = "model_policy"
	RejectionRequestSize    RejectionClass = "request_size"
	RejectionTrafficLimit   RejectionClass = "traffic_limit"
)

type RejectionErrorCode string

const (
	RejectionCodeAuthenticationRequired RejectionErrorCode = "AUTHENTICATION_REQUIRED"
	RejectionCodeInvalidAPIKey          RejectionErrorCode = "INVALID_API_KEY"
	RejectionCodeModelNotAllowed        RejectionErrorCode = "MODEL_NOT_ALLOWED"
	RejectionCodeRequestTooLarge        RejectionErrorCode = "REQUEST_TOO_LARGE"
	RejectionCodeRateLimited            RejectionErrorCode = "RATE_LIMITED"
)

type RejectionAttribution struct {
	Owner TrafficOwner
	KeyID string
}

type Rejection struct {
	Class         RejectionClass
	Attribution   *RejectionAttribution
	Rule          LimitRule
	RequestID     string
	ObservedAt    time.Time
	ObservedBytes int64
	ErrorCode     RejectionErrorCode
}

type RejectionRecorder interface {
	Record(context.Context, Rejection) error
}

type SecurityEventRejectionRecorder struct {
	events access.SecurityEventWriter
	newID  func() (string, error)
}

func NewSecurityEventRejectionRecorder(events access.SecurityEventWriter) (*SecurityEventRejectionRecorder, error) {
	if events == nil {
		return nil, ErrRejectionRecorderUnavailable
	}
	return &SecurityEventRejectionRecorder{events: events, newID: newRejectionEventID}, nil
}

func (recorder *SecurityEventRejectionRecorder) Record(ctx context.Context, rejection Rejection) error {
	if recorder == nil || recorder.events == nil || recorder.newID == nil {
		return ErrRejectionRecorderUnavailable
	}
	if ctx == nil {
		return ErrInvalidRejection
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	event, err := rejection.securityEvent()
	if err != nil {
		return err
	}
	event.ID, err = recorder.newID()
	if err != nil {
		return fmt.Errorf("%w: generate event id: %w", ErrRejectionRecorderUnavailable, err)
	}
	if !safeRejectionMetadata(event.ID, true) {
		return ErrRejectionRecorderUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := recorder.events.AppendSecurityEvent(ctx, event); err != nil {
		return fmt.Errorf("%w: append security event: %w", ErrRejectionRecorderUnavailable, err)
	}
	return nil
}

func (rejection Rejection) securityEvent() (access.SecurityEvent, error) {
	if !safeRejectionMetadata(rejection.RequestID, true) || rejection.ObservedAt.IsZero() {
		return access.SecurityEvent{}, ErrInvalidRejection
	}

	event := access.SecurityEvent{
		RequestID:  rejection.RequestID,
		Outcome:    access.SecurityEventDenied,
		DetailCode: string(rejection.ErrorCode),
		OccurredAt: rejection.ObservedAt.UTC(),
	}
	switch rejection.Class {
	case RejectionAuthentication:
		if rejection.Attribution != nil || rejection.Rule != "" || rejection.ObservedBytes != 0 ||
			(rejection.ErrorCode != RejectionCodeAuthenticationRequired && rejection.ErrorCode != RejectionCodeInvalidAPIKey) {
			return access.SecurityEvent{}, ErrInvalidRejection
		}
		event.EventType = "gateway_authentication_rejected"
	case RejectionModelPolicy:
		if rejection.Attribution == nil || rejection.Rule != "" || rejection.ObservedBytes != 0 || rejection.ErrorCode != RejectionCodeModelNotAllowed {
			return access.SecurityEvent{}, ErrInvalidRejection
		}
		event.EventType = "gateway_model_policy_rejected"
	case RejectionRequestSize:
		if rejection.Rule != "" || rejection.ObservedBytes <= 0 || rejection.ErrorCode != RejectionCodeRequestTooLarge {
			return access.SecurityEvent{}, ErrInvalidRejection
		}
		event.EventType = "gateway_request_size_rejected"
		event.Reason = fmt.Sprintf("observed_bytes_%d", rejection.ObservedBytes)
	case RejectionTrafficLimit:
		if rejection.Attribution == nil || !validLimitRule(rejection.Rule) || rejection.ObservedBytes != 0 || rejection.ErrorCode != RejectionCodeRateLimited {
			return access.SecurityEvent{}, ErrInvalidRejection
		}
		event.EventType = "gateway_traffic_limit_rejected"
		event.Reason = string(rejection.Rule)
	default:
		return access.SecurityEvent{}, ErrInvalidRejection
	}

	if rejection.Attribution == nil {
		return event, nil
	}
	if err := validateTrafficOwner(rejection.Attribution.Owner); err != nil ||
		!safeRejectionMetadata(rejection.Attribution.KeyID, true) {
		return access.SecurityEvent{}, ErrInvalidRejection
	}
	event.TargetKeyID = rejection.Attribution.KeyID
	if rejection.Attribution.Owner.Kind == TrafficOwnerEmployee {
		event.ActorIdentityID = rejection.Attribution.Owner.ID
	} else {
		event.TargetServiceAccountID = rejection.Attribution.Owner.ID
	}
	return event, nil
}

func validLimitRule(rule LimitRule) bool {
	switch rule {
	case LimitRuleGlobalConcurrency,
		LimitRuleEmployeeConcurrency,
		LimitRuleEmployeeRPM,
		LimitRuleServiceAccountConcurrency,
		LimitRuleServiceAccountRPM:
		return true
	default:
		return false
	}
}

func safeRejectionMetadata(value string, required bool) bool {
	if value == "" {
		return !required
	}
	if len(value) > maxRejectionMetadataLength || value != strings.TrimSpace(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func newRejectionEventID() (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	value[6] = (value[6] & 0x0f) | 0x40
	value[8] = (value[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}

var _ RejectionRecorder = (*SecurityEventRejectionRecorder)(nil)
