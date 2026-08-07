package policy

import (
	"context"
	"errors"
	"strings"
	"unicode"
)

var (
	ErrModelNotAllowed   = errors.New("model not allowed")
	ErrPolicyUnavailable = errors.New("model policy unavailable")
	ErrInvalidModelID    = errors.New("invalid model id")
)

type ModelAllowlistReader interface {
	ListAllowedModelIDs(context.Context) ([]string, error)
}

type Resolver struct {
	reader ModelAllowlistReader
}

func NewResolver(reader ModelAllowlistReader) (*Resolver, error) {
	if reader == nil {
		return nil, ErrPolicyUnavailable
	}
	return &Resolver{reader: reader}, nil
}

func (resolver *Resolver) Authorize(ctx context.Context, modelID string) error {
	if resolver == nil || resolver.reader == nil {
		return ErrPolicyUnavailable
	}
	modelID, err := normalizeModelID(modelID)
	if err != nil {
		return err
	}
	allowed, err := resolver.reader.ListAllowedModelIDs(ctx)
	if err != nil {
		return ErrPolicyUnavailable
	}
	for _, candidate := range allowed {
		candidate, err = normalizeModelID(candidate)
		if err != nil {
			return ErrPolicyUnavailable
		}
		if candidate == modelID {
			return nil
		}
	}
	return ErrModelNotAllowed
}

func (resolver *Resolver) FilterModelIDs(ctx context.Context, upstream []string) ([]string, error) {
	if resolver == nil || resolver.reader == nil {
		return nil, ErrPolicyUnavailable
	}
	allowed, err := resolver.reader.ListAllowedModelIDs(ctx)
	if err != nil {
		return nil, ErrPolicyUnavailable
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, modelID := range allowed {
		modelID, err = normalizeModelID(modelID)
		if err != nil {
			return nil, ErrPolicyUnavailable
		}
		allowedSet[modelID] = struct{}{}
	}
	filtered := make([]string, 0, len(upstream))
	seen := make(map[string]struct{}, len(upstream))
	for _, modelID := range upstream {
		modelID, err = normalizeModelID(modelID)
		if err != nil {
			return nil, ErrInvalidModelID
		}
		if _, ok := allowedSet[modelID]; !ok {
			continue
		}
		if _, duplicate := seen[modelID]; duplicate {
			continue
		}
		seen[modelID] = struct{}{}
		filtered = append(filtered, modelID)
	}
	return filtered, nil
}

func normalizeModelID(modelID string) (string, error) {
	trimmed := strings.TrimSpace(modelID)
	if modelID != trimmed || trimmed == "" || len(trimmed) > 255 {
		return "", ErrInvalidModelID
	}
	for _, r := range trimmed {
		if unicode.IsControl(r) {
			return "", ErrInvalidModelID
		}
	}
	return trimmed, nil
}
