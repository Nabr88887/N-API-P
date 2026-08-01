package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	defaultListenAddress       = ":8080"
	defaultRawRetentionDays    = 7
	defaultRawRetentionMaxDays = 30
	hardRawRetentionMaxDays    = 30
)

type Config struct {
	ListenAddress           string
	DatabaseURL             string
	NewAPIBaseURL           *url.URL
	NewAPITokenFile         string
	AuditKeyFile            string
	RawRetentionDefaultDays int
	RawRetentionMaxDays     int
}

func LoadFromEnvironment() (Config, error) {
	return Load(os.LookupEnv)
}

func Load(lookup func(string) (string, bool)) (Config, error) {
	if lookup == nil {
		return Config{}, errors.New("configuration lookup is required")
	}

	databaseURL, err := required(lookup, "N_API_P_DATABASE_URL")
	if err != nil {
		return Config{}, err
	}
	if err := validateDatabaseURL(databaseURL); err != nil {
		return Config{}, err
	}

	newAPIURLValue, err := required(lookup, "N_API_P_NEWAPI_BASE_URL")
	if err != nil {
		return Config{}, err
	}
	newAPIURL, err := validateNewAPIURL(newAPIURLValue)
	if err != nil {
		return Config{}, err
	}

	newAPITokenFile, err := requiredAbsolutePath(lookup, "N_API_P_NEWAPI_TOKEN_FILE")
	if err != nil {
		return Config{}, err
	}
	auditKeyFile, err := requiredAbsolutePath(lookup, "N_API_P_AUDIT_KEY_FILE")
	if err != nil {
		return Config{}, err
	}
	if filepath.Clean(newAPITokenFile) == filepath.Clean(auditKeyFile) {
		return Config{}, errors.New("N_API_P_NEWAPI_TOKEN_FILE and N_API_P_AUDIT_KEY_FILE must be different files")
	}

	listenAddress := optional(lookup, "N_API_P_LISTEN_ADDRESS", defaultListenAddress)
	if _, _, err := net.SplitHostPort(listenAddress); err != nil {
		return Config{}, errors.New("N_API_P_LISTEN_ADDRESS must be a valid host:port address")
	}

	retentionMaxDays, err := optionalInt(
		lookup,
		"N_API_P_RAW_RETENTION_MAX_DAYS",
		defaultRawRetentionMaxDays,
		1,
		hardRawRetentionMaxDays,
	)
	if err != nil {
		return Config{}, err
	}
	retentionDefaultDays, err := optionalInt(
		lookup,
		"N_API_P_RAW_RETENTION_DEFAULT_DAYS",
		defaultRawRetentionDays,
		1,
		retentionMaxDays,
	)
	if err != nil {
		return Config{}, err
	}

	return Config{
		ListenAddress:           listenAddress,
		DatabaseURL:             databaseURL,
		NewAPIBaseURL:           newAPIURL,
		NewAPITokenFile:         newAPITokenFile,
		AuditKeyFile:            auditKeyFile,
		RawRetentionDefaultDays: retentionDefaultDays,
		RawRetentionMaxDays:     retentionMaxDays,
	}, nil
}

func required(lookup func(string) (string, bool), key string) (string, error) {
	value, ok := lookup(key)
	if !ok || strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("%s is required", key)
	}
	return value, nil
}

func optional(lookup func(string) (string, bool), key, fallback string) string {
	value, ok := lookup(key)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func optionalInt(
	lookup func(string) (string, bool),
	key string,
	fallback int,
	minimum int,
	maximum int,
) (int, error) {
	value, ok := lookup(key)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf("%s must be an integer from %d through %d", key, minimum, maximum)
	}
	return parsed, nil
}

func requiredAbsolutePath(lookup func(string) (string, bool), key string) (string, error) {
	value, err := required(lookup, key)
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(value) {
		return "", fmt.Errorf("%s must be an absolute file path", key)
	}
	return filepath.Clean(value), nil
}

func validateDatabaseURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "postgres" && parsed.Scheme != "postgresql") || parsed.Host == "" {
		return errors.New("N_API_P_DATABASE_URL must be a valid PostgreSQL URL")
	}
	return nil
}

func validateNewAPIURL(value string) (*url.URL, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("N_API_P_NEWAPI_BASE_URL must be an HTTPS URL without credentials or fragments")
	}
	return parsed, nil
}
