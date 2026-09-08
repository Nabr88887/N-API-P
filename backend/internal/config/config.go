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
	"time"
)

const (
	defaultListenAddress       = ":8080"
	defaultRawRetentionDays    = 7
	defaultRawRetentionMaxDays = 30
	hardRawRetentionMaxDays    = 30
	maximumOperatorProxyCIDRs  = 16

	defaultNewAPIConnectTimeout        = 5 * time.Second
	defaultNewAPITLSHandshakeTimeout   = 5 * time.Second
	defaultNewAPIResponseHeaderTimeout = 60 * time.Second
	defaultNewAPIIdleConnTimeout       = 90 * time.Second
	defaultNewAPITotalTimeout          = 10 * time.Minute

	minimumNewAPIConnectTimeout        = 100 * time.Millisecond
	minimumNewAPITLSHandshakeTimeout   = 100 * time.Millisecond
	minimumNewAPIResponseHeaderTimeout = 1 * time.Second
	minimumNewAPIIdleConnTimeout       = 1 * time.Second
	minimumNewAPITotalTimeout          = 1 * time.Second

	maximumNewAPIConnectTimeout        = 30 * time.Second
	maximumNewAPITLSHandshakeTimeout   = 30 * time.Second
	maximumNewAPIResponseHeaderTimeout = 5 * time.Minute
	maximumNewAPIIdleConnTimeout       = 10 * time.Minute
	maximumNewAPITotalTimeout          = 30 * time.Minute
)

type Config struct {
	ListenAddress               string
	PortalOrigin                string
	DatabaseURL                 string
	NewAPIBaseURL               *url.URL
	NewAPITokenFile             string
	NewAPIConnectTimeout        time.Duration
	NewAPITLSHandshakeTimeout   time.Duration
	NewAPIResponseHeaderTimeout time.Duration
	NewAPIIdleConnTimeout       time.Duration
	NewAPITotalTimeout          time.Duration
	AuditKeyFile                string
	OperatorProxyCIDRs          []*net.IPNet
	RawRetentionDefaultDays     int
	RawRetentionMaxDays         int
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

	newAPIConnectTimeout, err := optionalDuration(
		lookup,
		"N_API_P_NEWAPI_CONNECT_TIMEOUT",
		defaultNewAPIConnectTimeout,
		minimumNewAPIConnectTimeout,
		maximumNewAPIConnectTimeout,
	)
	if err != nil {
		return Config{}, err
	}
	newAPITLSHandshakeTimeout, err := optionalDuration(
		lookup,
		"N_API_P_NEWAPI_TLS_HANDSHAKE_TIMEOUT",
		defaultNewAPITLSHandshakeTimeout,
		minimumNewAPITLSHandshakeTimeout,
		maximumNewAPITLSHandshakeTimeout,
	)
	if err != nil {
		return Config{}, err
	}
	newAPIResponseHeaderTimeout, err := optionalDuration(
		lookup,
		"N_API_P_NEWAPI_RESPONSE_HEADER_TIMEOUT",
		defaultNewAPIResponseHeaderTimeout,
		minimumNewAPIResponseHeaderTimeout,
		maximumNewAPIResponseHeaderTimeout,
	)
	if err != nil {
		return Config{}, err
	}
	newAPIIdleConnTimeout, err := optionalDuration(
		lookup,
		"N_API_P_NEWAPI_IDLE_CONN_TIMEOUT",
		defaultNewAPIIdleConnTimeout,
		minimumNewAPIIdleConnTimeout,
		maximumNewAPIIdleConnTimeout,
	)
	if err != nil {
		return Config{}, err
	}
	newAPITotalTimeout, err := optionalDuration(
		lookup,
		"N_API_P_NEWAPI_TOTAL_TIMEOUT",
		defaultNewAPITotalTimeout,
		minimumNewAPITotalTimeout,
		maximumNewAPITotalTimeout,
	)
	if err != nil {
		return Config{}, err
	}
	if newAPITotalTimeout < newAPIResponseHeaderTimeout {
		return Config{}, errors.New("N_API_P_NEWAPI_TOTAL_TIMEOUT must not be shorter than N_API_P_NEWAPI_RESPONSE_HEADER_TIMEOUT")
	}

	listenAddress := optional(lookup, "N_API_P_LISTEN_ADDRESS", defaultListenAddress)
	if _, _, err := net.SplitHostPort(listenAddress); err != nil {
		return Config{}, errors.New("N_API_P_LISTEN_ADDRESS must be a valid host:port address")
	}
	portalOrigin := optional(lookup, "N_API_P_PORTAL_ORIGIN", "https://n-api-p.internal")
	parsedOrigin, err := url.Parse(portalOrigin)
	if err != nil || parsedOrigin.Scheme != "https" || parsedOrigin.Host == "" || parsedOrigin.User != nil || parsedOrigin.Path != "" || parsedOrigin.RawQuery != "" || parsedOrigin.Fragment != "" {
		return Config{}, errors.New("N_API_P_PORTAL_ORIGIN must be an HTTPS origin")
	}
	operatorProxyCIDRs, err := optionalCIDRs(lookup, "N_API_P_OPERATOR_PROXY_CIDRS", maximumOperatorProxyCIDRs)
	if err != nil {
		return Config{}, err
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
		ListenAddress:               listenAddress,
		PortalOrigin:                parsedOrigin.String(),
		DatabaseURL:                 databaseURL,
		NewAPIBaseURL:               newAPIURL,
		NewAPITokenFile:             newAPITokenFile,
		NewAPIConnectTimeout:        newAPIConnectTimeout,
		NewAPITLSHandshakeTimeout:   newAPITLSHandshakeTimeout,
		NewAPIResponseHeaderTimeout: newAPIResponseHeaderTimeout,
		NewAPIIdleConnTimeout:       newAPIIdleConnTimeout,
		NewAPITotalTimeout:          newAPITotalTimeout,
		AuditKeyFile:                auditKeyFile,
		OperatorProxyCIDRs:          operatorProxyCIDRs,
		RawRetentionDefaultDays:     retentionDefaultDays,
		RawRetentionMaxDays:         retentionMaxDays,
	}, nil
}

func optionalCIDRs(lookup func(string) (string, bool), key string, maximum int) ([]*net.IPNet, error) {
	value, ok := lookup(key)
	if !ok || strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	if len(parts) > maximum {
		return nil, fmt.Errorf("%s must contain at most %d CIDRs", key, maximum)
	}
	networks := make([]*net.IPNet, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			return nil, fmt.Errorf("%s must contain only valid CIDRs", key)
		}
		_, network, err := net.ParseCIDR(trimmed)
		if err != nil {
			return nil, fmt.Errorf("%s must contain only valid CIDRs", key)
		}
		networks = append(networks, network)
	}
	return networks, nil
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

func optionalDuration(
	lookup func(string) (string, bool),
	key string,
	fallback, minimum, maximum time.Duration,
) (time.Duration, error) {
	value, ok := lookup(key)
	if !ok || strings.TrimSpace(value) == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return 0, fmt.Errorf("%s must be a duration from %s through %s", key, minimum, maximum)
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
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" || parsed.Opaque != "" {
		return nil, errors.New("N_API_P_NEWAPI_BASE_URL must be an HTTPS URL without credentials, query, or fragments")
	}
	return parsed, nil
}
