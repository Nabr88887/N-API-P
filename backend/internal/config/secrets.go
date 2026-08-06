package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
)

const (
	maxNewAPITokenBytes          = 4096
	maxAuditKeyFileBytes         = 64 * 1024
	maxAuditKeyEntries           = 32
	maxConfiguredAuditKeyVersion = 1<<31 - 1
	auditMasterKeyBytes          = 32
	newAPITokenPlaceholder       = "REPLACE_WITH_NEWAPI_TOKEN"
)

var (
	ErrInvalidSecretFile   = errors.New("invalid startup secret file")
	ErrInvalidNewAPIToken  = errors.New("invalid NewAPI token")
	ErrInvalidAuditKeyFile = errors.New("invalid audit key file")
	errDuplicateJSONField  = errors.New("duplicate JSON field")
)

type Secrets struct {
	newAPIToken     []byte
	activeAuditKey  int
	auditMasterKeys map[int][]byte
}

type auditKeyFile struct {
	ActiveVersion int             `json:"active_version"`
	Keys          []auditKeyEntry `json:"keys"`
}

type auditKeyEntry struct {
	Version   int    `json:"version"`
	KeyBase64 string `json:"key_base64"`
}

func LoadStartupFromEnvironment() (Config, *Secrets, error) {
	return LoadStartup(os.LookupEnv)
}

func LoadStartup(lookup func(string) (string, bool)) (Config, *Secrets, error) {
	cfg, err := Load(lookup)
	if err != nil {
		return Config{}, nil, err
	}
	secrets, err := LoadSecrets(cfg.NewAPITokenFile, cfg.AuditKeyFile)
	if err != nil {
		return Config{}, nil, err
	}
	return cfg, secrets, nil
}

func LoadSecrets(newAPITokenPath, auditKeyPath string) (*Secrets, error) {
	tokenFile, err := readRootOwnedSecretFile(
		newAPITokenPath, "NewAPI token", maxNewAPITokenBytes+2, ErrInvalidNewAPIToken,
	)
	if err != nil {
		return nil, err
	}
	defer clear(tokenFile)
	token, err := parseNewAPIToken(tokenFile)
	if err != nil {
		return nil, err
	}

	auditFile, err := readRootOwnedSecretFile(
		auditKeyPath, "audit key", maxAuditKeyFileBytes, ErrInvalidAuditKeyFile,
	)
	if err != nil {
		clear(token)
		return nil, err
	}
	defer clear(auditFile)
	activeVersion, keys, err := parseAuditKeyFile(auditFile)
	if err != nil {
		clear(token)
		return nil, err
	}

	return &Secrets{
		newAPIToken:     token,
		activeAuditKey:  activeVersion,
		auditMasterKeys: keys,
	}, nil
}

func parseNewAPIToken(content []byte) ([]byte, error) {
	if len(content) > 0 && content[len(content)-1] == '\n' {
		content = content[:len(content)-1]
		if len(content) > 0 && content[len(content)-1] == '\r' {
			content = content[:len(content)-1]
		}
	}
	if len(content) == 0 || len(content) > maxNewAPITokenBytes ||
		bytes.Equal(content, []byte(newAPITokenPlaceholder)) {
		return nil, ErrInvalidNewAPIToken
	}
	for _, value := range content {
		if value < 0x21 || value > 0x7e {
			return nil, ErrInvalidNewAPIToken
		}
	}
	return bytes.Clone(content), nil
}

func parseAuditKeyFile(content []byte) (int, map[int][]byte, error) {
	if err := rejectDuplicateJSONFields(content); err != nil {
		return 0, nil, ErrInvalidAuditKeyFile
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var document auditKeyFile
	if err := decoder.Decode(&document); err != nil {
		return 0, nil, ErrInvalidAuditKeyFile
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return 0, nil, ErrInvalidAuditKeyFile
	}
	if document.ActiveVersion <= 0 || document.ActiveVersion > maxConfiguredAuditKeyVersion ||
		len(document.Keys) == 0 || len(document.Keys) > maxAuditKeyEntries {
		return 0, nil, ErrInvalidAuditKeyFile
	}

	keys := make(map[int][]byte, len(document.Keys))
	for _, entry := range document.Keys {
		if entry.Version <= 0 || entry.Version > maxConfiguredAuditKeyVersion {
			clearAuditKeys(keys)
			return 0, nil, ErrInvalidAuditKeyFile
		}
		if _, exists := keys[entry.Version]; exists {
			clearAuditKeys(keys)
			return 0, nil, ErrInvalidAuditKeyFile
		}
		if len(entry.KeyBase64) != base64.StdEncoding.EncodedLen(auditMasterKeyBytes) {
			clearAuditKeys(keys)
			return 0, nil, ErrInvalidAuditKeyFile
		}
		decoded, err := base64.StdEncoding.Strict().DecodeString(entry.KeyBase64)
		if err != nil || len(decoded) != auditMasterKeyBytes {
			clear(decoded)
			clearAuditKeys(keys)
			return 0, nil, ErrInvalidAuditKeyFile
		}
		keys[entry.Version] = decoded
	}
	if _, ok := keys[document.ActiveVersion]; !ok {
		clearAuditKeys(keys)
		return 0, nil, ErrInvalidAuditKeyFile
	}
	return document.ActiveVersion, keys, nil
}

func rejectDuplicateJSONFields(content []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	first, err := decoder.Token()
	if err != nil {
		return err
	}
	return walkJSONTokens(decoder, first)
}

func walkJSONTokens(decoder *json.Decoder, token json.Token) error {
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			fieldToken, err := decoder.Token()
			if err != nil {
				return err
			}
			field, ok := fieldToken.(string)
			if !ok {
				return ErrInvalidAuditKeyFile
			}
			if _, exists := seen[field]; exists {
				return errDuplicateJSONField
			}
			seen[field] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := walkJSONTokens(decoder, value); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := walkJSONTokens(decoder, value); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	default:
		return ErrInvalidAuditKeyFile
	}
}

func (secrets Secrets) NewAPIToken() []byte {
	return bytes.Clone(secrets.newAPIToken)
}

func (secrets Secrets) AuditKeyring() (int, map[int][]byte) {
	keys := make(map[int][]byte, len(secrets.auditMasterKeys))
	for version, key := range secrets.auditMasterKeys {
		keys[version] = bytes.Clone(key)
	}
	return secrets.activeAuditKey, keys
}

func (secrets Secrets) String() string {
	return fmt.Sprintf(
		"Secrets{newapi_token_configured=%t active_audit_key_version=%d available_audit_key_versions=%d}",
		len(secrets.newAPIToken) > 0, secrets.activeAuditKey, len(secrets.auditMasterKeys),
	)
}

func (secrets Secrets) GoString() string {
	return secrets.String()
}

func (secrets Secrets) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Bool("newapi_token_configured", len(secrets.newAPIToken) > 0),
		slog.Int("active_audit_key_version", secrets.activeAuditKey),
		slog.Int("available_audit_key_versions", len(secrets.auditMasterKeys)),
	)
}

func clearAuditKeys(keys map[int][]byte) {
	for _, key := range keys {
		clear(key)
	}
}
