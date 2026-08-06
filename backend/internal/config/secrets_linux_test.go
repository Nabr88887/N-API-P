//go:build linux

package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadStartupLoadsSeparateRootOwnedReadOnlySecrets(t *testing.T) {
	token := []byte("synthetic-newapi-token-v1")
	auditKey := bytes.Repeat([]byte{0x21}, 32)
	tokenPath := writeRootSecretFile(t, "newapi-token", append(bytes.Clone(token), '\n'), 0o400)
	auditPath := writeRootSecretFile(t, "audit-keys.json", auditKeyFileJSON(1, map[int][]byte{1: auditKey}), 0o400)
	values := validEnvironment()
	values["N_API_P_NEWAPI_TOKEN_FILE"] = tokenPath
	values["N_API_P_AUDIT_KEY_FILE"] = auditPath

	cfg, secrets, err := LoadStartup(mapLookup(values))
	if err != nil {
		t.Fatalf("LoadStartup() error = %v", err)
	}
	if cfg.NewAPITokenFile != tokenPath || cfg.AuditKeyFile != auditPath {
		t.Fatalf("secret paths = (%q, %q), want (%q, %q)", cfg.NewAPITokenFile, cfg.AuditKeyFile, tokenPath, auditPath)
	}
	if got := secrets.NewAPIToken(); !bytes.Equal(got, token) {
		t.Fatalf("NewAPIToken() = %q, want synthetic token", got)
	}
	activeVersion, keys := secrets.AuditKeyring()
	if activeVersion != 1 || !bytes.Equal(keys[1], auditKey) {
		t.Fatalf("AuditKeyring() = (%d, %v), want version 1 synthetic key", activeVersion, keys)
	}

	returnedToken := secrets.NewAPIToken()
	returnedToken[0] ^= 0xff
	keys[1][0] ^= 0xff
	_, freshKeys := secrets.AuditKeyring()
	if bytes.Equal(secrets.NewAPIToken(), returnedToken) || bytes.Equal(freshKeys[1], keys[1]) {
		t.Fatal("secret accessors exposed mutable internal material")
	}
}

func TestLoadSecretsRejectsUnsafeFilesWithoutLeakingPathsOrContents(t *testing.T) {
	validTokenPath := writeRootSecretFile(t, "valid-token", []byte("synthetic-token"), 0o400)
	validAuditPath := writeRootSecretFile(t, "valid-audit", auditKeyFileJSON(1, map[int][]byte{1: bytes.Repeat([]byte{0x31}, 32)}), 0o400)

	unsafePath := func(name string, mode os.FileMode) string {
		t.Helper()
		return writeRootSecretFile(t, name, []byte("do-not-echo-secret-material"), mode)
	}
	nonRootPath := writeRootSecretFile(t, "non-root-owner", []byte("do-not-echo-non-root"), 0o400)
	if err := os.Chown(nonRootPath, 12345, 12345); err != nil {
		t.Fatalf("chown synthetic non-root file: %v", err)
	}
	directoryPath := filepath.Join(t.TempDir(), "secret-directory")
	if err := os.Mkdir(directoryPath, 0o400); err != nil {
		t.Fatalf("create synthetic secret directory: %v", err)
	}
	symlinkTarget := writeRootSecretFile(t, "symlink-target", []byte("do-not-echo-symlink"), 0o400)
	symlinkPath := filepath.Join(t.TempDir(), "secret-link")
	if err := os.Symlink(symlinkTarget, symlinkPath); err != nil {
		t.Fatalf("create synthetic secret symlink: %v", err)
	}

	tests := map[string]string{
		"missing":        filepath.Join(t.TempDir(), "missing-secret"),
		"owner writable": unsafePath("owner-writable", 0o600),
		"group readable": unsafePath("group-readable", 0o440),
		"world readable": unsafePath("world-readable", 0o404),
		"executable":     unsafePath("owner-executable", 0o500),
		"non-root owner": nonRootPath,
		"directory":      directoryPath,
		"symbolic link":  symlinkPath,
	}
	for name, tokenPath := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := LoadSecrets(tokenPath, validAuditPath)
			if !errors.Is(err, ErrInvalidSecretFile) {
				t.Fatalf("LoadSecrets() error = %v, want ErrInvalidSecretFile", err)
			}
			for _, forbidden := range []string{tokenPath, "do-not-echo"} {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatalf("LoadSecrets() error exposes %q: %q", forbidden, err)
				}
			}
		})
	}

	unsafeAuditPath := unsafePath("unsafe-audit", 0o600)
	if _, err := LoadSecrets(validTokenPath, unsafeAuditPath); !errors.Is(err, ErrInvalidSecretFile) {
		t.Fatalf("unsafe audit LoadSecrets() error = %v, want ErrInvalidSecretFile", err)
	}
}

func TestLoadSecretsRejectsMalformedTokenAndAuditKeyring(t *testing.T) {
	validTokenPath := writeRootSecretFile(t, "valid-token", []byte("synthetic-token"), 0o400)
	validAuditPath := writeRootSecretFile(t, "valid-audit", auditKeyFileJSON(1, map[int][]byte{1: bytes.Repeat([]byte{0x41}, 32)}), 0o400)

	invalidTokens := map[string][]byte{
		"empty":             {},
		"placeholder":       []byte("REPLACE_WITH_NEWAPI_TOKEN"),
		"leading space":     []byte(" synthetic-token"),
		"embedded newline":  []byte("synthetic\ntoken"),
		"control character": []byte{'s', 'y', 'n', 0, 't', 'h'},
		"non-ascii":         []byte("synthetic-token-\u5bc6"),
		"oversized":         bytes.Repeat([]byte{'a'}, maxNewAPITokenBytes+1),
	}
	for name, content := range invalidTokens {
		t.Run("token "+name, func(t *testing.T) {
			path := writeRootSecretFile(t, "invalid-token", content, 0o400)
			_, err := LoadSecrets(path, validAuditPath)
			if !errors.Is(err, ErrInvalidNewAPIToken) {
				t.Fatalf("LoadSecrets() error = %v, want ErrInvalidNewAPIToken", err)
			}
			if strings.Contains(err.Error(), string(content)) && len(content) > 0 {
				t.Fatalf("LoadSecrets() error exposes token content: %q", err)
			}
		})
	}

	validKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	base64WithNewline := validKey[:12] + "\n" + validKey[12:]
	tooManyEntries := make([]string, maxAuditKeyEntries+1)
	for index := range tooManyEntries {
		tooManyEntries[index] = fmt.Sprintf(`{"version":%d,"key_base64":%q}`, index+1, validKey)
	}
	invalidAuditFiles := map[string][]byte{
		"malformed json":        []byte(`{"active_version":`),
		"duplicate root field":  []byte(fmt.Sprintf(`{"active_version":1,"active_version":1,"keys":[{"version":1,"key_base64":%q}]}`, validKey)),
		"duplicate entry field": []byte(fmt.Sprintf(`{"active_version":1,"keys":[{"version":1,"version":1,"key_base64":%q}]}`, validKey)),
		"unknown field":         []byte(fmt.Sprintf(`{"active_version":1,"keys":[{"version":1,"key_base64":%q}],"extra":true}`, validKey)),
		"duplicate version":     []byte(fmt.Sprintf(`{"active_version":1,"keys":[{"version":1,"key_base64":%q},{"version":1,"key_base64":%q}]}`, validKey, validKey)),
		"missing active key":    []byte(fmt.Sprintf(`{"active_version":2,"keys":[{"version":1,"key_base64":%q}]}`, validKey)),
		"zero version":          []byte(fmt.Sprintf(`{"active_version":0,"keys":[{"version":0,"key_base64":%q}]}`, validKey)),
		"oversized version":     []byte(fmt.Sprintf(`{"active_version":2147483648,"keys":[{"version":2147483648,"key_base64":%q}]}`, validKey)),
		"invalid base64":        []byte(`{"active_version":1,"keys":[{"version":1,"key_base64":"not-base64"}]}`),
		"base64 newline":        []byte(fmt.Sprintf(`{"active_version":1,"keys":[{"version":1,"key_base64":%q}]}`, base64WithNewline)),
		"short key":             auditKeyFileJSON(1, map[int][]byte{1: bytes.Repeat([]byte{0x43}, 31)}),
		"too many keys":         []byte(fmt.Sprintf(`{"active_version":1,"keys":[%s]}`, strings.Join(tooManyEntries, ","))),
		"trailing json value":   append(auditKeyFileJSON(1, map[int][]byte{1: bytes.Repeat([]byte{0x44}, 32)}), []byte(` {}`)...),
		"oversized file":        bytes.Repeat([]byte{' '}, maxAuditKeyFileBytes+1),
	}
	for name, content := range invalidAuditFiles {
		t.Run("audit "+name, func(t *testing.T) {
			path := writeRootSecretFile(t, "invalid-audit", content, 0o400)
			_, err := LoadSecrets(validTokenPath, path)
			if !errors.Is(err, ErrInvalidAuditKeyFile) {
				t.Fatalf("LoadSecrets() error = %v, want ErrInvalidAuditKeyFile", err)
			}
			if strings.Contains(err.Error(), validKey) {
				t.Fatalf("LoadSecrets() error exposes audit key material: %q", err)
			}
		})
	}
}

func TestLoadSecretsRotatesTokenAndAuditKeysIndependently(t *testing.T) {
	tokenPath := writeRootSecretFile(t, "newapi-token", []byte("synthetic-token-v1"), 0o400)
	firstKey := bytes.Repeat([]byte{0x51}, 32)
	secondKey := bytes.Repeat([]byte{0x52}, 32)
	auditPath := writeRootSecretFile(t, "audit-keys", auditKeyFileJSON(1, map[int][]byte{1: firstKey}), 0o400)

	initial, err := LoadSecrets(tokenPath, auditPath)
	if err != nil {
		t.Fatalf("initial LoadSecrets() error = %v", err)
	}
	replaceRootSecretFile(t, tokenPath, []byte("synthetic-token-v2"))
	tokenRotated, err := LoadSecrets(tokenPath, auditPath)
	if err != nil {
		t.Fatalf("token-rotated LoadSecrets() error = %v", err)
	}
	initialVersion, initialKeys := initial.AuditKeyring()
	tokenVersion, tokenKeys := tokenRotated.AuditKeyring()
	if bytes.Equal(initial.NewAPIToken(), tokenRotated.NewAPIToken()) || tokenVersion != initialVersion || !bytes.Equal(tokenKeys[1], initialKeys[1]) {
		t.Fatal("NewAPI token rotation changed or reused audit key state")
	}

	replaceRootSecretFile(t, auditPath, auditKeyFileJSON(2, map[int][]byte{1: firstKey, 2: secondKey}))
	auditRotated, err := LoadSecrets(tokenPath, auditPath)
	if err != nil {
		t.Fatalf("audit-rotated LoadSecrets() error = %v", err)
	}
	auditVersion, auditKeys := auditRotated.AuditKeyring()
	if !bytes.Equal(auditRotated.NewAPIToken(), tokenRotated.NewAPIToken()) || auditVersion != 2 ||
		!bytes.Equal(auditKeys[1], firstKey) || !bytes.Equal(auditKeys[2], secondKey) {
		t.Fatal("audit key rotation changed token or dropped explicitly retained keys")
	}
}

func TestSecretsOutputContainsNoSecretMaterial(t *testing.T) {
	token := []byte("synthetic-output-token")
	key := bytes.Repeat([]byte{0x61}, 32)
	tokenPath := writeRootSecretFile(t, "newapi-token", token, 0o400)
	auditPath := writeRootSecretFile(t, "audit-keys", auditKeyFileJSON(7, map[int][]byte{7: key}), 0o400)
	secrets, err := LoadSecrets(tokenPath, auditPath)
	if err != nil {
		t.Fatalf("LoadSecrets() error = %v", err)
	}

	encoded, err := json.Marshal(secrets)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var logBuffer bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuffer, nil)).Info("startup secrets", "pointer", secrets, "value", *secrets)
	output := string(encoded) + fmt.Sprintf("%+v %#v %+v %#v", secrets, secrets, *secrets, *secrets) + logBuffer.String()
	for _, forbidden := range []string{
		string(token),
		base64.StdEncoding.EncodeToString(key),
		fmt.Sprint(token),
		fmt.Sprint(key),
		tokenPath,
		auditPath,
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("secret material %q appeared in output", forbidden)
		}
	}
}

func writeRootSecretFile(t *testing.T, name string, content []byte, mode os.FileMode) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("task 5.2 Linux permission tests require the documented root Docker toolchain")
	}
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatalf("write synthetic secret file: %v", err)
	}
	if err := os.Chown(path, 0, 0); err != nil {
		t.Fatalf("chown synthetic root secret file: %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod synthetic secret file: %v", err)
	}
	return path
}

func replaceRootSecretFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatalf("make synthetic secret writable: %v", err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("replace synthetic secret: %v", err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatalf("restore synthetic secret permissions: %v", err)
	}
}

func auditKeyFileJSON(activeVersion int, keys map[int][]byte) []byte {
	type entry struct {
		Version   int    `json:"version"`
		KeyBase64 string `json:"key_base64"`
	}
	versions := make([]int, 0, len(keys))
	for version := range keys {
		versions = append(versions, version)
	}
	for left := 0; left < len(versions); left++ {
		for right := left + 1; right < len(versions); right++ {
			if versions[right] < versions[left] {
				versions[left], versions[right] = versions[right], versions[left]
			}
		}
	}
	entries := make([]entry, 0, len(keys))
	for _, version := range versions {
		entries = append(entries, entry{Version: version, KeyBase64: base64.StdEncoding.EncodeToString(keys[version])})
	}
	content, err := json.Marshal(struct {
		ActiveVersion int     `json:"active_version"`
		Keys          []entry `json:"keys"`
	}{ActiveVersion: activeVersion, Keys: entries})
	if err != nil {
		panic(err)
	}
	return content
}
