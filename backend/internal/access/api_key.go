package access

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
)

const (
	apiKeyRandomBytes  = 32
	apiKeyPrefix       = "nap_"
	apiKeyPrefixLength = len(apiKeyPrefix) + 8
)

var ErrAPIKeyGenerationFailed = errors.New("api key generation failed")

// APIKeyGenerator creates opaque downstream credentials without retaining a
// reusable plaintext value after the caller consumes its one-time reveal.
type APIKeyGenerator struct {
	random io.Reader
}

// GeneratedAPIKey keeps the complete value private to the issuance boundary.
// Copies share the same one-time reveal state.
type GeneratedAPIKey struct {
	state *generatedAPIKeyState
}

type generatedAPIKeyState struct {
	mu               sync.Mutex
	value            string
	prefix           string
	verificationHash [sha256.Size]byte
}

func NewAPIKeyGenerator() *APIKeyGenerator {
	return &APIKeyGenerator{random: rand.Reader}
}

func (generator *APIKeyGenerator) Generate() (*GeneratedAPIKey, error) {
	if generator == nil || generator.random == nil {
		return nil, ErrAPIKeyGenerationFailed
	}
	randomBytes := make([]byte, apiKeyRandomBytes)
	if _, err := io.ReadFull(generator.random, randomBytes); err != nil {
		return nil, fmt.Errorf("%w: random source: %w", ErrAPIKeyGenerationFailed, err)
	}
	value := apiKeyPrefix + base64.RawURLEncoding.EncodeToString(randomBytes)
	hash := sha256.Sum256([]byte(value))
	return &GeneratedAPIKey{state: &generatedAPIKeyState{
		value:            value,
		prefix:           value[:apiKeyPrefixLength],
		verificationHash: hash,
	}}, nil
}

// Reveal returns the complete key exactly once. The caller is responsible for
// putting the returned value only in the explicit issuance response.
func (key GeneratedAPIKey) Reveal() (string, bool) {
	if key.state == nil {
		return "", false
	}
	key.state.mu.Lock()
	defer key.state.mu.Unlock()
	if key.state.value == "" {
		return "", false
	}
	value := key.state.value
	key.state.value = ""
	return value, true
}

func (key GeneratedAPIKey) Prefix() string {
	if key.state == nil {
		return ""
	}
	return key.state.prefix
}

func (key GeneratedAPIKey) VerificationHash() []byte {
	if key.state == nil {
		return nil
	}
	value := make([]byte, len(key.state.verificationHash))
	copy(value, key.state.verificationHash[:])
	return value
}

// VerifyAPIKey compares only the SHA-256 verification material, never a
// stored plaintext credential.
func VerifyAPIKey(candidate string, expectedHash []byte) bool {
	actualHash := sha256.Sum256([]byte(candidate))
	if len(expectedHash) != len(actualHash) {
		return false
	}
	return subtle.ConstantTimeCompare(actualHash[:], expectedHash) == 1
}

func (key GeneratedAPIKey) String() string {
	if key.state == nil {
		return "GeneratedAPIKey{}"
	}
	return "GeneratedAPIKey{prefix=" + key.state.prefix + "}"
}

func (key GeneratedAPIKey) GoString() string {
	return key.String()
}

func (key GeneratedAPIKey) LogValue() slog.Value {
	if key.state == nil {
		return slog.GroupValue()
	}
	return slog.GroupValue(slog.String("prefix", key.state.prefix))
}
