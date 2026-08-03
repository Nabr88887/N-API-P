package access

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestAPIKeyGeneratorCreates256BitKeyWithSafePrefixAndOneTimeReveal(t *testing.T) {
	randomBytes := bytes.Repeat([]byte{0x5a}, 32)
	generator := NewAPIKeyGenerator()
	generator.random = bytes.NewReader(randomBytes)

	material, err := generator.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	materialCopy := *material
	secret, ok := materialCopy.Reveal()
	if !ok || secret == "" {
		t.Fatal("first Reveal() did not return a key")
	}
	if second, ok := material.Reveal(); ok || second != "" {
		t.Fatalf("second Reveal() = (%q, %t), want empty and false", second, ok)
	}

	encodedRandom := base64.RawURLEncoding.EncodeToString(randomBytes)
	wantSecret := "nap_" + encodedRandom
	if secret != wantSecret {
		t.Fatalf("secret = %q, want deterministic 256-bit encoding", secret)
	}
	wantPrefix := "nap_" + encodedRandom[:8]
	if material.Prefix() != wantPrefix || len(material.Prefix()) < 4 || len(material.Prefix()) > 32 {
		t.Fatalf("prefix = %q, want safe bounded prefix of the key", material.Prefix())
	}
	if material.Prefix() == secret {
		t.Fatal("prefix exposed the complete key")
	}

	wantHash := sha256.Sum256([]byte(secret))
	hash := material.VerificationHash()
	if !bytes.Equal(hash, wantHash[:]) || bytes.Contains(hash, []byte(secret)) {
		t.Fatal("verification hash is missing, incorrect, or contains the complete key")
	}
	hash[0] ^= 0xff
	if !VerifyAPIKey(secret, material.VerificationHash()) {
		t.Fatal("mutating returned hash changed the stored verification material")
	}
	if !VerifyAPIKey(secret, wantHash[:]) || VerifyAPIKey(secret+"x", wantHash[:]) || VerifyAPIKey(secret, wantHash[:31]) {
		t.Fatal("API key verification accepted an invalid credential")
	}
}

func TestAPIKeyMaterialIsSecretFreeForJSONAndLogging(t *testing.T) {
	randomBytes := bytes.Repeat([]byte{0x33}, 32)
	generator := NewAPIKeyGenerator()
	generator.random = bytes.NewReader(randomBytes)
	material, err := generator.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	secret := "nap_" + base64.RawURLEncoding.EncodeToString(randomBytes)
	hash := sha256.Sum256([]byte(secret))
	materialValue := *material
	jsonValue, err := json.Marshal(materialValue)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var logBuffer bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuffer, nil)).Info("generated API key", "pointer", material, "value", materialValue)
	formatted := fmt.Sprintf("%+v %#v %+v %#v", material, material, materialValue, materialValue)
	output := string(jsonValue) + logBuffer.String() + formatted
	for _, forbidden := range []string{secret, base64.RawStdEncoding.EncodeToString(hash[:]), hex.EncodeToString(hash[:])} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("secret material appeared in output %q", forbidden)
		}
	}
	if !strings.Contains(logBuffer.String(), material.Prefix()) {
		t.Fatalf("safe prefix %q was omitted from structured log", material.Prefix())
	}
}

func TestAPIKeyRevealIsSingleUseAcrossConcurrentCopies(t *testing.T) {
	generator := NewAPIKeyGenerator()
	generator.random = bytes.NewReader(bytes.Repeat([]byte{0x44}, 32))
	material, err := generator.Generate()
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}

	type revealResult struct {
		value string
		ok    bool
	}
	const callers = 16
	start := make(chan struct{})
	results := make(chan revealResult, callers)
	for range callers {
		materialCopy := *material
		go func() {
			<-start
			value, ok := materialCopy.Reveal()
			results <- revealResult{value: value, ok: ok}
		}()
	}
	close(start)

	successes := 0
	for range callers {
		result := <-results
		if result.ok {
			successes++
			if result.value == "" {
				t.Fatal("successful Reveal() returned an empty value")
			}
		} else if result.value != "" {
			t.Fatal("rejected Reveal() returned key material")
		}
	}
	if successes != 1 {
		t.Fatalf("successful Reveal() calls = %d, want 1", successes)
	}
}

func TestAPIKeyGeneratorReturnsRandomSourceFailureWithoutMaterial(t *testing.T) {
	generator := NewAPIKeyGenerator()
	generator.random = apiKeyFailingReader{err: errors.New("random unavailable")}

	material, err := generator.Generate()
	if err == nil {
		t.Fatal("Generate() error = nil, want random source failure")
	}
	if material != nil {
		t.Fatal("Generate() returned material after random source failure")
	}
}

type apiKeyFailingReader struct {
	err error
}

func (reader apiKeyFailingReader) Read([]byte) (int, error) {
	return 0, reader.err
}

var _ io.Reader = apiKeyFailingReader{}
