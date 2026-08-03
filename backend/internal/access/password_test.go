package access

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestPasswordPolicyUsesUnicodeCodePoints(t *testing.T) {
	hasher := NewArgon2idPasswordHasher()

	tests := []struct {
		name      string
		plaintext string
		wantErr   error
	}{
		{name: "empty", plaintext: "", wantErr: ErrPasswordRejected},
		{name: "eleven ASCII code points", plaintext: strings.Repeat("a", 11), wantErr: ErrPasswordRejected},
		{name: "twelve ASCII code points", plaintext: strings.Repeat("a", 12)},
		{name: "twelve multibyte code points", plaintext: strings.Repeat("界", 12)},
		{name: "one hundred twenty eight multibyte code points", plaintext: strings.Repeat("界", 128)},
		{name: "one hundred twenty nine code points", plaintext: strings.Repeat("界", 129), wantErr: ErrPasswordRejected},
		{name: "invalid UTF-8", plaintext: string([]byte{0xff, 0xfe, 0xfd}), wantErr: ErrPasswordRejected},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			hash, err := hasher.Initialize(test.plaintext)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("Initialize() error = %v, want %v", err, test.wantErr)
			}
			if test.wantErr == nil && hash == "" {
				t.Fatal("Initialize() returned an empty hash for an accepted password")
			}
			if test.wantErr != nil && hash != "" {
				t.Fatalf("Initialize() hash = %q for a rejected password", hash)
			}
		})
	}
}

func TestPasswordHashingDoesNotTrimOrNormalize(t *testing.T) {
	hasher := NewArgon2idPasswordHasher()
	withLeadingSpace := " " + strings.Repeat("a", 11)

	encoded, err := hasher.Initialize(withLeadingSpace)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	verified, err := hasher.Verify(strings.TrimSpace(withLeadingSpace), encoded)
	if err != nil {
		t.Fatalf("Verify(trimmed) error = %v", err)
	}
	if verified {
		t.Fatal("Verify() accepted a password after implicit trimming")
	}

	composed := strings.Repeat("é", 12)
	decomposed := strings.Repeat("e\u0301", 12)
	encoded, err = hasher.Initialize(composed)
	if err != nil {
		t.Fatalf("Initialize(composed) error = %v", err)
	}
	verified, err = hasher.Verify(decomposed, encoded)
	if err != nil {
		t.Fatalf("Verify(decomposed) error = %v", err)
	}
	if verified {
		t.Fatal("Verify() accepted a canonically equivalent password after implicit normalization")
	}
}

func TestArgon2idHashRecordsCalibratedParametersAndRandomSalt(t *testing.T) {
	hasher := NewArgon2idPasswordHasher()
	plaintext := "correct horse battery staple"

	first, err := hasher.Initialize(plaintext)
	if err != nil {
		t.Fatalf("first Initialize() error = %v", err)
	}
	second, err := hasher.Initialize(plaintext)
	if err != nil {
		t.Fatalf("second Initialize() error = %v", err)
	}
	if first == second {
		t.Fatal("Initialize() reused a salt for the same plaintext")
	}

	wantPrefix := "$argon2id$v=19$m=65536,t=3,p=1$"
	if !strings.HasPrefix(first, wantPrefix) {
		t.Fatalf("encoded hash prefix = %q, want %q", first, wantPrefix)
	}
	parts := strings.Split(first, "$")
	if len(parts) != 6 {
		t.Fatalf("encoded hash has %d PHC fields, want 6", len(parts))
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		t.Fatalf("decode salt: %v", err)
	}
	if len(salt) != 16 {
		t.Fatalf("salt length = %d, want 16", len(salt))
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		t.Fatalf("decode key: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key length = %d, want 32", len(key))
	}
}

func TestArgon2idVerifyAcceptsOnlyTheCorrectPassword(t *testing.T) {
	hasher := NewArgon2idPasswordHasher()
	encoded, err := hasher.Initialize("correct horse battery staple")
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	hasher.parameters = argon2idParameters{
		memoryKiB:   minimumArgon2idMemoryKiB,
		iterations:  minimumArgon2idIterations,
		parallelism: minimumArgon2idParallelism,
	}

	verified, err := hasher.Verify("correct horse battery staple", encoded)
	if err != nil {
		t.Fatalf("Verify(correct) error = %v", err)
	}
	if !verified {
		t.Fatal("Verify() rejected the correct password")
	}
	verified, err = hasher.Verify("wrong horse battery staple", encoded)
	if err != nil {
		t.Fatalf("Verify(wrong) error = %v", err)
	}
	if verified {
		t.Fatal("Verify() accepted the wrong password")
	}
}

func TestArgon2idVerifyRejectsMalformedAndUnsafeHashes(t *testing.T) {
	hasher := NewArgon2idPasswordHasher()
	salt := base64.RawStdEncoding.EncodeToString(make([]byte, 16))
	key := base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	encode := func(algorithm, version, parameters, encodedSalt, encodedKey string) string {
		return fmt.Sprintf("$%s$%s$%s$%s$%s", algorithm, version, parameters, encodedSalt, encodedKey)
	}

	tests := []struct {
		name    string
		encoded string
	}{
		{name: "empty", encoded: ""},
		{name: "not PHC", encoded: "password-hash"},
		{name: "unsupported algorithm", encoded: encode("argon2i", "v=19", "m=65536,t=3,p=1", salt, key)},
		{name: "unsupported version", encoded: encode("argon2id", "v=18", "m=65536,t=3,p=1", salt, key)},
		{name: "insufficient memory", encoded: encode("argon2id", "v=19", "m=1024,t=3,p=1", salt, key)},
		{name: "excessive memory", encoded: encode("argon2id", "v=19", "m=1048576,t=3,p=1", salt, key)},
		{name: "insufficient iterations", encoded: encode("argon2id", "v=19", "m=65536,t=1,p=1", salt, key)},
		{name: "excessive iterations", encoded: encode("argon2id", "v=19", "m=65536,t=1000000,p=1", salt, key)},
		{name: "memory integer overflow", encoded: encode("argon2id", "v=19", "m=4294967296,t=3,p=1", salt, key)},
		{name: "zero parallelism", encoded: encode("argon2id", "v=19", "m=65536,t=3,p=0", salt, key)},
		{name: "excessive parallelism", encoded: encode("argon2id", "v=19", "m=65536,t=3,p=255", salt, key)},
		{name: "unknown parameter", encoded: encode("argon2id", "v=19", "m=65536,t=3,p=1,x=1", salt, key)},
		{name: "short salt", encoded: encode("argon2id", "v=19", "m=65536,t=3,p=1", base64.RawStdEncoding.EncodeToString(make([]byte, 15)), key)},
		{name: "short key", encoded: encode("argon2id", "v=19", "m=65536,t=3,p=1", salt, base64.RawStdEncoding.EncodeToString(make([]byte, 31)))},
		{name: "invalid base64", encoded: encode("argon2id", "v=19", "m=65536,t=3,p=1", "***", key)},
		{name: "oversized encoding", encoded: strings.Repeat("x", 1024)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			verified, err := hasher.Verify("correct horse battery staple", test.encoded)
			if verified {
				t.Fatal("Verify() accepted an invalid encoded hash")
			}
			if !errors.Is(err, ErrInvalidPasswordHash) {
				t.Fatalf("Verify() error = %v, want ErrInvalidPasswordHash", err)
			}
		})
	}
}

func TestPasswordHashAndErrorsDoNotExposePlaintext(t *testing.T) {
	plaintext := "plaintext-leak-marker-2026"
	hasher := NewArgon2idPasswordHasher()

	encoded, err := hasher.Initialize(plaintext)
	if err != nil {
		t.Fatalf("Initialize() error = %v", err)
	}
	if strings.Contains(encoded, plaintext) {
		t.Fatal("encoded hash contains plaintext")
	}

	_, err = hasher.Initialize("short-pass")
	if !errors.Is(err, ErrPasswordRejected) {
		t.Fatalf("Initialize(short) error = %v, want ErrPasswordRejected", err)
	}
	if strings.Contains(err.Error(), "short-pass") {
		t.Fatal("policy error contains plaintext")
	}

	hasher.random = failingReader{err: errors.New("entropy unavailable")}
	_, err = hasher.Initialize(plaintext)
	if err == nil {
		t.Fatal("Initialize() error = nil with a failed entropy source")
	}
	if strings.Contains(err.Error(), plaintext) {
		t.Fatal("initialization error contains plaintext")
	}
}

type failingReader struct {
	err error
}

func (reader failingReader) Read([]byte) (int, error) {
	return 0, reader.err
}
