package access

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const (
	minimumPasswordRunes = 12
	maximumPasswordRunes = 128

	argon2idSaltBytes = 16
	argon2idKeyBytes  = 32

	minimumArgon2idMemoryKiB   = 19 * 1024
	maximumArgon2idMemoryKiB   = 128 * 1024
	minimumArgon2idIterations  = 2
	maximumArgon2idIterations  = 5
	minimumArgon2idParallelism = 1
	maximumArgon2idParallelism = 4

	maximumEncodedPasswordHashBytes = 512
)

var ErrInvalidPasswordHash = errors.New("invalid password hash")

type argon2idParameters struct {
	memoryKiB   uint32
	iterations  uint32
	parallelism uint8
}

var calibratedArgon2idParameters = argon2idParameters{
	memoryKiB:   64 * 1024,
	iterations:  3,
	parallelism: 1,
}

// PasswordVerifier verifies a plaintext candidate against an encoded password
// hash without exposing either value.
type PasswordVerifier interface {
	Verify(plaintext, encodedHash string) (bool, error)
}

// Argon2idPasswordHasher initializes and verifies access-owned password hashes.
type Argon2idPasswordHasher struct {
	random     io.Reader
	parameters argon2idParameters
}

func NewArgon2idPasswordHasher() *Argon2idPasswordHasher {
	return &Argon2idPasswordHasher{
		random:     rand.Reader,
		parameters: calibratedArgon2idParameters,
	}
}

func (hasher *Argon2idPasswordHasher) Initialize(plaintext string) (string, error) {
	if !validPassword(plaintext) {
		return "", ErrPasswordRejected
	}

	salt := make([]byte, argon2idSaltBytes)
	if _, err := io.ReadFull(hasher.random, salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	key := argon2.IDKey(
		[]byte(plaintext),
		salt,
		hasher.parameters.iterations,
		hasher.parameters.memoryKiB,
		hasher.parameters.parallelism,
		argon2idKeyBytes,
	)

	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		hasher.parameters.memoryKiB,
		hasher.parameters.iterations,
		hasher.parameters.parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

func (hasher *Argon2idPasswordHasher) Verify(plaintext, encodedHash string) (bool, error) {
	if !validPassword(plaintext) {
		return false, nil
	}

	parameters, salt, expectedKey, err := parseArgon2idHash(encodedHash)
	if err != nil {
		return false, err
	}
	actualKey := argon2.IDKey(
		[]byte(plaintext),
		salt,
		parameters.iterations,
		parameters.memoryKiB,
		parameters.parallelism,
		uint32(len(expectedKey)),
	)

	return subtle.ConstantTimeCompare(actualKey, expectedKey) == 1, nil
}

func validPassword(plaintext string) bool {
	if !utf8.ValidString(plaintext) {
		return false
	}
	length := utf8.RuneCountInString(plaintext)
	return length >= minimumPasswordRunes && length <= maximumPasswordRunes
}

func parseArgon2idHash(encodedHash string) (argon2idParameters, []byte, []byte, error) {
	if len(encodedHash) == 0 || len(encodedHash) > maximumEncodedPasswordHashBytes {
		return argon2idParameters{}, nil, nil, ErrInvalidPasswordHash
	}
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return argon2idParameters{}, nil, nil, ErrInvalidPasswordHash
	}

	parameters, err := parseArgon2idParameters(parts[3])
	if err != nil {
		return argon2idParameters{}, nil, nil, ErrInvalidPasswordHash
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(parts[4])
	if err != nil || len(salt) != argon2idSaltBytes {
		return argon2idParameters{}, nil, nil, ErrInvalidPasswordHash
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(parts[5])
	if err != nil || len(key) != argon2idKeyBytes {
		return argon2idParameters{}, nil, nil, ErrInvalidPasswordHash
	}

	return parameters, salt, key, nil
}

func parseArgon2idParameters(encoded string) (argon2idParameters, error) {
	fields := strings.Split(encoded, ",")
	if len(fields) != 3 {
		return argon2idParameters{}, ErrInvalidPasswordHash
	}
	memory, err := parseArgon2idParameter(fields[0], "m=", 32)
	if err != nil {
		return argon2idParameters{}, ErrInvalidPasswordHash
	}
	iterations, err := parseArgon2idParameter(fields[1], "t=", 32)
	if err != nil {
		return argon2idParameters{}, ErrInvalidPasswordHash
	}
	parallelism, err := parseArgon2idParameter(fields[2], "p=", 8)
	if err != nil {
		return argon2idParameters{}, ErrInvalidPasswordHash
	}

	parameters := argon2idParameters{
		memoryKiB:   uint32(memory),
		iterations:  uint32(iterations),
		parallelism: uint8(parallelism),
	}
	if parameters.memoryKiB < minimumArgon2idMemoryKiB || parameters.memoryKiB > maximumArgon2idMemoryKiB ||
		parameters.iterations < minimumArgon2idIterations || parameters.iterations > maximumArgon2idIterations ||
		parameters.parallelism < minimumArgon2idParallelism || parameters.parallelism > maximumArgon2idParallelism {
		return argon2idParameters{}, ErrInvalidPasswordHash
	}
	return parameters, nil
}

func parseArgon2idParameter(field, prefix string, bitSize int) (uint64, error) {
	if !strings.HasPrefix(field, prefix) || len(field) == len(prefix) {
		return 0, ErrInvalidPasswordHash
	}
	value, err := strconv.ParseUint(field[len(prefix):], 10, bitSize)
	if err != nil {
		return 0, ErrInvalidPasswordHash
	}
	return value, nil
}
