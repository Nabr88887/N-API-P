package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

const artifactHeader = "NAPI105\x00"

func main() {
	if len(os.Args) < 2 {
		fatal("mode is required")
	}
	key, err := artifactKey()
	if err != nil {
		fatal(err.Error())
	}
	switch os.Args[1] {
	case "encrypt":
		encrypt(key, os.Args[2:])
	case "decrypt":
		decrypt(key, os.Args[2:])
	default:
		fatal("unknown mode")
	}
}

func artifactKey() ([]byte, error) {
	encoded := os.Getenv("TASK105_BACKUP_KEY_B64")
	if encoded == "" {
		return nil, errors.New("TASK105_BACKUP_KEY_B64 is required")
	}
	key, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || len(key) != 32 {
		return nil, errors.New("TASK105_BACKUP_KEY_B64 must decode to 32 bytes")
	}
	return key, nil
}

func encrypt(key []byte, args []string) {
	output := outputPath(args)
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal(err.Error())
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		fatal(err.Error())
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		fatal(err.Error())
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		fatal(err.Error())
	}
	sealed := aead.Seal(nil, nonce, input, []byte(artifactHeader))
	if err := os.WriteFile(output, append(append([]byte(artifactHeader), nonce...), sealed...), 0o600); err != nil {
		fatal(err.Error())
	}
}

func decrypt(key []byte, _ []string) {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal(err.Error())
	}
	if len(input) < len(artifactHeader) {
		fatal("artifact is too short")
	}
	if string(input[:len(artifactHeader)]) != artifactHeader {
		fatal("artifact header mismatch")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		fatal(err.Error())
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		fatal(err.Error())
	}
	start := len(artifactHeader)
	end := start + aead.NonceSize()
	if len(input) <= end {
		fatal("artifact has no encrypted payload")
	}
	plain, err := aead.Open(nil, input[start:end], input[end:], []byte(artifactHeader))
	if err != nil {
		fatal("artifact authentication failed")
	}
	if _, err := os.Stdout.Write(plain); err != nil {
		fatal(err.Error())
	}
}

func outputPath(args []string) string {
	flags := flag.NewFlagSet("task105artifact", flag.ExitOnError)
	output := flags.String("out", "", "encrypted artifact path")
	_ = flags.Parse(args)
	if *output == "" {
		fatal("-out is required for encrypt")
	}
	return *output
}

func fatal(message string) {
	_, _ = fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
