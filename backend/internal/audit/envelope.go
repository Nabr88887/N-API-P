package audit

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

const (
	CompressionGZIP             = "gzip"
	aes256KeyBytes              = 32
	gcmNonceBytes               = 12
	gcmTagBytes                 = 16
	maxAssociatedDataFieldBytes = 1024
	maxAuditKeyVersion          = 1<<31 - 1
	contentAADDomain            = "n-api-p/audit-envelope/content/v1"
	wrappedKeyAADDomain         = "n-api-p/audit-envelope/wrapped-key/v1"
)

var (
	ErrInvalidMasterKey         = errors.New("invalid audit master key")
	ErrInvalidEncryptionContext = errors.New("invalid audit encryption context")
	ErrInvalidPlaintext         = errors.New("invalid audit plaintext")
	ErrInvalidEncryptedContent  = errors.New("invalid encrypted audit content")
	ErrUnknownKeyVersion        = errors.New("unknown audit key version")
	ErrRandomSource             = errors.New("audit encryption random source failed")
	ErrAuthenticationFailed     = errors.New("audit content authentication failed")
	ErrInvalidCompressedContent = errors.New("invalid compressed audit content")
)

type ContentKind string

const (
	ContentKindRequest  ContentKind = "request"
	ContentKindResponse ContentKind = "response"
)

type OwnerKind string

const (
	OwnerKindPersonal OwnerKind = "personal"
	OwnerKindService  OwnerKind = "service"
)

type EncryptionContext struct {
	AuditID               string
	ContentKind           ContentKind
	OwnerKind             OwnerKind
	IdentityID            string
	ServiceAccountID      string
	ResponsibleIdentityID string
	TeamID                string
	CreatedAt             time.Time
}

type EncryptedContent struct {
	Compression    string `json:"compression"`
	Ciphertext     []byte `json:"-"`
	CipherNonce    []byte `json:"-"`
	WrappedDataKey []byte `json:"-"`
	WrapNonce      []byte `json:"-"`
	KeyVersion     int    `json:"key_version"`
}

type EnvelopeService struct {
	activeVersion int
	masterKeys    map[int][aes256KeyBytes]byte
	random        io.Reader
}

func NewEnvelopeService(activeVersion int, keys map[int][]byte) (*EnvelopeService, error) {
	if activeVersion <= 0 || activeVersion > maxAuditKeyVersion || len(keys) == 0 {
		return nil, ErrInvalidMasterKey
	}
	masterKeys := make(map[int][aes256KeyBytes]byte, len(keys))
	for version, key := range keys {
		if version <= 0 || version > maxAuditKeyVersion || len(key) != aes256KeyBytes {
			return nil, ErrInvalidMasterKey
		}
		var copied [aes256KeyBytes]byte
		copy(copied[:], key)
		masterKeys[version] = copied
	}
	if _, ok := masterKeys[activeVersion]; !ok {
		return nil, ErrInvalidMasterKey
	}
	return &EnvelopeService{activeVersion: activeVersion, masterKeys: masterKeys, random: rand.Reader}, nil
}

func (service *EnvelopeService) Encrypt(plaintext []byte, context EncryptionContext) (EncryptedContent, error) {
	if service == nil || service.random == nil || len(service.masterKeys) == 0 {
		return EncryptedContent{}, ErrInvalidMasterKey
	}
	if len(plaintext) == 0 {
		return EncryptedContent{}, ErrInvalidPlaintext
	}
	if err := context.validate(); err != nil {
		return EncryptedContent{}, err
	}
	masterKey, ok := service.masterKeys[service.activeVersion]
	if !ok {
		return EncryptedContent{}, ErrUnknownKeyVersion
	}
	defer clear(masterKey[:])

	compressed, err := compressJSON(plaintext)
	if err != nil {
		return EncryptedContent{}, err
	}
	defer clear(compressed)

	dataKey := make([]byte, aes256KeyBytes)
	defer clear(dataKey)
	cipherNonce := make([]byte, gcmNonceBytes)
	wrapNonce := make([]byte, gcmNonceBytes)
	if err := fillRandom(service.random, dataKey, "data key"); err != nil {
		return EncryptedContent{}, err
	}
	if err := fillRandom(service.random, cipherNonce, "content nonce"); err != nil {
		return EncryptedContent{}, err
	}
	if err := fillRandom(service.random, wrapNonce, "wrap nonce"); err != nil {
		return EncryptedContent{}, err
	}

	contentAAD := associatedData(contentAADDomain, context, service.activeVersion)
	ciphertext, err := sealAES256GCM(dataKey, cipherNonce, compressed, contentAAD)
	if err != nil {
		return EncryptedContent{}, err
	}
	wrappedKeyAAD := associatedData(wrappedKeyAADDomain, context, service.activeVersion)
	wrappedDataKey, err := sealAES256GCM(masterKey[:], wrapNonce, dataKey, wrappedKeyAAD)
	if err != nil {
		return EncryptedContent{}, err
	}
	return EncryptedContent{
		Compression:    CompressionGZIP,
		Ciphertext:     ciphertext,
		CipherNonce:    cipherNonce,
		WrappedDataKey: wrappedDataKey,
		WrapNonce:      wrapNonce,
		KeyVersion:     service.activeVersion,
	}, nil
}

func (service *EnvelopeService) Decrypt(record EncryptedContent, context EncryptionContext) ([]byte, error) {
	if service == nil || len(service.masterKeys) == 0 {
		return nil, ErrInvalidMasterKey
	}
	if err := context.validate(); err != nil {
		return nil, err
	}
	if err := record.validate(); err != nil {
		return nil, err
	}
	masterKey, ok := service.masterKeys[record.KeyVersion]
	if !ok {
		return nil, ErrUnknownKeyVersion
	}
	defer clear(masterKey[:])

	wrappedKeyAAD := associatedData(wrappedKeyAADDomain, context, record.KeyVersion)
	dataKey, err := openAES256GCM(masterKey[:], record.WrapNonce, record.WrappedDataKey, wrappedKeyAAD)
	if err != nil || len(dataKey) != aes256KeyBytes {
		clear(dataKey)
		return nil, ErrAuthenticationFailed
	}
	defer clear(dataKey)

	contentAAD := associatedData(contentAADDomain, context, record.KeyVersion)
	compressed, err := openAES256GCM(dataKey, record.CipherNonce, record.Ciphertext, contentAAD)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	defer clear(compressed)
	plaintext, err := decompressJSON(compressed)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (context EncryptionContext) validate() error {
	if !validAssociatedDataField(context.AuditID) ||
		!validAssociatedDataField(context.TeamID) || context.CreatedAt.IsZero() {
		return ErrInvalidEncryptionContext
	}
	switch context.ContentKind {
	case ContentKindRequest, ContentKindResponse:
	default:
		return ErrInvalidEncryptionContext
	}
	switch context.OwnerKind {
	case OwnerKindPersonal:
		if !validAssociatedDataField(context.IdentityID) ||
			context.ServiceAccountID != "" || context.ResponsibleIdentityID != "" {
			return ErrInvalidEncryptionContext
		}
	case OwnerKindService:
		if context.IdentityID != "" || !validAssociatedDataField(context.ServiceAccountID) ||
			!validAssociatedDataField(context.ResponsibleIdentityID) {
			return ErrInvalidEncryptionContext
		}
	default:
		return ErrInvalidEncryptionContext
	}
	return nil
}

func validAssociatedDataField(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= maxAssociatedDataFieldBytes
}

func (record EncryptedContent) validate() error {
	if record.Compression != CompressionGZIP || record.KeyVersion <= 0 || record.KeyVersion > maxAuditKeyVersion ||
		len(record.CipherNonce) != gcmNonceBytes || len(record.WrapNonce) != gcmNonceBytes ||
		len(record.Ciphertext) <= gcmTagBytes || len(record.WrappedDataKey) != aes256KeyBytes+gcmTagBytes {
		return ErrInvalidEncryptedContent
	}
	return nil
}

func associatedData(domain string, context EncryptionContext, keyVersion int) []byte {
	result := make([]byte, 0, 256)
	for _, value := range []string{
		domain,
		context.AuditID,
		string(context.ContentKind),
		string(context.OwnerKind),
		context.IdentityID,
		context.ServiceAccountID,
		context.ResponsibleIdentityID,
		context.TeamID,
	} {
		result = binary.BigEndian.AppendUint32(result, uint32(len(value)))
		result = append(result, value...)
	}
	createdAt := context.CreatedAt.UTC().Truncate(time.Microsecond)
	result = binary.BigEndian.AppendUint64(result, uint64(createdAt.Unix()))
	result = binary.BigEndian.AppendUint32(result, uint32(createdAt.Nanosecond()))
	result = binary.BigEndian.AppendUint32(result, uint32(keyVersion))
	return result
}

func fillRandom(source io.Reader, destination []byte, name string) error {
	if _, err := io.ReadFull(source, destination); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrRandomSource, name, err)
	}
	return nil
}

func sealAES256GCM(key, nonce, plaintext, associatedData []byte) ([]byte, error) {
	aead, err := newAES256GCM(key, nonce)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, associatedData), nil
}

func openAES256GCM(key, nonce, ciphertext, associatedData []byte) ([]byte, error) {
	aead, err := newAES256GCM(key, nonce)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, associatedData)
	if err != nil {
		return nil, ErrAuthenticationFailed
	}
	return plaintext, nil
}

func newAES256GCM(key, nonce []byte) (cipher.AEAD, error) {
	if len(key) != aes256KeyBytes || len(nonce) != gcmNonceBytes {
		return nil, ErrInvalidEncryptedContent
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES-256 cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-256-GCM: %w", err)
	}
	return aead, nil
}

func compressJSON(plaintext []byte) ([]byte, error) {
	var buffer bytes.Buffer
	writer, err := gzip.NewWriterLevel(&buffer, gzip.BestCompression)
	if err != nil {
		return nil, fmt.Errorf("create gzip writer: %w", err)
	}
	if _, err := writer.Write(plaintext); err != nil {
		return nil, fmt.Errorf("compress audit content: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("finish audit compression: %w", err)
	}
	return buffer.Bytes(), nil
}

func decompressJSON(compressed []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, ErrInvalidCompressedContent
	}
	plaintext, readErr := io.ReadAll(reader)
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil {
		clear(plaintext)
		return nil, ErrInvalidCompressedContent
	}
	return plaintext, nil
}

func (record EncryptedContent) String() string {
	return fmt.Sprintf(
		"EncryptedContent{compression=%s ciphertext_bytes=%d wrapped_key_bytes=%d key_version=%d}",
		record.Compression, len(record.Ciphertext), len(record.WrappedDataKey), record.KeyVersion,
	)
}

func (record EncryptedContent) GoString() string {
	return record.String()
}

func (record EncryptedContent) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("compression", record.Compression),
		slog.Int("ciphertext_bytes", len(record.Ciphertext)),
		slog.Int("wrapped_key_bytes", len(record.WrappedDataKey)),
		slog.Int("key_version", record.KeyVersion),
	)
}

func (service EnvelopeService) String() string {
	return fmt.Sprintf("EnvelopeService{active_key_version=%d available_key_versions=%d}", service.activeVersion, len(service.masterKeys))
}

func (service EnvelopeService) GoString() string {
	return service.String()
}

func (service EnvelopeService) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Int("active_key_version", service.activeVersion),
		slog.Int("available_key_versions", len(service.masterKeys)),
	)
}
