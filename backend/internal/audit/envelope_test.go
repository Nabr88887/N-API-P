package audit

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

var envelopeTestTime = time.Date(2026, time.August, 4, 18, 0, 0, 123456789, time.UTC)

func TestAES256GCMKnownAnswer(t *testing.T) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	plaintext := make([]byte, 16)

	sealed, err := sealAES256GCM(key, nonce, plaintext, nil)
	if err != nil {
		t.Fatalf("sealAES256GCM() error = %v", err)
	}
	want, err := hex.DecodeString("cea7403d4d606b6e074ec5d3baf39d18d0d1c8a799996bf0265b98b5d48ab919")
	if err != nil {
		t.Fatalf("decode known answer: %v", err)
	}
	if !bytes.Equal(sealed, want) {
		t.Fatalf("sealed = %x, want %x", sealed, want)
	}

	opened, err := openAES256GCM(key, nonce, sealed, nil)
	if err != nil {
		t.Fatalf("openAES256GCM() error = %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened = %x, want %x", opened, plaintext)
	}
}

func TestGZIPCompressionRoundTripsValidatedJSON(t *testing.T) {
	plaintext := []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"` + strings.Repeat("repeat ", 64) + `"}]}`)
	compressed, err := compressJSON(plaintext)
	if err != nil {
		t.Fatalf("compressJSON() error = %v", err)
	}
	if len(compressed) >= len(plaintext) || !bytes.Equal(compressed[:3], []byte{0x1f, 0x8b, 0x08}) {
		t.Fatalf("compressed length/header = (%d, %x)", len(compressed), compressed[:3])
	}
	opened, err := decompressJSON(compressed)
	if err != nil {
		t.Fatalf("decompressJSON() error = %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("decompressed = %q, want %q", opened, plaintext)
	}
}

func TestEnvelopeEncryptionRoundTripsAndUsesIndependentRandomMaterial(t *testing.T) {
	randomMaterial := sequentialBytes(112)
	masterKey := bytes.Repeat([]byte{0x22}, 32)
	service := newDeterministicEnvelopeService(t, 2, map[int][]byte{
		1: bytes.Repeat([]byte{0x11}, 32),
		2: masterKey,
	}, randomMaterial)
	context := personalEncryptionContext()
	plaintext := []byte(`{"messages":[{"role":"user","content":"sensitive company context"}]}`)

	first, err := service.Encrypt(plaintext, context)
	if err != nil {
		t.Fatalf("first Encrypt() error = %v", err)
	}
	second, err := service.Encrypt(plaintext, context)
	if err != nil {
		t.Fatalf("second Encrypt() error = %v", err)
	}
	if first.Compression != CompressionGZIP || first.KeyVersion != 2 {
		t.Fatalf("first metadata = (%q, %d)", first.Compression, first.KeyVersion)
	}
	if len(first.CipherNonce) != 12 || len(first.WrapNonce) != 12 || len(first.WrappedDataKey) != 48 {
		t.Fatalf("first nonce/wrapped lengths = (%d, %d, %d)", len(first.CipherNonce), len(first.WrapNonce), len(first.WrappedDataKey))
	}
	if bytes.Equal(first.CipherNonce, first.WrapNonce) || bytes.Equal(second.CipherNonce, second.WrapNonce) ||
		bytes.Equal(first.CipherNonce, second.CipherNonce) || bytes.Equal(first.WrapNonce, second.WrapNonce) ||
		bytes.Equal(first.Ciphertext, second.Ciphertext) || bytes.Equal(first.WrappedDataKey, second.WrappedDataKey) {
		t.Fatal("two encryptions reused data-key or nonce-derived output")
	}
	firstDataKey, err := openAES256GCM(
		masterKey, first.WrapNonce, first.WrappedDataKey,
		associatedData(wrappedKeyAADDomain, context, first.KeyVersion),
	)
	if err != nil {
		t.Fatalf("unwrap first deterministic data key: %v", err)
	}
	secondDataKey, err := openAES256GCM(
		masterKey, second.WrapNonce, second.WrappedDataKey,
		associatedData(wrappedKeyAADDomain, context, second.KeyVersion),
	)
	if err != nil {
		t.Fatalf("unwrap second deterministic data key: %v", err)
	}
	if !bytes.Equal(firstDataKey, randomMaterial[:32]) || !bytes.Equal(secondDataKey, randomMaterial[56:88]) ||
		bytes.Equal(firstDataKey, secondDataKey) {
		t.Fatal("encryption did not consume an independent 32-byte data key per record")
	}

	opened, err := service.Decrypt(first, context)
	if err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("Decrypt() = %q, want %q", opened, plaintext)
	}
}

func TestEnvelopeKeyRotationKeepsOnlyExplicitVersionsDecryptable(t *testing.T) {
	keys := map[int][]byte{
		1: bytes.Repeat([]byte{0x31}, 32),
		2: bytes.Repeat([]byte{0x32}, 32),
	}
	oldService := newDeterministicEnvelopeService(t, 1, keys, sequentialBytes(56))
	oldRecord, err := oldService.Encrypt([]byte(`{"version":"old"}`), personalEncryptionContext())
	if err != nil {
		t.Fatalf("encrypt old record: %v", err)
	}
	rotatedService := newDeterministicEnvelopeService(t, 2, keys, sequentialBytes(56))
	newRecord, err := rotatedService.Encrypt([]byte(`{"version":"new"}`), personalEncryptionContext())
	if err != nil {
		t.Fatalf("encrypt new record: %v", err)
	}
	if oldRecord.KeyVersion != 1 || newRecord.KeyVersion != 2 {
		t.Fatalf("record versions = (%d, %d), want (1, 2)", oldRecord.KeyVersion, newRecord.KeyVersion)
	}
	for name, test := range map[string]struct {
		record EncryptedContent
		want   string
	}{
		"retained old version": {record: oldRecord, want: `{"version":"old"}`},
		"active new version":   {record: newRecord, want: `{"version":"new"}`},
	} {
		t.Run(name, func(t *testing.T) {
			opened, err := rotatedService.Decrypt(test.record, personalEncryptionContext())
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}
			if string(opened) != test.want {
				t.Fatalf("Decrypt() = %q, want %q", opened, test.want)
			}
		})
	}

	newOnly, err := NewEnvelopeService(2, map[int][]byte{2: keys[2]})
	if err != nil {
		t.Fatalf("NewEnvelopeService() error = %v", err)
	}
	if plaintext, err := newOnly.Decrypt(oldRecord, personalEncryptionContext()); !errors.Is(err, ErrUnknownKeyVersion) || plaintext != nil {
		t.Fatalf("missing old key Decrypt() = (%q, %v), want nil ErrUnknownKeyVersion", plaintext, err)
	}
}

func TestEnvelopeAuthenticationRejectsTamperingAndCrossRecordSubstitution(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0x41}, 32)
	service := newDeterministicEnvelopeService(t, 1, map[int][]byte{
		1: masterKey,
		2: masterKey,
	}, sequentialBytes(168))
	context := personalEncryptionContext()
	record, err := service.Encrypt([]byte(`{"record":"one"}`), context)
	if err != nil {
		t.Fatalf("encrypt first record: %v", err)
	}
	otherContext := context
	otherContext.AuditID = "audit-2"
	other, err := service.Encrypt([]byte(`{"record":"two"}`), otherContext)
	if err != nil {
		t.Fatalf("encrypt second record: %v", err)
	}
	serviceContext := serviceEncryptionContext()
	serviceRecord, err := service.Encrypt([]byte(`{"record":"service"}`), serviceContext)
	if err != nil {
		t.Fatalf("encrypt service record: %v", err)
	}

	tests := map[string]struct {
		record  EncryptedContent
		context EncryptionContext
	}{
		"ciphertext byte":           {record: mutateEncryptedContent(record, func(value *EncryptedContent) { value.Ciphertext[0] ^= 0x01 }), context: context},
		"wrapped key byte":          {record: mutateEncryptedContent(record, func(value *EncryptedContent) { value.WrappedDataKey[0] ^= 0x01 }), context: context},
		"cipher nonce byte":         {record: mutateEncryptedContent(record, func(value *EncryptedContent) { value.CipherNonce[0] ^= 0x01 }), context: context},
		"wrap nonce byte":           {record: mutateEncryptedContent(record, func(value *EncryptedContent) { value.WrapNonce[0] ^= 0x01 }), context: context},
		"ciphertext substitution":   {record: mutateEncryptedContent(record, func(value *EncryptedContent) { value.Ciphertext = bytes.Clone(other.Ciphertext) }), context: context},
		"wrapped key substitution":  {record: mutateEncryptedContent(record, func(value *EncryptedContent) { value.WrappedDataKey = bytes.Clone(other.WrappedDataKey) }), context: context},
		"whole record substitution": {record: other, context: context},
		"compression":               {record: mutateEncryptedContent(record, func(value *EncryptedContent) { value.Compression = "unknown" }), context: context},
		"key version":               {record: mutateEncryptedContent(record, func(value *EncryptedContent) { value.KeyVersion = 2 }), context: context},
		"audit id":                  {record: record, context: withContext(context, func(value *EncryptionContext) { value.AuditID = "audit-other" })},
		"content kind":              {record: record, context: withContext(context, func(value *EncryptionContext) { value.ContentKind = ContentKindResponse })},
		"owner kind":                {record: record, context: serviceEncryptionContext()},
		"identity":                  {record: record, context: withContext(context, func(value *EncryptionContext) { value.IdentityID = "employee-other" })},
		"team":                      {record: record, context: withContext(context, func(value *EncryptionContext) { value.TeamID = "team-other" })},
		"created time":              {record: record, context: withContext(context, func(value *EncryptionContext) { value.CreatedAt = value.CreatedAt.Add(time.Microsecond) })},
		"service account":           {record: serviceRecord, context: withContext(serviceContext, func(value *EncryptionContext) { value.ServiceAccountID = "service-other" })},
		"responsible identity":      {record: serviceRecord, context: withContext(serviceContext, func(value *EncryptionContext) { value.ResponsibleIdentityID = "employee-other" })},
	}
	malformedCompressed := mutateEncryptedContent(record, func(value *EncryptedContent) {
		value.Ciphertext, err = sealAES256GCM(
			sequentialBytes(32), value.CipherNonce, []byte("not-gzip"),
			associatedData(contentAADDomain, context, value.KeyVersion),
		)
	})
	if err != nil {
		t.Fatalf("seal malformed compressed content: %v", err)
	}
	tests["authenticated malformed compression"] = struct {
		record  EncryptedContent
		context EncryptionContext
	}{record: malformedCompressed, context: context}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			plaintext, err := service.Decrypt(test.record, test.context)
			if err == nil || plaintext != nil {
				t.Fatalf("Decrypt() = (%q, %v), want nil authentication failure", plaintext, err)
			}
		})
	}
}

func TestEnvelopeDecryptsAfterPostgresTimestampPrecisionRoundTrip(t *testing.T) {
	service := newDeterministicEnvelopeService(t, 1, map[int][]byte{
		1: bytes.Repeat([]byte{0x41}, 32),
	}, sequentialBytes(64))
	createdAt := time.Date(2026, time.September, 8, 9, 10, 11, 123456789, time.UTC)
	context := personalEncryptionContext()
	context.CreatedAt = createdAt
	record, err := service.Encrypt([]byte(`{"record":"precision"}`), context)
	if err != nil {
		t.Fatalf("encrypt record: %v", err)
	}

	context.CreatedAt = createdAt.Truncate(time.Microsecond)
	plaintext, err := service.Decrypt(record, context)
	if err != nil {
		t.Fatalf("decrypt after PostgreSQL timestamp round trip: %v", err)
	}
	if string(plaintext) != `{"record":"precision"}` {
		t.Fatalf("plaintext = %s", plaintext)
	}
}

func TestEnvelopeValidatesKeysContextsRecordsAndRandomFailures(t *testing.T) {
	validKey := bytes.Repeat([]byte{0x51}, 32)
	for name, test := range map[string]struct {
		active int
		keys   map[int][]byte
	}{
		"non-positive version": {active: 0, keys: map[int][]byte{0: validKey}},
		"oversized version":    {active: maxAuditKeyVersion + 1, keys: map[int][]byte{maxAuditKeyVersion + 1: validKey}},
		"missing active key":   {active: 2, keys: map[int][]byte{1: validKey}},
		"short key":            {active: 1, keys: map[int][]byte{1: validKey[:31]}},
		"empty keyring":        {active: 1, keys: map[int][]byte{}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewEnvelopeService(test.active, test.keys); !errors.Is(err, ErrInvalidMasterKey) {
				t.Fatalf("NewEnvelopeService() error = %v, want ErrInvalidMasterKey", err)
			}
		})
	}

	service, err := NewEnvelopeService(1, map[int][]byte{1: validKey})
	if err != nil {
		t.Fatalf("NewEnvelopeService() error = %v", err)
	}
	invalidContexts := []EncryptionContext{
		{},
		withContext(personalEncryptionContext(), func(value *EncryptionContext) { value.AuditID = "" }),
		withContext(personalEncryptionContext(), func(value *EncryptionContext) { value.ContentKind = "unknown" }),
		withContext(personalEncryptionContext(), func(value *EncryptionContext) { value.TeamID = "" }),
		withContext(personalEncryptionContext(), func(value *EncryptionContext) { value.ServiceAccountID = "service-1" }),
		withContext(serviceEncryptionContext(), func(value *EncryptionContext) { value.ResponsibleIdentityID = "" }),
	}
	for index, context := range invalidContexts {
		if _, err := service.Encrypt([]byte(`{"valid":true}`), context); !errors.Is(err, ErrInvalidEncryptionContext) {
			t.Fatalf("invalid context %d error = %v, want ErrInvalidEncryptionContext", index, err)
		}
	}
	if _, err := service.Encrypt(nil, personalEncryptionContext()); !errors.Is(err, ErrInvalidPlaintext) {
		t.Fatalf("empty plaintext error = %v, want ErrInvalidPlaintext", err)
	}

	service.random = errorReader{}
	if _, err := service.Encrypt([]byte(`{"valid":true}`), personalEncryptionContext()); !errors.Is(err, ErrRandomSource) {
		t.Fatalf("random failure error = %v, want ErrRandomSource", err)
	}

	invalidRecord := EncryptedContent{Compression: CompressionGZIP, KeyVersion: 1}
	if plaintext, err := service.Decrypt(invalidRecord, personalEncryptionContext()); !errors.Is(err, ErrInvalidEncryptedContent) || plaintext != nil {
		t.Fatalf("invalid record Decrypt() = (%q, %v), want nil ErrInvalidEncryptedContent", plaintext, err)
	}
}

func TestEncryptedContentOutputContainsOnlySafeMetadata(t *testing.T) {
	record := EncryptedContent{
		Compression:    CompressionGZIP,
		Ciphertext:     bytes.Repeat([]byte{0x61}, 37),
		CipherNonce:    bytes.Repeat([]byte{0x62}, 12),
		WrappedDataKey: bytes.Repeat([]byte{0x63}, 48),
		WrapNonce:      bytes.Repeat([]byte{0x64}, 12),
		KeyVersion:     7,
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var logBuffer bytes.Buffer
	slog.New(slog.NewJSONHandler(&logBuffer, nil)).Info("encrypted audit content", "record", record)
	output := string(encoded) + fmt.Sprintf("%+v %#v", record, record) + logBuffer.String()
	for _, safe := range []string{CompressionGZIP, "37", "7"} {
		if !strings.Contains(output, safe) {
			t.Fatalf("safe metadata %q missing from output", safe)
		}
	}
	for _, value := range [][]byte{record.Ciphertext, record.CipherNonce, record.WrappedDataKey, record.WrapNonce} {
		for _, forbidden := range []string{base64.StdEncoding.EncodeToString(value), hex.EncodeToString(value), fmt.Sprint(value)} {
			if strings.Contains(output, forbidden) {
				t.Fatalf("encrypted material %q appeared in output", forbidden)
			}
		}
	}

	masterKey := bytes.Repeat([]byte{0x65}, 32)
	service, err := NewEnvelopeService(7, map[int][]byte{7: masterKey})
	if err != nil {
		t.Fatalf("NewEnvelopeService() error = %v", err)
	}
	logBuffer.Reset()
	slog.New(slog.NewJSONHandler(&logBuffer, nil)).Info(
		"envelope service", "service_pointer", service, "service_value", *service,
	)
	serviceOutput := fmt.Sprintf("%+v %#v %+v %#v", service, service, *service, *service) + logBuffer.String()
	for _, forbidden := range []string{base64.StdEncoding.EncodeToString(masterKey), hex.EncodeToString(masterKey), fmt.Sprint(masterKey)} {
		if strings.Contains(serviceOutput, forbidden) {
			t.Fatalf("master key %q appeared in service output", forbidden)
		}
	}
}

func newDeterministicEnvelopeService(t *testing.T, activeVersion int, keys map[int][]byte, random []byte) *EnvelopeService {
	t.Helper()
	service, err := NewEnvelopeService(activeVersion, keys)
	if err != nil {
		t.Fatalf("NewEnvelopeService() error = %v", err)
	}
	service.random = bytes.NewReader(random)
	return service
}

func personalEncryptionContext() EncryptionContext {
	return EncryptionContext{
		AuditID: "audit-1", ContentKind: ContentKindRequest, OwnerKind: OwnerKindPersonal,
		IdentityID: "employee-1", TeamID: "team-1", CreatedAt: envelopeTestTime,
	}
}

func serviceEncryptionContext() EncryptionContext {
	return EncryptionContext{
		AuditID: "audit-1", ContentKind: ContentKindRequest, OwnerKind: OwnerKindService,
		ServiceAccountID: "service-1", ResponsibleIdentityID: "employee-1",
		TeamID: "team-1", CreatedAt: envelopeTestTime,
	}
}

func sequentialBytes(length int) []byte {
	values := make([]byte, length)
	for index := range values {
		values[index] = byte(index + 1)
	}
	return values
}

func mutateEncryptedContent(value EncryptedContent, mutate func(*EncryptedContent)) EncryptedContent {
	value.Ciphertext = bytes.Clone(value.Ciphertext)
	value.CipherNonce = bytes.Clone(value.CipherNonce)
	value.WrappedDataKey = bytes.Clone(value.WrappedDataKey)
	value.WrapNonce = bytes.Clone(value.WrapNonce)
	mutate(&value)
	return value
}

func withContext(value EncryptionContext, mutate func(*EncryptionContext)) EncryptionContext {
	mutate(&value)
	return value
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, errors.New("synthetic random failure")
}
