package access

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAuthenticationRejectsUnknownWrongDisabledAndLockedCredentialsIndistinguishably(t *testing.T) {
	tests := []struct {
		name           string
		candidate      LoginCandidate
		password       string
		wantVerifyHash string
		wantCompletion bool
	}{
		{name: "unknown email", password: "wrong-password", wantVerifyHash: "dummy-password-hash"},
		{
			name: "wrong password",
			candidate: LoginCandidate{
				Found: true, IdentityID: "identity-1", Email: "employee@example.internal", Status: IdentityStatusActive, PasswordHash: "stored-password-hash",
			},
			password: "wrong-password", wantVerifyHash: "stored-password-hash", wantCompletion: true,
		},
		{
			name: "disabled identity",
			candidate: LoginCandidate{
				Found: true, IdentityID: "identity-1", Email: "employee@example.internal", Status: IdentityStatus("disabled"), PasswordHash: "stored-password-hash",
			},
			password: "correct-password", wantVerifyHash: "dummy-password-hash",
		},
		{
			name: "locked identity",
			candidate: LoginCandidate{
				Found: true, IdentityID: "identity-1", Email: "employee@example.internal", Status: IdentityStatusActive, PasswordHash: "stored-password-hash", LockedUntil: timePointer(fixedNow.Add(time.Minute)),
			},
			password: "correct-password", wantVerifyHash: "dummy-password-hash",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &memoryAuthenticationRepository{candidate: test.candidate}
			passwords := newFakePasswordCodec()
			service := newTestAuthenticationService(t, repository, passwords)

			session, err := service.Login(context.Background(), LoginInput{
				Email: " Employee@Example.Internal ", Password: test.password,
			})

			if err != ErrInvalidCredentials {
				t.Fatalf("Login() error = %v, want ErrInvalidCredentials", err)
			}
			if session != (PortalSession{}) {
				t.Fatalf("Login() session = %+v, want zero value", session)
			}
			calls := passwords.verificationCalls()
			if len(calls) != 1 || calls[0].encodedHash != test.wantVerifyHash {
				t.Fatalf("password verification calls = %+v, want hash %q", calls, test.wantVerifyHash)
			}
			if calls[0].plaintext != test.password {
				t.Fatal("password verifier did not receive the submitted password")
			}
			if got := repository.completionCount(); got != boolCount(test.wantCompletion) {
				t.Fatalf("repository completions = %d, want %d", got, boolCount(test.wantCompletion))
			}
		})
	}
}

func TestAuthenticationUnknownEmailLimiterAllowsFiveConcurrentAttempts(t *testing.T) {
	repository := &memoryAuthenticationRepository{}
	passwords := newFakePasswordCodec()
	service := newTestAuthenticationService(t, repository, passwords)
	start := make(chan struct{})
	var wait sync.WaitGroup
	errorsByCall := make([]error, 20)

	for index := range errorsByCall {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			_, errorsByCall[index] = service.Login(context.Background(), LoginInput{
				Email: "missing@example.internal", Password: "wrong-password",
			})
		}()
	}
	close(start)
	wait.Wait()

	for index, err := range errorsByCall {
		if err != ErrInvalidCredentials {
			t.Fatalf("Login() call %d error = %v, want ErrInvalidCredentials", index, err)
		}
	}
	if got := len(passwords.verificationCalls()); got != loginFailureLimit {
		t.Fatalf("password verification calls = %d, want %d", got, loginFailureLimit)
	}

	service.now = func() time.Time { return fixedNow.Add(loginLockDuration) }
	_, err := service.Login(context.Background(), LoginInput{
		Email: "missing@example.internal", Password: "wrong-password",
	})
	if err != ErrInvalidCredentials {
		t.Fatalf("Login() at lock expiry error = %v, want ErrInvalidCredentials", err)
	}
	if got := len(passwords.verificationCalls()); got != loginFailureLimit+1 {
		t.Fatalf("password verification calls after expiry = %d, want %d", got, loginFailureLimit+1)
	}
}

func TestAuthenticationLocksKnownIdentityAfterFiveFailuresAndClearsOnSuccess(t *testing.T) {
	repository := &memoryAuthenticationRepository{candidate: LoginCandidate{
		Found: true, IdentityID: "identity-1", Email: "employee@example.internal", Status: IdentityStatusActive, PasswordHash: "stored-password-hash",
	}}
	passwords := newFakePasswordCodec()
	service := newTestAuthenticationService(t, repository, passwords)

	for attempt := 1; attempt <= loginFailureLimit; attempt++ {
		_, err := service.Login(context.Background(), LoginInput{
			Email: "employee@example.internal", Password: "wrong-password",
		})
		if err != ErrInvalidCredentials {
			t.Fatalf("failed Login() attempt %d error = %v, want ErrInvalidCredentials", attempt, err)
		}
	}
	if lockedUntil := repository.lockedUntil(); lockedUntil == nil || !lockedUntil.Equal(fixedNow.Add(loginLockDuration)) {
		t.Fatalf("locked until = %v, want %v", lockedUntil, fixedNow.Add(loginLockDuration))
	}

	_, err := service.Login(context.Background(), LoginInput{
		Email: "employee@example.internal", Password: "correct-password",
	})
	if err != ErrInvalidCredentials {
		t.Fatalf("correct Login() during lock error = %v, want ErrInvalidCredentials", err)
	}
	if got := repository.sessionCount(); got != 0 {
		t.Fatalf("sessions created during lock = %d, want 0", got)
	}

	service.now = func() time.Time { return fixedNow.Add(loginLockDuration) }
	session, err := service.Login(context.Background(), LoginInput{
		Email: "employee@example.internal", Password: "correct-password",
	})
	if err != nil {
		t.Fatalf("Login() at lock expiry error = %v", err)
	}
	if session.Token == "" {
		t.Fatal("Login() at lock expiry returned an empty session token")
	}
	if attempts, windowStart, lockedUntil := repository.failureState(); attempts != 0 || windowStart != nil || lockedUntil != nil {
		t.Fatalf("failure state after success = (%d, %v, %v), want cleared", attempts, windowStart, lockedUntil)
	}
}

func TestAuthenticationCreatesIndependentHashOnlyServerSessions(t *testing.T) {
	repository := &memoryAuthenticationRepository{candidate: LoginCandidate{
		Found: true, IdentityID: "identity-1", Email: "employee@example.internal", Status: IdentityStatusActive, PasswordHash: "stored-password-hash",
	}}
	passwords := newFakePasswordCodec()
	service := newTestAuthenticationService(t, repository, passwords)
	service.random = bytes.NewReader(append(
		append(bytes.Repeat([]byte{0x11}, sessionRandomBytes), bytes.Repeat([]byte{0x22}, sessionRandomBytes)...),
		append(bytes.Repeat([]byte{0x33}, sessionRandomBytes), bytes.Repeat([]byte{0x44}, sessionRandomBytes)...)...,
	))
	ids := []string{"session-1", "session-2"}
	service.newID = func() (string, error) {
		id := ids[0]
		ids = ids[1:]
		return id, nil
	}

	first, err := service.Login(context.Background(), LoginInput{
		Email: " Employee@Example.Internal ", Password: "correct-password",
	})
	if err != nil {
		t.Fatalf("first Login() error = %v", err)
	}
	second, err := service.Login(context.Background(), LoginInput{
		Email: "employee@example.internal", Password: "correct-password",
	})
	if err != nil {
		t.Fatalf("second Login() error = %v", err)
	}
	if first.Token == second.Token || first.CSRFToken == second.CSRFToken {
		t.Fatal("successful login reused session or CSRF token material")
	}
	if got := repository.sessionCount(); got != 2 {
		t.Fatalf("stored sessions = %d, want 2 independent sessions", got)
	}

	stored := repository.sessionAt(0)
	wantTokenHash := sha256.Sum256([]byte(first.Token))
	wantCSRFHash := sha256.Sum256([]byte(first.CSRFToken))
	if !bytes.Equal(stored.TokenHash, wantTokenHash[:]) || !bytes.Equal(stored.CSRFTokenHash, wantCSRFHash[:]) {
		t.Fatal("repository did not receive the session and CSRF verification hashes")
	}
	if bytes.Equal(stored.TokenHash, []byte(first.Token)) || bytes.Equal(stored.CSRFTokenHash, []byte(first.CSRFToken)) {
		t.Fatal("repository received plaintext session credential material")
	}
	if !stored.CreatedAt.Equal(fixedNow) || !stored.LastSeenAt.Equal(fixedNow) {
		t.Fatalf("session creation times = (%v, %v), want %v", stored.CreatedAt, stored.LastSeenAt, fixedNow)
	}
	if !stored.IdleExpiresAt.Equal(fixedNow.Add(sessionIdleLifetime)) {
		t.Fatalf("idle expiry = %v, want %v", stored.IdleExpiresAt, fixedNow.Add(sessionIdleLifetime))
	}
	if !stored.AbsoluteExpiresAt.Equal(fixedNow.Add(sessionAbsoluteLifetime)) {
		t.Fatalf("absolute expiry = %v, want %v", stored.AbsoluteExpiresAt, fixedNow.Add(sessionAbsoluteLifetime))
	}
	if first.IdentityID != "identity-1" || first.ExpiresAt != stored.AbsoluteExpiresAt {
		t.Fatalf("portal session = %+v, want identity and absolute expiry", first)
	}
	if got := repository.lookupEmail(); got != "employee@example.internal" {
		t.Fatalf("lookup email = %q, want normalized email", got)
	}
}

func TestAuthenticationInternalFailuresDoNotExposePasswordOrPersistSession(t *testing.T) {
	plaintext := "plaintext-login-marker"
	repository := &memoryAuthenticationRepository{
		candidate: LoginCandidate{
			Found: true, IdentityID: "identity-1", Email: "employee@example.internal", Status: IdentityStatusActive, PasswordHash: "stored-password-hash",
		},
		completionErr: errors.New("synthetic database failure"),
	}
	passwords := newFakePasswordCodec()
	passwords.correctPassword = plaintext
	service := newTestAuthenticationService(t, repository, passwords)

	_, err := service.Login(context.Background(), LoginInput{
		Email: "employee@example.internal", Password: plaintext,
	})
	if !errors.Is(err, ErrAuthenticationUnavailable) {
		t.Fatalf("Login() error = %v, want ErrAuthenticationUnavailable", err)
	}
	if strings.Contains(err.Error(), plaintext) {
		t.Fatal("authentication error contains plaintext password")
	}
	if got := repository.sessionCount(); got != 0 {
		t.Fatalf("sessions persisted after repository failure = %d, want 0", got)
	}
}

func newTestAuthenticationService(t *testing.T, repository AuthenticationRepository, passwords PasswordCodec) *AuthenticationService {
	t.Helper()
	service, err := NewAuthenticationService(repository, passwords)
	if err != nil {
		t.Fatalf("NewAuthenticationService() error = %v", err)
	}
	service.now = func() time.Time { return fixedNow }
	return service
}

type passwordVerification struct {
	plaintext   string
	encodedHash string
}

type fakePasswordCodec struct {
	mu              sync.Mutex
	correctPassword string
	verifyCalls     []passwordVerification
}

func newFakePasswordCodec() *fakePasswordCodec {
	return &fakePasswordCodec{correctPassword: "correct-password"}
}

func (codec *fakePasswordCodec) Initialize(string) (string, error) {
	return "dummy-password-hash", nil
}

func (codec *fakePasswordCodec) Verify(plaintext, encodedHash string) (bool, error) {
	codec.mu.Lock()
	defer codec.mu.Unlock()
	codec.verifyCalls = append(codec.verifyCalls, passwordVerification{plaintext: plaintext, encodedHash: encodedHash})
	return plaintext == codec.correctPassword && encodedHash == "stored-password-hash", nil
}

func (codec *fakePasswordCodec) verificationCalls() []passwordVerification {
	codec.mu.Lock()
	defer codec.mu.Unlock()
	return append([]passwordVerification(nil), codec.verifyCalls...)
}

type memoryAuthenticationRepository struct {
	mu            sync.Mutex
	candidate     LoginCandidate
	lookup        LoginLookup
	completions   []LoginCompletion
	sessions      []LoginSessionRecord
	completionErr error
}

func (repository *memoryAuthenticationRepository) FindLoginCandidate(_ context.Context, lookup LoginLookup) (LoginCandidate, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.lookup = lookup
	return repository.candidate, nil
}

func (repository *memoryAuthenticationRepository) CompleteLogin(_ context.Context, completion LoginCompletion) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.completions = append(repository.completions, completion)
	if repository.completionErr != nil {
		return repository.completionErr
	}
	if repository.candidate.LockedUntil != nil && repository.candidate.LockedUntil.After(completion.AttemptedAt) {
		return ErrInvalidCredentials
	}
	if !completion.PasswordValid {
		cutoff := completion.AttemptedAt.Add(-loginFailureWindow)
		if repository.candidate.FailureWindowStartedAt == nil || !repository.candidate.FailureWindowStartedAt.After(cutoff) {
			repository.candidate.FailedAttempts = 1
			repository.candidate.FailureWindowStartedAt = timePointer(completion.AttemptedAt)
		} else {
			repository.candidate.FailedAttempts++
		}
		if repository.candidate.FailedAttempts >= loginFailureLimit {
			repository.candidate.LockedUntil = timePointer(completion.AttemptedAt.Add(loginLockDuration))
		}
		return nil
	}
	repository.candidate.FailedAttempts = 0
	repository.candidate.FailureWindowStartedAt = nil
	repository.candidate.LockedUntil = nil
	repository.sessions = append(repository.sessions, completion.Session)
	return nil
}

func (repository *memoryAuthenticationRepository) completionCount() int {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return len(repository.completions)
}

func (repository *memoryAuthenticationRepository) sessionCount() int {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return len(repository.sessions)
}

func (repository *memoryAuthenticationRepository) sessionAt(index int) LoginSessionRecord {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.sessions[index]
}

func (repository *memoryAuthenticationRepository) lockedUntil() *time.Time {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.candidate.LockedUntil
}

func (repository *memoryAuthenticationRepository) failureState() (int, *time.Time, *time.Time) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.candidate.FailedAttempts, repository.candidate.FailureWindowStartedAt, repository.candidate.LockedUntil
}

func (repository *memoryAuthenticationRepository) lookupEmail() string {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.lookup.Email
}

func boolCount(value bool) int {
	if value {
		return 1
	}
	return 0
}
