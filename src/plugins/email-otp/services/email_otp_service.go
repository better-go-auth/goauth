package services

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	authint "github.com/better-go-auth/goauth/src/app/services/interfaces"
	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	modeldtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/models/enums"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
)

var (
	ErrInvalidOTP          = autherr.Err(http.StatusBadRequest, "INVALID_OTP", "Invalid or expired OTP code")
	ErrOTPExpired          = autherr.Err(http.StatusBadRequest, "OTP_EXPIRED", "OTP expired")
	ErrTooManyAttempts     = autherr.Err(http.StatusForbidden, "TOO_MANY_ATTEMPTS", "Too many attempts")
	ErrRateLimitExceeded   = autherr.Err(http.StatusTooManyRequests, "TOO_MANY_REQUESTS", "Rate limit exceeded. Please try again later.")
	ErrSenderNotConfigured = autherr.Err(http.StatusInternalServerError, "SENDER_NOT_CONFIGURED", "No sendVerificationOTP callback configured")
	ErrUserNotFound        = autherr.ErrUserNotFound
	ErrInvalidEmailAddress = autherr.ErrInvalidEmail
	ErrPasswordTooShort    = autherr.ErrPasswordTooShort
	ErrPasswordTooLong     = autherr.ErrPasswordTooLong
	ErrEmailAlreadyExists  = autherr.ErrUserAlreadyExistsUseAnotherEmail
	ErrChangeEmailDisabled = autherr.ErrChangeEmailDisabled
)

type rlBucket struct {
	Count     int       `json:"count"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type EmailOTPService struct {
	config     emailotpconfig.EmailOTPConfig
	rootConfig config.AuthConfig
	repos      repo_interfaces.IAuthRepos
	sessionMgr authint.ISessionManager
	passwords  *authcrypto.Passwords
	txMgr      interfaces.ITransactionManager
	secStorage sec_storage.SecondaryStorage

	rlMu      sync.Mutex
	rlBuckets map[string]rlBucket
}

func NewEmailOTPService(
	cfg emailotpconfig.EmailOTPConfig,
	rootCfg config.AuthConfig,
	repos repo_interfaces.IAuthRepos,
	sessionMgr authint.ISessionManager,
	passwords *authcrypto.Passwords,
	txMgr interfaces.ITransactionManager,
) *EmailOTPService {
	// Step 1: Apply default values for core OTP settings
	if cfg.OtpLength <= 0 {
		cfg.OtpLength = 6
	}
	if cfg.ExpiresIn <= 0 {
		cfg.ExpiresIn = 5 * time.Minute
	}
	if cfg.AllowedAttempts <= 0 {
		cfg.AllowedAttempts = 3
	}
	if cfg.StoreOTP.Mode == "" && cfg.StoreOTP.Hash == nil && cfg.StoreOTP.Encrypt == nil {
		cfg.StoreOTP.Mode = emailotpconfig.StoreOTPPlain
	}
	if cfg.ResendStrategy == "" {
		cfg.ResendStrategy = emailotpconfig.ResendStrategyRotate
	}
	if passwords == nil {
		passwords = authcrypto.NewPasswords(rootCfg)
	}
	return &EmailOTPService{
		config:     cfg,
		rootConfig: rootCfg,
		repos:      repos,
		sessionMgr: sessionMgr,
		passwords:  passwords,
		txMgr:      txMgr,
		rlBuckets:  make(map[string]rlBucket),
	}
}

// SetSecondaryStorage configures secondary storage used for distributed rate limiting.
func (s *EmailOTPService) SetSecondaryStorage(storage sec_storage.SecondaryStorage) {
	s.secStorage = storage
}

func (s *EmailOTPService) SessionManager() authint.ISessionManager {
	return s.sessionMgr
}

func (s *EmailOTPService) otpIdentifier(otpType emailotpconfig.OTPType, email string) string {
	return fmt.Sprintf("email-otp:%s:%s", otpType, strings.ToLower(strings.TrimSpace(email)))
}

func (s *EmailOTPService) generateNumericCode(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	for i := 0; i < length; i++ {
		bytes[i] = '0' + (bytes[i] % 10)
	}
	return string(bytes), nil
}

func validEmail(email string) bool {
	a, err := mail.ParseAddress(email)
	return err == nil && a.Address == email
}

func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "not found") {
		return true
	}
	ae := autherr.AsAuthError(err)
	return ae != nil && ae.StatusCode == http.StatusNotFound
}

func acceptNotFound[T any](v *T, err error) (*T, error) {
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return v, nil
}

func (s *EmailOTPService) withTx(ctx context.Context, fn func(txCtx context.Context) error) error {
	if s.txMgr != nil {
		return s.txMgr.Transaction(ctx, fn)
	}
	return fn(ctx)
}

// ─── OTP Storage, Hashing, Encryption, and Attempt Tracking Helpers ──────────

func (s *EmailOTPService) encryptionKey() []byte {
	secret := s.rootConfig.Secret
	if secret == "" {
		secret = "goauth-default-email-otp-secret-key"
	}
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

func (s *EmailOTPService) encryptOTP(plain string) (string, error) {
	// Step 1: Initialize AES-256-GCM cipher using SHA-256 derived secret key
	block, err := aes.NewCipher(s.encryptionKey())
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	// Step 2: Generate random nonce and seal plaintext
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

func (s *EmailOTPService) decryptOTP(encoded string) (string, error) {
	// Step 1: Decode base64url ciphertext and initialize AES-256-GCM cipher
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(s.encryptionKey())
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	// Step 2: Split nonce and decrypt ciphertext
	if len(raw) < gcm.NonceSize() {
		return "", fmt.Errorf("invalid encrypted otp payload")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func hashOTPValue(otp string) string {
	sum := sha256.Sum256([]byte(otp))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func splitOTPValue(raw string) (string, int) {
	idx := strings.LastIndex(raw, ":")
	if idx == -1 {
		return raw, 0
	}
	attempts, err := strconv.Atoi(raw[idx+1:])
	if err != nil || attempts < 0 {
		return raw, 0
	}
	return raw[:idx], attempts
}

func formatOTPValue(storedOTP string, attempts int) string {
	return fmt.Sprintf("%s:%d", storedOTP, attempts)
}

func (s *EmailOTPService) storeOTPValue(otp string) (string, error) {
	// Step 1: Handle custom Hash / Encrypt callbacks if provided
	if s.config.StoreOTP.Hash != nil {
		return s.config.StoreOTP.Hash(otp)
	}
	if s.config.StoreOTP.Encrypt != nil {
		return s.config.StoreOTP.Encrypt(otp)
	}
	// Step 2: Handle built-in modes (hashed, encrypted, plain)
	switch s.config.StoreOTP.Mode {
	case emailotpconfig.StoreOTPHashed:
		return hashOTPValue(otp), nil
	case emailotpconfig.StoreOTPEncrypted:
		return s.encryptOTP(otp)
	default:
		return otp, nil
	}
}

func (s *EmailOTPService) verifyStoredOTPValue(storedOTP, providedOTP string) (bool, error) {
	// Step 1: Handle custom Hash / Decrypt callbacks
	if s.config.StoreOTP.Hash != nil {
		h, err := s.config.StoreOTP.Hash(providedOTP)
		if err != nil {
			return false, err
		}
		return subtle.ConstantTimeCompare([]byte(h), []byte(storedOTP)) == 1, nil
	}
	if s.config.StoreOTP.Decrypt != nil {
		plain, err := s.config.StoreOTP.Decrypt(storedOTP)
		if err != nil {
			return false, err
		}
		return subtle.ConstantTimeCompare([]byte(plain), []byte(providedOTP)) == 1, nil
	}
	// Step 2: Handle built-in modes with constant-time comparison
	switch s.config.StoreOTP.Mode {
	case emailotpconfig.StoreOTPHashed:
		h := hashOTPValue(providedOTP)
		return subtle.ConstantTimeCompare([]byte(h), []byte(storedOTP)) == 1, nil
	case emailotpconfig.StoreOTPEncrypted:
		plain, err := s.decryptOTP(storedOTP)
		if err != nil {
			return false, err
		}
		return subtle.ConstantTimeCompare([]byte(plain), []byte(providedOTP)) == 1, nil
	default:
		return subtle.ConstantTimeCompare([]byte(providedOTP), []byte(storedOTP)) == 1, nil
	}
}

func (s *EmailOTPService) retrieveStoredOTP(storedOTP string) (string, bool) {
	// Step 1: Hashed OTPs are one-way and cannot be recovered for reuse
	if s.config.StoreOTP.Hash != nil || s.config.StoreOTP.Mode == emailotpconfig.StoreOTPHashed {
		return "", false
	}
	// Step 2: Recover plaintext from custom Decrypt callback, built-in encrypted mode, or plain mode
	if s.config.StoreOTP.Decrypt != nil {
		plain, err := s.config.StoreOTP.Decrypt(storedOTP)
		if err != nil {
			return "", false
		}
		return plain, true
	}
	if s.config.StoreOTP.Mode == emailotpconfig.StoreOTPEncrypted {
		plain, err := s.decryptOTP(storedOTP)
		if err != nil {
			return "", false
		}
		return plain, true
	}
	return storedOTP, true
}

func (s *EmailOTPService) tryReuseOTP(ctx context.Context, identifier string) (string, bool) {
	// Step 1: Lookup existing verification record
	existing, err := s.repos.FindVerificationValue(ctx, identifier)
	if err != nil || existing == nil || existing.IsExpired() {
		return "", false
	}
	// Step 2: Ensure attempt limit has not already been exhausted
	storedOTP, attempts := splitOTPValue(existing.Value)
	allowedAttempts := s.config.AllowedAttempts
	if allowedAttempts <= 0 {
		allowedAttempts = 3
	}
	if attempts >= allowedAttempts {
		return "", false
	}
	// Step 3: Attempt to recover plaintext OTP; hashed modes return false and fall back to rotate
	plainOTP, ok := s.retrieveStoredOTP(storedOTP)
	if !ok || plainOTP == "" {
		return "", false
	}
	// Step 4: Extend expiry while keeping existing stored OTP and attempt counter
	newExpiresAt := time.Now().Add(s.config.ExpiresIn).UTC()
	if _, err := s.repos.UpsertVerificationValue(ctx, &models.Verification{
		Base:       models.Base{ID: existing.ID},
		Identifier: identifier,
		Value:      existing.Value,
		ExpiresAt:  newExpiresAt,
	}); err != nil {
		return "", false
	}
	return plainOTP, true
}

func (s *EmailOTPService) generateOTPCode(email string, otpType emailotpconfig.OTPType, req *http.Request) (string, error) {
	// Step 1: Use custom GenerateOTP callback if configured
	if s.config.GenerateOTP != nil {
		custom, err := s.config.GenerateOTP(emailotpconfig.GenerateOTPData{
			Email: email,
			Type:  otpType,
		}, req)
		if err != nil {
			return "", err
		}
		if custom != "" {
			return custom, nil
		}
	}
	// Step 2: Fall back to default random numeric generator
	return s.generateNumericCode(s.config.OtpLength)
}

func (s *EmailOTPService) verifyOTPAttempt(ctx context.Context, identifier, providedOTP string, consumeOnSuccess bool) error {
	// Step 1: Fetch verification record by identifier
	rec, err := s.repos.FindVerificationValue(ctx, identifier)
	if err != nil || rec == nil {
		return ErrInvalidOTP
	}

	// Step 2: If expired, clean up record and return ErrOTPExpired
	if rec.IsExpired() {
		_ = s.repos.DeleteVerificationByIdentifier(ctx, identifier)
		return ErrOTPExpired
	}

	// Step 3: Extract stored OTP value and attempt count; reject if max attempts exceeded
	storedOTP, attempts := splitOTPValue(rec.Value)
	allowedAttempts := s.config.AllowedAttempts
	if allowedAttempts <= 0 {
		allowedAttempts = 3
	}
	if attempts >= allowedAttempts {
		_ = s.repos.DeleteVerificationByIdentifier(ctx, identifier)
		return ErrTooManyAttempts
	}

	// Step 4: Verify provided OTP against stored OTP
	ok, err := s.verifyStoredOTPValue(storedOTP, providedOTP)
	if err != nil || !ok {
		// Step 5: Increment failed attempt counter while preserving original expiry
		_, _ = s.repos.UpsertVerificationValue(ctx, &models.Verification{
			Base:       models.Base{ID: rec.ID},
			Identifier: identifier,
			Value:      formatOTPValue(storedOTP, attempts+1),
			ExpiresAt:  rec.ExpiresAt,
		})
		return ErrInvalidOTP
	}

	// Step 6: Consume OTP immediately if requested
	if consumeOnSuccess {
		_ = s.repos.DeleteVerificationByIdentifier(ctx, identifier)
	}
	return nil
}

// ─── Rate Limiting ────────────────────────────────────────────────────────────

func (s *EmailOTPService) rateLimitSettings() (enabled bool, window time.Duration, max int) {
	rl := s.config.RateLimit
	if rl.Enabled != nil {
		enabled = *rl.Enabled
	} else {
		enabled = rl.Window > 0 || rl.Max > 0 || s.rootConfig.RateLimit.Enabled
	}
	if !enabled {
		return false, 0, 0
	}
	window = rl.Window
	if window <= 0 {
		window = s.rootConfig.RateLimit.Window
	}
	if window <= 0 {
		window = 60 * time.Second
	}
	max = rl.Max
	if max <= 0 {
		max = s.rootConfig.RateLimit.Max
	}
	if max <= 0 {
		max = 3
	}
	return true, window, max
}

// CheckRateLimit enforces per-endpoint rate limiting matching Better Auth's rateLimit option.
func (s *EmailOTPService) CheckRateLimit(ctx context.Context, endpointPath, clientKey string) error {
	// Step 1: Check whether rate limiting is active and resolve window/max
	enabled, window, max := s.rateLimitSettings()
	if !enabled {
		return nil
	}
	if clientKey == "" {
		clientKey = "global"
	}
	key := fmt.Sprintf("email-otp:rl:%s:%s", endpointPath, clientKey)
	now := time.Now().UTC()

	s.rlMu.Lock()
	defer s.rlMu.Unlock()

	// Step 2: Check SecondaryStorage if available, otherwise fall back to in-memory buckets
	if s.secStorage != nil {
		var bucket rlBucket
		if raw, exists, err := s.secStorage.Get(ctx, key); err == nil && exists {
			switch v := raw.(type) {
			case string:
				_ = json.Unmarshal([]byte(v), &bucket)
			case []byte:
				_ = json.Unmarshal(v, &bucket)
			}
		}
		if bucket.ExpiresAt.IsZero() || now.After(bucket.ExpiresAt) {
			bucket = rlBucket{Count: 1, ExpiresAt: now.Add(window)}
		} else {
			if bucket.Count >= max {
				return ErrRateLimitExceeded
			}
			bucket.Count++
		}
		if b, err := json.Marshal(bucket); err == nil {
			_ = s.secStorage.Set(ctx, key, string(b), time.Until(bucket.ExpiresAt))
		}
		return nil
	}

	bucket, ok := s.rlBuckets[key]
	if !ok || now.After(bucket.ExpiresAt) {
		s.rlBuckets[key] = rlBucket{Count: 1, ExpiresAt: now.Add(window)}
		return nil
	}
	if bucket.Count >= max {
		return ErrRateLimitExceeded
	}
	bucket.Count++
	s.rlBuckets[key] = bucket
	return nil
}

// ─── Public OTP Flows ─────────────────────────────────────────────────────────

// SendVerificationOTP generates (or reuses), stores, and dispatches an OTP code via the configured sender.
func (s *EmailOTPService) SendVerificationOTP(ctx context.Context, email string, otpType emailotpconfig.OTPType, req *http.Request) error {
	return s.sendVerificationOTP(ctx, email, otpType, req, otpType != emailotpconfig.OTPTypeChangeEmail)
}

// SendSignUpVerificationOTP dispatches an email-verification OTP for a newly created user without re-querying user existence.
func (s *EmailOTPService) SendSignUpVerificationOTP(ctx context.Context, email string, req *http.Request) error {
	return s.sendVerificationOTP(ctx, email, emailotpconfig.OTPTypeEmailVerification, req, false)
}

func (s *EmailOTPService) sendVerificationOTP(ctx context.Context, email string, otpType emailotpconfig.OTPType, req *http.Request, checkUserExists bool) error {
	// Step 1: Validate callback and target email
	if s.config.SendVerificationOTP == nil {
		return ErrSenderNotConfigured
	}
	if !validEmail(email) {
		return ErrInvalidEmailAddress
	}

	identifier := s.otpIdentifier(otpType, email)

	// Step 2: Enforce Better Auth user-existence / DisableSignUp rules before sending OTPs
	// Only sign-in (with DisableSignUp=false) and already-known user/email-change flows send OTPs to unregistered addresses.
	if checkUserExists {
		existingUser, findErr := acceptNotFound(s.repos.FindUserByEmail(ctx, strings.ToLower(email)))
		if findErr != nil {
			return fmt.Errorf("email-otp: failed to lookup user: %w", findErr)
		}
		shouldSendToMissingUser := otpType == emailotpconfig.OTPTypeSignIn && !s.config.DisableSignUp
		if existingUser == nil && !shouldSendToMissingUser {
			_ = s.repos.DeleteVerificationByIdentifier(ctx, identifier)
			return nil
		}
	}

	// Step 3: Check reuse strategy before generating a fresh OTP
	if s.config.ResendStrategy == emailotpconfig.ResendStrategyReuse {
		if reusedCode, ok := s.tryReuseOTP(ctx, identifier); ok {
			return s.config.SendVerificationOTP(emailotpconfig.SendVerificationOTPData{
				Email: email,
				OTP:   reusedCode,
				Type:  otpType,
			}, req)
		}
	}

	// Step 4: Generate new OTP code (custom GenerateOTP or default numeric)
	code, err := s.generateOTPCode(email, otpType, req)
	if err != nil {
		return fmt.Errorf("email-otp: failed to generate code: %w", err)
	}

	// Step 5: Encode OTP according to StoreOTP mode and persist with attempt counter 0
	storedOTP, err := s.storeOTPValue(code)
	if err != nil {
		return fmt.Errorf("email-otp: failed to encode code: %w", err)
	}
	expiresAt := time.Now().Add(s.config.ExpiresIn).UTC()

	_, err = s.repos.UpsertVerificationValue(ctx, &models.Verification{
		Base:       models.Base{ID: models.NewID()},
		Identifier: identifier,
		Value:      formatOTPValue(storedOTP, 0),
		ExpiresAt:  expiresAt,
	})
	if err != nil {
		return fmt.Errorf("email-otp: failed to store verification value: %w", err)
	}

	// Step 6: Dispatch plaintext OTP via caller's email sender callback
	return s.config.SendVerificationOTP(emailotpconfig.SendVerificationOTPData{
		Email: email,
		OTP:   code,
		Type:  otpType,
	}, req)
}

// CheckVerificationOTP checks an OTP code without consuming it (tracks failed attempts).
func (s *EmailOTPService) CheckVerificationOTP(ctx context.Context, email, otp string, otpType emailotpconfig.OTPType) error {
	// Step 1: Validate input email and OTP
	if !validEmail(email) || otp == "" {
		return ErrInvalidOTP
	}
	identifier := s.otpIdentifier(otpType, email)

	// Step 2: Validate OTP with attempt tracking without consuming on success
	return s.verifyOTPAttempt(ctx, identifier, otp, false)
}

// VerifyEmail verifies a user's email address using the supplied OTP code.
func (s *EmailOTPService) VerifyEmail(ctx context.Context, email, otp string, meta authint.SessionMeta, req *http.Request) (*modeldtos.SessionWithUser, *models.User, error) {
	// Step 1: Validate input email and OTP
	if !validEmail(email) || otp == "" {
		return nil, nil, ErrInvalidOTP
	}
	identifier := s.otpIdentifier(emailotpconfig.OTPTypeEmailVerification, email)

	// Step 2: Validate OTP with attempt tracking (do not consume until user update succeeds, or verify first)
	if err := s.verifyOTPAttempt(ctx, identifier, otp, false); err != nil {
		return nil, nil, err
	}

	// Step 3: Mark user email as verified in transaction and consume OTP
	var updatedUser *models.User
	err := s.withTx(ctx, func(txCtx context.Context) error {
		user, err := s.repos.FindUserByEmail(txCtx, strings.ToLower(email))
		if err != nil || user == nil {
			return ErrUserNotFound
		}

		if s.rootConfig.EmailVerification.BeforeEmailVerification != nil {
			if err := s.rootConfig.EmailVerification.BeforeEmailVerification(*user, req); err != nil {
				return err
			}
		}

		updated, err := s.repos.UpdateUser(txCtx, user.ID, map[string]interface{}{
			"EmailVerified": true,
		})
		if err != nil {
			return autherr.ErrFailedToUpdateUser
		}
		updatedUser = updated
		// Step 4: Consume OTP upon successful verification
		_ = s.repos.DeleteVerificationByIdentifier(txCtx, identifier)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	if s.rootConfig.EmailVerification.AfterEmailVerification != nil {
		_ = s.rootConfig.EmailVerification.AfterEmailVerification(*updatedUser, req)
	}

	// Step 4b: Refresh cached user copy across active sessions
	s.refreshSessionUser(ctx, updatedUser)

	// Step 5: Optionally create session if AutoSignInAfterVerification is enabled
	var session *modeldtos.SessionWithUser
	if s.rootConfig.EmailVerification.AutoSignInAfterVerification && s.sessionMgr != nil {
		var err error
		session, err = s.sessionMgr.Create(ctx, updatedUser, meta, sessionsvc.CreateOptions{})
		if err != nil {
			return nil, updatedUser, nil // User is verified, session creation failure is non-fatal
		}
	}

	return session, updatedUser, nil
}

// SignIn signs the user in using an OTP code, creating the user if passwordless signup is allowed.
func (s *EmailOTPService) SignIn(ctx context.Context, email, otp string, meta authint.SessionMeta) (*modeldtos.SessionWithUser, error) {
	return s.SignInWithProfile(ctx, email, otp, "", "", meta)
}

// SignInWithProfile signs the user in using an OTP code with optional initial profile name/image.
func (s *EmailOTPService) SignInWithProfile(ctx context.Context, email, otp, name, image string, meta authint.SessionMeta) (*modeldtos.SessionWithUser, error) {
	// Step 1: Validate input email and OTP
	if !validEmail(email) || otp == "" {
		return nil, ErrInvalidOTP
	}
	identifier := s.otpIdentifier(emailotpconfig.OTPTypeSignIn, email)

	// Step 2: Validate OTP with attempt tracking
	if err := s.verifyOTPAttempt(ctx, identifier, otp, false); err != nil {
		return nil, err
	}

	// Step 3: Load or create user and create authenticated session
	var user *models.User
	err := s.withTx(ctx, func(txCtx context.Context) error {
		existingUser, err := acceptNotFound(s.repos.FindUserByEmail(txCtx, strings.ToLower(email)))
		if err != nil {
			return err
		}

		// Auto sign up if user does not exist and signup is not disabled
		if existingUser == nil {
			if s.config.DisableSignUp {
				return ErrInvalidOTP
			}
			displayName := strings.TrimSpace(name)
			if displayName == "" {
				displayName = strings.Split(email, "@")[0]
			}
			var imgPtr *string
			if image != "" {
				imgPtr = &image
			}
			newUser := &models.User{
				Base: models.Base{ID: models.NewID()},
				UserDto: models.UserDto{
					Email:         strings.ToLower(email),
					Name:          displayName,
					Image:         imgPtr,
					Role:          enums.User,
					EmailVerified: true,
				},
			}
			created, err := s.repos.CreateUser(txCtx, newUser)
			if err != nil {
				return autherr.ErrFailedToCreateUser
			}
			now := time.Now().UTC()
			_, _ = s.repos.CreateAccount(txCtx, &models.Account{
				Base:       models.Base{ID: models.NewID(), CreatedAt: now, UpdatedAt: now},
				UserID:     created.ID,
				ProviderID: models.ProvCredential,
				AccountID:  created.ID,
			})
			user = created
		} else {
			user = existingUser
		}

		// Ban check
		if user.Banned && (user.BanExpires == nil || user.BanExpires.After(time.Now())) {
			return autherr.ErrUserBanned
		}

		now := time.Now().UTC()
		updates := map[string]interface{}{"LastLoginAt": now}
		if !user.EmailVerified {
			updates["EmailVerified"] = true
		}
		if updated, uErr := s.repos.UpdateUser(txCtx, user.ID, updates); uErr == nil && updated != nil {
			user = updated
		}
		// Step 4: Consume OTP upon successful verification
		_ = s.repos.DeleteVerificationByIdentifier(txCtx, identifier)
		return nil
	})
	if err != nil {
		return nil, err
	}

	sw, err := s.sessionMgr.Create(ctx, user, meta, sessionsvc.CreateOptions{})
	if err != nil {
		return nil, autherr.ErrFailedToCreateSession
	}

	return sw, nil
}

// ResetPassword resets the user's password after validating the OTP code.
func (s *EmailOTPService) ResetPassword(ctx context.Context, email, otp, newPassword string) error {
	// Step 1: Validate input email, OTP, and password bounds
	if !validEmail(email) || otp == "" {
		return ErrInvalidOTP
	}

	minLen := s.rootConfig.EmailAndPassword.MinPasswordLength
	if minLen <= 0 {
		minLen = 8
	}
	maxLen := s.rootConfig.EmailAndPassword.MaxPasswordLength
	if maxLen <= 0 {
		maxLen = 128
	}
	if len(newPassword) < minLen {
		return ErrPasswordTooShort
	}
	if len(newPassword) > maxLen {
		return ErrPasswordTooLong
	}

	hash, err := s.passwords.Hash(newPassword)
	if err != nil {
		return err
	}

	// Step 2: Validate OTP with attempt tracking
	identifier := s.otpIdentifier(emailotpconfig.OTPTypeForgetPassword, email)
	if err := s.verifyOTPAttempt(ctx, identifier, otp, false); err != nil {
		return err
	}

	// Step 3: Update user credential account with new password and consume OTP
	var userID string
	err = s.withTx(ctx, func(txCtx context.Context) error {
		user, err := s.repos.FindUserByEmail(txCtx, strings.ToLower(email))
		if err != nil || user == nil {
			return ErrUserNotFound
		}
		userID = user.ID

		account, err := s.repos.FindAccountByUserAndProvider(txCtx, user.ID, models.ProvCredential)
		if err != nil || account == nil {
			// Create credential account if one didn't exist
			now := time.Now().UTC()
			_, err = s.repos.CreateAccount(txCtx, &models.Account{
				Base:       models.Base{ID: models.NewID(), CreatedAt: now, UpdatedAt: now},
				UserID:     user.ID,
				ProviderID: models.ProvCredential,
				AccountID:  user.ID,
				Password:   &hash,
			})
			if err != nil {
				return err
			}
		} else {
			_, err = s.repos.UpdateAccount(txCtx, account.ID, map[string]interface{}{"Password": hash})
			if err != nil {
				return err
			}
		}
		// Step 4: Consume OTP upon successful verification
		_ = s.repos.DeleteVerificationByIdentifier(txCtx, identifier)
		return nil
	})
	if err != nil {
		return err
	}

	if s.rootConfig.EmailAndPassword.RevokeSessionsOnPasswordReset && s.sessionMgr != nil {
		_ = s.sessionMgr.DeleteUserSessions(ctx, userID)
	}

	return nil
}

func (s *EmailOTPService) refreshSessionUser(ctx context.Context, user *models.User) {
	if s.sessionMgr == nil || user == nil {
		return
	}
	if r, ok := s.sessionMgr.(interface{ RefreshUser(context.Context, *models.User) }); ok {
		r.RefreshUser(ctx, user)
	}
}

// Config returns the plugin's configuration.
func (s *EmailOTPService) Config() emailotpconfig.EmailOTPConfig {
	return s.config
}
