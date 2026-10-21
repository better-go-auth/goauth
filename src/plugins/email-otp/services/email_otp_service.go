package services

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	authint "github.com/better-go-auth/goauth/src/app/services/interfaces"
	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	modeldtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/models/enums"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
)

var (
	ErrInvalidOTP          = autherr.Err(http.StatusBadRequest, "INVALID_OTP", "Invalid or expired OTP code")
	ErrSenderNotConfigured = autherr.Err(http.StatusInternalServerError, "SENDER_NOT_CONFIGURED", "No sendVerificationOTP callback configured")
	ErrUserNotFound        = autherr.ErrUserNotFound
	ErrInvalidEmailAddress = autherr.ErrInvalidEmail
	ErrPasswordTooShort    = autherr.ErrPasswordTooShort
	ErrPasswordTooLong     = autherr.ErrPasswordTooLong
	ErrEmailAlreadyExists  = autherr.ErrUserAlreadyExistsUseAnotherEmail
	ErrChangeEmailDisabled = autherr.ErrChangeEmailDisabled
)

type EmailOTPService struct {
	config     emailotpconfig.EmailOTPConfig
	rootConfig config.AuthConfig
	repos      repo_interfaces.IAuthRepos
	sessionMgr authint.ISessionManager
	passwords  *authcrypto.Passwords
	txMgr      interfaces.ITransactionManager
}

func NewEmailOTPService(
	cfg emailotpconfig.EmailOTPConfig,
	rootCfg config.AuthConfig,
	repos repo_interfaces.IAuthRepos,
	sessionMgr authint.ISessionManager,
	passwords *authcrypto.Passwords,
	txMgr interfaces.ITransactionManager,
) *EmailOTPService {
	if cfg.OtpLength <= 0 {
		cfg.OtpLength = 6
	}
	if cfg.ExpiresIn <= 0 {
		cfg.ExpiresIn = 5 * time.Minute
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
	}
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

// SendVerificationOTP generates, stores, and dispatches an OTP code via the configured sender.
func (s *EmailOTPService) SendVerificationOTP(ctx context.Context, email string, otpType emailotpconfig.OTPType, req *http.Request) error {
	if s.config.SendVerificationOTP == nil {
		return ErrSenderNotConfigured
	}
	if !validEmail(email) {
		return ErrInvalidEmailAddress
	}

	code, err := s.generateNumericCode(s.config.OtpLength)
	if err != nil {
		return fmt.Errorf("email-otp: failed to generate code: %w", err)
	}

	codeHash, err := s.passwords.Hash(code)
	if err != nil {
		return fmt.Errorf("email-otp: failed to hash code: %w", err)
	}

	identifier := s.otpIdentifier(otpType, email)
	expiresAt := time.Now().Add(s.config.ExpiresIn).UTC()

	_, err = s.repos.UpsertVerificationValue(ctx, &models.Verification{
		Base:       models.Base{ID: models.NewID()},
		Identifier: identifier,
		Value:      codeHash,
		ExpiresAt:  expiresAt,
	})
	if err != nil {
		return fmt.Errorf("email-otp: failed to store verification value: %w", err)
	}

	return s.config.SendVerificationOTP(emailotpconfig.SendVerificationOTPData{
		Email: email,
		OTP:   code,
		Type:  otpType,
	}, req)
}

// CheckVerificationOTP checks an OTP code without consuming it.
func (s *EmailOTPService) CheckVerificationOTP(ctx context.Context, email, otp string, otpType emailotpconfig.OTPType) error {
	// Step 1: Validate input email and OTP
	if !validEmail(email) || otp == "" {
		return ErrInvalidOTP
	}
	identifier := s.otpIdentifier(otpType, email)

	// Step 2: Fetch verification record by identifier
	rec, err := s.repos.FindVerificationValue(ctx, identifier)
	if err != nil || rec == nil || rec.IsExpired() {
		return ErrInvalidOTP
	}

	// Step 3: Verify OTP hash; rate limiting is handled globally at the route level
	if ok, _, err := s.passwords.Verify(rec.Value, otp); err != nil || !ok {
		return ErrInvalidOTP
	}
	return nil
}

// VerifyEmail verifies a user's email address using the supplied OTP code.
func (s *EmailOTPService) VerifyEmail(ctx context.Context, email, otp string, meta authint.SessionMeta, req *http.Request) (*modeldtos.SessionWithUser, *models.User, error) {
	// Step 1: Validate input email and OTP
	if !validEmail(email) || otp == "" {
		return nil, nil, ErrInvalidOTP
	}
	identifier := s.otpIdentifier(emailotpconfig.OTPTypeEmailVerification, email)

	// Step 2: Fetch verification record by identifier
	rec, err := s.repos.FindVerificationValue(ctx, identifier)
	if err != nil || rec == nil || rec.IsExpired() {
		return nil, nil, ErrInvalidOTP
	}

	// Step 3: Verify OTP hash; rate limiting is handled globally at the route level
	if ok, _, err := s.passwords.Verify(rec.Value, otp); err != nil || !ok {
		return nil, nil, ErrInvalidOTP
	}

	// Step 4: Mark user email as verified in transaction

	var updatedUser *models.User
	err = s.withTx(ctx, func(txCtx context.Context) error {
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
		// Step 5: Consume OTP upon successful verification
		_ = s.repos.DeleteVerificationByIdentifier(txCtx, identifier)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}

	if s.rootConfig.EmailVerification.AfterEmailVerification != nil {
		_ = s.rootConfig.EmailVerification.AfterEmailVerification(*updatedUser, req)
	}

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
	// Step 1: Validate input email and OTP
	if !validEmail(email) || otp == "" {
		return nil, ErrInvalidOTP
	}
	identifier := s.otpIdentifier(emailotpconfig.OTPTypeSignIn, email)

	// Step 2: Fetch verification record by identifier
	rec, err := s.repos.FindVerificationValue(ctx, identifier)
	if err != nil || rec == nil || rec.IsExpired() {
		return nil, ErrInvalidOTP
	}

	// Step 3: Verify OTP hash; rate limiting is handled globally at the route level
	if ok, _, err := s.passwords.Verify(rec.Value, otp); err != nil || !ok {
		return nil, ErrInvalidOTP
	}

	// Step 5: Load or create user and create authenticated session
	var user *models.User
	err = s.withTx(ctx, func(txCtx context.Context) error {
		existingUser, err := acceptNotFound(s.repos.FindUserByEmail(txCtx, strings.ToLower(email)))
		if err != nil {
			return err
		}

		// Auto sign up if user does not exist and signup is not disabled
		if existingUser == nil {
			if s.config.DisableSignUp {
				return ErrUserNotFound
			}
			newUser := &models.User{
				Base: models.Base{ID: models.NewID()},
				UserDto: models.UserDto{
					Email:         strings.ToLower(email),
					Name:          strings.Split(email, "@")[0],
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
		_, _ = s.repos.UpdateUser(txCtx, user.ID, map[string]interface{}{"LastLoginAt": now})
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

	// Step 4: Fetch verification record and verify OTP
	identifier := s.otpIdentifier(emailotpconfig.OTPTypeForgetPassword, email)
	rec, err := s.repos.FindVerificationValue(ctx, identifier)
	if err != nil || rec == nil || rec.IsExpired() {
		return ErrInvalidOTP
	}

	// Step 5: Verify OTP hash; rate limiting is handled globally at the route level
	if ok, _, err := s.passwords.Verify(rec.Value, otp); err != nil || !ok {
		return ErrInvalidOTP
	}

	// Step 6: Update user credential account with new password
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
		// Step 7: Consume OTP upon successful verification
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

// Config returns the plugin's configuration.
func (s *EmailOTPService) Config() emailotpconfig.EmailOTPConfig {
	return s.config
}
