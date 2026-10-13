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
	if !validEmail(email) || otp == "" {
		return ErrInvalidOTP
	}
	identifier := s.otpIdentifier(otpType, email)
	rec, err := s.repos.FindVerificationValue(ctx, identifier)
	if err != nil || rec == nil || rec.IsExpired() {
		return ErrInvalidOTP
	}

	if ok, _, err := s.passwords.Verify(rec.Value, otp); err != nil || !ok {
		return ErrInvalidOTP
	}
	return nil
}

// VerifyEmail verifies a user's email address using the supplied OTP code.
func (s *EmailOTPService) VerifyEmail(ctx context.Context, email, otp string, meta authint.SessionMeta, req *http.Request) (*modeldtos.SessionWithUser, *models.User, error) {
	if !validEmail(email) || otp == "" {
		return nil, nil, ErrInvalidOTP
	}
	identifier := s.otpIdentifier(emailotpconfig.OTPTypeEmailVerification, email)

	var updatedUser *models.User
	err := s.withTx(ctx, func(txCtx context.Context) error {
		rec, err := s.repos.ConsumeVerificationValue(txCtx, identifier)
		if err != nil || rec == nil || rec.IsExpired() {
			return ErrInvalidOTP
		}

		if ok, _, err := s.passwords.Verify(rec.Value, otp); err != nil || !ok {
			return ErrInvalidOTP
		}

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
	if !validEmail(email) || otp == "" {
		return nil, ErrInvalidOTP
	}
	identifier := s.otpIdentifier(emailotpconfig.OTPTypeSignIn, email)

	var user *models.User
	err := s.withTx(ctx, func(txCtx context.Context) error {
		rec, err := s.repos.ConsumeVerificationValue(txCtx, identifier)
		if err != nil || rec == nil || rec.IsExpired() {
			return ErrInvalidOTP
		}

		if ok, _, err := s.passwords.Verify(rec.Value, otp); err != nil || !ok {
			return ErrInvalidOTP
		}

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

	identifier := s.otpIdentifier(emailotpconfig.OTPTypeForgetPassword, email)
	var userID string
	err = s.withTx(ctx, func(txCtx context.Context) error {
		rec, err := s.repos.ConsumeVerificationValue(txCtx, identifier)
		if err != nil || rec == nil || rec.IsExpired() {
			return ErrInvalidOTP
		}

		if ok, _, err := s.passwords.Verify(rec.Value, otp); err != nil || !ok {
			return ErrInvalidOTP
		}

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

// RequestEmailChange dispatches a change-email OTP to the target new email address.
func (s *EmailOTPService) RequestEmailChange(ctx context.Context, userID, newEmail string, currentOTP *string, req *http.Request) error {
	if !s.config.ChangeEmail.Enabled {
		return ErrChangeEmailDisabled
	}
	if !validEmail(newEmail) {
		return ErrInvalidEmailAddress
	}

	user, err := s.repos.FindUserByID(ctx, userID)
	if err != nil || user == nil {
		return ErrUserNotFound
	}
	if strings.EqualFold(user.Email, newEmail) {
		return autherr.Err(http.StatusBadRequest, "SAME_EMAIL", "New email must be different from current email")
	}

	// If verifyCurrentEmail is required, check that currentOTP is valid for user.Email
	if s.config.ChangeEmail.VerifyCurrentEmail {
		if currentOTP == nil || *currentOTP == "" {
			return autherr.Err(http.StatusBadRequest, "CURRENT_EMAIL_OTP_REQUIRED", "OTP for current email is required")
		}
		if err := s.CheckVerificationOTP(ctx, user.Email, *currentOTP, emailotpconfig.OTPTypeEmailVerification); err != nil {
			return ErrInvalidOTP
		}
	}

	// Check if new email already belongs to another user
	existing, err := acceptNotFound(s.repos.FindUserByEmail(ctx, strings.ToLower(newEmail)))
	if err != nil {
		return err
	}
	if existing != nil && existing.ID != userID {
		return ErrEmailAlreadyExists
	}

	return s.SendVerificationOTP(ctx, newEmail, emailotpconfig.OTPTypeChangeEmail, req)
}

// ChangeEmail verifies the OTP sent to newEmail and updates the user's email.
func (s *EmailOTPService) ChangeEmail(ctx context.Context, userID, newEmail, otp string) (*models.User, error) {
	if !s.config.ChangeEmail.Enabled {
		return nil, ErrChangeEmailDisabled
	}
	if !validEmail(newEmail) || otp == "" {
		return nil, ErrInvalidOTP
	}
	identifier := s.otpIdentifier(emailotpconfig.OTPTypeChangeEmail, newEmail)

	var updatedUser *models.User
	err := s.withTx(ctx, func(txCtx context.Context) error {
		rec, err := s.repos.ConsumeVerificationValue(txCtx, identifier)
		if err != nil || rec == nil || rec.IsExpired() {
			return ErrInvalidOTP
		}

		if ok, _, err := s.passwords.Verify(rec.Value, otp); err != nil || !ok {
			return ErrInvalidOTP
		}

		user, err := s.repos.FindUserByID(txCtx, userID)
		if err != nil || user == nil {
			return ErrUserNotFound
		}

		// Ensure target email is not already taken by another user
		existing, err := acceptNotFound(s.repos.FindUserByEmail(txCtx, strings.ToLower(newEmail)))
		if err != nil {
			return err
		}
		if existing != nil && existing.ID != userID {
			return ErrEmailAlreadyExists
		}

		updated, err := s.repos.UpdateUser(txCtx, userID, map[string]interface{}{
			"Email":         strings.ToLower(newEmail),
			"EmailVerified": true,
		})
		if err != nil {
			return autherr.ErrFailedToUpdateUser
		}
		updatedUser = updated

		// In Better Auth, for providerId "credential", accountId is the user ID.
		acc, err := acceptNotFound(s.repos.FindAccountByUserAndProvider(txCtx, userID, models.ProvCredential))
		if err != nil {
			return err
		}
		if acc != nil {
			if acc.AccountID != user.ID {
				_, err = s.repos.UpdateAccount(txCtx, acc.ID, map[string]interface{}{
					"AccountID": user.ID,
				})
				if err != nil {
					return fmt.Errorf("email-otp: failed to update account: %w", err)
				}
			}
		} else {
			now := time.Now().UTC()
			_, err = s.repos.CreateAccount(txCtx, &models.Account{
				Base:       models.Base{ID: models.NewID(), CreatedAt: now, UpdatedAt: now},
				UserID:     userID,
				ProviderID: models.ProvCredential,
				AccountID:  user.ID,
			})
			if err != nil {
				return fmt.Errorf("email-otp: failed to create account: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}
	return updatedUser, nil
}

// Config returns the plugin's configuration.
func (s *EmailOTPService) Config() emailotpconfig.EmailOTPConfig {
	return s.config
}
