package services

import (
	"context"
	"net/http"
	"strings"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
)

// RequestEmailChange dispatches a change-email OTP to the target new email address.
func (s *EmailOTPService) RequestEmailChange(ctx context.Context, userID, newEmail string, currentOTP *string, req *http.Request) error {
	// Step 1: Ensure email change is enabled and validate target email
	if !s.config.ChangeEmail.Enabled {
		return ErrChangeEmailDisabled
	}
	if !validEmail(newEmail) {
		return ErrInvalidEmailAddress
	}

	// Step 2: Load current user and ensure target email differs from current email
	user, err := s.repos.FindUserByID(ctx, userID)
	if err != nil || user == nil {
		return ErrUserNotFound
	}
	if strings.EqualFold(user.Email, newEmail) {
		return ErrEmailIsTheSame
	}

	// Step 3: If verifyCurrentEmail is required, verify and consume OTP for current email
	if s.config.ChangeEmail.VerifyCurrentEmail {
		if currentOTP == nil || *currentOTP == "" {
			return autherr.Err(http.StatusBadRequest, "CURRENT_EMAIL_OTP_REQUIRED", "OTP for current email is required")
		}
		currentIdentifier := s.otpIdentifier(emailotpconfig.OTPTypeEmailVerification, user.Email)
		if err := s.verifyOTPAttempt(ctx, currentIdentifier, *currentOTP, true); err != nil {
			return err
		}
	}

	// Step 4: A taken address gets the same success answer but no code, so the endpoint can't be used to
	// probe which emails are registered (better-auth behaviour)
	identifier := s.changeEmailIdentifier(user.Email, newEmail)
	existing, err := acceptNotFound(s.repos.FindUserByEmail(ctx, strings.ToLower(newEmail)))
	if err != nil {
		return err
	}
	if existing != nil {
		_ = s.repos.DeleteVerificationByIdentifier(ctx, identifier)
		return nil
	}
	if s.config.SendVerificationOTP == nil {
		return ErrSenderNotConfigured
	}

	// Step 5: Send change-email OTP to the new email address, stored under "change-email-otp-<current>-<new>"
	return s.issueOTP(ctx, identifier, strings.ToLower(newEmail), emailotpconfig.OTPTypeChangeEmail, req)
}

// ChangeEmail verifies the OTP sent to newEmail and updates the user's email.
func (s *EmailOTPService) ChangeEmail(ctx context.Context, userID, newEmail, otp string) (*models.User, error) {
	// Step 1: Ensure email change is enabled and validate inputs
	if !s.config.ChangeEmail.Enabled {
		return nil, ErrChangeEmailDisabled
	}
	if !validEmail(newEmail) {
		return nil, ErrInvalidEmailAddress
	}
	if otp == "" {
		return nil, ErrInvalidOTP
	}
	current, err := s.repos.FindUserByID(ctx, userID)
	if err != nil || current == nil {
		return nil, ErrUserNotFoundBadRequest
	}
	if strings.EqualFold(current.Email, newEmail) {
		return nil, ErrEmailIsTheSame
	}

	// Step 2: Verify OTP against stored value with attempt tracking
	identifier := s.changeEmailIdentifier(current.Email, newEmail)
	if err := s.verifyOTPAttempt(ctx, identifier, otp, false); err != nil {
		return nil, err
	}

	// Step 3: Update user email in transaction
	var updatedUser *models.User
	err = s.withTx(ctx, func(txCtx context.Context) error {
		user, err := s.repos.FindUserByID(txCtx, userID)
		if err != nil || user == nil {
			return ErrUserNotFoundBadRequest
		}

		// Ensure target email is not already taken by another user
		existing, err := acceptNotFound(s.repos.FindUserByEmail(txCtx, strings.ToLower(newEmail)))
		if err != nil {
			return err
		}
		if existing != nil && existing.ID != userID {
			return ErrEmailAlreadyInUse
		}

		// config: EmailVerification.BeforeEmailVerification runs before the new address is marked verified
		if before := s.rootConfig.EmailVerification.BeforeEmailVerification; before != nil {
			if err := before(*user, config.GetHTTPRequest(txCtx)); err != nil {
				return err
			}
		}

		updated, err := s.repos.UpdateUser(txCtx, userID, map[string]interface{}{
			"Email":         strings.ToLower(newEmail),
			"EmailVerified": true,
		})
		if err != nil {
			return autherr.ErrFailedToUpdateUser
		}
		updatedUser = updated

		// better-auth keeps accounts untouched on an email change (a credential account's accountId is the
		// user id, not the email), so no account is created or rewritten here
		// Step 4: Consume OTP upon successful verification
		_ = s.repos.DeleteVerificationByIdentifier(txCtx, identifier)

		return nil
	})
	if err != nil {
		return nil, err
	}

	// config: EmailVerification.AfterEmailVerification
	if after := s.rootConfig.EmailVerification.AfterEmailVerification; after != nil {
		_ = after(*updatedUser, config.GetHTTPRequest(ctx))
	}

	// Step 5: Refresh cached user copy across active sessions so getSession reflects the new email
	s.refreshSessionUser(ctx, updatedUser)
	return updatedUser, nil
}
