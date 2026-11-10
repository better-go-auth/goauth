package services

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
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
		return autherr.Err(http.StatusBadRequest, "SAME_EMAIL", "New email must be different from current email")
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

	// Step 4: Check if new email already belongs to another user
	existing, err := acceptNotFound(s.repos.FindUserByEmail(ctx, strings.ToLower(newEmail)))
	if err != nil {
		return err
	}
	if existing != nil && existing.ID != userID {
		return ErrEmailAlreadyExists
	}

	// Step 5: Send change-email OTP to the new email address
	return s.SendVerificationOTP(ctx, newEmail, emailotpconfig.OTPTypeChangeEmail, req)
}

// ChangeEmail verifies the OTP sent to newEmail and updates the user's email.
func (s *EmailOTPService) ChangeEmail(ctx context.Context, userID, newEmail, otp string) (*models.User, error) {
	// Step 1: Ensure email change is enabled and validate inputs
	if !s.config.ChangeEmail.Enabled {
		return nil, ErrChangeEmailDisabled
	}
	if !validEmail(newEmail) || otp == "" {
		return nil, ErrInvalidOTP
	}

	// Step 2: Verify OTP against stored value with attempt tracking
	identifier := s.otpIdentifier(emailotpconfig.OTPTypeChangeEmail, newEmail)
	if err := s.verifyOTPAttempt(ctx, identifier, otp, false); err != nil {
		return nil, err
	}

	// Step 3: Update user email in transaction
	var updatedUser *models.User
	err := s.withTx(ctx, func(txCtx context.Context) error {
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
		// Step 4: Consume OTP upon successful verification
		_ = s.repos.DeleteVerificationByIdentifier(txCtx, identifier)

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Step 5: Refresh cached user copy across active sessions so getSession reflects the new email
	s.refreshSessionUser(ctx, updatedUser)
	return updatedUser, nil
}
