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
	// Step 2: Fetch verification record by identifier
	identifier := s.otpIdentifier(emailotpconfig.OTPTypeChangeEmail, newEmail)
	rec, err := s.repos.FindVerificationValue(ctx, identifier)
	if err != nil || rec == nil || rec.IsExpired() {
		return nil, ErrInvalidOTP
	}

	// Step 3: Verify OTP hash; rate limiting is handled globally at the route level
	if ok, _, err := s.passwords.Verify(rec.Value, otp); err != nil || !ok {
		return nil, ErrInvalidOTP
	}

	// Step 4: Update user email in transaction

	var updatedUser *models.User
	err = s.withTx(ctx, func(txCtx context.Context) error {
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
		// Step 5: Consume OTP upon successful verification
		_ = s.repos.DeleteVerificationByIdentifier(txCtx, identifier)

		return nil
	})
	if err != nil {
		return nil, err
	}
	return updatedUser, nil
}
