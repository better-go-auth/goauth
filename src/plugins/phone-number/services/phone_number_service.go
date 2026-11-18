// Package services implements better-auth's phone-number plugin endpoints (SMS OTP sign-in / sign-up,
// phone + password sign-in and password reset by SMS).
package services

import (
	"context"
	"crypto/rand"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/models/enums"
	phoneconfig "github.com/better-go-auth/goauth/src/plugins/phone-number/config"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
)

// PasswordResetSuffix is appended to the phone number to build the password reset verification identifier.
const PasswordResetSuffix = "-request-password-reset"

// PasswordResetIdentifier returns better-auth's verification identifier for a phone password reset code.
func PasswordResetIdentifier(phoneNumber string) string { return phoneNumber + PasswordResetSuffix }

// PhoneNumberService holds the phone-number plugin logic. Codes live in the verification table in
// better-auth's format: identifier = phone number (or "<phone>-request-password-reset"), value = "code:attempts".
type PhoneNumberService struct {
	cfg phoneconfig.PhoneNumberConfig
	kit *pluginkit.Kit
	now func() time.Time
}

// NewPhoneNumberService builds the service; cfg defaults are applied here.
func NewPhoneNumberService(cfg phoneconfig.PhoneNumberConfig, kit *pluginkit.Kit) *PhoneNumberService {
	return &PhoneNumberService{cfg: cfg.WithDefaults(), kit: kit, now: time.Now}
}

// Config returns the effective configuration (defaults applied).
func (s *PhoneNumberService) Config() phoneconfig.PhoneNumberConfig { return s.cfg }

// Kit returns the shared plugin runtime.
func (s *PhoneNumberService) Kit() *pluginkit.Kit { return s.kit }

// ─── Helpers ─────────────────────────────────────────────────────────────────

// GenerateOTP returns a random numeric code of length digits (better-auth's generateRandomString(size, "0-9")).
func GenerateOTP(length int) (string, error) {
	var b strings.Builder
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		b.WriteByte(byte('0' + n.Int64()))
	}
	return b.String(), nil
}

func (s *PhoneNumberService) request(ctx context.Context) *http.Request { return s.kit.Request(ctx) }

// validatePhone runs PhoneNumberValidator (send-otp and sign-in only, like better-auth).
func (s *PhoneNumberService) validatePhone(phoneNumber string) error {
	if s.cfg.PhoneNumberValidator != nil && !s.cfg.PhoneNumberValidator(phoneNumber) {
		return ErrInvalidPhoneNumber
	}
	return nil
}

// storeCode writes a verification row (replacing any previous code for identifier) expiring after ExpiresIn.
func (s *PhoneNumberService) storeCode(ctx context.Context, identifier, value string) error {
	_, err := s.kit.Repos.UpsertVerificationValue(ctx, &models.Verification{
		Identifier: identifier,
		Value:      value,
		ExpiresAt:  s.now().Add(s.cfg.ExpiresIn).UTC(),
	})
	return err
}

// findUserByPhone returns the user owning phoneNumber, or nil.
func (s *PhoneNumberService) findUserByPhone(ctx context.Context, phoneNumber string) (*models.User, error) {
	return pluginkit.AcceptNotFound(s.kit.Repos.FindUserByPhoneNumber(ctx, phoneNumber))
}

// splitCode splits a stored "code:attempts" value. A value without attempts (written by sign-in's
// requireVerification branch) reports hasAttempts=false, which skips the lockout check like better-auth.
func splitCode(value string) (code string, attempts int, hasAttempts bool) {
	code, rest, found := strings.Cut(value, ":")
	if !found || rest == "" {
		return code, 0, false
	}
	n, err := strconv.Atoi(rest)
	if err != nil {
		// better-auth: parseInt("x") is NaN, NaN >= allowed is false and NaN + 1 stays NaN
		return code, 0, false
	}
	return code, n, true
}

// checkCode validates code against the verification row identifier with better-auth's attempt counter.
// On success the matching row is returned and left in place; the caller deletes it.
// The attempt counter is written with a compare-and-swap and the check is retried when a concurrent
// request changed the row first, so parallel wrong guesses can't exceed AllowedAttempts.
func (s *PhoneNumberService) checkCode(ctx context.Context, identifier, code string) (*models.Verification, error) {
	for try := 0; try < maxCodeCASRetries; try++ {
		// Step 1: load the newest code for identifier
		v, err := pluginkit.AcceptNotFound(s.kit.Repos.FindVerificationValue(ctx, identifier))
		if err != nil {
			return nil, err
		}
		if v == nil {
			return nil, ErrOTPNotFound
		}
		// Step 2: expired codes are reported as such (and kept, like better-auth)
		if v.ExpiresAt.Before(s.now()) {
			return nil, ErrOTPExpired
		}
		// Step 3: too many wrong attempts → delete the code and lock out
		stored, attempts, hasAttempts := splitCode(v.Value)
		if hasAttempts && attempts >= s.cfg.AllowedAttempts {
			_ = s.kit.Repos.DeleteVerificationByIdentifier(ctx, identifier)
			return nil, ErrTooManyAttempts
		}
		// Step 4: wrong code → count the attempt atomically; retry when another request counted first
		if !authcrypto.SecureEqual(stored, code) {
			swapped, err := s.kit.Repos.UpdateVerificationValue(ctx, v.ID, v.Value, stored+":"+strconv.Itoa(attempts+1))
			if err != nil {
				return nil, err
			}
			if !swapped {
				continue
			}
			return nil, ErrInvalidOTP
		}
		return v, nil
	}
	return nil, ErrInvalidOTP
}

// maxCodeCASRetries bounds how often a code check is retried after losing a compare-and-swap race.
const maxCodeCASRetries = 10

// UpdatePhoneNumber writes a user's phone number. Clearing it (nil) also clears PhoneNumberVerified,
// like better-auth's databaseHooks.user.update.before registered by the plugin.
func (s *PhoneNumberService) UpdatePhoneNumber(ctx context.Context, userID string, phoneNumber *string, verified bool) (*models.User, error) {
	data := map[string]interface{}{"PhoneNumber": phoneNumber, "PhoneNumberVerified": verified}
	if phoneNumber == nil {
		data["PhoneNumberVerified"] = false
	}
	return s.kit.Repos.UpdateUser(ctx, userID, data)
}

// ─── Send OTP ────────────────────────────────────────────────────────────────

// SendOTP mirrors POST /phone-number/send-otp.
func (s *PhoneNumberService) SendOTP(ctx context.Context, phoneNumber string) error {
	// Step 1: the endpoint is unusable without an SMS sender
	if s.cfg.SendOTP == nil {
		return ErrSendOTPNotImplemented
	}
	// Step 2: optional phone number format check
	if err := s.validatePhone(phoneNumber); err != nil {
		return err
	}
	// Step 3: generate and store the code as "code:0"
	code, err := GenerateOTP(s.cfg.OTPLength)
	if err != nil {
		return err
	}
	if err := s.storeCode(ctx, phoneNumber, code+":0"); err != nil {
		return err
	}
	// Step 4: deliver it (config: Advanced.BackgroundTasks.Handler runs the sender without blocking)
	data := phoneconfig.OTPData{PhoneNumber: phoneNumber, Code: code}
	return s.kit.Conf.RunInBackgroundOrAwait(ctx, func(ctx context.Context) error { return s.cfg.SendOTP(data, s.request(ctx)) })
}

// ─── Sign in with phone number + password ───────────────────────────────────

// SignInResult is a successful phone + password sign-in.
type SignInResult struct {
	Session      *dtos.SessionWithUser
	DontRemember bool
}

// SignIn mirrors POST /sign-in/phone-number.
func (s *PhoneNumberService) SignIn(ctx context.Context, phoneNumber, password string, rememberMe *bool) (*SignInResult, error) {
	// Step 1: optional phone number format check
	if err := s.validatePhone(phoneNumber); err != nil {
		return nil, err
	}
	// Step 2: find the user by phone number
	user, err := s.findUserByPhone(ctx, phoneNumber)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrInvalidPhoneNumberOrPassword
	}
	// Step 3: requireVerification → send a fresh code instead of signing in an unverified number
	if s.cfg.RequireVerification && !user.PhoneNumberVerified {
		code, err := GenerateOTP(s.cfg.OTPLength)
		if err != nil {
			return nil, err
		}
		// better-auth stores this code without the ":attempts" suffix
		if err := s.storeCode(ctx, phoneNumber, code); err != nil {
			return nil, err
		}
		if s.cfg.SendOTP != nil {
			data := phoneconfig.OTPData{PhoneNumber: phoneNumber, Code: code}
			if err := s.kit.Conf.RunInBackgroundOrAwait(ctx, func(ctx context.Context) error { return s.cfg.SendOTP(data, s.request(ctx)) }); err != nil {
				return nil, err
			}
		}
		return nil, ErrPhoneNumberNotVerified
	}
	// Step 4: the credential account must exist and hold a password
	acc, err := pluginkit.AcceptNotFound(s.kit.Repos.FindAccountByUserAndProvider(ctx, user.ID, models.ProvCredential))
	if err != nil {
		return nil, err
	}
	if acc == nil {
		return nil, ErrInvalidPhoneNumberOrPassword
	}
	if acc.Password == nil || *acc.Password == "" {
		return nil, ErrUnexpected
	}
	// Step 5: check the password
	ok, _, err := s.kit.Passwords.Verify(*acc.Password, password)
	if err != nil || !ok {
		return nil, ErrInvalidPhoneNumberOrPassword
	}
	// Step 6: create the session (rememberMe=false → session cookie without Max-Age)
	dontRemember := rememberMe != nil && !*rememberMe
	sw, err := s.kit.CreateSession(ctx, user, dontRemember)
	if err != nil {
		if ae := autherr.AsAuthError(err); ae != nil && ae.Code == autherr.ErrFailedToCreateSession.Code {
			return nil, autherr.ErrFailedToCreateSession.WithStatus(http.StatusUnauthorized)
		}
		return nil, err
	}
	return &SignInResult{Session: sw, DontRemember: dontRemember}, nil
}

// ─── Verify ──────────────────────────────────────────────────────────────────

// VerifyInput is the body of POST /phone-number/verify.
type VerifyInput struct {
	PhoneNumber       string
	Code              string
	DisableSession    bool
	UpdatePhoneNumber bool
	// Extra holds the remaining body fields (better-auth's additional user fields for sign-up).
	Extra map[string]any
}

// VerifyResult is the outcome of a verification.
type VerifyResult struct {
	User *models.User
	// Session is the new session (nil with disableSession, or when updatePhoneNumber reused the current one).
	Session *dtos.SessionWithUser
	// Current is the caller's session with the updated user (updatePhoneNumber only).
	Current *dtos.SessionWithUser
	// Token is the response token: the new or current session token, nil with disableSession.
	Token *string
}

// Verify mirrors POST /phone-number/verify.
func (s *PhoneNumberService) Verify(ctx context.Context, in VerifyInput) (*VerifyResult, error) {
	// Step 1: check the code (custom VerifyOTP or the stored "code:attempts" row), then consume it
	if err := s.consumeVerifyCode(ctx, in.PhoneNumber, in.Code); err != nil {
		return nil, err
	}
	// Step 2: updatePhoneNumber → attach the verified number to the signed-in user
	if in.UpdatePhoneNumber {
		return s.verifyUpdate(ctx, in.PhoneNumber)
	}
	// Step 3: find the owner of the number, or create one with signUpOnVerification
	user, err := s.findUserByPhone(ctx, in.PhoneNumber)
	if err != nil {
		return nil, err
	}
	if user == nil {
		if s.cfg.SignUpOnVerification != nil {
			if user, err = s.signUpUser(ctx, in); err != nil {
				return nil, err
			}
		}
	} else {
		user, err = s.kit.Repos.UpdateUser(ctx, user.ID, map[string]interface{}{"PhoneNumberVerified": true})
		if err != nil {
			return nil, autherr.ErrFailedToUpdateUser
		}
		s.kit.RefreshUser(ctx, user)
	}
	if user == nil {
		return nil, autherr.ErrFailedToUpdateUser
	}
	// Step 4: let the app react to the verification
	if s.cfg.CallbackOnVerification != nil {
		if err := s.cfg.CallbackOnVerification(phoneconfig.VerificationData{PhoneNumber: in.PhoneNumber, User: user}, s.request(ctx)); err != nil {
			return nil, err
		}
	}
	// Step 5: sign the user in unless disableSession
	res := &VerifyResult{User: user}
	if !in.DisableSession {
		sw, err := s.kit.CreateSession(ctx, user, false)
		if err != nil {
			return nil, err
		}
		tok := sw.Session.Token
		res.Session, res.Token = sw, &tok
	}
	return res, nil
}

// consumeVerifyCode checks the code for phoneNumber and deletes it when valid.
func (s *PhoneNumberService) consumeVerifyCode(ctx context.Context, phoneNumber, code string) error {
	// Step 1: a custom verifier replaces the stored code check (Twilio Verify and friends)
	if s.cfg.VerifyOTP != nil {
		ok, err := s.cfg.VerifyOTP(phoneconfig.OTPData{PhoneNumber: phoneNumber, Code: code}, s.request(ctx))
		if err != nil {
			return err
		}
		if !ok {
			return ErrInvalidOTP
		}
		// a stored code for the number is dropped all the same
		return s.kit.Repos.DeleteVerificationByIdentifier(ctx, phoneNumber)
	}
	// Step 2: built-in check with the attempt counter
	v, err := s.checkCode(ctx, phoneNumber, code)
	if err != nil {
		return err
	}
	// Step 3: consume the code atomically; losing the race means a concurrent request already used it
	deleted, err := s.kit.Repos.DeleteVerificationIfValue(ctx, v.ID, v.Value)
	if err != nil {
		return err
	}
	if !deleted {
		return ErrInvalidOTP
	}
	return nil
}

// verifyUpdate is the updatePhoneNumber branch of Verify.
func (s *PhoneNumberService) verifyUpdate(ctx context.Context, phoneNumber string) (*VerifyResult, error) {
	// Step 1: a session is required (better-auth answers 401 USER_NOT_FOUND)
	current := s.kit.CurrentOrResolve(ctx)
	if current == nil {
		return nil, ErrNoSessionForUpdate
	}
	// Step 2: the number must not belong to any user yet (including the caller)
	owner, err := s.findUserByPhone(ctx, phoneNumber)
	if err != nil {
		return nil, err
	}
	if owner != nil {
		return nil, ErrPhoneNumberExist
	}
	// Step 3: store the verified number
	phone := phoneNumber
	user, err := s.UpdatePhoneNumber(ctx, current.User.ID, &phone, true)
	if err != nil || user == nil {
		return nil, autherr.ErrFailedToUpdateUser
	}
	s.kit.RefreshUser(ctx, user)
	// Step 4: let the app react to the verification
	if s.cfg.CallbackOnVerification != nil {
		if err := s.cfg.CallbackOnVerification(phoneconfig.VerificationData{PhoneNumber: phoneNumber, User: user}, s.request(ctx)); err != nil {
			return nil, err
		}
	}
	// Step 5: answer with the current session token and the updated user snapshot
	sw := *current
	sw.User = dtos.UserFromModel(user)
	tok := current.Session.Token
	return &VerifyResult{User: user, Current: &sw, Token: &tok}, nil
}

// signUpUser creates the user of an unknown, just-verified phone number (signUpOnVerification).
func (s *PhoneNumberService) signUpUser(ctx context.Context, in VerifyInput) (*models.User, error) {
	// Step 1: better-auth's parseUserInput rejects input:false plugin fields such as phoneNumberVerified
	if truthy(in.Extra["phoneNumberVerified"]) {
		return nil, ErrPhoneNumberVerifiedNotAllowed
	}
	// Step 2: placeholder email and name
	opts := s.cfg.SignUpOnVerification
	email := in.PhoneNumber + "@phone.invalid"
	if opts.GetTempEmail != nil {
		email = opts.GetTempEmail(in.PhoneNumber)
	}
	name := in.PhoneNumber
	if opts.GetTempName != nil {
		name = opts.GetTempName(in.PhoneNumber)
	}
	// Step 3: create the user with a verified phone number (hooks run like core sign-up)
	phone := in.PhoneNumber
	u := &models.User{}
	u.Name, u.Email, u.Role = name, strings.ToLower(email), enums.User
	u.PhoneNumber, u.PhoneNumberVerified = &phone, true
	created, err := s.kit.CreateUser(ctx, u)
	if err != nil {
		if ae := autherr.AsAuthError(err); ae != nil && ae.Code == autherr.ErrFailedToCreateUser.Code {
			return nil, autherr.ErrFailedToCreateUser.WithStatus(http.StatusInternalServerError)
		}
		return nil, err
	}
	return created, nil
}

// truthy mirrors JavaScript truthiness for decoded JSON values.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case float64:
		return x != 0
	default:
		return true
	}
}

// ─── Password reset ──────────────────────────────────────────────────────────

// RequestPasswordReset mirrors POST /phone-number/request-password-reset. It always succeeds so callers
// cannot probe which numbers are registered.
func (s *PhoneNumberService) RequestPasswordReset(ctx context.Context, phoneNumber string) error {
	// Step 1: look up the user (unknown numbers still get a stored code, like better-auth)
	user, err := s.findUserByPhone(ctx, phoneNumber)
	if err != nil {
		return err
	}
	// Step 2: generate and store "code:0" under "<phone>-request-password-reset"
	code, err := GenerateOTP(s.cfg.OTPLength)
	if err != nil {
		return err
	}
	if err := s.storeCode(ctx, PasswordResetIdentifier(phoneNumber), code+":0"); err != nil {
		return err
	}
	// Step 3: only registered numbers receive the SMS
	if user == nil || s.cfg.SendPasswordResetOTP == nil {
		return nil
	}
	data := phoneconfig.OTPData{PhoneNumber: phoneNumber, Code: code}
	return s.kit.Conf.RunInBackgroundOrAwait(ctx, func(ctx context.Context) error {
		return s.cfg.SendPasswordResetOTP(data, s.request(ctx))
	})
}

// ResetPassword mirrors POST /phone-number/reset-password.
func (s *PhoneNumberService) ResetPassword(ctx context.Context, phoneNumber, otp, newPassword string) error {
	identifier := PasswordResetIdentifier(phoneNumber)
	// Step 1: check the reset code with the attempt counter
	if _, err := s.checkCode(ctx, identifier, otp); err != nil {
		return err
	}
	// Step 2: the number must belong to a user
	user, err := s.findUserByPhone(ctx, phoneNumber)
	if err != nil {
		return err
	}
	if user == nil {
		return ErrUnexpectedBadRequest
	}
	// Step 3: password length policy (EmailAndPassword.Min/MaxPasswordLength)
	ep := s.kit.Conf.EmailAndPassword
	minLen, maxLen := ep.MinPasswordLength, ep.MaxPasswordLength
	if minLen <= 0 {
		minLen = 8
	}
	if maxLen <= 0 {
		maxLen = 128
	}
	if len(newPassword) < minLen {
		return autherr.ErrPasswordTooShort
	}
	if len(newPassword) > maxLen {
		return autherr.ErrPasswordTooLong
	}
	// Step 4: hash and store the password, creating the credential account when the user had none
	hash, err := s.kit.Passwords.HashContext(ctx, newPassword)
	if err != nil {
		return err
	}
	err = s.kit.InTx(ctx, func(ctx context.Context) error {
		acc, err := pluginkit.AcceptNotFound(s.kit.Repos.FindAccountByUserAndProvider(ctx, user.ID, models.ProvCredential))
		if err != nil {
			return err
		}
		if acc == nil {
			_, err = s.kit.Repos.CreateAccount(ctx, &models.Account{
				Base:       models.Base{ID: s.kit.NewID()},
				UserID:     user.ID,
				ProviderID: models.ProvCredential,
				AccountID:  user.ID,
				Password:   &hash,
			})
			return err
		}
		_, err = s.kit.Repos.UpdateAccount(ctx, acc.ID, map[string]interface{}{"Password": hash})
		return err
	})
	if err != nil {
		return err
	}
	// Step 5: the code is single use
	if err := s.kit.Repos.DeleteVerificationByIdentifier(ctx, identifier); err != nil {
		return err
	}
	// Step 6: EmailAndPassword.OnPasswordReset callback
	if cb := ep.OnPasswordReset; cb != nil {
		if err := cb(config.PasswordResetData{User: *user}, s.request(ctx)); err != nil {
			return err
		}
	}
	// Step 7: EmailAndPassword.RevokeSessionsOnPasswordReset signs the user out everywhere
	if ep.RevokeSessionsOnPasswordReset {
		return s.kit.Sessions.DeleteUserSessions(ctx, user.ID)
	}
	return nil
}
