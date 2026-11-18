// Package services implements the two-factor plugin (better-auth v1.6 plugins/two-factor).
package services

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	tfconfig "github.com/better-go-auth/goauth/src/plugins/two-factor/config"
	tfdtos "github.com/better-go-auth/goauth/src/plugins/two-factor/dtos"
	tfmodels "github.com/better-go-auth/goauth/src/plugins/two-factor/models"
	"github.com/better-go-auth/goauth/src/plugins/two-factor/repository"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
	"github.com/better-go-auth/goauth/src/providers/cookies"
)

// Cookie base names (better-auth TWO_FACTOR_COOKIE_NAME / TRUST_DEVICE_COOKIE_NAME).
const (
	TwoFactorCookie   = "two_factor"
	TrustDeviceCookie = "trust_device"
)

// Two-factor methods reported in the sign-in challenge.
const (
	MethodTOTP = "totp"
	MethodOTP  = "otp"
)

// signInPaths are the sign-in endpoints the two-factor after-hook intercepts.
var signInPaths = map[string]bool{
	"/sign-in/email":        true,
	"/sign-in/username":     true,
	"/sign-in/phone-number": true,
}

// Result is an endpoint response: a JSON body plus the cookies to set.
type Result struct {
	Body    any
	Cookies []http.Cookie
}

// Service implements every two-factor endpoint.
type Service struct {
	cfg  tfconfig.Config
	kit  *pluginkit.Kit
	repo repository.ITwoFactorRepo
	now  func() time.Time
}

// New builds the service; cfg must already have its defaults applied.
func New(cfg tfconfig.Config, kit *pluginkit.Kit, repo repository.ITwoFactorRepo) *Service {
	return &Service{cfg: cfg, kit: kit, repo: repo, now: time.Now}
}

// Config returns the effective configuration.
func (s *Service) Config() tfconfig.Config { return s.cfg }

// Repo returns the twoFactor repository.
func (s *Service) Repo() repository.ITwoFactorRepo { return s.repo }

// SetClock overrides the clock (tests: OTP expiry, TOTP time steps).
func (s *Service) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

func (s *Service) secret() string { return s.kit.Conf.Secret }

func (s *Service) appName() string {
	if s.kit.Conf.AppName != "" {
		return s.kit.Conf.AppName
	}
	return "Better Auth"
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// checkPassword is better-auth's shouldRequirePassword + validatePassword / checkPassword.
func (s *Service) checkPassword(ctx context.Context, userID string, password *string, allowPasswordless bool) error {
	// Step 1: passwordless users skip the check when allowed
	if allowPasswordless && !s.kit.HasPassword(ctx, userID) {
		return nil
	}
	// Step 2: a password is required
	if password == nil || *password == "" {
		return ErrInvalidPassword
	}
	// Step 3: it must match the credential account
	ok, err := s.kit.VerifyUserPassword(ctx, userID, *password)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvalidPassword
	}
	return nil
}

// RequirePasswordField mirrors the zod body schema: password is required unless allowPasswordless.
func RequirePasswordField(password *string, allowPasswordless bool) error {
	if password == nil && !allowPasswordless {
		return ErrPasswordRequired
	}
	return nil
}

// requestDontRemember reports whether the request carries a signed dont_remember cookie.
func (s *Service) requestDontRemember(ctx context.Context) bool {
	v, ok := s.kit.ReadSignedCookie(ctx, cookies.CookieDontRemember)
	return ok && v != ""
}

// sessionCookies is better-auth's setSessionCookie(ctx, {session, user}) without the dontRememberMe argument:
// the token cookie becomes a browser-session cookie when the request has dont_remember, and the existing
// dont_remember cookie is left untouched.
func (s *Service) sessionCookies(sw *dtos.SessionWithUser, dontRemember bool) []http.Cookie {
	drName := s.kit.Cookies.Name(cookies.CookieDontRemember)
	all := s.kit.SessionCookies(sw, dontRemember)
	out := all[:0]
	for _, c := range all {
		if c.Name != drName {
			out = append(out, c)
		}
	}
	return out
}

// replaceSession is better-auth's "updateUser + createSession(userId, false, oldSession) + setSessionCookie +
// deleteSession(old)" used when 2FA is switched on or off.
func (s *Service) replaceSession(ctx context.Context, current *dtos.SessionWithUser, enabled bool) (*models.User, *dtos.SessionWithUser, []http.Cookie, error) {
	// Step 1: flip twoFactorEnabled on the user
	updated, err := s.kit.Repos.UpdateUser(ctx, current.User.ID, map[string]interface{}{"TwoFactorEnabled": enabled})
	if err != nil {
		return nil, nil, nil, err
	}
	// Step 2: new session carrying the fresh user, old session revoked
	sw, err := s.kit.ReplaceSession(ctx, current, updated)
	if err != nil {
		return nil, nil, nil, err
	}
	// Step 3: keep cached copies of the user in other sessions in sync
	s.kit.RefreshUser(ctx, updated)
	return updated, sw, s.sessionCookies(sw, s.requestDontRemember(ctx)), nil
}

// newTrustDevice stores a trust-device verification row and returns the signed trust_device cookie
// holding `${hmac}!${trustIdentifier}`.
func (s *Service) newTrustDevice(ctx context.Context, userID string) (http.Cookie, error) {
	// Step 1: random identifier and its HMAC bound to the user
	identifier := "trust-device-" + RandomString(32, defaultAlphabet)
	token := TrustDeviceToken(s.secret(), userID, identifier)
	// Step 2: verification row so the server can validate and revoke it
	_, err := s.kit.Repos.UpsertVerificationValue(ctx, &models.Verification{
		Base:       models.Base{ID: s.kit.NewID()},
		Identifier: identifier,
		Value:      userID,
		UserID:     userID,
		ExpiresAt:  s.now().Add(s.cfg.TrustDeviceMaxAge).UTC(),
	})
	if err != nil {
		return http.Cookie{}, err
	}
	// Step 3: the signed cookie
	return s.kit.Cookies.SignedCookie(TrustDeviceCookie, token+"!"+identifier, int(s.cfg.TrustDeviceMaxAge/time.Second)), nil
}

func (s *Service) findVerification(ctx context.Context, identifier string) (*models.Verification, error) {
	return pluginkit.AcceptNotFound(s.kit.Repos.FindVerificationValue(ctx, identifier))
}

func (s *Service) decryptSecret(row *tfmodels.TwoFactor) (string, error) {
	return authcrypto.SymmetricDecrypt(s.secret(), row.Secret)
}

func strPtr(v string) *string { return &v }

// maxOTPCASRetries bounds how often an OTP check is retried after losing a compare-and-swap race.
const maxOTPCASRetries = 10

// ─── Sign-in interception ────────────────────────────────────────────────────

// AfterSignIn is better-auth's two-factor after-hook on /sign-in/email, /sign-in/username and
// /sign-in/phone-number: users with 2FA enabled get {twoFactorRedirect: true} instead of a session,
// unless the request carries a valid trust_device cookie (which is then rotated).
func (s *Service) AfterSignIn(ctx context.Context, ev plugins.SignInEvent) (*plugins.SignInChallenge, error) {
	// Step 1: only credential sign-ins of users with 2FA enabled
	if !signInPaths[ev.Path] || ev.Session == nil || !ev.Session.User.TwoFactorEnabled {
		return nil, nil
	}
	userID := ev.Session.User.ID
	var cookieHeader string
	if ev.Request != nil {
		cookieHeader = ev.Request.Header.Get("Cookie")
	}
	var out []http.Cookie

	// Step 2: a valid trust_device cookie skips 2FA; the trust record and cookie are rotated
	if raw, ok := s.kit.Cookies.ReadSigned(cookieHeader, TrustDeviceCookie); ok {
		token, identifier, _ := strings.Cut(raw, "!")
		if token != "" && identifier != "" &&
			subtle.ConstantTimeCompare([]byte(token), []byte(TrustDeviceToken(s.secret(), userID, identifier))) == 1 {
			rec, err := s.findVerification(ctx, identifier)
			if err != nil {
				return nil, err
			}
			if rec != nil && rec.Value == userID && rec.ExpiresAt.After(s.now()) {
				_ = s.kit.Repos.DeleteVerificationByIdentifier(ctx, identifier)
				cookie, err := s.newTrustDevice(ctx, userID)
				if err != nil {
					return nil, err
				}
				return &plugins.SignInChallenge{ExtraCookies: []http.Cookie{cookie}}, nil
			}
		}
		// invalid or expired trust: forget the cookie and continue with the challenge
		out = append(out, s.kit.Cookies.ExpireCookie(TrustDeviceCookie))
	}

	// Step 3: revoke the session the sign-in created; keep dont_remember so verify honours rememberMe=false
	_ = s.kit.Sessions.Delete(ctx, ev.Session.Session.Token)
	out = append(out, s.kit.ExpireSessionCookies(true)...)
	if ev.DontRemember {
		out = append(out, s.kit.Cookies.SignedCookie(cookies.CookieDontRemember, "true", 0))
	}

	// Step 4: pending sign-in → verification row + signed two_factor cookie
	identifier := "2fa-" + RandomString(20, defaultAlphabet)
	_, err := s.kit.Repos.UpsertVerificationValue(ctx, &models.Verification{
		Base:       models.Base{ID: s.kit.NewID()},
		Identifier: identifier,
		Value:      userID,
		UserID:     userID,
		ExpiresAt:  s.now().Add(s.cfg.TwoFactorCookieMaxAge).UTC(),
	})
	if err != nil {
		return nil, err
	}
	out = append(out, s.kit.Cookies.SignedCookie(TwoFactorCookie, identifier, int(s.cfg.TwoFactorCookieMaxAge/time.Second)))

	// Step 5: available methods (totp needs a verified secret, otp needs a sender)
	methods := []string{}
	if !s.cfg.TOTPOptions.Disable {
		row, err := s.repo.FindByUserID(ctx, userID)
		if err != nil {
			return nil, err
		}
		if row != nil && row.Verified {
			methods = append(methods, MethodTOTP)
		}
	}
	if s.cfg.OTPOptions.SendOTP != nil {
		methods = append(methods, MethodOTP)
	}
	return &plugins.SignInChallenge{
		Body:    tfdtos.TwoFactorRedirect{TwoFactorRedirect: true, TwoFactorMethods: methods},
		Cookies: out,
	}, nil
}

// ─── verifyTwoFactor ─────────────────────────────────────────────────────────

// pending is better-auth's verifyTwoFactor result: either the current session (2FA management while
// signed in) or the pending sign-in identified by the two_factor cookie.
type pending struct {
	session      *dtos.SessionWithUser
	user         dtos.UserResponse
	userModel    *models.User
	key          string
	identifier   string
	dontRemember bool
}

func (p *pending) isSignIn() bool { return p.session == nil }

// resolve is better-auth's verifyTwoFactor (minus valid/invalid).
func (s *Service) resolve(ctx context.Context) (*pending, error) {
	// Step 1: signed in → the session itself is the subject, key `${userId}!${sessionId}`
	if sw := s.kit.CurrentOrResolve(ctx); sw != nil {
		return &pending{session: sw, user: sw.User, key: sw.User.ID + "!" + sw.Session.ID}, nil
	}
	// Step 2: otherwise the signed two_factor cookie → verification row → user
	identifier, ok := s.kit.ReadSignedCookie(ctx, TwoFactorCookie)
	if !ok || identifier == "" {
		return nil, ErrInvalidTwoFactorCookie
	}
	rec, err := s.findVerification(ctx, identifier)
	if err != nil {
		return nil, err
	}
	if rec == nil || !rec.ExpiresAt.After(s.now()) {
		return nil, ErrInvalidTwoFactorCookie
	}
	user, err := pluginkit.AcceptNotFound(s.kit.Repos.FindUserByID(ctx, rec.Value))
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrInvalidTwoFactorCookie
	}
	// Step 3: remember rememberMe=false from the sign-in
	return &pending{
		user:         dtos.UserFromModel(user),
		userModel:    user,
		key:          identifier,
		identifier:   identifier,
		dontRemember: s.requestDontRemember(ctx),
	}, nil
}

// valid completes a successful verification: signed in → {token, user} of the session; pending sign-in →
// create the session, drop the two_factor state and optionally trust the device.
func (s *Service) valid(ctx context.Context, p *pending, trustDevice bool) (*Result, error) {
	// Step 1: already signed in → nothing to create
	if !p.isSignIn() {
		return &Result{Body: tfdtos.TokenUserResponse{Token: strPtr(p.session.Session.Token), User: p.session.User}}, nil
	}
	// Step 2: consume the pending sign-in atomically, so concurrent verifications create one session only
	consumed, err := pluginkit.AcceptNotFound(s.kit.Repos.ConsumeVerificationValue(ctx, p.identifier))
	if err != nil {
		return nil, err
	}
	if consumed == nil {
		return nil, ErrInvalidTwoFactorCookie
	}
	// Step 3: create the session (rememberMe=false is carried by the dont_remember cookie)
	sw, err := s.kit.CreateSession(ctx, p.userModel, p.dontRemember)
	if err != nil {
		return nil, err
	}
	out := s.sessionCookies(sw, p.dontRemember)
	out = append(out, s.kit.Cookies.ExpireCookie(TwoFactorCookie))
	// Step 4: trust this device for TrustDeviceMaxAge
	if trustDevice {
		cookie, err := s.newTrustDevice(ctx, p.userModel.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, cookie, s.kit.Cookies.ExpireCookie(cookies.CookieDontRemember))
	}
	return &Result{
		Body:    tfdtos.TokenUserResponse{Token: strPtr(sw.Session.Token), User: dtos.UserFromModel(p.userModel)},
		Cookies: out,
	}, nil
}

// ─── Enable / disable ────────────────────────────────────────────────────────

// Enable is POST /two-factor/enable: new TOTP secret and backup codes; 2FA turns on after the first
// verify-totp (or immediately with SkipVerificationOnEnable).
func (s *Service) Enable(ctx context.Context, current *dtos.SessionWithUser, in tfdtos.EnableInput) (*Result, error) {
	user := current.User
	// Step 1: password check (skipped for passwordless users when allowed)
	if err := s.checkPassword(ctx, user.ID, in.Password, s.cfg.AllowPasswordless); err != nil {
		return nil, err
	}
	// Step 2: new secret (stored encrypted) and backup codes
	secret := RandomString(32, defaultAlphabet)
	encSecret, err := authcrypto.SymmetricEncrypt(s.secret(), secret)
	if err != nil {
		return nil, err
	}
	codes := GenerateBackupCodeList(s.cfg.BackupCodeOptions)
	storedCodes, err := EncodeBackupCodes(codes, s.secret(), s.cfg.BackupCodeOptions)
	if err != nil {
		return nil, err
	}
	res := &Result{}
	// Step 3: skipVerificationOnEnable turns 2FA on right away and refreshes the session cookie
	if s.cfg.SkipVerificationOnEnable {
		_, _, ck, err := s.replaceSession(ctx, current, true)
		if err != nil {
			return nil, err
		}
		res.Cookies = ck
	}
	// Step 4: replace the user's row; an already verified setup stays verified
	existing, err := s.repo.FindByUserID(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	err = s.kit.InTx(ctx, func(ctx context.Context) error {
		if err := s.repo.DeleteByUserID(ctx, user.ID); err != nil {
			return err
		}
		return s.repo.Create(ctx, &tfmodels.TwoFactor{
			ID:          s.kit.NewID(),
			Secret:      encSecret,
			BackupCodes: storedCodes,
			UserID:      user.ID,
			Verified:    (existing != nil && existing.Verified) || s.cfg.SkipVerificationOnEnable,
		})
	})
	if err != nil {
		return nil, err
	}
	// Step 5: TOTP URI for the authenticator app (body issuer → Issuer option → app name)
	issuer := s.cfg.Issuer
	if in.Issuer != nil && *in.Issuer != "" {
		issuer = *in.Issuer
	}
	if issuer == "" {
		issuer = s.appName()
	}
	res.Body = tfdtos.EnableResponse{
		TotpURI:     TOTPURI(secret, issuer, user.Email, s.cfg.TOTPOptions.Digits, s.cfg.TOTPOptions.Period),
		BackupCodes: codes,
	}
	return res, nil
}

// Disable is POST /two-factor/disable (fresh session): turns 2FA off, deletes the secrets, rotates the
// session and revokes this device's trust.
func (s *Service) Disable(ctx context.Context, current *dtos.SessionWithUser, password *string) (*Result, error) {
	// Step 1: password check
	if err := s.checkPassword(ctx, current.User.ID, password, s.cfg.AllowPasswordless); err != nil {
		return nil, err
	}
	// Step 2: turn 2FA off and drop the secrets
	updated, err := s.kit.Repos.UpdateUser(ctx, current.User.ID, map[string]interface{}{"TwoFactorEnabled": false})
	if err != nil {
		return nil, err
	}
	if err := s.repo.DeleteByUserID(ctx, updated.ID); err != nil {
		return nil, err
	}
	// Step 3: new session with the fresh user, old one revoked
	sw, err := s.kit.ReplaceSession(ctx, current, updated)
	if err != nil {
		return nil, err
	}
	s.kit.RefreshUser(ctx, updated)
	out := s.sessionCookies(sw, s.requestDontRemember(ctx))
	// Step 4: revoke the trusted device of this browser
	if raw, ok := s.kit.ReadSignedCookie(ctx, TrustDeviceCookie); ok && raw != "" {
		parts := strings.Split(raw, "!")
		if len(parts) > 1 && parts[1] != "" {
			_ = s.kit.Repos.DeleteVerificationByIdentifier(ctx, parts[1])
		}
		out = append(out, s.kit.Cookies.ExpireCookie(TrustDeviceCookie))
	}
	return &Result{Body: tfdtos.StatusResponse{Status: true}, Cookies: out}, nil
}

// ─── TOTP ────────────────────────────────────────────────────────────────────

// GenerateTOTP is better-auth's server-only generateTOTP endpoint: the current code for secret.
func (s *Service) GenerateTOTP(secret string) (string, error) {
	if s.cfg.TOTPOptions.Disable {
		return "", ErrTOTPNotConfigured
	}
	return TOTP(secret, s.now(), s.cfg.TOTPOptions.Period, s.cfg.TOTPOptions.Digits), nil
}

// GetTOTPURI is POST /two-factor/get-totp-uri.
func (s *Service) GetTOTPURI(ctx context.Context, current *dtos.SessionWithUser, password *string) (*Result, error) {
	// Step 1: TOTP must be configured and set up for the user
	if s.cfg.TOTPOptions.Disable {
		return nil, ErrTOTPNotConfigured
	}
	row, err := s.repo.FindByUserID(ctx, current.User.ID)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, ErrTOTPNotEnabled
	}
	secret, err := s.decryptSecret(row)
	if err != nil {
		return nil, err
	}
	// Step 2: password check
	if err := s.checkPassword(ctx, current.User.ID, password, s.cfg.TOTPAllowPasswordless()); err != nil {
		return nil, err
	}
	// Step 3: better-auth's totp sub-plugin has no issuer option (totpOptions omits it), so the app name is used
	uri := TOTPURI(secret, s.appName(), current.User.Email, s.cfg.TOTPOptions.Digits, s.cfg.TOTPOptions.Period)
	return &Result{Body: tfdtos.TotpURIResponse{TotpURI: uri}}, nil
}

// VerifyTOTP is POST /two-factor/verify-totp: completes a pending sign-in, or (signed in) confirms the
// TOTP setup and turns 2FA on.
func (s *Service) VerifyTOTP(ctx context.Context, in tfdtos.VerifyCodeInput) (*Result, error) {
	// Step 1: TOTP must be configured
	if s.cfg.TOTPOptions.Disable {
		return nil, ErrTOTPNotConfigured
	}
	// Step 2: who is verifying
	p, err := s.resolve(ctx)
	if err != nil {
		return nil, err
	}
	// Step 3: the user's TOTP secret (sign-in requires a verified setup)
	row, err := s.repo.FindByUserID(ctx, p.user.ID)
	if err != nil {
		return nil, err
	}
	if row == nil || (p.isSignIn() && !row.Verified) {
		return nil, ErrTOTPNotEnabled
	}
	secret, err := s.decryptSecret(row)
	if err != nil {
		return nil, err
	}
	// Step 4: check the code (current step ± 1)
	if !VerifyTOTP(secret, in.Code, s.now(), s.cfg.TOTPOptions.Period, s.cfg.TOTPOptions.Digits) {
		return nil, ErrInvalidCode
	}
	var extra []http.Cookie
	// Step 5: first successful check confirms the setup (and enables 2FA for a signed-in user)
	if !row.Verified {
		if !p.user.TwoFactorEnabled && p.session != nil {
			_, _, ck, err := s.replaceSession(ctx, p.session, true)
			if err != nil {
				return nil, err
			}
			extra = ck
		}
		if err := s.repo.SetVerified(ctx, row.ID); err != nil {
			return nil, err
		}
	}
	// Step 6: success response (better-auth answers with the pre-rotation session token and user)
	res, err := s.valid(ctx, p, in.TrustDevice != nil && *in.TrustDevice)
	if err != nil {
		return nil, err
	}
	res.Cookies = append(extra, res.Cookies...)
	return res, nil
}

// ─── OTP ─────────────────────────────────────────────────────────────────────

func otpIdentifier(key string) string { return "2fa-otp-" + key }

// SendOTP is POST /two-factor/send-otp.
func (s *Service) SendOTP(ctx context.Context) (*Result, error) {
	// Step 1: OTP needs a sender
	if s.cfg.OTPOptions.SendOTP == nil {
		slog.Error("two-factor: send otp isn't configured. Please configure the send otp function on otp options.")
		return nil, ErrOTPNotConfigured
	}
	// Step 2: who asks
	p, err := s.resolve(ctx)
	if err != nil {
		return nil, err
	}
	// Step 3: new code stored as "<stored>:<attempts>"
	code := RandomString(s.cfg.OTPOptions.Digits, digits09)
	stored, err := StoreOTP(code, s.secret(), s.cfg.OTPOptions.StoreOTP)
	if err != nil {
		return nil, err
	}
	_, err = s.kit.Repos.UpsertVerificationValue(ctx, &models.Verification{
		Base:       models.Base{ID: s.kit.NewID()},
		Identifier: otpIdentifier(p.key),
		Value:      stored + ":0",
		UserID:     p.user.ID,
		ExpiresAt:  s.now().Add(s.cfg.OTPOptions.Period).UTC(),
	})
	if err != nil {
		return nil, err
	}
	// Step 4: deliver it; failures are logged, never reported (better-auth runs it in the background)
	if err := s.cfg.OTPOptions.SendOTP(ctx, tfconfig.SendOTPData{User: p.user, OTP: code}, s.kit.Request(ctx)); err != nil {
		slog.Error("two-factor: failed to send two-factor OTP", "error", err)
	}
	return &Result{Body: tfdtos.StatusResponse{Status: true}}, nil
}

// VerifyOTP is POST /two-factor/verify-otp.
func (s *Service) VerifyOTP(ctx context.Context, in tfdtos.VerifyCodeInput) (*Result, error) {
	// Step 1: who is verifying
	p, err := s.resolve(ctx)
	if err != nil {
		return nil, err
	}
	// Steps 2–4 retry when a concurrent request changed the code row first: the attempt counter is written
	// with a compare-and-swap, so parallel wrong guesses can't exceed AllowedAttempts.
	id := otpIdentifier(p.key)
	matched := false
	for try := 0; try < maxOTPCASRetries && !matched; try++ {
		// Step 2: the pending code must exist and be unexpired
		rec, err := s.findVerification(ctx, id)
		if err != nil {
			return nil, err
		}
		if rec == nil || rec.ExpiresAt.Before(s.now()) {
			if rec != nil {
				_ = s.kit.Repos.DeleteVerificationByIdentifier(ctx, id)
			}
			return nil, ErrOTPHasExpired
		}
		stored, counterStr := rec.Value, ""
		if i := strings.LastIndexByte(rec.Value, ':'); i >= 0 {
			stored, counterStr = rec.Value[:i], rec.Value[i+1:]
		}
		counter, _ := strconv.Atoi(counterStr)
		// Step 3: too many wrong attempts burns the code
		if counter >= s.cfg.OTPOptions.AllowedAttempts {
			_ = s.kit.Repos.DeleteVerificationByIdentifier(ctx, id)
			return nil, ErrTooManyAttempts
		}
		// Step 4: wrong code → count the attempt (retry the check when another request counted first)
		if !OTPMatches(stored, in.Code, s.secret(), s.cfg.OTPOptions.StoreOTP) {
			swapped, err := s.kit.Repos.UpdateVerificationValue(ctx, rec.ID, rec.Value, stored+":"+strconv.Itoa(counter+1))
			if err != nil {
				return nil, err
			}
			if !swapped {
				continue
			}
			return nil, ErrInvalidCode
		}
		matched = true
	}
	if !matched {
		return nil, ErrInvalidCode
	}
	// Step 5: OTP used to turn 2FA on for a signed-in user
	if !p.user.TwoFactorEnabled {
		if p.session == nil {
			return nil, ErrFailedToCreateSession
		}
		updated, sw, ck, err := s.replaceSession(ctx, p.session, true)
		if err != nil {
			return nil, err
		}
		return &Result{
			Body:    tfdtos.TokenUserResponse{Token: strPtr(sw.Session.Token), User: dtos.UserFromModel(updated)},
			Cookies: ck,
		}, nil
	}
	// Step 6: success
	return s.valid(ctx, p, in.TrustDevice != nil && *in.TrustDevice)
}

// ─── Backup codes ────────────────────────────────────────────────────────────

// VerifyBackupCode is POST /two-factor/verify-backup-code: each code works once.
func (s *Service) VerifyBackupCode(ctx context.Context, in tfdtos.VerifyBackupCodeInput) (*Result, error) {
	// Step 1: who is verifying
	p, err := s.resolve(ctx)
	if err != nil {
		return nil, err
	}
	// Step 2: the user's codes
	row, err := s.repo.FindByUserID(ctx, p.user.ID)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, ErrBackupCodesNotEnabled
	}
	codes := DecodeBackupCodes(row.BackupCodes, s.secret(), s.cfg.BackupCodeOptions)
	if codes == nil {
		return nil, ErrInvalidBackupCode
	}
	// Step 3: the code must be one of them; it is removed from the list
	found := false
	remaining := make([]string, 0, len(codes))
	for _, c := range codes {
		if !found && authcrypto.SecureEqual(c, in.Code) {
			found = true
			continue
		}
		remaining = append(remaining, c)
	}
	if !found {
		return nil, ErrInvalidBackupCode
	}
	// Step 4: compare-and-swap so a concurrent request cannot reuse the same code
	updated, err := EncodeBackupCodes(remaining, s.secret(), s.cfg.BackupCodeOptions)
	if err != nil {
		return nil, err
	}
	ok, err := s.repo.SwapBackupCodes(ctx, row.ID, row.BackupCodes, updated)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrBackupCodeConflict
	}
	// Step 5: disableSession → answer without creating a session
	if in.DisableSession != nil && *in.DisableSession {
		body := tfdtos.TokenUserResponse{User: p.user}
		if p.session != nil {
			body.Token = strPtr(p.session.Session.Token)
		}
		return &Result{Body: body}, nil
	}
	return s.valid(ctx, p, in.TrustDevice != nil && *in.TrustDevice)
}

// GenerateBackupCodes is POST /two-factor/generate-backup-codes: replaces all backup codes.
func (s *Service) GenerateBackupCodes(ctx context.Context, current *dtos.SessionWithUser, password *string) (*Result, error) {
	// Step 1: 2FA must be on
	if !current.User.TwoFactorEnabled {
		return nil, ErrTwoFactorNotEnabled
	}
	// Step 2: password check
	if err := s.checkPassword(ctx, current.User.ID, password, s.cfg.BackupCodesAllowPasswordless()); err != nil {
		return nil, err
	}
	row, err := s.repo.FindByUserID(ctx, current.User.ID)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, ErrTwoFactorNotEnabled
	}
	// Step 3: new codes replace the old ones
	codes := GenerateBackupCodeList(s.cfg.BackupCodeOptions)
	stored, err := EncodeBackupCodes(codes, s.secret(), s.cfg.BackupCodeOptions)
	if err != nil {
		return nil, err
	}
	if err := s.repo.UpdateBackupCodes(ctx, row.ID, stored); err != nil {
		return nil, err
	}
	return &Result{Body: tfdtos.BackupCodesResponse{Status: true, BackupCodes: codes}}, nil
}

// ViewBackupCodes is better-auth's server-only viewBackupCodes endpoint: the user's remaining codes.
func (s *Service) ViewBackupCodes(ctx context.Context, userID string) ([]string, error) {
	// Step 1: the user's row
	row, err := s.repo.FindByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, ErrBackupCodesNotEnabled
	}
	// Step 2: decode the stored list
	codes := DecodeBackupCodes(row.BackupCodes, s.secret(), s.cfg.BackupCodeOptions)
	if codes == nil {
		return nil, ErrInvalidBackupCodeView
	}
	return codes, nil
}
