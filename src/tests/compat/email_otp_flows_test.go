package compattest

import (
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	emailotp "github.com/better-go-auth/goauth/src/plugins/email-otp"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
	"github.com/stretchr/testify/require"
)

// TestEmailOTP_BothRegistrationFlows verifies both Better Auth email-otp registration flows via HTTP handlers:
// 1. Passwordless registration via send-verification-otp ("sign-in") + /sign-in/email-otp
// 2. Standard /sign-up/email + OverrideDefaultEmailVerification -> auto-sent OTP -> /email-otp/verify-email
func TestEmailOTP_BothRegistrationFlows(t *testing.T) {
	t.Run("Flow1_Passwordless_AutoSignUp_And_DisableSignUp", func(t *testing.T) {
		var mu sync.Mutex
		otps := make(map[string]string)

		otpPlugin := emailotp.New(emailotpconfig.EmailOTPConfig{
			SendVerificationOTP: func(data emailotpconfig.SendVerificationOTPData, req *http.Request) error {
				mu.Lock()
				otps[strings.ToLower(data.Email)] = data.OTP
				mu.Unlock()
				return nil
			},
		})
		s := NewServer(t, WithPlugin(otpPlugin), WithConfig(compatMode))

		// Step 1: Send sign-in OTP for a brand-new email that does not exist yet
		email := "flow1-new@example.com"
		res := s.Post(t, "/api/auth/email-otp/send-verification-otp", map[string]any{
			"email": email,
			"type":  "sign-in",
		})
		require.Equal(t, http.StatusOK, res.Status, string(res.Body))

		mu.Lock()
		code := otps[email]
		mu.Unlock()
		require.NotEmpty(t, code)

		// Step 2: Sign in with OTP + profile fields -> creates user automatically with emailVerified=true
		res = s.Post(t, "/api/auth/sign-in/email-otp", map[string]any{
			"email": email,
			"otp":   code,
			"name":  "Flow One User",
			"image": "https://example.com/avatar.png",
		})
		require.Equal(t, http.StatusOK, res.Status, string(res.Body))
		var signInResp struct {
			Token string `json:"token"`
			User  struct {
				ID            string  `json:"id"`
				Email         string  `json:"email"`
				Name          string  `json:"name"`
				Image         *string `json:"image"`
				EmailVerified bool    `json:"emailVerified"`
			} `json:"user"`
		}
		res.JSON(t, &signInResp)
		require.NotEmpty(t, signInResp.Token)
		require.Equal(t, email, signInResp.User.Email)
		require.Equal(t, "Flow One User", signInResp.User.Name)
		require.NotNil(t, signInResp.User.Image)
		require.Equal(t, "https://example.com/avatar.png", *signInResp.User.Image)
		require.True(t, signInResp.User.EmailVerified)

		// Step 3: Cookie jar from sign-in works with /get-session
		sessRes := s.Get(t, "/api/auth/get-session")
		require.Equal(t, http.StatusOK, sessRes.Status, string(sessRes.Body))
		require.Contains(t, string(sessRes.Body), email)

		// Step 4: When DisableSignUp=true, SendVerificationOTP skips unregistered users and /sign-in/email-otp returns 400 INVALID_OTP
		var mu2 sync.Mutex
		otps2 := make(map[string]string)
		sDisabled := NewServer(t,
			WithPlugin(emailotp.New(emailotpconfig.EmailOTPConfig{
				DisableSignUp: true,
				SendVerificationOTP: func(data emailotpconfig.SendVerificationOTPData, req *http.Request) error {
					mu2.Lock()
					otps2[strings.ToLower(data.Email)] = data.OTP
					mu2.Unlock()
					return nil
				},
			})),
			WithConfig(compatMode),
		)
		res = sDisabled.Post(t, "/api/auth/email-otp/send-verification-otp", map[string]any{
			"email": "blocked-signup@example.com",
			"type":  "sign-in",
		})
		require.Equal(t, http.StatusOK, res.Status)
		mu2.Lock()
		_, wasSent := otps2["blocked-signup@example.com"]
		mu2.Unlock()
		require.False(t, wasSent, "DisableSignUp=true must not send OTP to unregistered email")

		res = sDisabled.Post(t, "/api/auth/sign-in/email-otp", map[string]any{
			"email": "blocked-signup@example.com",
			"otp":   "123456",
		})
		require.Equal(t, http.StatusBadRequest, res.Status, string(res.Body))
		require.Contains(t, string(res.Body), "INVALID_OTP")
	})

	t.Run("Flow2_SignUpEmail_With_OverrideDefaultEmailVerification", func(t *testing.T) {
		var mu sync.Mutex
		linkCalls := 0
		var otpCalls []emailotpconfig.SendVerificationOTPData

		otpPlugin := emailotp.New(emailotpconfig.EmailOTPConfig{
			OverrideDefaultEmailVerification: true,
			SendVerificationOTP: func(data emailotpconfig.SendVerificationOTPData, req *http.Request) error {
				mu.Lock()
				otpCalls = append(otpCalls, data)
				mu.Unlock()
				return nil
			},
		})

		s := NewServer(t,
			WithPlugin(otpPlugin),
			WithConfig(func(c *config.AuthConfig) {
				compatMode(c)
				c.EmailAndPassword.RequireEmailVerification = true
				c.EmailVerification.AutoSignInAfterVerification = true
				c.EmailVerification.SendOnSignIn = true
				c.EmailVerification.SendVerificationEmail = func(data config.EmailVerificationData, r *http.Request) error {
					mu.Lock()
					linkCalls++
					mu.Unlock()
					return nil
				}
			}),
		)

		// Step 1: Standard email+password registration triggers AfterUserCreate -> OTP, and suppresses core link email
		email := "flow2-verify@example.com"
		res := s.Post(t, "/api/auth/sign-up/email", map[string]any{
			"email":    email,
			"password": "Password123!",
			"name":     "Flow Two User",
		})
		require.Equal(t, http.StatusOK, res.Status, string(res.Body))
		var upResp struct {
			Token *string `json:"token"`
			User  struct {
				ID            string `json:"id"`
				Email         string `json:"email"`
				EmailVerified bool   `json:"emailVerified"`
			} `json:"user"`
		}
		res.JSON(t, &upResp)
		require.Nil(t, upResp.Token, "RequireEmailVerification=true should not issue session token before verification")
		require.False(t, upResp.User.EmailVerified)

		mu.Lock()
		linksAfterSignUp := linkCalls
		otpsAfterSignUp := append([]emailotpconfig.SendVerificationOTPData(nil), otpCalls...)
		mu.Unlock()

		require.Equal(t, 0, linksAfterSignUp, "OverrideDefaultEmailVerification must suppress core verification link email on /sign-up/email")
		require.Len(t, otpsAfterSignUp, 1)
		require.Equal(t, emailotpconfig.OTPTypeEmailVerification, otpsAfterSignUp[0].Type)
		require.Equal(t, email, otpsAfterSignUp[0].Email)

		// Step 2: Signing in with password before verifying email is rejected (403 EMAIL_NOT_VERIFIED)
		signInBlocked := s.Post(t, "/api/auth/sign-in/email", map[string]any{
			"email":    email,
			"password": "Password123!",
		})
		require.Equal(t, http.StatusForbidden, signInBlocked.Status, string(signInBlocked.Body))
		require.Contains(t, string(signInBlocked.Body), "EMAIL_NOT_VERIFIED")

		// Blocked SignIn with SendOnSignIn=true must route through OTP override (0 links, 2nd OTP)
		mu.Lock()
		linksAfterSignIn := linkCalls
		otpsAfterSignIn := len(otpCalls)
		mu.Unlock()
		require.Equal(t, 0, linksAfterSignIn, "SendOnSignIn must not call core link sender when overridden")
		require.Equal(t, 2, otpsAfterSignIn, "SendOnSignIn must dispatch OTP when overridden")

		// POST /send-verification-email must route through OTP override (0 links, 3rd OTP)
		sendVerRes := s.Post(t, "/api/auth/send-verification-email", map[string]any{
			"email": email,
		})
		require.Equal(t, http.StatusOK, sendVerRes.Status, string(sendVerRes.Body))
		mu.Lock()
		linksAfterSendVerEndpoint := linkCalls
		latestOTP := otpCalls[len(otpCalls)-1]
		totalOTPs := len(otpCalls)
		mu.Unlock()
		require.Equal(t, 0, linksAfterSendVerEndpoint, "/send-verification-email must not call core link sender when overridden")
		require.Equal(t, 3, totalOTPs, "/send-verification-email must dispatch OTP when overridden")

		// Step 3: Verify email using the latest OTP -> sets emailVerified=true and auto-signs in
		verRes := s.Post(t, "/api/auth/email-otp/verify-email", map[string]any{
			"email": email,
			"otp":   latestOTP.OTP,
		})
		require.Equal(t, http.StatusOK, verRes.Status, string(verRes.Body))
		var verResp struct {
			Status bool    `json:"status"`
			Token  *string `json:"token"`
			User   struct {
				Email         string `json:"email"`
				EmailVerified bool   `json:"emailVerified"`
			} `json:"user"`
		}
		verRes.JSON(t, &verResp)
		require.True(t, verResp.Status)
		require.True(t, verResp.User.EmailVerified)
		require.NotNil(t, verResp.Token, "AutoSignInAfterVerification=true should issue session token")
		require.NotEmpty(t, *verResp.Token)

		// Step 4: Authenticated session from VerifyEmail works on /get-session
		sessRes := s.Get(t, "/api/auth/get-session")
		require.Equal(t, http.StatusOK, sessRes.Status, string(sessRes.Body))
		require.Contains(t, string(sessRes.Body), email)

		// Step 5: Verify /send-verification-email works even when core EmailVerification.SendVerificationEmail is nil
		var otpOnlyMu sync.Mutex
		var otpOnlyCalls []emailotpconfig.SendVerificationOTPData
		sOTPOnly := NewServer(t,
			WithPlugin(emailotp.New(emailotpconfig.EmailOTPConfig{
				OverrideDefaultEmailVerification: true,
				SendVerificationOTP: func(data emailotpconfig.SendVerificationOTPData, req *http.Request) error {
					otpOnlyMu.Lock()
					otpOnlyCalls = append(otpOnlyCalls, data)
					otpOnlyMu.Unlock()
					return nil
				},
			})),
			WithConfig(func(c *config.AuthConfig) {
				compatMode(c)
				c.EmailAndPassword.RequireEmailVerification = true
			}),
		)
		res = sOTPOnly.Post(t, "/api/auth/sign-up/email", map[string]any{
			"email":    "otponly@example.com",
			"password": "Password123!",
			"name":     "OTP Only User",
		})
		require.Equal(t, http.StatusOK, res.Status, string(res.Body))
		res = sOTPOnly.Post(t, "/api/auth/send-verification-email", map[string]any{
			"email": "otponly@example.com",
		})
		require.Equal(t, http.StatusOK, res.Status, string(res.Body))
		otpOnlyMu.Lock()
		require.Len(t, otpOnlyCalls, 2)
		otpOnlyMu.Unlock()
	})
}
