package compattest

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	bearer "github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	emailotp "github.com/better-go-auth/goauth/src/plugins/email-otp"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
	"github.com/stretchr/testify/require"
)

// TestGoMirror_EmailOTP mirrors src/tests/compat/client/test-email-otp.mjs in pure Go.
func TestGoMirror_EmailOTP(t *testing.T) {
	var mu sync.Mutex
	lastOTPs := make(map[string]string)
	var otpSeq int64

	otpPlugin := emailotp.New(emailotpconfig.EmailOTPConfig{
		SendVerificationOTP: func(data emailotpconfig.SendVerificationOTPData, req *http.Request) error {
			mu.Lock()
			lastOTPs[strings.ToLower(data.Email)] = data.OTP
			mu.Unlock()
			return nil
		},
		GenerateOTP: func(data emailotpconfig.GenerateOTPData, req *http.Request) (string, error) {
			n := atomic.AddInt64(&otpSeq, 1)
			return fmt.Sprintf("GO-%04d", n), nil
		},
		AllowedAttempts: 3,
		StoreOTP:        emailotpconfig.StoreOTPConfig{Mode: emailotpconfig.StoreOTPEncrypted},
		ResendStrategy:  emailotpconfig.ResendStrategyReuse,
		ChangeEmail:     emailotpconfig.EmailOTPChangeEmailConfig{Enabled: true},
	})
	s := NewServer(t,
		WithPlugin(bearer.New(bearerconfig.DefaultConfig())),
		WithPlugin(otpPlugin),
		WithConfig(func(c *config.AuthConfig) {
			compatMode(c)
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	getOTP := func(email string) string {
		mu.Lock()
		defer mu.Unlock()
		return lastOTPs[strings.ToLower(email)]
	}

	ts := time.Now().UnixNano()
	signInEmail := fmt.Sprintf("go-otp-signin-%d@example.com", ts)
	c := newBearerTestClient(s.URL)

	// [1] sendVerificationOtp (sign-in) + GenerateOTP + ResendStrategy=reuse
	res := c.post(t, "/api/auth/email-otp/send-verification-otp", map[string]any{"email": signInEmail, "type": "sign-in"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	otp1 := getOTP(signInEmail)
	require.True(t, strings.HasPrefix(otp1, "GO-"))

	res = c.post(t, "/api/auth/email-otp/send-verification-otp", map[string]any{"email": signInEmail, "type": "sign-in"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	otp2 := getOTP(signInEmail)
	require.Equal(t, otp1, otp2, "ResendStrategy=reuse must reuse same OTP")

	// [2] AllowedAttempts=3 -> 4th attempt fails with 403 TOO_MANY_ATTEMPTS
	for i := 0; i < 3; i++ {
		bad := c.post(t, "/api/auth/sign-in/email-otp", map[string]any{"email": signInEmail, "otp": "GO-0000"})
		require.Equal(t, http.StatusBadRequest, bad.Status, string(bad.Body))
		require.Contains(t, string(bad.Body), "INVALID_OTP")
	}
	locked := c.post(t, "/api/auth/sign-in/email-otp", map[string]any{"email": signInEmail, "otp": otp2})
	require.Equal(t, http.StatusForbidden, locked.Status, string(locked.Body))
	require.Contains(t, string(locked.Body), "TOO_MANY_ATTEMPTS")

	// [3] Fresh OTP & signIn.emailOtp with name
	res = c.post(t, "/api/auth/email-otp/send-verification-otp", map[string]any{"email": signInEmail, "type": "sign-in"})
	require.Equal(t, http.StatusOK, res.Status)
	otp3 := getOTP(signInEmail)
	res = c.post(t, "/api/auth/sign-in/email-otp", map[string]any{"email": signInEmail, "otp": otp3, "name": "OTP Registered"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var siResp struct {
		Token string `json:"token"`
		User  struct {
			Email         string `json:"email"`
			Name          string `json:"name"`
			EmailVerified bool   `json:"emailVerified"`
		} `json:"user"`
	}
	res.JSON(t, &siResp)
	require.NotEmpty(t, siResp.Token)
	require.Equal(t, signInEmail, siResp.User.Email)
	require.Equal(t, "OTP Registered", siResp.User.Name)
	require.True(t, siResp.User.EmailVerified)

	// [4] SignUp password user -> sendVerificationOtp -> checkVerificationOtp -> verifyEmail
	user2Email := fmt.Sprintf("go-otp-verify-%d@example.com", ts)
	c2 := newBearerTestClient(s.URL)
	res = c2.post(t, "/api/auth/sign-up/email", map[string]any{"email": user2Email, "password": "Password123!", "name": "Verify User"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	res = c2.post(t, "/api/auth/email-otp/send-verification-otp", map[string]any{"email": user2Email, "type": "email-verification"})
	require.Equal(t, http.StatusOK, res.Status)
	verifyOTP := getOTP(user2Email)

	res = c2.post(t, "/api/auth/email-otp/check-verification-otp", map[string]any{"email": user2Email, "otp": verifyOTP, "type": "email-verification"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	res = c2.post(t, "/api/auth/email-otp/verify-email", map[string]any{"email": user2Email, "otp": verifyOTP})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	require.Contains(t, string(res.Body), `"emailVerified":true`)

	// [5] requestPasswordReset + resetPassword + signIn.email
	res = c2.post(t, "/api/auth/email-otp/request-password-reset", map[string]any{"email": user2Email})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	resetOTP := getOTP(user2Email)
	res = c2.post(t, "/api/auth/email-otp/reset-password", map[string]any{"email": user2Email, "otp": resetOTP, "password": "NewPassword456!"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	res = c2.post(t, "/api/auth/sign-in/email", map[string]any{"email": user2Email, "password": "NewPassword456!"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))

	// [6] requestEmailChange + changeEmail + getSession
	newEmail := fmt.Sprintf("go-otp-changed-%d@example.com", ts)
	res = c2.post(t, "/api/auth/email-otp/request-email-change", map[string]any{"newEmail": newEmail})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	changeOTP := getOTP(newEmail)
	res = c2.post(t, "/api/auth/email-otp/change-email", map[string]any{"newEmail": newEmail, "otp": changeOTP})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	res = c2.get(t, "/api/auth/get-session")
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	require.Contains(t, string(res.Body), newEmail)

	// [7] RateLimit (Max=2)
	rls := NewServer(t,
		WithPlugin(emailotp.New(emailotpconfig.EmailOTPConfig{
			SendVerificationOTP: func(data emailotpconfig.SendVerificationOTPData, req *http.Request) error { return nil },
		}, emailotp.WithRateLimit(60*time.Second, 2))),
		WithConfig(func(c *config.AuthConfig) {
			compatMode(c)
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)
	rlClient := newBearerTestClient(rls.URL)
	rlEmail := fmt.Sprintf("go-rl-%d@example.com", ts)
	require.Equal(t, http.StatusOK, rlClient.post(t, "/api/auth/email-otp/send-verification-otp", map[string]any{"email": rlEmail, "type": "sign-in"}).Status)
	require.Equal(t, http.StatusOK, rlClient.post(t, "/api/auth/email-otp/send-verification-otp", map[string]any{"email": rlEmail, "type": "sign-in"}).Status)
	r3 := rlClient.post(t, "/api/auth/email-otp/send-verification-otp", map[string]any{"email": rlEmail, "type": "sign-in"})
	require.Equal(t, http.StatusTooManyRequests, r3.Status, string(r3.Body))
}

