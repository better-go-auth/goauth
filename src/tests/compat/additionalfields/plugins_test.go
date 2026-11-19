package additionalfields

import (
	"net/http"
	"sync"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/admin"
	emailotp "github.com/better-go-auth/goauth/src/plugins/email-otp"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
	phonenumber "github.com/better-go-auth/goauth/src/plugins/phone-number"
	phoneconfig "github.com/better-go-auth/goauth/src/plugins/phone-number/config"
	"github.com/better-go-auth/goauth/src/plugins/username"
	usernameconfig "github.com/better-go-auth/goauth/src/plugins/username/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
	"github.com/stretchr/testify/require"
)

// codes collects OTP codes sent by plugins.
type codes struct {
	mu   sync.Mutex
	last map[string]string
}

func (c *codes) set(k, v string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.last == nil {
		c.last = map[string]string{}
	}
	c.last[k] = v
}

func (c *codes) get(k string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last[k]
}

// TestPhoneNumberUpdateUser (missing-tasks 3.9): update-user rejects a phone number with
// PHONE_NUMBER_CANNOT_BE_UPDATED whenever it is sent and not null; null clears it and the phone-number
// plugin's database hook clears phoneNumberVerified too. A sign-up on verification parses the extra body
// fields like better-auth.
func TestPhoneNumberUpdateUser(t *testing.T) {
	sent := &codes{}
	s := compattest.NewServer(t, compattest.WithDB(openDB(t)), compattest.WithConfig(func(c *config.AuthConfig) {
		c.User.AdditionalFields = userFields()
	}), withPlugins(phonenumber.New(phoneconfig.PhoneNumberConfig{
		SendOTP: func(d phoneconfig.OTPData, _ *http.Request) error { sent.set(d.PhoneNumber, d.Code); return nil },
		SignUpOnVerification: &phoneconfig.SignUpOnVerification{
			GetTempEmail: func(p string) string { return "tmp" + p[1:] + "@phone.example" },
		},
	})))

	// Step 1: sign up on verification with additional fields (better-auth's parseUserInput(rest, "create"))
	require.Equal(t, http.StatusOK, s.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": "+15550001"}).Status)
	res := s.Post(t, "/api/auth/phone-number/verify", map[string]any{"phoneNumber": "+15550001", "code": sent.get("+15550001"), "plan": "phone-plan", "age": 33})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	user := object(t, jsonBody(t, res), "user")
	require.Equal(t, "phone-plan", user["plan"])
	require.EqualValues(t, 33, user["age"])
	require.Equal(t, "+15550001", user["phoneNumber"])
	require.Equal(t, true, user["phoneNumberVerified"])
	// invalid additional fields fail the sign-up
	require.Equal(t, http.StatusOK, s.Post(t, "/api/auth/phone-number/send-otp", map[string]any{"phoneNumber": "+15550002"}).Status)
	requireError(t, s.Post(t, "/api/auth/phone-number/verify", map[string]any{"phoneNumber": "+15550002", "code": sent.get("+15550002"), "age": 2}),
		400, "VALIDATION_ERROR", "age must be at least 18")

	// Step 2: update-user can't set the number (any value but null), with the plugin's own error
	for _, v := range []any{"+15559999", "", false} {
		requireError(t, s.Post(t, "/api/auth/update-user", map[string]any{"phoneNumber": v}), 400, "PHONE_NUMBER_CANNOT_BE_UPDATED", "Phone number cannot be updated")
	}
	// Step 3: null clears it, and phoneNumberVerified with it
	res = s.Post(t, "/api/auth/update-user", map[string]any{"phoneNumber": nil})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	user = object(t, getSession(t, s), "user")
	require.Nil(t, user["phoneNumber"])
	require.Contains(t, []any{false, nil}, user["phoneNumberVerified"])
	stored, err := s.Auth.Repositories().FindUserByEmail(t.Context(), "tmp15550001@phone.example")
	require.NoError(t, err)
	require.False(t, stored.PhoneNumberVerified)
}

// TestUsernameValidatedOnAdminUpdateUser (missing-tasks 3.4): the username plugin's update database hook
// validates and normalizes usernames written by /admin/update-user.
func TestUsernameValidatedOnAdminUpdateUser(t *testing.T) {
	db := openDB(t)
	adminPlugin, err := admin.NewWithGorm(db)
	require.NoError(t, err)
	s := compattest.NewServer(t, compattest.WithDB(db), withPlugins(adminPlugin, username.New(usernameconfig.UsernameConfig{})))
	// Step 1: a user with a username and a target user
	res := s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "owner@example.com", "password": password, "name": "Owner", "username": "taken_name"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	res = s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "target@example.com", "password": password, "name": "Target", "username": "target_name"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	targetID := object(t, jsonBody(t, res), "user")["id"]
	signInAdmin(t, s, "boss@example.com")

	// Step 2: invalid and taken usernames are rejected with the username plugin's errors
	requireError(t, s.Post(t, "/api/auth/admin/update-user", map[string]any{"userId": targetID, "data": map[string]any{"username": "no spaces allowed"}}),
		400, "INVALID_USERNAME", "")
	requireError(t, s.Post(t, "/api/auth/admin/update-user", map[string]any{"userId": targetID, "data": map[string]any{"username": "taken_name"}}),
		400, "USERNAME_IS_ALREADY_TAKEN", "")
	// Step 3: the user keeps their own username; a new one is normalized
	res = s.Post(t, "/api/auth/admin/update-user", map[string]any{"userId": targetID, "data": map[string]any{"username": "target_name"}})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	res = s.Post(t, "/api/auth/admin/update-user", map[string]any{"userId": targetID, "data": map[string]any{"username": "New_Name"}})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	require.Equal(t, "new_name", object(t, jsonBody(t, res), "user")["username"])
}

// TestEmailOTPSignUpParsesAdditionalFields: POST /sign-in/email-otp creating a user parses the rest of the
// body (better-auth's parseUserInput(rest, "create")).
func TestEmailOTPSignUpParsesAdditionalFields(t *testing.T) {
	sent := &codes{}
	s := compattest.NewServer(t, compattest.WithDB(openDB(t)), compattest.WithConfig(func(c *config.AuthConfig) {
		c.User.AdditionalFields = userFields()
	}), withPlugins(emailotp.New(emailotpconfig.EmailOTPConfig{
		SendVerificationOTP: func(d emailotpconfig.SendVerificationOTPData, _ *http.Request) error {
			sent.set(d.Email, d.OTP)
			return nil
		},
	})))
	send := func(email string) {
		res := s.Post(t, "/api/auth/email-otp/send-verification-otp", map[string]any{"email": email, "type": "sign-in"})
		require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	}
	// Step 1: invalid additional field → validation error, no user
	send("otp-bad@example.com")
	requireError(t, s.Post(t, "/api/auth/sign-in/email-otp", map[string]any{"email": "otp-bad@example.com", "otp": sent.get("otp-bad@example.com"), "verifiedPro": true}),
		400, "FIELD_NOT_ALLOWED", "verifiedPro is not allowed to be set")
	// Step 2: valid fields are stored on the new user
	send("otp@example.com")
	res := s.Post(t, "/api/auth/sign-in/email-otp", map[string]any{"email": "otp@example.com", "otp": sent.get("otp@example.com"), "name": "OTP", "plan": "otp-plan", "handle": "LOUD"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	user := object(t, jsonBody(t, res), "user")
	require.Equal(t, "otp-plan", user["plan"])
	require.Equal(t, "loud", user["handle"])
	require.EqualValues(t, 10, user["credits"])
	require.Equal(t, "otp-plan", object(t, getSession(t, s), "user")["plan"])
}
