package compattest

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/admin"
)

type mailbox struct {
	verify []config.EmailVerificationData
	reset  []config.ResetPasswordData
	del    []config.DeleteAccountVerificationData
}

func flowServer(t *testing.T, mb *mailbox, more ...func(*config.AuthConfig)) *Server {
	t.Helper()
	return NewServer(t, WithConfig(func(c *config.AuthConfig) {
		compatMode(c)
		c.EmailVerification.SendVerificationEmail = func(d config.EmailVerificationData, _ *http.Request) error {
			mb.verify = append(mb.verify, d)
			return nil
		}
		c.EmailAndPassword.SendResetPassword = func(d config.ResetPasswordData, _ *http.Request) error {
			mb.reset = append(mb.reset, d)
			return nil
		}
		c.User.DeleteUser.Enabled = true
		c.User.ChangeEmail.Enabled = true
		for _, fn := range more {
			fn(c)
		}
	}))
}

func signUpBody(email string) map[string]any {
	return map[string]any{"email": email, "password": "password123", "name": "Ada Lovelace"}
}

func expectStatus(t *testing.T, r *Response, status int) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("want %d, got %d: %s", status, r.Status, r.Body)
	}
}

func expectCode(t *testing.T, r *Response, status int, code string) {
	t.Helper()
	var body struct{ Code string }
	r.JSON(t, &body)
	if r.Status != status || body.Code != code {
		t.Fatalf("want %d %s, got %d %s", status, code, r.Status, r.Body)
	}
}

func TestEmailPasswordFlow(t *testing.T) {
	mb := &mailbox{}
	s := flowServer(t, mb)

	r := s.Post(t, "/api/auth/sign-up/email", signUpBody("ada@example.com"))
	expectStatus(t, r, http.StatusOK)
	AssertJSONShape(t, r.Body, "sign_up")
	if r.Cookie("better-auth.session_token") == nil {
		t.Fatal("sign-up must set the session cookie")
	}
	expectCode(t, s.Post(t, "/api/auth/sign-up/email", signUpBody("ada@example.com")), http.StatusUnprocessableEntity, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL")

	r = s.Get(t, "/api/auth/get-session")
	AssertJSONShape(t, r.Body, "get_session")

	r = s.Post(t, "/api/auth/update-user", map[string]any{"name": "Ada King"})
	expectStatus(t, r, http.StatusOK)
	AssertJSONShape(t, r.Body, "status")
	var sess struct{ User struct{ Name string } }
	s.Get(t, "/api/auth/get-session").JSON(t, &sess)
	if sess.User.Name != "Ada King" {
		t.Fatalf("update-user not applied: %+v", sess)
	}
	expectCode(t, s.Post(t, "/api/auth/update-user", map[string]any{"email": "x@example.com"}), http.StatusBadRequest, "EMAIL_CAN_NOT_BE_UPDATED")
	expectCode(t, s.Post(t, "/api/auth/update-user", map[string]any{"role": "admin"}), http.StatusBadRequest, "FIELD_NOT_ALLOWED")
	expectCode(t, s.Post(t, "/api/auth/update-session", map[string]any{"foo": "bar"}), http.StatusBadRequest, "NO_FIELDS_TO_UPDATE")
	expectCode(t, s.Post(t, "/api/auth/update-session", map[string]any{"activeOrganizationId": "org"}), http.StatusBadRequest, "FIELD_NOT_ALLOWED")
	r = s.Post(t, "/api/auth/update-session", map[string]any{"deviceName": "Pixel 9", "deviceToken": "fcm:abc"})
	expectStatus(t, r, http.StatusOK)
	AssertJSONShape(t, r.Body, "update_session")
	var dev struct{ Session struct{ DeviceName string } }
	s.Get(t, "/api/auth/get-session").JSON(t, &dev)
	if dev.Session.DeviceName != "Pixel 9" {
		t.Fatalf("update-session not applied: %+v", dev)
	}

	r = s.Post(t, "/api/auth/sign-out", nil)
	expectStatus(t, r, http.StatusOK)
	AssertJSONShape(t, r.Body, "sign_out")
	if strings.TrimSpace(string(s.Get(t, "/api/auth/get-session").Body)) != "null" {
		t.Fatal("signed out")
	}
	expectCode(t, s.Get(t, "/api/auth/list-sessions"), http.StatusUnauthorized, "UNAUTHORIZED")

	expectCode(t, s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "ada@example.com", "password": "nope-nope"}), http.StatusUnauthorized, "INVALID_EMAIL_OR_PASSWORD")
	r = s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "ada@example.com", "password": "password123", "callbackURL": "/dashboard"})
	expectStatus(t, r, http.StatusOK)
	AssertJSONShape(t, r.Body, "sign_in")
	if r.Header.Get("Location") != "/dashboard" {
		t.Fatalf("sign-in with callbackURL sets Location, got %q", r.Header.Get("Location"))
	}

	r = s.Get(t, "/api/auth/list-sessions")
	expectStatus(t, r, http.StatusOK)
	AssertJSONShape(t, r.Body, "list_sessions")

	r = s.Get(t, "/api/auth/list-accounts")
	expectStatus(t, r, http.StatusOK)
	AssertJSONShape(t, r.Body, "list_accounts")
	expectCode(t, s.Post(t, "/api/auth/unlink-account", map[string]any{"providerId": "credential"}), http.StatusBadRequest, "FAILED_TO_UNLINK_LAST_ACCOUNT")

	expectStatus(t, s.Post(t, "/api/auth/verify-password", map[string]any{"password": "password123"}), http.StatusOK)
	expectCode(t, s.Post(t, "/api/auth/verify-password", map[string]any{"password": "wrong-password"}), http.StatusBadRequest, "INVALID_PASSWORD")

	r = s.Post(t, "/api/auth/change-password", map[string]any{"currentPassword": "password123", "newPassword": "password456", "revokeOtherSessions": true})
	expectStatus(t, r, http.StatusOK)
	AssertJSONShape(t, r.Body, "change_password")
	if r.Cookie("better-auth.session_token") == nil {
		t.Fatal("change-password with revokeOtherSessions sets the new session cookie")
	}
	expectStatus(t, s.Get(t, "/api/auth/list-sessions"), http.StatusOK)
}

func TestPasswordResetFlow(t *testing.T) {
	mb := &mailbox{}
	s := flowServer(t, mb, func(c *config.AuthConfig) { c.EmailAndPassword.RevokeSessionsOnPasswordReset = true })
	expectStatus(t, s.Post(t, "/api/auth/sign-up/email", signUpBody("reset@example.com")), http.StatusOK)

	expectCode(t, s.Post(t, "/api/auth/request-password-reset", map[string]any{"email": "reset@example.com", "redirectTo": "https://evil.com"}), http.StatusForbidden, "INVALID_REDIRECT_URL")
	r := s.Post(t, "/api/auth/request-password-reset", map[string]any{"email": "reset@example.com", "redirectTo": "/reset"})
	expectStatus(t, r, http.StatusOK)
	AssertJSONShape(t, r.Body, "request_password_reset")
	r = s.Post(t, "/api/auth/request-password-reset", map[string]any{"email": "nobody@example.com"})
	expectStatus(t, r, http.StatusOK)
	if len(mb.reset) != 1 {
		t.Fatalf("one reset email expected, got %d", len(mb.reset))
	}

	link, _ := url.Parse(mb.reset[0].URL)
	r = s.Get(t, link.Path+"?"+link.RawQuery)
	if r.Status != http.StatusFound || r.Header.Get("Location") != "http://localhost:3000/reset?token="+mb.reset[0].Token {
		t.Fatalf("valid link redirects with the token: %d %s", r.Status, r.Header.Get("Location"))
	}
	r = s.Get(t, "/api/auth/reset-password/bogus?callbackURL=/reset")
	if r.Header.Get("Location") != "http://localhost:3000/reset?error=INVALID_TOKEN" {
		t.Fatalf("invalid link redirects with an error: %s", r.Header.Get("Location"))
	}

	expectStatus(t, s.Post(t, "/api/auth/reset-password", map[string]any{"token": mb.reset[0].Token, "newPassword": "brand-new-pass"}), http.StatusOK)
	expectCode(t, s.Post(t, "/api/auth/reset-password", map[string]any{"token": mb.reset[0].Token, "newPassword": "brand-new-pass"}), http.StatusBadRequest, "INVALID_TOKEN")
	if strings.TrimSpace(string(s.Get(t, "/api/auth/get-session").Body)) != "null" {
		t.Fatal("RevokeSessionsOnPasswordReset signs the user out")
	}
	expectStatus(t, s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "reset@example.com", "password": "brand-new-pass"}), http.StatusOK)
}

func TestEmailVerificationFlow(t *testing.T) {
	mb := &mailbox{}
	s := flowServer(t, mb, func(c *config.AuthConfig) {
		c.EmailAndPassword.RequireEmailVerification = true
		c.EmailVerification.AutoSignInAfterVerification = true
	})
	r := s.Post(t, "/api/auth/sign-up/email", signUpBody("verify@example.com"))
	expectStatus(t, r, http.StatusOK)
	AssertJSONShape(t, r.Body, "sign_up_unverified")
	expectCode(t, s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "verify@example.com", "password": "password123"}), http.StatusForbidden, "EMAIL_NOT_VERIFIED")

	link, _ := url.Parse(mb.verify[0].URL)
	r = s.Get(t, "/api/auth/verify-email?token=garbage&callbackURL=/welcome")
	if r.Status != http.StatusFound || r.Header.Get("Location") != "/welcome?error=INVALID_TOKEN" {
		t.Fatalf("bad token redirects with an error: %d %s", r.Status, r.Header.Get("Location"))
	}
	r = s.Get(t, link.Path+"?token="+link.Query().Get("token"))
	expectStatus(t, r, http.StatusOK)
	AssertJSONShape(t, r.Body, "verify_email")
	if r.Cookie("better-auth.session_token") == nil {
		t.Fatal("AutoSignInAfterVerification sets the session cookie")
	}
	var sess struct{ User struct{ EmailVerified bool } }
	s.Get(t, "/api/auth/get-session").JSON(t, &sess)
	if !sess.User.EmailVerified {
		t.Fatal("email should be verified")
	}
}

func TestDeleteUserEndpoint(t *testing.T) {
	mb := &mailbox{}
	s := flowServer(t, mb, func(c *config.AuthConfig) {
		c.User.DeleteUser.SendDeleteAccountVerification = func(d config.DeleteAccountVerificationData, _ *http.Request) error {
			mb.del = append(mb.del, d)
			return nil
		}
	})
	expectStatus(t, s.Post(t, "/api/auth/sign-up/email", signUpBody("bye@example.com")), http.StatusOK)

	r := s.Post(t, "/api/auth/delete-user", map[string]any{"callbackURL": "/goodbye"})
	expectStatus(t, r, http.StatusOK)
	AssertJSONShape(t, r.Body, "delete_user")
	if len(mb.del) != 1 {
		t.Fatal("confirmation email expected")
	}
	link, _ := url.Parse(mb.del[0].URL)
	r = s.Get(t, link.Path+"?"+link.RawQuery)
	if r.Status != http.StatusFound || r.Header.Get("Location") != "/goodbye" {
		t.Fatalf("callback redirects to callbackURL: %d %s", r.Status, r.Header.Get("Location"))
	}
	var count int64
	s.DB.Model(&models.User{}).Where("email = ?", "bye@example.com").Count(&count)
	if count != 0 {
		t.Fatal("user should be deleted")
	}
}

func TestOriginChecks(t *testing.T) {
	s := flowServer(t, &mailbox{})
	expectStatus(t, s.Post(t, "/api/auth/sign-up/email", signUpBody("origin@example.com")), http.StatusOK)

	evil := map[string]string{"Origin": "https://evil.com"}
	expectCode(t, s.Post(t, "/api/auth/revoke-sessions", nil, evil), http.StatusForbidden, "INVALID_ORIGIN")
	expectCode(t, s.Post(t, "/api/auth/revoke-sessions", nil, map[string]string{"Origin": "null"}), http.StatusForbidden, "MISSING_OR_NULL_ORIGIN")
	expectCode(t, s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "origin@example.com", "password": "password123", "callbackURL": "https://evil.com/x"}), http.StatusForbidden, "INVALID_CALLBACK_URL")

	// cookieless sign-in: Fetch Metadata decides
	fresh := NewServer(t, WithConfig(compatMode))
	expectStatus(t, fresh.Post(t, "/api/auth/sign-up/email", signUpBody("nav@example.com")), http.StatusOK)
	fresh.Jar, _ = cookiejar.New(nil)
	fresh.Client.Jar = fresh.Jar
	nav := map[string]string{"Origin": "", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate"}
	expectCode(t, fresh.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "nav@example.com", "password": "password123"}, nav), http.StatusForbidden, "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED")
	expectCode(t, fresh.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "nav@example.com", "password": "password123"}, evil), http.StatusForbidden, "INVALID_ORIGIN")
	expectStatus(t, fresh.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "nav@example.com", "password": "password123"}, map[string]string{"Origin": ""}), http.StatusOK)
}

func TestAdminPluginBlocksBannedSignIn(t *testing.T) {
	s := NewServer(t, WithConfig(compatMode), func(o *goauth.GoAuthOptions) {
		p, err := admin.NewWithGorm(o.Conn)
		if err != nil {
			t.Fatal(err)
		}
		o.Plugins = append(o.Plugins, p)
	})
	expectStatus(t, s.Post(t, "/api/auth/sign-up/email", signUpBody("banned@example.com")), http.StatusOK)
	s.DB.Model(&models.User{}).Where("email = ?", "banned@example.com").Update("banned", true)
	expectCode(t, s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "banned@example.com", "password": "password123"}), http.StatusForbidden, "BANNED_USER")

	s.DB.Model(&models.User{}).Where("email = ?", "banned@example.com").Update("ban_expires", time.Now().Add(-time.Minute))
	expectStatus(t, s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "banned@example.com", "password": "password123"}), http.StatusOK)
}
