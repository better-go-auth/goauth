package auth_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/memory"
	authsvc "github.com/better-go-auth/goauth/src/app/services/auth"
	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	memstore "github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	"github.com/better-go-auth/goauth/src/providers/token"
)

const secret = "test-secret-at-least-32-characters-long"

type httpRequest = http.Request

type env struct {
	svc      *authsvc.Service
	repos    *memory.Repos
	sessions *sessionsvc.Manager
	mails    []config.EmailVerificationData
	resets   []config.ResetPasswordData
}

func newEnv(t *testing.T, mutate func(*config.AuthConfig), store sec_storage.SecondaryStorage) *env {
	t.Helper()
	e := &env{repos: memory.New()}
	cfg := config.AuthConfig{
		Secret:  secret,
		BaseURL: "http://localhost:3000",
		GoAuth:  config.GoAuthConfig{Mode: config.ModeCompat},
	}
	cfg.EmailVerification.SendVerificationEmail = func(d config.EmailVerificationData, _ *httpRequest) error {
		e.mails = append(e.mails, d)
		return nil
	}
	cfg.EmailAndPassword.SendResetPassword = func(d config.ResetPasswordData, _ *httpRequest) error {
		e.resets = append(e.resets, d)
		return nil
	}
	if mutate != nil {
		mutate(&cfg)
	}
	cfg.SetDefaults()
	e.sessions = sessionsvc.NewManager(cfg.Session, e.repos, e.repos, store, nil)
	e.svc = authsvc.New(authsvc.Deps{Config: cfg, Repos: e.repos, Sessions: e.sessions})
	return e
}

func ptr[T any](v T) *T { return &v }

func errCode(err error) string {
	if ae := autherr.AsAuthError(err); ae != nil {
		return string(ae.Code)
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

func (e *env) signUp(t *testing.T, email, password string) *authsvc.SignUpResult {
	t.Helper()
	res, err := e.svc.SignUpEmail(context.Background(), dtos.SignUpEmailInput{Email: email, Password: password, Name: "Test"}, authsvc.Meta{})
	if err != nil {
		t.Fatalf("sign up: %v", err)
	}
	return res
}

func tokenFrom(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if tok := u.Query().Get("token"); tok != "" {
		return tok
	}
	return u.Path[strings.LastIndex(u.Path, "/")+1:]
}

func TestSignUpAndSignIn(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil, nil)

	res := e.signUp(t, "Alice@Example.com", "password123")
	if res.Token == nil || res.Session == nil || res.User.Email != "alice@example.com" {
		t.Fatalf("unexpected sign-up result %+v", res)
	}
	acc, err := e.repos.FindAccountByUserAndProvider(ctx, res.User.ID, models.ProvCredential)
	if err != nil || acc.AccountID != res.User.ID || strings.HasPrefix(*acc.Password, "$2") {
		t.Fatalf("credential account should use the user id and scrypt: %+v %v", acc, err)
	}

	_, err = e.svc.SignUpEmail(ctx, dtos.SignUpEmailInput{Email: "alice@example.com", Password: "password123", Name: "x"}, authsvc.Meta{})
	if errCode(err) != "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL" {
		t.Fatalf("duplicate sign-up: %v", err)
	}

	in, err := e.svc.SignInEmail(ctx, dtos.SignInEmailInput{Email: "ALICE@example.com", Password: "password123", RememberMe: ptr(false)}, authsvc.Meta{IPAddress: "1.2.3.4"})
	if err != nil || in.Token == "" || !in.DontRemember {
		t.Fatalf("sign in: %+v %v", in, err)
	}
	if got := time.Until(time.Time(in.Session.Session.ExpiresAt)); got > 25*time.Hour {
		t.Fatalf("rememberMe=false should give a 1-day session, got %v", got)
	}
	u, _ := e.repos.FindUserByID(ctx, res.User.ID)
	if u.LastLoginAt == nil || u.LastLoginIP == nil || *u.LastLoginIP != "1.2.3.4" {
		t.Fatalf("last login not recorded: %+v", u)
	}

	for _, tc := range []dtos.SignInEmailInput{
		{Email: "alice@example.com", Password: "wrong-password"},
		{Email: "nobody@example.com", Password: "password123"},
	} {
		if _, err := e.svc.SignInEmail(ctx, tc, authsvc.Meta{}); errCode(err) != "INVALID_EMAIL_OR_PASSWORD" {
			t.Fatalf("%s: got %v", tc.Email, err)
		}
	}
	if _, err := e.svc.SignInEmail(ctx, dtos.SignInEmailInput{Email: "not-an-email", Password: "x"}, authsvc.Meta{}); errCode(err) != "INVALID_EMAIL" {
		t.Fatalf("invalid email: %v", err)
	}

	if err := e.svc.SignOut(ctx, in.Token); err != nil {
		t.Fatal(err)
	}
	if sw, _ := e.sessions.Get(ctx, in.Token); sw != nil {
		t.Fatal("session should be revoked after sign-out")
	}
}

func TestSignUpValidation(t *testing.T) {
	e := newEnv(t, func(c *config.AuthConfig) { c.EmailAndPassword.DisableSignUp = true }, nil)
	_, err := e.svc.SignUpEmail(context.Background(), dtos.SignUpEmailInput{Email: "a@b.co", Password: "password123"}, authsvc.Meta{})
	if errCode(err) != "EMAIL_PASSWORD_SIGN_UP_DISABLED" {
		t.Fatalf("got %v", err)
	}

	e = newEnv(t, nil, nil)
	for pw, code := range map[string]string{"short": "PASSWORD_TOO_SHORT", strings.Repeat("x", 129): "PASSWORD_TOO_LONG"} {
		_, err := e.svc.SignUpEmail(context.Background(), dtos.SignUpEmailInput{Email: "a@b.co", Password: pw}, authsvc.Meta{})
		if errCode(err) != code {
			t.Fatalf("want %s, got %v", code, err)
		}
	}
}

func TestRequireEmailVerification(t *testing.T) {
	ctx := context.Background()
	var existing []string
	e := newEnv(t, func(c *config.AuthConfig) {
		c.EmailAndPassword.RequireEmailVerification = true
		c.EmailVerification.SendOnSignIn = true
		c.EmailAndPassword.OnExistingUserSignUp = func(d config.ExistingUserSignUpData, _ *httpRequest) error {
			existing = append(existing, d.User.Email)
			return nil
		}
	}, nil)

	res := e.signUp(t, "bob@example.com", "password123")
	if res.Token != nil || res.Session != nil || len(e.mails) != 1 {
		t.Fatalf("sign-up should not sign in and should mail: %+v mails=%d", res, len(e.mails))
	}
	// duplicate gets a synthetic user, not an error
	dup := e.signUp(t, "bob@example.com", "password123")
	if dup.User.ID == res.User.ID || dup.Token != nil || len(existing) != 1 {
		t.Fatalf("duplicate should return a synthetic user: %+v", dup)
	}

	_, err := e.svc.SignInEmail(ctx, dtos.SignInEmailInput{Email: "bob@example.com", Password: "password123"}, authsvc.Meta{})
	if errCode(err) != "EMAIL_NOT_VERIFIED" || len(e.mails) != 2 {
		t.Fatalf("got %v, mails=%d", err, len(e.mails))
	}

	v, err := e.svc.VerifyEmail(ctx, nil, tokenFrom(t, e.mails[0].URL), "", authsvc.Meta{})
	if err != nil || !v.Status || v.Session != nil {
		t.Fatalf("verify: %+v %v", v, err)
	}
	if _, err := e.svc.SignInEmail(ctx, dtos.SignInEmailInput{Email: "bob@example.com", Password: "password123"}, authsvc.Meta{}); err != nil {
		t.Fatalf("sign-in after verification: %v", err)
	}
}

func TestVerifyEmailTokens(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, func(c *config.AuthConfig) { c.EmailVerification.AutoSignInAfterVerification = true }, nil)
	res := e.signUp(t, "carol@example.com", "password123")

	if err := e.svc.SendVerificationEmail(ctx, res.Session, dtos.SendVerificationEmailInput{Email: "other@example.com"}); errCode(err) != "EMAIL_MISMATCH" {
		t.Fatalf("got %v", err)
	}
	if err := e.svc.SendVerificationEmail(ctx, res.Session, dtos.SendVerificationEmailInput{Email: "carol@example.com", CallbackURL: "/done"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.mails[0].URL, "/api/auth/verify-email?token=") || !strings.Contains(e.mails[0].URL, "callbackURL=%2Fdone") {
		t.Fatalf("unexpected url %s", e.mails[0].URL)
	}

	if _, err := e.svc.VerifyEmail(ctx, nil, "garbage", "", authsvc.Meta{}); errCode(err) != "INVALID_TOKEN" {
		t.Fatalf("got %v", err)
	}
	v, err := e.svc.VerifyEmail(ctx, nil, tokenFrom(t, e.mails[0].URL), "", authsvc.Meta{})
	if err != nil || v.Session == nil || !v.Session.User.EmailVerified {
		t.Fatalf("auto sign-in after verification: %+v %v", v, err)
	}
	if err := e.svc.SendVerificationEmail(ctx, v.Session, dtos.SendVerificationEmailInput{Email: "carol@example.com"}); errCode(err) != "EMAIL_ALREADY_VERIFIED" {
		t.Fatalf("got %v", err)
	}
}

func TestPasswordReset(t *testing.T) {
	ctx := context.Background()
	var resetFor []string
	e := newEnv(t, func(c *config.AuthConfig) {
		c.EmailAndPassword.RevokeSessionsOnPasswordReset = true
		c.EmailAndPassword.OnPasswordReset = func(d config.PasswordResetData, _ *httpRequest) error {
			resetFor = append(resetFor, d.User.Email)
			return nil
		}
	}, nil)
	res := e.signUp(t, "dave@example.com", "password123")

	if err := e.svc.RequestPasswordReset(ctx, dtos.RequestPasswordResetInput{Email: "nobody@example.com"}); err != nil || len(e.resets) != 0 {
		t.Fatalf("unknown email should succeed silently: %v", err)
	}
	if err := e.svc.RequestPasswordReset(ctx, dtos.RequestPasswordResetInput{Email: "dave@example.com", RedirectTo: "/reset"}); err != nil {
		t.Fatal(err)
	}
	tok := e.resets[0].Token
	if !strings.HasSuffix(e.resets[0].URL, "/api/auth/reset-password/"+tok+"?callbackURL=%2Freset") {
		t.Fatalf("unexpected url %s", e.resets[0].URL)
	}
	if v, _ := e.repos.FindVerificationValue(ctx, "reset-password:"+tok); v == nil || v.Value != res.User.ID {
		t.Fatalf("verification row should be better-auth shaped: %+v", v)
	}
	if err := e.svc.ValidateResetToken(ctx, tok); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ResetPassword(ctx, dtos.ResetPasswordInput{Token: tok, NewPassword: "short"}); errCode(err) != "PASSWORD_TOO_SHORT" {
		t.Fatalf("got %v", err)
	}
	if err := e.svc.ResetPassword(ctx, dtos.ResetPasswordInput{Token: tok, NewPassword: "new-password"}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.ResetPassword(ctx, dtos.ResetPasswordInput{Token: tok, NewPassword: "new-password"}); errCode(err) != "INVALID_TOKEN" {
		t.Fatalf("token must be single use: %v", err)
	}
	if sw, _ := e.sessions.Get(ctx, *res.Token); sw != nil {
		t.Fatal("sessions should be revoked on reset")
	}
	if len(resetFor) != 1 {
		t.Fatal("OnPasswordReset not called")
	}
	if _, err := e.svc.SignInEmail(ctx, dtos.SignInEmailInput{Email: "dave@example.com", Password: "new-password"}, authsvc.Meta{}); err != nil {
		t.Fatalf("sign in with new password: %v", err)
	}
}

func TestChangePassword(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil, nil)
	res := e.signUp(t, "erin@example.com", "password123")
	other, _ := e.svc.SignInEmail(ctx, dtos.SignInEmailInput{Email: "erin@example.com", Password: "password123"}, authsvc.Meta{})

	_, err := e.svc.ChangePassword(ctx, res.Session, dtos.ChangePasswordInput{CurrentPassword: "wrong", NewPassword: "new-password"}, authsvc.Meta{})
	if errCode(err) != "INVALID_PASSWORD" {
		t.Fatalf("got %v", err)
	}
	out, err := e.svc.ChangePassword(ctx, res.Session, dtos.ChangePasswordInput{CurrentPassword: "password123", NewPassword: "new-password", RevokeOtherSessions: true}, authsvc.Meta{})
	if err != nil || out.Token == nil || *out.Token == *res.Token {
		t.Fatalf("change password: %+v %v", out, err)
	}
	for _, tok := range []string{*res.Token, other.Token} {
		if sw, _ := e.sessions.Get(ctx, tok); sw != nil {
			t.Fatal("old sessions should be revoked")
		}
	}
	if err := e.svc.VerifyPassword(ctx, out.Session, "new-password"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.VerifyPassword(ctx, out.Session, "password123"); errCode(err) != "INVALID_PASSWORD" {
		t.Fatalf("got %v", err)
	}
}

func TestChangeEmail(t *testing.T) {
	ctx := context.Background()
	var confirmations []config.ChangeEmailConfirmationData
	e := newEnv(t, func(c *config.AuthConfig) {
		c.User.ChangeEmail.Enabled = true
		c.User.ChangeEmail.SendChangeEmailConfirmation = func(d config.ChangeEmailConfirmationData, _ *httpRequest) error {
			confirmations = append(confirmations, d)
			return nil
		}
	}, nil)
	res := e.signUp(t, "frank@example.com", "password123")
	e.signUp(t, "taken@example.com", "password123")

	if _, err := e.svc.ChangeEmail(ctx, res.Session, dtos.ChangeEmailInput{NewEmail: "frank@example.com"}); errCode(err) != "EMAIL_IS_THE_SAME" {
		t.Fatalf("got %v", err)
	}
	if sw, err := e.svc.ChangeEmail(ctx, res.Session, dtos.ChangeEmailInput{NewEmail: "taken@example.com"}); err != nil || sw != nil || len(e.mails) != 0 {
		t.Fatalf("taken email should succeed silently without mail: %v", err)
	}

	// unverified user: verification goes to the new address, applied on verify
	if _, err := e.svc.ChangeEmail(ctx, res.Session, dtos.ChangeEmailInput{NewEmail: "frank2@example.com"}); err != nil {
		t.Fatal(err)
	}
	if len(e.mails) != 1 || e.mails[0].User.Email != "frank2@example.com" {
		t.Fatalf("expected mail to the new address: %+v", e.mails)
	}
	v, err := e.svc.VerifyEmail(ctx, res.Session, tokenFrom(t, e.mails[0].URL), "", authsvc.Meta{})
	if err != nil || v.User == nil || v.User.Email != "frank2@example.com" || !v.User.EmailVerified || v.Session == nil {
		t.Fatalf("verify change: %+v %v", v, err)
	}

	// verified user with confirmation: old address confirms, then new address verifies
	if _, err := e.svc.ChangeEmail(ctx, v.Session, dtos.ChangeEmailInput{NewEmail: "frank3@example.com"}); err != nil {
		t.Fatal(err)
	}
	if len(confirmations) != 1 || confirmations[0].User.Email != "frank2@example.com" {
		t.Fatalf("expected confirmation to the old address: %+v", confirmations)
	}
	if _, err := e.svc.VerifyEmail(ctx, nil, tokenFrom(t, confirmations[0].URL), "", authsvc.Meta{}); err != nil {
		t.Fatal(err)
	}
	if len(e.mails) != 2 || e.mails[1].User.Email != "frank3@example.com" {
		t.Fatalf("expected verification to the new address: %+v", e.mails)
	}
	v, err = e.svc.VerifyEmail(ctx, nil, tokenFrom(t, e.mails[1].URL), "", authsvc.Meta{})
	if err != nil || v.User.Email != "frank3@example.com" {
		t.Fatalf("final verify: %+v %v", v, err)
	}

	e2 := newEnv(t, nil, nil)
	r2 := e2.signUp(t, "gina@example.com", "password123")
	if _, err := e2.svc.ChangeEmail(ctx, r2.Session, dtos.ChangeEmailInput{NewEmail: "x@example.com"}); errCode(err) != "CHANGE_EMAIL_DISABLED" {
		t.Fatalf("got %v", err)
	}
}

func TestSessions(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil, nil)
	a := e.signUp(t, "hank@example.com", "password123")
	b, _ := e.svc.SignInEmail(ctx, dtos.SignInEmailInput{Email: "hank@example.com", Password: "password123"}, authsvc.Meta{})
	other := e.signUp(t, "ivy@example.com", "password123")

	list, err := e.svc.ListSessions(ctx, a.Session)
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %d %v", len(list), err)
	}
	// another user's token is ignored
	if err := e.svc.RevokeSession(ctx, a.Session, *other.Token); err != nil {
		t.Fatal(err)
	}
	if sw, _ := e.sessions.Get(ctx, *other.Token); sw == nil {
		t.Fatal("must not revoke another user's session")
	}
	if err := e.svc.RevokeOtherSessions(ctx, a.Session); err != nil {
		t.Fatal(err)
	}
	if sw, _ := e.sessions.Get(ctx, b.Token); sw != nil {
		t.Fatal("other session should be revoked")
	}
	got, err := e.svc.GetSession(ctx, *a.Token, authsvc.GetSessionOptions{})
	if err != nil || got.Session == nil || got.Refreshed {
		t.Fatalf("get session: %+v %v", got, err)
	}
	if err := e.svc.RevokeSessions(ctx, a.Session); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.svc.GetSession(ctx, *a.Token, authsvc.GetSessionOptions{}); got.Session != nil {
		t.Fatal("all sessions should be revoked")
	}
}

func TestUpdateUserRefreshesCachedSessions(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil, memstore.New())
	res := e.signUp(t, "jack@example.com", "password123")

	if _, err := e.svc.UpdateUser(ctx, res.Session, authsvc.UpdateUserInput{Email: ptr("x@example.com")}); errCode(err) != "EMAIL_CAN_NOT_BE_UPDATED" {
		t.Fatalf("got %v", err)
	}
	if _, err := e.svc.UpdateUser(ctx, res.Session, authsvc.UpdateUserInput{Fields: map[string]any{"Role": "admin"}}); errCode(err) != "FIELD_NOT_ALLOWED" {
		t.Fatalf("role must not be updatable: %v", err)
	}
	if _, err := e.svc.UpdateUser(ctx, res.Session, authsvc.UpdateUserInput{}); errCode(err) != "NO_FIELDS_TO_UPDATE" {
		t.Fatalf("got %v", err)
	}
	sw, err := e.svc.UpdateUser(ctx, res.Session, authsvc.UpdateUserInput{Name: ptr("Jack"), Fields: map[string]any{"Bio": ptr("hi")}})
	if err != nil || sw.User.Name != "Jack" {
		t.Fatalf("update: %+v %v", sw, err)
	}
	cached, _ := e.sessions.Get(ctx, *res.Token)
	if cached == nil || cached.User.Name != "Jack" {
		t.Fatalf("cached session should carry the new user: %+v", cached)
	}
}

func TestDeleteUserAndAccounts(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil, nil)
	res := e.signUp(t, "kim@example.com", "password123")
	if _, err := e.svc.DeleteUser(ctx, res.Session, dtos.DeleteUserInput{}); errCode(err) != "NOT_FOUND" {
		t.Fatalf("delete should be disabled by default: %v", err)
	}

	accounts, err := e.svc.ListAccounts(ctx, res.Session)
	if err != nil || len(accounts) != 1 || accounts[0].ProviderID != "credential" {
		t.Fatalf("list accounts: %+v %v", accounts, err)
	}
	if err := e.svc.UnlinkAccount(ctx, res.Session, dtos.UnlinkAccountInput{ProviderID: "credential"}); errCode(err) != "FAILED_TO_UNLINK_LAST_ACCOUNT" {
		t.Fatalf("got %v", err)
	}
	for _, id := range []string{"gh-1", "gh-2"} {
		if _, err := e.repos.CreateAccount(ctx, &models.Account{UserID: res.User.ID, AccountID: id, ProviderID: models.ProvGithub}); err != nil {
			t.Fatal(err)
		}
	}
	if err := e.svc.UnlinkAccount(ctx, res.Session, dtos.UnlinkAccountInput{ProviderID: "github", AccountID: "gh-2"}); err != nil {
		t.Fatal(err)
	}
	if accounts, _ := e.svc.ListAccounts(ctx, res.Session); len(accounts) != 2 {
		t.Fatalf("unlink must remove only the matching account, left %d", len(accounts))
	}

	var deleted []string
	e = newEnv(t, func(c *config.AuthConfig) {
		c.User.DeleteUser.Enabled = true
		c.User.DeleteUser.AfterDelete = func(u models.User, _ *httpRequest) error {
			deleted = append(deleted, u.ID)
			return nil
		}
	}, nil)
	res = e.signUp(t, "kim@example.com", "password123")
	if _, err := e.svc.DeleteUser(ctx, res.Session, dtos.DeleteUserInput{Password: ptr("wrong")}); errCode(err) != "INVALID_PASSWORD" {
		t.Fatalf("got %v", err)
	}
	if msg, err := e.svc.DeleteUser(ctx, res.Session, dtos.DeleteUserInput{Password: ptr("password123")}); err != nil || msg != authsvc.MsgUserDeleted {
		t.Fatal(msg, err)
	}
	if _, err := e.repos.FindUserByID(ctx, res.User.ID); err == nil {
		t.Fatal("user should be deleted")
	}
	if sw, _ := e.sessions.Get(ctx, *res.Token); sw != nil || len(deleted) != 1 {
		t.Fatal("sessions should be revoked and AfterDelete called")
	}
}

func TestDeleteUserWithEmailConfirmation(t *testing.T) {
	ctx := context.Background()
	var links []config.DeleteAccountVerificationData
	e := newEnv(t, func(c *config.AuthConfig) {
		c.User.DeleteUser.Enabled = true
		c.User.DeleteUser.SendDeleteAccountVerification = func(d config.DeleteAccountVerificationData, _ *httpRequest) error {
			links = append(links, d)
			return nil
		}
	}, nil)
	res := e.signUp(t, "mia@example.com", "password123")
	other := e.signUp(t, "noa@example.com", "password123")

	msg, err := e.svc.DeleteUser(ctx, res.Session, dtos.DeleteUserInput{CallbackURL: ptr("/bye")})
	if err != nil || msg != authsvc.MsgVerificationEmailSent || len(links) != 1 {
		t.Fatalf("expected a confirmation email: %q %v", msg, err)
	}
	if !strings.Contains(links[0].URL, "/api/auth/delete-user/callback?token="+links[0].Token+"&callbackURL=%2Fbye") {
		t.Fatalf("unexpected url %s", links[0].URL)
	}
	if _, err := e.repos.FindUserByID(ctx, res.User.ID); err != nil {
		t.Fatal("nothing is deleted before confirmation")
	}
	if err := e.svc.DeleteUserCallback(ctx, other.Session, links[0].Token); errCode(err) != "INVALID_TOKEN" {
		t.Fatalf("another user's session must not use the token: %v", err)
	}
	// the wrong-owner attempt burned the token, like better-auth
	if err := e.svc.DeleteUserCallback(ctx, res.Session, links[0].Token); errCode(err) != "INVALID_TOKEN" {
		t.Fatalf("token must be single use: %v", err)
	}

	if _, err := e.svc.DeleteUser(ctx, res.Session, dtos.DeleteUserInput{}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteUserCallback(ctx, res.Session, links[1].Token); err != nil {
		t.Fatal(err)
	}
	if _, err := e.repos.FindUserByID(ctx, res.User.ID); err == nil {
		t.Fatal("user should be deleted after confirmation")
	}
}

func TestSetPassword(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil, nil)
	res := e.signUp(t, "oli@example.com", "password123")
	if err := e.svc.SetPassword(ctx, res.User.ID, "another-password"); errCode(err) != "PASSWORD_ALREADY_SET" {
		t.Fatalf("got %v", err)
	}
	if err := e.repos.DeleteAccounts(ctx, res.User.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SetPassword(ctx, res.User.ID, "short"); errCode(err) != "PASSWORD_TOO_SHORT" {
		t.Fatalf("got %v", err)
	}
	if err := e.svc.SetPassword(ctx, res.User.ID, "another-password"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SignInEmail(ctx, dtos.SignInEmailInput{Email: "oli@example.com", Password: "another-password"}, authsvc.Meta{}); err != nil {
		t.Fatal(err)
	}
}

func TestSessionHookCanRejectSignIn(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil, nil)
	hooks := plugins.NewHookRegistry()
	hooks.OnBeforeSessionCreate(func(context.Context, *models.Session, *token.CustomClaims) error {
		return autherr.ErrBannedUser
	})
	cfg := config.AuthConfig{Secret: secret, BaseURL: "http://localhost:3000"}
	cfg.SetDefaults()
	mgr := sessionsvc.NewManager(cfg.Session, e.repos, e.repos, nil, hooks)
	svc := authsvc.New(authsvc.Deps{Config: cfg, Repos: e.repos, Sessions: mgr})

	e.signUp(t, "leo@example.com", "password123")
	if _, err := svc.SignInEmail(ctx, dtos.SignInEmailInput{Email: "leo@example.com", Password: "password123"}, authsvc.Meta{}); errCode(err) != "BANNED_USER" {
		t.Fatalf("hook error must be returned as-is: %v", err)
	}
}

func TestUpdateSessionDeviceFields(t *testing.T) {
	ctx := context.Background()
	for name, mutate := range map[string]func(*config.AuthConfig){
		"database + cache": nil,
		"cache only":       func(c *config.AuthConfig) { c.Session.StoreSessionInDatabase = ptr(false) },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, mutate, memstore.New())
			res := e.signUp(t, "dev@example.com", "password123")

			sw, err := e.svc.UpdateSession(ctx, res.Session, map[string]any{"deviceName": "Pixel", "deviceToken": "fcm:1", "unknown": 1})
			if err != nil || sw.Session.DeviceName == nil || *sw.Session.DeviceName != "Pixel" || *sw.Session.DeviceToken != "fcm:1" {
				t.Fatalf("update: %+v %v", sw, err)
			}
			got, _ := e.sessions.Get(ctx, *res.Token)
			if got == nil || got.Session.DeviceName == nil || *got.Session.DeviceName != "Pixel" {
				t.Fatalf("stored session must carry the update: %+v", got)
			}
			if sw, err = e.svc.UpdateSession(ctx, got, map[string]any{"deviceName": nil}); err != nil || sw.Session.DeviceName != nil {
				t.Fatalf("null clears the field: %+v %v", sw, err)
			}

			for want, body := range map[string]map[string]any{
				"FIELD_NOT_ALLOWED":   {"activeOrganizationId": "org-1"},
				"VALIDATION_ERROR":    {"deviceName": 42},
				"NO_FIELDS_TO_UPDATE": {"unknown": "x"},
			} {
				if _, err := e.svc.UpdateSession(ctx, res.Session, body); errCode(err) != want {
					t.Fatalf("%v: want %s, got %v", body, want, err)
				}
			}

			if err := e.sessions.Delete(ctx, *res.Token); err != nil {
				t.Fatal(err)
			}
			if _, err := e.svc.UpdateSession(ctx, res.Session, map[string]any{"deviceName": "x"}); errCode(err) != "FAILED_TO_GET_SESSION" {
				t.Fatalf("revoked session must fail closed: %v", err)
			}
		})
	}
}

func TestUpdatableSessionFieldsConfig(t *testing.T) {
	for _, fields := range [][]string{{"activeOrganizationId"}, {"token"}, {"nope"}} {
		cfg := config.AuthConfig{}
		cfg.GoAuth.Session.UpdatableFields = fields
		if authsvc.ValidateConfig(cfg) == nil {
			t.Fatalf("%v must be rejected", fields)
		}
	}
	cfg := config.AuthConfig{}
	cfg.GoAuth.Session.UpdatableFields = config.DefaultUpdatableSessionFields
	if err := authsvc.ValidateConfig(cfg); err != nil {
		t.Fatal(err)
	}

	e := newEnv(t, func(c *config.AuthConfig) { c.GoAuth.Session.UpdatableFields = []string{} }, nil)
	res := e.signUp(t, "none@example.com", "password123")
	if _, err := e.svc.UpdateSession(context.Background(), res.Session, map[string]any{"deviceName": "x"}); errCode(err) != "NO_FIELDS_TO_UPDATE" {
		t.Fatalf("an empty allowlist disables update-session: %v", err)
	}
}

func TestSingleResetLink(t *testing.T) {
	ctx := context.Background()
	for _, single := range []bool{false, true} {
		e := newEnv(t, func(c *config.AuthConfig) { c.EmailAndPassword.GoAuth.SingleResetLink = single }, nil)
		e.signUp(t, "link@example.com", "password123")
		for range 3 {
			if err := e.svc.RequestPasswordReset(ctx, dtos.RequestPasswordResetInput{Email: "link@example.com"}); err != nil {
				t.Fatal(err)
			}
		}
		first, second, last := e.resets[0].Token, e.resets[1].Token, e.resets[2].Token
		if got := e.svc.ValidateResetToken(ctx, first) == nil; got == single {
			t.Fatalf("single=%v: first link valid=%v", single, got)
		}
		if err := e.svc.ResetPassword(ctx, dtos.ResetPasswordInput{Token: last, NewPassword: "new-password"}); err != nil {
			t.Fatal(err)
		}
		if got := e.svc.ValidateResetToken(ctx, second) == nil; got == single {
			t.Fatalf("single=%v: older link valid after reset=%v", single, got)
		}
	}
}
