package auth_test

import (
	"context"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/app/core/auth"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
	"github.com/better-go-auth/goauth/src/providers/idgen"
	jwttoken "github.com/better-go-auth/goauth/src/providers/token/jwt-token"
	"github.com/better-go-auth/goauth/src/tests/helpers"
)

func createActiveUser(t *testing.T, env *helpers.TestEnv, email, password string) *models.User {
	t.Helper()
	ctx := context.Background()
	active := true
	usr := &models.User{UserDto: models.UserDto{
		FirstName: "Fix", LastName: "User", Email: email,
		EmailVerified: true, Active: &active, Role: enums.User,
	}}
	if err := env.DB.Create(usr).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	hash, err := authcrypto.HashPasswordBcrypt(password)
	if err != nil {
		t.Fatal(err)
	}
	acc := &models.Account{UserID: usr.ID, AccountID: email, ProviderID: models.ProvCredential, Password: &hash}
	if err := env.DB.WithContext(ctx).Create(acc).Error; err != nil {
		t.Fatalf("create account: %v", err)
	}
	return usr
}

func login(t *testing.T, env *helpers.TestEnv, email, password string) *models.AuthTokens {
	t.Helper()
	res, err := env.AuthService.Login(context.Background(), auth.LoginData{LoginInfo: email, Password: password})
	if err != nil || res.Body.AuthTokens == nil {
		t.Fatalf("login failed: %v", err)
	}
	return res.Body.AuthTokens
}

// sessionIDOf finds the session row behind a refresh token, which is now the session token itself.
func sessionIDOf(t *testing.T, env *helpers.TestEnv, refresh string) string {
	t.Helper()
	var s models.Session
	if err := env.DB.Where("token = ?", refresh).Take(&s).Error; err != nil {
		t.Fatalf("find session for refresh token: %v", err)
	}
	return s.ID
}

func TestLoginKeepsOtherSessions(t *testing.T) {
	env := helpers.SetupTestEnv(t, true)
	email, pwd := "multi_session@example.com", "password123!"
	usr := createActiveUser(t, env, email, pwd)

	first := login(t, env, email, pwd)
	login(t, env, email, pwd)

	var count int64
	env.DB.Model(&models.Session{}).Where("user_id = ?", usr.ID).Count(&count)
	if count != 2 {
		t.Fatalf("expected 2 sessions after two logins, got %d", count)
	}
	if _, err := env.AuthService.ResetToken(context.Background(), first.RefreshToken); err != nil {
		t.Fatalf("first session should still refresh: %v", err)
	}
}

func TestRefreshKeepsOrgContextAndRotates(t *testing.T) {
	env := helpers.SetupTestEnv(t, true)
	ctx := context.Background()
	email, pwd := "org_refresh@example.com", "password123!"
	usr := createActiveUser(t, env, email, pwd)

	sessionID := models.NewSecureId()
	orgID, orgRole := "org_123", "owner"
	if err := env.DB.Create(&orgmodels.Organization{Base: models.Base{ID: orgID}, Name: "Org", Slug: "org-123"}).Error; err != nil {
		t.Fatal(err)
	}
	tokens, err := env.AuthService.SesSvc.CreateSession(ctx, sessionID, usr.Role.S(), usr.ID, &models.SessionOpt{
		ActiveOrgID: &orgID, OrgRole: &orgRole, DeviceToken: "device-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	var stored models.Session
	env.DB.Where("id = ?", sessionID).Take(&stored)
	if stored.Token != tokens.RefreshToken || !idgen.IsToken(stored.Token) {
		t.Fatalf("refresh token must be the session's opaque token, got %q (row %q)", tokens.RefreshToken, stored.Token)
	}

	res, err := env.AuthService.ResetToken(ctx, tokens.RefreshToken)
	if err != nil {
		t.Fatalf("refresh failed: %v", err)
	}
	claims, err := jwttoken.ValidateToken(res.Body.AuthTokens.AccessToken, helpers.TestAccessSecret)
	if err != nil {
		t.Fatal(err)
	}
	if claims.ActiveOrgId != orgID || claims.ActiveOrgRole != orgRole || claims.SessionID != sessionID {
		t.Fatalf("org context lost on refresh: org=%q role=%q sid=%q", claims.ActiveOrgId, claims.ActiveOrgRole, claims.SessionID)
	}
	env.DB.Where("id = ?", sessionID).Take(&stored)
	if stored.DeviceToken != "device-1" {
		t.Fatalf("device token lost on refresh: %q", stored.DeviceToken)
	}

	if _, err := env.AuthService.ResetToken(ctx, tokens.RefreshToken); err == nil {
		t.Fatal("old refresh token must be rejected after rotation")
	}
	if _, err := env.AuthService.ResetToken(ctx, res.Body.AuthTokens.RefreshToken); err != nil {
		t.Fatalf("rotated refresh token must work: %v", err)
	}
}

func TestRefreshRejectsBlockedUsersAndExpiredSessions(t *testing.T) {
	env := helpers.SetupTestEnv(t, true)
	ctx := context.Background()

	t.Run("banned user", func(t *testing.T) {
		email, pwd := "banned_refresh@example.com", "password123!"
		usr := createActiveUser(t, env, email, pwd)
		tokens := login(t, env, email, pwd)
		env.DB.Model(usr).Update("banned", true)
		if _, err := env.AuthService.ResetToken(ctx, tokens.RefreshToken); err == nil {
			t.Fatal("banned user must not refresh")
		}
	})

	t.Run("inactive user", func(t *testing.T) {
		email, pwd := "inactive_refresh@example.com", "password123!"
		usr := createActiveUser(t, env, email, pwd)
		tokens := login(t, env, email, pwd)
		env.DB.Model(usr).Update("active", false)
		if _, err := env.AuthService.ResetToken(ctx, tokens.RefreshToken); err == nil {
			t.Fatal("inactive user must not refresh")
		}
	})

	t.Run("expired session", func(t *testing.T) {
		email, pwd := "expired_refresh@example.com", "password123!"
		createActiveUser(t, env, email, pwd)
		tokens := login(t, env, email, pwd)
		env.DB.Model(&models.Session{}).Where("id = ?", sessionIDOf(t, env, tokens.RefreshToken)).
			Update("expires_at", time.Now().Add(-time.Hour))
		// the cached copy (keyed by token, TTL = expiry) is read first; drop it as its TTL would have
		_ = env.SecondaryStorage.Delete(ctx, tokens.RefreshToken)
		if _, err := env.AuthService.ResetToken(ctx, tokens.RefreshToken); err == nil {
			t.Fatal("expired session must not refresh")
		}
	})
}

func TestTokenCookiesAttributes(t *testing.T) {
	c := auth.CreateCookie("access-token", "v", time.Hour, auth.CookieAttrs{Secure: true, Domain: "example.com"})
	if !c.Secure || c.Domain != "example.com" || !c.HttpOnly || c.MaxAge != 3600 {
		t.Fatalf("unexpected cookie: %+v", c)
	}
	e := auth.ExpireCookie("access-token", auth.CookieAttrs{Secure: true})
	if e.MaxAge >= 0 || e.Value != "" || !e.Secure {
		t.Fatalf("unexpected expire cookie: %+v", e)
	}
}
