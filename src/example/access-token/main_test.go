package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
)

// tokenBody is the body of /login and /refresh: a legacy envelope around better-auth's sign-in response
// plus the token pair.
type tokenBody struct {
	Body struct {
		Token string `json:"token"`
		User  struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
		AuthTokens struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"authTokens"`
	} `json:"body"`
}

func bearer(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

func TestAccessTokenFlow(t *testing.T) {
	a, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, a.App)

	// Step 1: sign up through the legacy /signup route (201); it sends a verification code. lName and avatar
	// are optional; the email must be a bare address and the password 8..128 characters (core config)
	for name, body := range map[string]map[string]any{
		"invalid email":  {"fName": "Alice", "email": "not-an-email", "password": "Password123!"},
		"short password": {"fName": "Alice", "email": "alice@example.com", "password": "short"},
	} {
		if r := c.Post("/api/auth/signup", body); r.Status != http.StatusBadRequest {
			t.Fatalf("signup with %s: %d, want 400: %s", name, r.Status, r.Body)
		}
	}
	c.MustStatus(c.Post("/api/auth/signup", map[string]any{
		"fName": "Alice", "email": "alice@example.com", "password": "Password123!",
	}), http.StatusCreated, nil)
	if a.Outbox.Last("verification-code", "alice@example.com") == "" {
		t.Fatal("no verification code sent")
	}

	// Step 2: /login answers 201 with the access token (JWT) and the refresh token, also set as cookies
	var login tokenBody
	r := c.MustStatus(c.Post("/api/auth/login", map[string]any{"info": "alice@example.com", "password": "Password123!"}), http.StatusCreated, &login)
	access, refresh := login.Body.AuthTokens.AccessToken, login.Body.AuthTokens.RefreshToken
	if strings.Count(access, ".") != 2 || refresh == "" || strings.Count(refresh, ".") == 2 {
		t.Fatalf("unexpected tokens: %+v", login.Body.AuthTokens)
	}
	if login.Body.Token != access || login.Body.User.Email != "alice@example.com" {
		t.Fatalf("unexpected login body: %s", r.Body)
	}
	if r.Cookie("access-token") == nil || r.Cookie("refresh-token") == nil {
		t.Fatal("missing access-token / refresh-token cookies")
	}

	// Step 3: a new client (no cookies) uses the access token on the route protected by AuthMiddleware
	api := c.Fork()
	if r := api.Get("/api/example/jwt/me"); r.Status != http.StatusUnauthorized {
		t.Fatalf("jwt/me without token: %d, want 401", r.Status)
	}
	var me exkit.MeOutput
	api.MustOK(api.Get("/api/example/jwt/me", bearer(access)), &me.Body)
	if me.Body.Email != "alice@example.com" || me.Body.UserID != login.Body.User.ID {
		t.Fatalf("jwt/me = %+v", me.Body)
	}
	// routes without AuthMiddleware ignore access tokens (AutoRegisterMiddleware is off)
	if r := api.Get("/api/example/me", bearer(access)); r.Status != http.StatusUnauthorized {
		t.Fatalf("cookie-only route with access token: %d, want 401", r.Status)
	}
	// a token signed with another key is rejected
	if r := api.Get("/api/example/jwt/me", bearer(access[:len(access)-4]+"AAAA")); r.Status != http.StatusUnauthorized {
		t.Fatalf("tampered token: %d, want 401", r.Status)
	}

	// Step 4: /refresh trades the refresh token for a new pair; an access token is not accepted there
	if r := api.Post("/api/auth/refresh", map[string]any{"token": access}); r.Status != http.StatusUnauthorized {
		t.Fatalf("refresh with access token: %d, want 401", r.Status)
	}
	var refreshed tokenBody
	api.MustStatus(api.Post("/api/auth/refresh", map[string]any{"token": refresh}), http.StatusCreated, &refreshed)
	newAccess, newRefresh := refreshed.Body.AuthTokens.AccessToken, refreshed.Body.AuthTokens.RefreshToken
	if newAccess == "" || newRefresh != refresh {
		// RotateSessionToken is off by default: the refresh token stays the same
		t.Fatalf("unexpected refreshed tokens: %+v", refreshed.Body.AuthTokens)
	}
	api.MustOK(api.Get("/api/example/jwt/me", bearer(newAccess)), nil)

	// Step 5: log out through the core sign-out route with the access token (the refresh token works too, as
	// "Authorization: Bearer <refresh token>" or the refresh-token cookie); the plugin cookies are expired
	out := api.MustOK(api.Post("/api/auth/sign-out", nil, bearer(newAccess)), nil)
	if ck := out.Cookie("access-token"); ck == nil || ck.MaxAge >= 0 {
		t.Fatalf("sign-out must expire the access-token cookie: %v", out.Header.Values("Set-Cookie"))
	}

	// Step 6: the session is gone: its access tokens (blacklisted) and its refresh token stop working
	if r := api.Get("/api/example/jwt/me", bearer(newAccess)); r.Status != http.StatusUnauthorized {
		t.Fatalf("access token after logout: %d, want 401", r.Status)
	}
	if r := api.Post("/api/auth/refresh", map[string]any{"token": newRefresh}); r.Status != http.StatusUnauthorized {
		t.Fatalf("refresh after logout: %d, want 401", r.Status)
	}

	// Step 7: a wrong password is a 401
	if r := c.Fork().Post("/api/auth/login", map[string]any{"info": "alice@example.com", "password": "wrong-password"}); r.Status != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d %s", r.Status, r.Body)
	}
}
