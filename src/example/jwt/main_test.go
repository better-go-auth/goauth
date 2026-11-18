package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
)

type jwksBody struct {
	Keys []struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		Alg string `json:"alg"`
	} `json:"keys"`
}

func TestJWTFlow(t *testing.T) {
	app, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)
	ctx := context.Background()

	// Step 1: a JWT needs a session
	if r := c.Get("/api/auth/token"); r.Status != http.StatusUnauthorized {
		t.Fatalf("token without session: status %d, want 401", r.Status)
	}

	// Step 2: sign up, then exchange the session for a JWT
	var signUp struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	c.MustOK(c.SignUp("alice@example.com", "Password123!", "Alice"), &signUp)
	var tok struct {
		Token string `json:"token"`
	}
	c.MustOK(c.Get("/api/auth/token"), &tok)
	if strings.Count(tok.Token, ".") != 2 {
		t.Fatalf("token = %q, want a JWT", tok.Token)
	}

	// Step 3: the JWKS lists the public key (EdDSA / Ed25519), at /api/auth/jwks and at /jwks
	var set jwksBody
	c.MustOK(c.Get("/api/auth/jwks"), &set)
	if len(set.Keys) != 1 || set.Keys[0].Kty != "OKP" || set.Keys[0].Crv != "Ed25519" || set.Keys[0].Alg != "EdDSA" {
		t.Fatalf("jwks = %+v", set)
	}
	var root jwksBody
	c.MustOK(c.Get("/jwks"), &root)
	if len(root.Keys) != 1 || root.Keys[0].Kid != set.Keys[0].Kid {
		t.Fatalf("root /jwks = %+v", root)
	}

	// Step 4: another service verifies the JWT with the JWKS only (no database, no secret)
	verifier := &JWKSVerifier{JWKSURL: c.BaseURL + "/api/auth/jwks", Issuer: Issuer, Audience: Audience}
	claims, err := verifier.Verify(ctx, tok.Token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Step 5: the claims are the custom payload plus sub, iss, aud, iat and exp
	if claims["sub"] != signUp.User.ID || claims["email"] != "alice@example.com" || claims["name"] != "Alice" || claims["sessionId"] == nil {
		t.Fatalf("claims = %v", claims)
	}
	if _, hasID := claims["id"]; hasID {
		t.Fatalf("DefinePayload replaces the default user claims, got %v", claims)
	}
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if exp-iat != 600 {
		t.Fatalf("lifetime = %vs, want 600", exp-iat)
	}

	// Step 6: get-session also hands out a JWT, in the set-auth-jwt header
	r := c.MustOK(c.Get("/api/auth/get-session"), nil)
	headerJWT := r.Header.Get("set-auth-jwt")
	if headerJWT == "" || !strings.Contains(r.Header.Get("Access-Control-Expose-Headers"), "set-auth-jwt") {
		t.Fatalf("get-session headers = %v", r.Header)
	}
	if _, err := verifier.Verify(ctx, headerJWT); err != nil {
		t.Fatalf("verify set-auth-jwt: %v", err)
	}

	// Step 7: a tampered payload, the wrong audience or the wrong issuer are rejected
	parts := strings.Split(tok.Token, ".")
	forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"someone-else"}`)) + "." + parts[2]
	if _, err := verifier.Verify(ctx, forged); err == nil {
		t.Fatal("a tampered token must not verify")
	}
	other := &JWKSVerifier{JWKSURL: verifier.JWKSURL, Issuer: Issuer, Audience: "https://other.example.com"}
	if _, err := other.Verify(ctx, tok.Token); err == nil {
		t.Fatal("a token for another audience must not verify")
	}
	other = &JWKSVerifier{JWKSURL: verifier.JWKSURL, Issuer: "https://evil.example.com", Audience: Audience}
	if _, err := other.Verify(ctx, tok.Token); err == nil {
		t.Fatal("a token from another issuer must not verify")
	}
}

func TestServerOnlyRoutesNotExposed(t *testing.T) {
	app, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	// Step 1: serve the app the way main does
	ts := httptest.NewServer(app.Mux)
	t.Cleanup(ts.Close)

	// Step 2: nobody can sign or verify arbitrary JWTs over HTTP (better-auth's server-only endpoints)
	for _, path := range []string{"/api/auth/sign-jwt", "/api/auth/verify-jwt"} {
		resp, err := http.Post(ts.URL+path, "application/json", strings.NewReader(`{"payload":{"sub":"admin"}}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("POST %s: status %d, want 404", path, resp.StatusCode)
		}
	}

	// Step 3: the public endpoints still work
	resp, err := http.Get(ts.URL + "/api/auth/jwks")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/auth/jwks: status %d", resp.StatusCode)
	}

	// Step 4: signing works from Go, and the token verifies with the public JWKS
	ctx := context.Background()
	tok, err := SignServiceToken(ctx, app, "billing")
	if err != nil {
		t.Fatalf("SignServiceToken: %v", err)
	}
	verifier := &JWKSVerifier{JWKSURL: ts.URL + "/api/auth/jwks", Issuer: Issuer, Audience: Audience}
	claims, err := verifier.Verify(ctx, tok)
	if err != nil {
		t.Fatalf("verify service token: %v", err)
	}
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if claims["sub"] != "service:billing" || claims["scope"] != "internal" || exp-iat != 300 {
		t.Fatalf("claims = %v", claims)
	}
}
