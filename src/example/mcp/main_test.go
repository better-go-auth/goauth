package main

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
)

const clientCallback = "http://localhost:6274/oauth/callback"

func TestMCPClientFlow(t *testing.T) {
	app, _, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)
	c.MustOK(c.SignUp("dev@example.com", "Password123!", "Dev"), nil)

	// Step 1: the MCP endpoint rejects anonymous calls and says where the metadata is
	mcpClient := c.Fork()
	r := mcpClient.Post("/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "whoami"})
	if r.Status != 401 || !strings.Contains(r.Header.Get("WWW-Authenticate"), "/api/auth/.well-known/oauth-protected-resource") {
		t.Fatalf("anonymous: %d %v", r.Status, r.Header)
	}
	var as map[string]any
	mcpClient.MustOK(mcpClient.Get("/.well-known/oauth-authorization-server"), &as)
	if as["registration_endpoint"] != exkit.DefaultBaseURL+"/api/auth/mcp/register" {
		t.Fatalf("metadata: %v", as)
	}

	// Step 2: dynamic registration of a public client
	var reg struct {
		ClientID string `json:"client_id"`
	}
	mcpClient.MustStatus(mcpClient.Post("/api/auth/mcp/register", map[string]any{
		"client_name": "Example MCP client", "redirect_uris": []string{clientCallback}, "token_endpoint_auth_method": "none",
	}), 201, &reg)

	// Step 3: the user's browser: authorize → login page → sign-in → back to the client with a code
	verifier := "a-long-random-pkce-verifier-0123456789-abcdefghijkl"
	sum := sha256.Sum256([]byte(verifier))
	query := url.Values{"response_type": {"code"}, "client_id": {reg.ClientID}, "redirect_uri": {clientCallback}, "state": {"s1"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}, "scope": {"openid offline_access"}}.Encode()
	browser := c.Fork()
	r = browser.Get("/api/auth/mcp/authorize?" + query)
	if r.Status != 302 || r.Header.Get("Location") != "/login?"+query {
		t.Fatalf("authorize: %d %s", r.Status, r.Header.Get("Location"))
	}
	r = browser.SignIn("dev@example.com", "Password123!")
	back, _ := url.Parse(r.Header.Get("Location"))
	if r.Status != 302 || back.Query().Get("state") != "s1" || back.Query().Get("code") == "" {
		t.Fatalf("sign-in: %d %s", r.Status, r.Header.Get("Location"))
	}

	// Step 4: the client exchanges the code with the PKCE verifier (no secret)
	var tok struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	mcpClient.MustOK(mcpClient.Post("/api/auth/mcp/token", map[string]any{
		"grant_type": "authorization_code", "code": back.Query().Get("code"), "redirect_uri": clientCallback,
		"client_id": reg.ClientID, "code_verifier": verifier,
	}), &tok)

	// Step 5: the MCP call with the access token
	var res struct {
		Result map[string]any `json:"result"`
	}
	mcpClient.MustOK(mcpClient.Post("/mcp", map[string]any{"jsonrpc": "2.0", "id": 2, "method": "whoami"},
		map[string]string{"Authorization": "Bearer " + tok.AccessToken}), &res)
	if res.Result["clientId"] != reg.ClientID || res.Result["method"] != "whoami" || res.Result["scopes"] != "openid offline_access" {
		t.Fatalf("whoami: %v", res.Result)
	}
}
