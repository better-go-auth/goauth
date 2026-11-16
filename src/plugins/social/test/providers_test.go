package test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
)

var ctx = context.Background()

func authURL(t *testing.T, p providers.Provider, in providers.AuthorizationURLInput) url.Values {
	t.Helper()
	u, err := p.CreateAuthorizationURL(ctx, in)
	if err != nil {
		t.Fatalf("%s: %v", p.ID(), err)
	}
	return u.Query()
}

func opts() providers.ProviderOptions {
	return providers.ProviderOptions{ClientID: "cid", ClientSecret: "secret"}
}

func TestBuiltInAuthorizationURLs(t *testing.T) {
	in := providers.AuthorizationURLInput{State: "st", CodeVerifier: "verifier", RedirectURI: "http://app/cb", Scopes: []string{"x"}, LoginHint: "lh"}
	cases := []struct {
		p         providers.Provider
		host      string
		scope     string
		pkce      bool
		extraKey  string
		extraWant string
	}{
		{providers.Google(providers.GoogleOptions{ProviderOptions: opts(), HD: "corp.com"}), "accounts.google.com", "email profile openid x", true, "hd", "corp.com"},
		{providers.GitHub(providers.GitHubOptions{ProviderOptions: opts()}), "github.com", "read:user user:email x", true, "login_hint", "lh"},
		{providers.Microsoft(providers.MicrosoftOptions{ProviderOptions: opts(), TenantID: "tenant-1"}), "login.microsoftonline.com", "openid profile email User.Read offline_access x", true, "login_hint", "lh"},
		{providers.Apple(providers.AppleOptions{ProviderOptions: opts()}), "appleid.apple.com", "email name x", false, "response_mode", "form_post"},
		{providers.Facebook(providers.FacebookOptions{ProviderOptions: opts(), ConfigID: "cfg"}), "www.facebook.com", "email public_profile x", false, "config_id", "cfg"},
		{providers.GitLab(providers.GitLabOptions{ProviderOptions: opts()}), "gitlab.com", "read_user x", true, "login_hint", "lh"},
		{providers.Discord(providers.DiscordOptions{ProviderOptions: opts()}), "discord.com", "identify email x", false, "prompt", "none"},
	}
	for _, c := range cases {
		u, err := c.p.CreateAuthorizationURL(ctx, in)
		if err != nil {
			t.Fatalf("%s: %v", c.p.ID(), err)
		}
		q := u.Query()
		if u.Host != c.host {
			t.Errorf("%s: host %s", c.p.ID(), u.Host)
		}
		if q.Get("scope") != c.scope {
			t.Errorf("%s: scope %q, want %q", c.p.ID(), q.Get("scope"), c.scope)
		}
		if q.Get("client_id") != "cid" || q.Get("state") != "st" || q.Get("redirect_uri") != "http://app/cb" {
			t.Errorf("%s: missing standard params: %s", c.p.ID(), u)
		}
		if got := q.Get("code_challenge") != ""; got != c.pkce {
			t.Errorf("%s: pkce=%v want %v", c.p.ID(), got, c.pkce)
		}
		if c.pkce && q.Get("code_challenge") != providers.CodeChallenge("verifier") {
			t.Errorf("%s: wrong challenge", c.p.ID())
		}
		if q.Get(c.extraKey) != c.extraWant {
			t.Errorf("%s: %s=%q want %q", c.p.ID(), c.extraKey, q.Get(c.extraKey), c.extraWant)
		}
	}
	// microsoft tenant path, apple response_type
	ms, _ := providers.Microsoft(providers.MicrosoftOptions{ProviderOptions: opts(), TenantID: "tenant-1"}).CreateAuthorizationURL(ctx, in)
	if ms.Path != "/tenant-1/oauth2/v2.0/authorize" {
		t.Errorf("microsoft path %s", ms.Path)
	}
	if q := authURL(t, providers.Apple(providers.AppleOptions{ProviderOptions: opts()}), in); q.Get("response_type") != "code id_token" {
		t.Errorf("apple response_type %q", q.Get("response_type"))
	}
	if q := authURL(t, providers.Google(providers.GoogleOptions{ProviderOptions: opts()}), in); q.Get("include_granted_scopes") != "true" {
		t.Error("google include_granted_scopes missing")
	}
}

func TestProviderOptions(t *testing.T) {
	in := providers.AuthorizationURLInput{State: "st", CodeVerifier: "v", RedirectURI: "http://app/cb", Scopes: []string{"req"}}
	o := opts()
	o.DisableDefaultScope = true
	o.Scope = []string{"cfg"}
	o.RedirectURI = "http://override/cb"
	o.Prompt = "consent"
	o.AccessType = "offline"
	o.AuthorizationEndpoint = "http://fake/auth"
	q := authURL(t, providers.Google(providers.GoogleOptions{ProviderOptions: o}), in)
	if q.Get("scope") != "cfg req" || q.Get("redirect_uri") != "http://override/cb" || q.Get("prompt") != "consent" || q.Get("access_type") != "offline" {
		t.Fatalf("options ignored: %v", q)
	}
	// google and apple require client credentials
	if _, err := providers.Google(providers.GoogleOptions{}).CreateAuthorizationURL(ctx, in); err == nil {
		t.Fatal("google without credentials should fail")
	}
	if _, err := providers.Google(providers.GoogleOptions{ProviderOptions: opts()}).CreateAuthorizationURL(ctx, providers.AuthorizationURLInput{State: "s"}); err == nil {
		t.Fatal("google without code verifier should fail")
	}
	if _, err := providers.Apple(providers.AppleOptions{}).CreateAuthorizationURL(ctx, in); err == nil {
		t.Fatal("apple without credentials should fail")
	}
	// id token support detection
	if _, ok := providers.AsIDTokenVerifier(providers.GitHub(providers.GitHubOptions{})); ok {
		t.Fatal("github does not support id tokens")
	}
	if _, ok := providers.AsIDTokenVerifier(providers.Google(providers.GoogleOptions{})); !ok {
		t.Fatal("google supports id tokens")
	}
	if _, ok := providers.AsIDTokenVerifier(providers.Generic(providers.GenericOptions{ProviderID: "g"})); ok {
		t.Fatal("generic without JWKS does not support id tokens")
	}
}

// apiServer serves fixed JSON per path and records Authorization headers.
func apiServer(t *testing.T, routes map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, ok := routes[r.URL.Path]
		if !ok || r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestGitHubUserInfo(t *testing.T) {
	srv := apiServer(t, map[string]any{
		"/user":   map[string]any{"id": 42, "login": "octo", "name": "", "email": nil, "avatar_url": "https://a/42"},
		"/emails": []map[string]any{{"email": "other@x.com", "primary": false, "verified": true}, {"email": "octo@x.com", "primary": true, "verified": true}},
	})
	o := opts()
	o.UserInfoEndpoint = srv.URL + "/user"
	p := providers.GitHub(providers.GitHubOptions{ProviderOptions: o, EmailsEndpoint: srv.URL + "/emails"})
	res, err := p.GetUserInfo(ctx, providers.UserInfoInput{OAuth2Tokens: providers.OAuth2Tokens{AccessToken: "tok"}})
	if err != nil || res == nil {
		t.Fatalf("github user info: %v", err)
	}
	u := res.User
	if u.ID != "42" || u.Name != "octo" || u.Email != "octo@x.com" || !u.EmailVerified || u.Image != "https://a/42" {
		t.Fatalf("unexpected github user %+v", u)
	}
	// bad token → nil
	if res, _ := p.GetUserInfo(ctx, providers.UserInfoInput{OAuth2Tokens: providers.OAuth2Tokens{AccessToken: "bad"}}); res != nil {
		t.Fatal("expected nil user for a bad token")
	}
}

func TestDiscordAndGitLabUserInfo(t *testing.T) {
	srv := apiServer(t, map[string]any{
		"/discord": map[string]any{"id": "80351110224678912", "username": "nelly", "global_name": "Nelly", "avatar": "a_abc", "discriminator": "0", "email": "n@x.com", "verified": true},
		"/gitlab":  map[string]any{"id": 7, "username": "gl", "name": "Git Lab", "email": "gl@x.com", "state": "active", "avatar_url": "https://gl/7"},
		"/blocked": map[string]any{"id": 8, "state": "blocked", "email": "b@x.com"},
	})
	o := opts()
	o.UserInfoEndpoint = srv.URL + "/discord"
	d, _ := providers.Discord(providers.DiscordOptions{ProviderOptions: o}).GetUserInfo(ctx, providers.UserInfoInput{OAuth2Tokens: providers.OAuth2Tokens{AccessToken: "tok"}})
	if d == nil || d.User.Name != "Nelly" || d.User.Image != "https://cdn.discordapp.com/avatars/80351110224678912/a_abc.gif" || !d.User.EmailVerified {
		t.Fatalf("unexpected discord user %+v", d)
	}
	o.UserInfoEndpoint = srv.URL + "/gitlab"
	g, _ := providers.GitLab(providers.GitLabOptions{ProviderOptions: o}).GetUserInfo(ctx, providers.UserInfoInput{OAuth2Tokens: providers.OAuth2Tokens{AccessToken: "tok"}})
	if g == nil || g.User.ID != "7" || g.User.Name != "Git Lab" || g.User.Email != "gl@x.com" {
		t.Fatalf("unexpected gitlab user %+v", g)
	}
	o.UserInfoEndpoint = srv.URL + "/blocked"
	if b, _ := providers.GitLab(providers.GitLabOptions{ProviderOptions: o}).GetUserInfo(ctx, providers.UserInfoInput{OAuth2Tokens: providers.OAuth2Tokens{AccessToken: "tok"}}); b != nil {
		t.Fatal("blocked gitlab user must be rejected")
	}
}

func TestIDTokenProviders(t *testing.T) {
	fake := socialtest.New("cid", "secret")
	defer fake.Close()
	prof := socialtest.Profile{Sub: "s1", Email: "e@x.com", EmailVerified: true, Name: "N"}

	// apple: issuer appleid.apple.com, sha256 nonce, name from the `user` field
	fake.Issuer = "https://appleid.apple.com"
	o := opts()
	o.JWKSEndpoint = fake.JWKSEndpoint()
	apple := providers.Apple(providers.AppleOptions{ProviderOptions: o}).(providers.IDTokenVerifier)
	tok := fake.SignIDToken(prof, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", nil) // sha256("test")
	if ok, _ := apple.VerifyIDToken(ctx, tok, "test"); !ok {
		t.Fatal("apple should accept a sha256 nonce")
	}
	if ok, _ := apple.VerifyIDToken(ctx, tok, "other"); ok {
		t.Fatal("apple should reject a wrong nonce")
	}
	res, _ := providers.Apple(providers.AppleOptions{ProviderOptions: o}).GetUserInfo(ctx, providers.UserInfoInput{
		OAuth2Tokens: providers.OAuth2Tokens{IDToken: tok},
		User:         &providers.AppleUser{Name: &providers.AppleUserName{FirstName: "Ada", LastName: "L"}},
	})
	if res == nil || res.User.Name != "Ada L" || res.User.ID != "s1" {
		t.Fatalf("unexpected apple user %+v", res)
	}

	// microsoft: issuer pinned for a specific tenant
	fake.Issuer = "https://login.example.com/tenant-1/v2.0"
	ms := providers.Microsoft(providers.MicrosoftOptions{ProviderOptions: o, TenantID: "tenant-1", Authority: "https://login.example.com", DisableProfilePhoto: true})
	if ok, _ := ms.(providers.IDTokenVerifier).VerifyIDToken(ctx, fake.SignIDToken(prof, "", nil), ""); !ok {
		t.Fatal("microsoft should accept its tenant issuer")
	}
	fake.Issuer = "https://elsewhere"
	if ok, _ := ms.(providers.IDTokenVerifier).VerifyIDToken(ctx, fake.SignIDToken(prof, "", nil), ""); ok {
		t.Fatal("microsoft should reject another issuer")
	}
	// disableIdTokenSignIn
	o.DisableIDTokenSignIn = true
	fake.Issuer = "https://accounts.google.com"
	if ok, _ := providers.Google(providers.GoogleOptions{ProviderOptions: o}).(providers.IDTokenVerifier).VerifyIDToken(ctx, fake.SignIDToken(prof, "", nil), ""); ok {
		t.Fatal("disableIdTokenSignIn ignored")
	}
}

func TestParseTokensAndCodeChallenge(t *testing.T) {
	tk := providers.ParseTokens(map[string]any{"access_token": "a", "refresh_token": "r", "expires_in": float64(60), "scope": "a b", "id_token": "i", "token_type": "Bearer"})
	if tk.AccessToken != "a" || tk.RefreshToken != "r" || tk.AccessTokenExpiresAt == nil || strings.Join(tk.Scopes, ",") != "a,b" || tk.IDToken != "i" {
		t.Fatalf("unexpected tokens %+v", tk)
	}
	// RFC 7636 appendix B
	if got := providers.CodeChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("code challenge %s", got)
	}
}
