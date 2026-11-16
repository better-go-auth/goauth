// Package socialtest provides an in-process fake OAuth 2.0 / OpenID Connect provider for testing the social
// plugin: authorize (redirects back with code + state), token (checks client credentials, redirect_uri and the
// PKCE S256 code_verifier; refresh_token grant), userinfo and JWKS endpoints, plus id_token signing helpers.
package socialtest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Profile is the user the fake provider authenticates (standard OIDC claims).
type Profile struct {
	Sub           string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name,omitempty"`
	Picture       string `json:"picture,omitempty"`
}

func (p Profile) claims() map[string]any {
	c := map[string]any{"sub": p.Sub, "email_verified": p.EmailVerified}
	if p.Email != "" {
		c["email"] = p.Email
	}
	if p.Name != "" {
		c["name"] = p.Name
	}
	if p.Picture != "" {
		c["picture"] = p.Picture
	}
	return c
}

type grant struct {
	challenge, method, redirectURI, scope, clientID string
	profile                                         Profile
}

// Provider is the fake. All fields guarded by mu; use the methods.
type Provider struct {
	Server       *httptest.Server
	ClientID     string
	ClientSecret string
	// Issuer is the "iss" of minted id tokens (default: the server URL).
	Issuer string
	Key    *rsa.PrivateKey
	KID    string

	mu sync.Mutex
	// RedirectBase rewrites the scheme+host of redirect_uri when redirecting back (the app's BaseURL is not the
	// test server's address).
	redirectBase  string
	user          Profile
	authorizeErr  string
	expiresIn     int
	codes         map[string]*grant
	access        map[string]Profile
	refresh       map[string]Profile
	lastAuthorize url.Values
	lastToken     url.Values
	refreshCount  int
	rotateRefresh bool
	userinfoFail  bool
}

// New starts a fake provider; it is closed with Close.
func New(clientID, clientSecret string) *Provider {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	p := &Provider{
		ClientID: clientID, ClientSecret: clientSecret, Key: key, KID: "fake-key-1",
		expiresIn: 3600, codes: map[string]*grant{}, access: map[string]Profile{}, refresh: map[string]Profile{},
		rotateRefresh: true,
		user:          Profile{Sub: "fake-user-1", Email: "fake.user@example.com", EmailVerified: true, Name: "Fake User", Picture: "https://img.example.com/u1.png"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", p.authorize)
	mux.HandleFunc("/token", p.token)
	mux.HandleFunc("/userinfo", p.userinfo)
	mux.HandleFunc("/jwks", p.jwks)
	p.Server = httptest.NewServer(mux)
	p.Issuer = p.Server.URL
	return p
}

// Close stops the server.
func (p *Provider) Close() { p.Server.Close() }

// URL returns the server URL.
func (p *Provider) URL() string { return p.Server.URL }

// AuthorizationEndpoint, TokenEndpoint, UserInfoEndpoint and JWKSEndpoint are the fake's endpoints.
func (p *Provider) AuthorizationEndpoint() string { return p.Server.URL + "/authorize" }
func (p *Provider) TokenEndpoint() string         { return p.Server.URL + "/token" }
func (p *Provider) UserInfoEndpoint() string      { return p.Server.URL + "/userinfo" }
func (p *Provider) JWKSEndpoint() string          { return p.Server.URL + "/jwks" }

// SetRedirectBase makes authorize redirect to base + the redirect_uri's path.
func (p *Provider) SetRedirectBase(base string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.redirectBase = strings.TrimRight(base, "/")
}

// SetUser selects the user the next authorization signs in.
func (p *Provider) SetUser(u Profile) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.user = u
}

// SetAuthorizeError makes authorize redirect back with ?error=code.
func (p *Provider) SetAuthorizeError(code string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.authorizeErr = code
}

// SetExpiresIn sets expires_in of issued access tokens (seconds).
func (p *Provider) SetExpiresIn(s int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expiresIn = s
}

// SetUserInfoFailure makes /userinfo answer 500.
func (p *Provider) SetUserInfoFailure(fail bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.userinfoFail = fail
}

// LastAuthorize returns the query of the last authorize request.
func (p *Provider) LastAuthorize() url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastAuthorize
}

// LastTokenRequest returns the form of the last token request.
func (p *Provider) LastTokenRequest() url.Values {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastToken
}

// RefreshCount is the number of successful refresh_token grants.
func (p *Provider) RefreshCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.refreshCount
}

// IsAccessToken reports whether tok was issued and is still known.
func (p *Provider) IsAccessToken(tok string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.access[tok]
	return ok
}

// RefreshTokens returns the refresh tokens currently valid.
func (p *Provider) RefreshTokens() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []string
	for k := range p.refresh {
		out = append(out, k)
	}
	return out
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	// Step 1: record and validate the request
	q := r.URL.Query()
	p.mu.Lock()
	p.lastAuthorize = q
	user, authErr, base := p.user, p.authorizeErr, p.redirectBase
	p.mu.Unlock()
	if q.Get("client_id") != p.ClientID || q.Get("response_type") != "code" || q.Get("redirect_uri") == "" {
		http.Error(w, "invalid_request", http.StatusBadRequest)
		return
	}
	target, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	if base != "" {
		b, _ := url.Parse(base)
		target.Scheme, target.Host = b.Scheme, b.Host
	}
	// Step 2: redirect back with either an error or a one-time code
	back := target.Query()
	back.Set("state", q.Get("state"))
	if authErr != "" {
		back.Set("error", authErr)
		back.Set("error_description", "The user denied access")
	} else {
		code := "code-" + randHex(12)
		p.mu.Lock()
		p.codes[code] = &grant{challenge: q.Get("code_challenge"), method: q.Get("code_challenge_method"), redirectURI: q.Get("redirect_uri"), scope: q.Get("scope"), clientID: q.Get("client_id"), profile: user}
		p.mu.Unlock()
		back.Set("code", code)
	}
	target.RawQuery = back.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (p *Provider) clientOK(r *http.Request) bool {
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	return id == p.ClientID && secret == p.ClientSecret
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	// Step 1: client authentication
	if err := r.ParseForm(); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid_request"})
		return
	}
	p.mu.Lock()
	p.lastToken = r.PostForm
	p.mu.Unlock()
	if !p.clientOK(r) {
		writeJSON(w, 401, map[string]string{"error": "invalid_client"})
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		// Step 2: one-time code, same redirect_uri, PKCE S256
		p.mu.Lock()
		g, ok := p.codes[r.PostForm.Get("code")]
		delete(p.codes, r.PostForm.Get("code"))
		p.mu.Unlock()
		if !ok || g.redirectURI != r.PostForm.Get("redirect_uri") {
			writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
			return
		}
		if g.challenge != "" {
			sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if g.method != "S256" || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
				writeJSON(w, 400, map[string]string{"error": "invalid_grant", "error_description": "PKCE verification failed"})
				return
			}
		}
		writeJSON(w, 200, p.issue(g.profile, g.scope, true))
	case "refresh_token":
		// Step 3: refresh grant
		p.mu.Lock()
		prof, ok := p.refresh[r.PostForm.Get("refresh_token")]
		if ok {
			p.refreshCount++
			if p.rotateRefresh {
				delete(p.refresh, r.PostForm.Get("refresh_token"))
			}
		}
		p.mu.Unlock()
		if !ok {
			writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
			return
		}
		writeJSON(w, 200, p.issue(prof, "", p.rotateRefresh))
	default:
		writeJSON(w, 400, map[string]string{"error": "unsupported_grant_type"})
	}
}

// issue mints access (+ refresh) tokens and an id_token for prof.
func (p *Provider) issue(prof Profile, scope string, withRefresh bool) map[string]any {
	p.mu.Lock()
	expiresIn := p.expiresIn
	at := "at-" + randHex(12)
	p.access[at] = prof
	out := map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": expiresIn}
	if withRefresh {
		rt := "rt-" + randHex(12)
		p.refresh[rt] = prof
		out["refresh_token"] = rt
	}
	p.mu.Unlock()
	if scope != "" {
		out["scope"] = scope
	}
	out["id_token"] = p.SignIDToken(prof, "", nil)
	return out
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	fail := p.userinfoFail
	prof, ok := p.access[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	p.mu.Unlock()
	if fail {
		writeJSON(w, 500, map[string]string{"error": "server_error"})
		return
	}
	if !ok {
		writeJSON(w, 401, map[string]string{"error": "invalid_token"})
		return
	}
	writeJSON(w, 200, prof.claims())
}

func (p *Provider) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := p.Key.PublicKey
	writeJSON(w, 200, map[string]any{"keys": []map[string]any{{
		"kty": "RSA", "kid": p.KID, "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// SignIDToken mints an RS256 id_token for prof (iss = Issuer, aud = ClientID, 1h expiry). extra overrides claims.
func (p *Provider) SignIDToken(prof Profile, nonce string, extra map[string]any) string {
	return p.SignIDTokenWithKey(p.Key, prof, nonce, extra)
}

// SignIDTokenWithKey is SignIDToken with another signing key (for invalid signature tests); the kid stays.
func (p *Provider) SignIDTokenWithKey(key *rsa.PrivateKey, prof Profile, nonce string, extra map[string]any) string {
	now := time.Now()
	claims := jwt.MapClaims{"iss": p.Issuer, "aud": p.ClientID, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()}
	for k, v := range prof.claims() {
		claims[k] = v
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	for k, v := range extra {
		if v == nil {
			delete(claims, k)
			continue
		}
		claims[k] = v
	}
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	t.Header["kid"] = p.KID
	s, err := t.SignedString(key)
	if err != nil {
		panic(err)
	}
	return s
}
