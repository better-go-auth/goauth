package cookies

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/dtos"
)

// tsVectors are written by a TypeScript better-auth 1.6 (src/tests/compat/client/gen-secret-vectors.mjs).
type tsVectors struct {
	LegacySecret     string `json:"legacySecret"`
	SecretV1         string `json:"secretV1"`
	SecretV2         string `json:"secretV2"`
	JWESessionV2     string `json:"jweSessionV2"`
	JWESessionV1     string `json:"jweSessionV1"`
	JWTSessionV2     string `json:"jwtSessionV2"`
	CompactSessionV2 string `json:"compactSessionV2"`
	SignedCookieV1   string `json:"signedCookieV1"`
	SignedCookieV2   string `json:"signedCookieV2"`
}

func loadTSVectors(t *testing.T) tsVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "authcrypto", "testdata", "better_auth_rotation_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v tsVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// rotatedManager is a Manager configured like the TypeScript server: secrets [v2, v1], legacy secret.
func rotatedManager(v tsVectors, mut func(*config.AuthConfig)) *Manager {
	conf := config.AuthConfig{
		BaseURL: "http://localhost:3000",
		Secret:  v.LegacySecret,
		Secrets: []config.SecretVersion{{Version: 2, Value: v.SecretV2}, {Version: 1, Value: v.SecretV1}},
	}
	if mut != nil {
		mut(&conf)
	}
	conf.SetDefaults()
	return New(conf)
}

func header(name, value string) string { return name + "=" + value }

func TestRotationSignsWithCurrentAndVerifiesOlderSecrets(t *testing.T) {
	v := loadTSVectors(t)
	m := rotatedManager(v, nil)
	name := m.Name(CookieSessionToken)

	// Step 1: new cookies are signed with v2, byte for byte what better-auth writes
	set := m.SessionCookies("tok_1", false)
	if DecodeCookieValue(set[0].Value) != v.SignedCookieV2 {
		t.Fatalf("v2 signature: %s want %s", DecodeCookieValue(set[0].Value), v.SignedCookieV2)
	}
	// Step 2: cookies signed with v1 (before the rotation) and with v2 verify
	for _, signed := range []string{v.SignedCookieV1, v.SignedCookieV2} {
		if tok, ok := m.SessionToken(header(name, EncodeCookieValue(signed))); !ok || tok != "tok_1" {
			t.Fatalf("verify %s: %q %v", signed, tok, ok)
		}
	}
	// Step 3: the legacy secret also verifies (sessions from before Secrets was configured)
	legacy := SignCookieValue("tok_1", v.LegacySecret)
	if tok, ok := m.SessionToken(header(name, EncodeCookieValue(legacy))); !ok || tok != "tok_1" {
		t.Fatalf("legacy verify: %q %v", tok, ok)
	}
	// Step 4: once v1 is retired its cookies are rejected; unknown secrets never verify
	retired := rotatedManager(v, func(c *config.AuthConfig) {
		c.Secret = ""
		c.Secrets = c.Secrets[:1]
	})
	if _, ok := retired.SessionToken(header(name, EncodeCookieValue(v.SignedCookieV1))); ok {
		t.Fatal("retired v1 cookie must not verify")
	}
	forged := SignCookieValue("tok_1", "attacker-secret-attacker-secret-xx")
	if _, ok := m.SessionToken(header(name, EncodeCookieValue(forged))); ok {
		t.Fatal("unknown secret must not verify")
	}
}

func TestCookieCacheReadsTypeScriptCookies(t *testing.T) {
	v := loadTSVectors(t)
	cases := map[config.CookieCacheStrategy][]string{
		config.CookieCacheStrategyJwe:     {v.JWESessionV2, v.JWESessionV1},
		config.CookieCacheStrategyJwt:     {v.JWTSessionV2},
		config.CookieCacheStrategyCompact: {v.CompactSessionV2},
	}
	for strategy, values := range cases {
		m := rotatedManager(v, func(c *config.AuthConfig) {
			c.Session.CookieCache = &config.CookieCache{Enabled: boolP(true), Strategy: strategy}
		})
		for _, val := range values {
			// Step 1: a cookie written by the TS server is accepted
			sw, err := m.ReadSessionData(header(m.Name(CookieSessionData), val))
			if err != nil {
				t.Fatalf("%s: %v", strategy, err)
			}
			if sw.Session.Token != "tok_1" || sw.User.Email != "a@example.com" || sw.User.Name != "Ann <A&B>" {
				t.Fatalf("%s: %+v", strategy, sw)
			}
			if sw.Session.UserAgent == nil || *sw.Session.UserAgent != "node <test> & co" {
				t.Fatalf("%s: user agent %v", strategy, sw.Session.UserAgent)
			}
			// Step 2: a tampered cookie is refused
			tampered := val[:len(val)-3] + "abc"
			if _, err := m.ReadSessionData(header(m.Name(CookieSessionData), tampered)); err == nil {
				t.Fatalf("%s: tampered cookie accepted", strategy)
			}
		}
	}
}

func TestCookieCacheRoundTripAfterRotation(t *testing.T) {
	v := loadTSVectors(t)
	for _, strategy := range []config.CookieCacheStrategy{config.CookieCacheStrategyCompact, config.CookieCacheStrategyJwt, config.CookieCacheStrategyJwe} {
		cache := func(c *config.AuthConfig) {
			c.Session.CookieCache = &config.CookieCache{Enabled: boolP(true), Strategy: strategy}
		}
		// Step 1: a cookie written while v1 was the current secret
		before := rotatedManager(v, func(c *config.AuthConfig) {
			cache(c)
			c.Secrets = []config.SecretVersion{{Version: 1, Value: v.SecretV1}}
		})
		sw := sample()
		ck, err := before.CreateSessionDataCookie(sw, false)
		if err != nil {
			t.Fatal(err)
		}
		// Step 2: still readable after rotating to v2 (v1 kept)
		after := rotatedManager(v, cache)
		got, err := after.ReadSessionData(header(ck.Name, ck.Value))
		if err != nil || got.Session.Token != sw.Session.Token {
			t.Fatalf("%s rotated read: %v", strategy, err)
		}
		// Step 3: unreadable once v1 is retired
		retired := rotatedManager(v, func(c *config.AuthConfig) {
			cache(c)
			c.Secret = ""
			c.Secrets = c.Secrets[:1]
		})
		if _, err := retired.ReadSessionData(header(ck.Name, ck.Value)); err == nil {
			t.Fatalf("%s: retired secret accepted", strategy)
		}
	}
}

func TestCompactCookieCacheIsBetterAuthFormat(t *testing.T) {
	v := loadTSVectors(t)
	m := rotatedManager(v, func(c *config.AuthConfig) {
		c.Session.CookieCache = &config.CookieCache{Enabled: boolP(true)}
	})
	sw := sample()
	sw.User.Name = "A <b> & c"
	ck, err := m.CreateSessionDataCookie(sw, false)
	if err != nil {
		t.Fatal(err)
	}
	// Step 1: the envelope has better-auth's keys; expiresAt is in milliseconds
	env, err := base64RawURL(ck.Value)
	if err != nil {
		t.Fatal(err)
	}
	var outer map[string]json.RawMessage
	if err := json.Unmarshal(env, &outer); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"session", "expiresAt", "signature"} {
		if _, ok := outer[k]; !ok {
			t.Fatalf("missing %s in %s", k, env)
		}
	}
	if !strings.Contains(string(outer["session"]), `"name":"A <b> & c"`) {
		t.Fatalf("html must not be escaped: %s", outer["session"])
	}
	var exp int64
	_ = json.Unmarshal(outer["expiresAt"], &exp)
	if exp < time.Now().Add(time.Minute).UnixMilli() {
		t.Fatalf("expiresAt must be ms: %d", exp)
	}
}

func TestCookieOverridesAndDefaultAttributes(t *testing.T) {
	yes, no := true, false
	conf := config.AuthConfig{
		BaseURL: "https://app.example.com",
		Secret:  "s3cret-s3cret-s3cret-s3cret-s3cret",
		Advanced: config.Advanced{
			DefaultCookieAttributes: &config.CookieAttributes{SameSite: "none", Partitioned: &yes},
			Cookies: map[string]config.CookieOverride{
				CookieSessionToken: {Name: "my_session", Attributes: config.CookieAttributes{Domain: "example.com", Path: "/app", SameSite: "strict"}},
				CookieDontRemember: {Attributes: config.CookieAttributes{HTTPOnly: &no}},
			},
		},
	}
	conf.SetDefaults()
	m := New(conf)

	// Step 1: the overridden name keeps the __Secure- prefix; per-cookie attributes win over the defaults
	set := m.SessionCookies("tok", true)
	tok := set[0]
	if tok.Name != "__Secure-my_session" || tok.Domain != "example.com" || tok.Path != "/app" || tok.SameSite != http.SameSiteStrictMode || !tok.Partitioned || !tok.Secure {
		t.Fatalf("session_token: %+v", tok)
	}
	// Step 2: default attributes apply to cookies without overrides
	dr := set[1]
	if dr.Name != "__Secure-better-auth.dont_remember" || dr.SameSite != http.SameSiteNoneMode || dr.HttpOnly || !dr.Partitioned {
		t.Fatalf("dont_remember: %+v", dr)
	}
	// Step 3: Set-Cookie carries the overrides and the renamed cookie is read back
	line := tok.String()
	for _, part := range []string{"__Secure-my_session=", "Domain=example.com", "Path=/app", "SameSite=Strict", "Partitioned", "Secure", "HttpOnly"} {
		if !strings.Contains(line, part) {
			t.Fatalf("Set-Cookie %q lacks %q", line, part)
		}
	}
	if got, ok := m.SessionToken(tok.Name + "=" + tok.Value); !ok || got != "tok" {
		t.Fatalf("read renamed cookie: %q %v", got, ok)
	}
	if _, ok := m.SessionToken("__Secure-better-auth.session_token=" + tok.Value); ok {
		t.Fatal("the default name must not be read once renamed")
	}
	// Step 4: deletions keep the overridden attributes so the browser removes the right cookie
	del := m.ExpireCookie(CookieSessionToken)
	if del.Domain != "example.com" || del.Path != "/app" || del.MaxAge != -1 {
		t.Fatalf("expire: %+v", del)
	}
}

func TestChunkedCookies(t *testing.T) {
	m := newTestCookies("http://localhost:3000")
	name := m.Name(CookieAccountData)
	big := strings.Repeat("x", 9000)

	// Step 1: a large value is split in 4096-200 byte chunks
	set := m.ChunkedCookies("", CookieAccountData, big, 300)
	if len(set) != 3 || set[0].Name != name+".0" || len(set[0].Value) != chunkSize || set[2].Name != name+".2" {
		t.Fatalf("chunks: %d %s", len(set), set[0].Name)
	}
	var hdr []string
	for _, c := range set {
		hdr = append(hdr, c.Name+"="+c.Value)
	}
	got, ok := m.ReadChunked(strings.Join(hdr, "; "), CookieAccountData)
	if !ok || got != big {
		t.Fatal("chunks must join back")
	}
	// Step 2: a small value replaces the chunks, which are expired
	set = m.ChunkedCookies(strings.Join(hdr, "; "), CookieAccountData, "small", 300)
	if len(set) != 4 || set[3].Name != name || set[0].MaxAge != -1 {
		t.Fatalf("replace: %+v", set)
	}
	// Step 3: expiring removes the cookie and its chunks
	if del := m.ExpireChunkedCookies(strings.Join(hdr, "; "), CookieAccountData); len(del) != 4 {
		t.Fatalf("expire: %d", len(del))
	}
}

func boolP(b bool) *bool { return &b }

func base64RawURL(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func sample() *dtos.SessionWithUser {
	now := dtos.Time(time.Now().UTC())
	ua := "Go"
	return &dtos.SessionWithUser{
		Session: dtos.SessionData{ID: "s1", UserID: "u1", Token: "tok-rot", ExpiresAt: dtos.Time(time.Now().Add(time.Hour).UTC()), UserAgent: &ua, CreatedAt: now, UpdatedAt: now},
		User:    dtos.UserResponse{ID: "u1", Name: "U", Email: "u@example.com", CreatedAt: now, UpdatedAt: now},
	}
}
