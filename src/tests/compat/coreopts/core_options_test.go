package coreopts

import (
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// mailbox records the password-reset links goauth "sends".
type mailbox struct {
	mu    sync.Mutex
	links []string
	toks  []string
}

func (m *mailbox) send(d config.ResetPasswordData, _ *http.Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.links = append(m.links, d.URL)
	m.toks = append(m.toks, d.Token)
	return nil
}

func (m *mailbox) last(t *testing.T) (string, string) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.links) == 0 {
		t.Fatal("no reset email sent")
	}
	return m.links[len(m.links)-1], m.toks[len(m.toks)-1]
}

func TestTrustedOriginsFunction(t *testing.T) {
	// Step 1: origins computed from each request (better-auth's trustedOrigins: (request) => [...])
	s := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) {
		c.TrustedOriginsFunc = func(r *http.Request) []string {
			if r != nil && r.Header.Get("X-Tenant") == "acme" {
				return []string{"https://acme.example.org"}
			}
			return nil
		}
	}))
	// Step 2: the origin check of sign-up accepts the tenant origin only for the matching request
	body := map[string]any{"email": "tenant@example.com", "password": password, "name": "T"}
	expectCode(t, call(t, s, http.MethodPost, "/api/auth/sign-up/email", body, map[string]string{"Origin": "https://acme.example.org"}), http.StatusForbidden, "INVALID_ORIGIN")
	r := call(t, s, http.MethodPost, "/api/auth/sign-up/email", body, map[string]string{"Origin": "https://acme.example.org", "X-Tenant": "acme"})
	if r.Status != http.StatusOK {
		t.Fatalf("tenant origin: %d %s", r.Status, r.Body)
	}
	// Step 3: redirect targets are checked against the same per-request list
	other := map[string]any{"email": "tenant2@example.com", "password": password, "name": "T", "callbackURL": "https://acme.example.org/welcome"}
	expectCode(t, call(t, s, http.MethodPost, "/api/auth/sign-up/email", other, map[string]string{"Origin": s.Origin}), http.StatusForbidden, "INVALID_CALLBACK_URL")
	r = call(t, s, http.MethodPost, "/api/auth/sign-up/email", other, map[string]string{"Origin": s.Origin, "X-Tenant": "acme"})
	if r.Status != http.StatusOK {
		t.Fatalf("tenant callbackURL: %d %s", r.Status, r.Body)
	}
}

func TestDynamicBaseURLAllowedHosts(t *testing.T) {
	box := &mailbox{}
	// Step 1: no static BaseURL, only allowed hosts (better-auth's baseURL: {allowedHosts})
	s := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) {
		c.BaseURL = ""
		c.DynamicBaseURL = &config.DynamicBaseURL{AllowedHosts: []string{"app.example.com", "*.preview.example.com"}}
		c.EmailAndPassword.SendResetPassword = box.send
	}))
	signUp(t, s, "dyn@example.com", map[string]string{"Host": "app.example.com", "Origin": "https://app.example.com"})
	reset := func(headers map[string]string) *http.Response {
		r := call(t, s, http.MethodPost, "/api/auth/request-password-reset", map[string]any{"email": "dyn@example.com"}, headers)
		return &http.Response{StatusCode: r.Status, Header: r.Header}
	}
	// Step 2: links use the request host (https by default for non-loopback hosts)
	if r := reset(map[string]string{"Host": "app.example.com"}); r.StatusCode != http.StatusOK {
		t.Fatalf("reset: %d", r.StatusCode)
	}
	if link, _ := box.last(t); !strings.HasPrefix(link, "https://app.example.com/api/auth/reset-password/") {
		t.Fatalf("link for Host: %s", link)
	}
	// Step 3: X-Forwarded-Host / -Proto are trusted by default with a dynamic base URL
	reset(map[string]string{"Host": "internal:8080", "X-Forwarded-Host": "pr-7.preview.example.com", "X-Forwarded-Proto": "http"})
	if link, _ := box.last(t); !strings.HasPrefix(link, "http://pr-7.preview.example.com/api/auth/reset-password/") {
		t.Fatalf("link for X-Forwarded-Host: %s", link)
	}
	// Step 4: hosts outside the list are rejected without a fallback
	r := call(t, s, http.MethodPost, "/api/auth/request-password-reset", map[string]any{"email": "dyn@example.com"}, map[string]string{"Host": "evil.example.net"})
	expectCode(t, r, http.StatusBadRequest, "HOST_NOT_ALLOWED")
	r = call(t, s, http.MethodGet, "/api/auth/get-session", nil, map[string]string{"Host": "app.example.com", "X-Forwarded-Host": "evil.example.net"})
	expectCode(t, r, http.StatusBadRequest, "HOST_NOT_ALLOWED")
	// Step 5: allowed hosts are trusted origins, others are not
	body := map[string]any{"email": "dyn2@example.com", "password": password, "name": "D"}
	expectCode(t, call(t, s, http.MethodPost, "/api/auth/sign-up/email", body, map[string]string{"Host": "app.example.com", "Origin": "https://evil.example.net"}), http.StatusForbidden, "INVALID_ORIGIN")
	if r := call(t, s, http.MethodPost, "/api/auth/sign-up/email", body, map[string]string{"Host": "app.example.com", "Origin": "https://x.preview.example.com"}); r.Status != http.StatusOK {
		t.Fatalf("allowed-host origin: %d %s", r.Status, r.Body)
	}
}

func TestDynamicBaseURLFallbackAndUntrustedProxy(t *testing.T) {
	box := &mailbox{}
	no := false
	s := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) {
		c.BaseURL = ""
		c.DynamicBaseURL = &config.DynamicBaseURL{AllowedHosts: []string{"app.example.com"}, Fallback: "https://main.example.com", Protocol: "https"}
		c.Advanced.TrustedProxyHeaders = &no
		c.EmailAndPassword.SendResetPassword = box.send
	}))
	signUp(t, s, "fb@example.com", map[string]string{"Host": "app.example.com", "Origin": "https://app.example.com"})
	// Step 1: unknown hosts use the fallback instead of failing
	call(t, s, http.MethodPost, "/api/auth/request-password-reset", map[string]any{"email": "fb@example.com"}, map[string]string{"Host": "unknown.example.net"})
	if link, _ := box.last(t); !strings.HasPrefix(link, "https://main.example.com/api/auth/") {
		t.Fatalf("fallback link: %s", link)
	}
	// Step 2: with trustedProxyHeaders off X-Forwarded-Host is ignored (the Host header decides)
	call(t, s, http.MethodPost, "/api/auth/request-password-reset", map[string]any{"email": "fb@example.com"}, map[string]string{"Host": "app.example.com", "X-Forwarded-Host": "unknown.example.net"})
	if link, _ := box.last(t); !strings.HasPrefix(link, "https://app.example.com/api/auth/") {
		t.Fatalf("Host link: %s", link)
	}
}

func TestCookieOverridesInSetCookie(t *testing.T) {
	yes, no := true, false
	s := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) {
		c.Advanced.DefaultCookieAttributes = &config.CookieAttributes{SameSite: "none", Secure: &yes, Partitioned: &yes}
		c.Advanced.Cookies = map[string]config.CookieOverride{
			"session_token": {Name: "my_app.sid", Attributes: config.CookieAttributes{Path: "/api", SameSite: "strict"}},
			"dont_remember": {Attributes: config.CookieAttributes{HTTPOnly: &no}},
		}
	}))
	// Step 1: sign-in with rememberMe=false sets both cookies
	signUp(t, s, "cookie@example.com", nil)
	r := call(t, s, http.MethodPost, "/api/auth/sign-in/email", map[string]any{"email": "cookie@example.com", "password": password, "rememberMe": false}, map[string]string{"Origin": s.Origin})
	if r.Status != http.StatusOK {
		t.Fatalf("sign-in: %d %s", r.Status, r.Body)
	}
	var tokenLine, drLine string
	for _, line := range r.Header.Values("Set-Cookie") {
		switch {
		case strings.HasPrefix(line, "my_app.sid="):
			tokenLine = line
		case strings.HasPrefix(line, "better-auth.dont_remember="):
			drLine = line
		}
	}
	// Step 2: the renamed session cookie carries its own attributes over the defaults
	for _, want := range []string{"Path=/api", "SameSite=Strict", "Secure", "Partitioned", "HttpOnly"} {
		if !strings.Contains(tokenLine, want) {
			t.Fatalf("session cookie %q lacks %q", tokenLine, want)
		}
	}
	// Step 3: other cookies get the default attributes and their own overrides
	if !strings.Contains(drLine, "SameSite=None") || !strings.Contains(drLine, "Partitioned") || strings.Contains(drLine, "HttpOnly") {
		t.Fatalf("dont_remember cookie: %q", drLine)
	}
	// Step 4: the renamed cookie is what goauth reads back
	if got := sessionEmail(t, s, cookieHeader(r)); got != "cookie@example.com" {
		t.Fatalf("session from renamed cookie: %q", got)
	}
}

func TestHashedVerificationIdentifiers(t *testing.T) {
	box := &mailbox{}
	s := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) {
		c.Verification.StoreIdentifier = config.StoreIdentifierOption{Mode: config.StoreIdentifierHashed}
		c.EmailAndPassword.SendResetPassword = box.send
	}))
	signUp(t, s, "hash@example.com", nil)
	// Step 1: the reset token is stored hashed: no row carries the plain identifier
	if r := call(t, s, http.MethodPost, "/api/auth/request-password-reset", map[string]any{"email": "hash@example.com"}, map[string]string{"Origin": s.Origin}); r.Status != http.StatusOK {
		t.Fatalf("request-password-reset: %d %s", r.Status, r.Body)
	}
	_, tok := box.last(t)
	plain := "reset-password:" + tok
	var n int64
	s.DB.Model(&models.Verification{}).Where("identifier = ?", plain).Count(&n)
	if n != 0 {
		t.Fatal("plain identifier must not be stored")
	}
	s.DB.Model(&models.Verification{}).Where("identifier = ?", config.HashIdentifier(plain)).Count(&n)
	if n != 1 {
		t.Fatalf("hashed identifier row: %d", n)
	}
	// Step 2: the token still works and is consumed
	r := call(t, s, http.MethodPost, "/api/auth/reset-password", map[string]any{"newPassword": "brand-new-password", "token": tok}, map[string]string{"Origin": s.Origin})
	if r.Status != http.StatusOK {
		t.Fatalf("reset-password: %d %s", r.Status, r.Body)
	}
	expectCode(t, call(t, s, http.MethodPost, "/api/auth/reset-password", map[string]any{"newPassword": "another-password-1", "token": tok}, map[string]string{"Origin": s.Origin}), http.StatusBadRequest, "INVALID_TOKEN")
	in := call(t, s, http.MethodPost, "/api/auth/sign-in/email", map[string]any{"email": "hash@example.com", "password": "brand-new-password"}, map[string]string{"Origin": s.Origin})
	if in.Status != http.StatusOK {
		t.Fatalf("sign-in with the new password: %d %s", in.Status, in.Body)
	}
}
