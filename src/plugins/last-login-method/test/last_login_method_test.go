package test

import (
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins"
	lastloginmethod "github.com/better-go-auth/goauth/src/plugins/last-login-method"
	llmconfig "github.com/better-go-auth/goauth/src/plugins/last-login-method/config"
	"github.com/better-go-auth/goauth/src/plugins/last-login-method/services"
	magiclink "github.com/better-go-auth/goauth/src/plugins/magic-link"
	magiclinkconfig "github.com/better-go-auth/goauth/src/plugins/magic-link/config"
	"github.com/better-go-auth/goauth/src/plugins/social"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	"github.com/better-go-auth/goauth/src/plugins/username"
	usernameconfig "github.com/better-go-auth/goauth/src/plugins/username/config"
	"github.com/better-go-auth/goauth/src/schema"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

const (
	cookieName = "better-auth.last_used_login_method"
	password   = "Password123!"
)

func newServer(t *testing.T, mutate func(*config.AuthConfig), ps ...plugins.Plugin) *compattest.Server {
	t.Helper()
	opts := []compattest.Option{compattest.WithConfig(func(c *config.AuthConfig) {
		c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		if mutate != nil {
			mutate(c)
		}
	})}
	for _, p := range ps {
		opts = append(opts, compattest.WithPlugin(p))
	}
	s := compattest.NewServer(t, opts...)
	s.Client.Jar = nil
	return s
}

func signUp(t *testing.T, s *compattest.Server, email string) *compattest.Response {
	t.Helper()
	r := s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": email, "password": password, "name": "Last"})
	if r.Status != http.StatusOK {
		t.Fatalf("sign-up = %d: %s", r.Status, r.Body)
	}
	return r
}

// lastMethod returns the last-login-method cookie of a response (nil when not set).
func lastMethod(r *compattest.Response, name string) *http.Cookie { return r.Cookie(name) }

func expectMethod(t *testing.T, r *compattest.Response, want string) *http.Cookie {
	t.Helper()
	c := lastMethod(r, cookieName)
	if c == nil {
		t.Fatalf("no %s cookie (status %d): %v", cookieName, r.Status, r.Header.Values("Set-Cookie"))
	}
	if c.Value != want {
		t.Fatalf("method = %q, want %q", c.Value, want)
	}
	return c
}

func expectNoMethod(t *testing.T, r *compattest.Response) {
	t.Helper()
	if c := lastMethod(r, cookieName); c != nil {
		t.Fatalf("unexpected %s=%s", cookieName, c.Value)
	}
}

// ─── unit ────────────────────────────────────────────────────────────────────

func TestDefaultResolveMethod(t *testing.T) {
	cases := []struct{ path, urlPath, want string }{
		{"/sign-in/email", "/sign-in/email", "email"},
		{"/sign-up/email", "/sign-up/email", "email"},
		{"/callback/{id}", "/callback/github", "github"},
		{"/callback/google", "", "google"},
		{"/oauth2/callback/{providerId}", "/oauth2/callback/my-oidc", "my-oidc"},
		{"/magic-link/verify", "/magic-link/verify", "magic-link"},
		{"/passkey/verify-authentication", "/passkey/verify-authentication", "passkey"},
		{"/siwe/verify", "/siwe/verify", "siwe"},
		{"/sign-in/email-otp", "/sign-in/email-otp", ""},
		{"/sign-in/username", "/sign-in/username", ""},
		{"/one-tap/callback", "/one-tap/callback", ""},
		{"/get-session", "/get-session", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		if got := services.DefaultResolveMethod(c.path, c.urlPath); got != c.want {
			t.Errorf("DefaultResolveMethod(%q, %q) = %q, want %q", c.path, c.urlPath, got, c.want)
		}
	}
}

// ─── cookie ──────────────────────────────────────────────────────────────────

func TestEmailSignUpAndSignIn(t *testing.T) {
	s := newServer(t, nil, lastloginmethod.New(llmconfig.LastLoginMethodConfig{}))

	// Step 1: sign-up sets the cookie with better-auth's attributes
	r := signUp(t, s, "email@example.com")
	c := expectMethod(t, r, "email")
	if c.HttpOnly || c.MaxAge != 30*24*3600 || c.Path != "/" || c.SameSite != http.SameSiteLaxMode || c.Secure {
		t.Fatalf("cookie attributes = %+v", c)
	}
	// Step 2: sign-in too
	r = s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "email@example.com", "password": password})
	expectMethod(t, r, "email")
	// Step 3: a failed sign-in sets nothing
	r = s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "email@example.com", "password": "wrong-password"})
	if r.Status != http.StatusUnauthorized {
		t.Fatalf("bad sign-in = %d", r.Status)
	}
	expectNoMethod(t, r)
	// Step 4: other endpoints set nothing
	expectNoMethod(t, s.Get(t, "/api/auth/get-session"))
}

func TestSecureCookiesAndPrefix(t *testing.T) {
	s := newServer(t, func(c *config.AuthConfig) {
		c.BaseURL = "https://auth.example.com"
		c.Advanced.CookiePrefix = "myapp"
		c.TrustedOrigins = append(c.TrustedOrigins, "https://auth.example.com")
	}, lastloginmethod.New(llmconfig.LastLoginMethodConfig{}))
	r := s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "secure@example.com", "password": password, "name": "S"},
		map[string]string{"Origin": "https://auth.example.com"})
	if r.Status != http.StatusOK {
		t.Fatalf("sign-up = %d: %s", r.Status, r.Body)
	}
	if r.Cookie("__Secure-myapp.session_token") == nil {
		t.Fatalf("session cookie = %v", r.Header.Values("Set-Cookie"))
	}
	// the name is better-auth's literal default; the attributes follow the session cookie
	c := expectMethod(t, r, "email")
	if !c.Secure || c.HttpOnly {
		t.Fatalf("cookie = %+v", c)
	}
}

func TestCustomCookieNameMaxAgeAndResolver(t *testing.T) {
	p := lastloginmethod.New(llmconfig.LastLoginMethodConfig{CookieName: "last_method", MaxAge: time.Hour},
		lastloginmethod.WithCustomResolveMethod(func(c *endpointhooks.Context) (string, bool) {
			switch c.Path {
			case "/sign-in/username":
				return "username", true
			case "/sign-up/email":
				return "", true // explicitly no method
			}
			return "", false
		}))
	s := newServer(t, nil, username.New(usernameconfig.UsernameConfig{}), p)
	r := s.Post(t, "/api/auth/sign-up/email", map[string]any{"email": "u@example.com", "password": password, "name": "U", "username": "custom_user"})
	if r.Status != http.StatusOK {
		t.Fatalf("sign-up = %d: %s", r.Status, r.Body)
	}
	if r.Cookie("last_method") != nil {
		t.Fatal("resolver returned no method for sign-up")
	}
	r = s.Post(t, "/api/auth/sign-in/username", map[string]any{"username": "custom_user", "password": password})
	c := r.Cookie("last_method")
	if c == nil || c.Value != "username" || c.MaxAge != 3600 {
		t.Fatalf("cookie = %+v (%v)", c, r.Header.Values("Set-Cookie"))
	}
	// deferring falls back to the default rules
	r = s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "u@example.com", "password": password})
	if c := r.Cookie("last_method"); c == nil || c.Value != "email" {
		t.Fatalf("cookie = %+v", c)
	}
}

func TestMagicLink(t *testing.T) {
	var mu sync.Mutex
	var link string
	ml := magiclink.New(magiclinkconfig.MagicLinkConfig{SendMagicLink: func(d magiclinkconfig.SendMagicLinkData, _ *http.Request) error {
		mu.Lock()
		link = d.URL
		mu.Unlock()
		return nil
	}})
	s := newServer(t, nil, ml, lastloginmethod.New(llmconfig.LastLoginMethodConfig{}))
	r := s.Post(t, "/api/auth/sign-in/magic-link", map[string]any{"email": "magic@example.com"})
	if r.Status != http.StatusOK {
		t.Fatalf("magic-link = %d: %s", r.Status, r.Body)
	}
	mu.Lock()
	u, err := url.Parse(link)
	mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	r = s.Get(t, u.Path+"?"+u.RawQuery)
	expectMethod(t, r, "magic-link")
}

func TestSocialCallback(t *testing.T) {
	fake := socialtest.New("client-id", "client-secret")
	t.Cleanup(fake.Close)
	fake.SetUser(socialtest.Profile{Sub: "sub-1", Email: "social@example.com", EmailVerified: true, Name: "Social"})
	provider := providers.Generic(providers.GenericOptions{
		ProviderID: "fakeprov", Issuer: fake.Issuer,
		ProviderOptions: providers.ProviderOptions{
			ClientID: "client-id", ClientSecret: "client-secret",
			AuthorizationEndpoint: fake.AuthorizationEndpoint(), TokenEndpoint: fake.TokenEndpoint(),
			UserInfoEndpoint: fake.UserInfoEndpoint(), JWKSEndpoint: fake.JWKSEndpoint(),
		},
	})
	s := newServer(t, func(c *config.AuthConfig) { c.BaseURL = "http://localhost:3000" },
		social.New(socialconfig.SocialConfig{Providers: []providers.Provider{provider}}),
		lastloginmethod.New(llmconfig.LastLoginMethodConfig{}))
	fake.SetRedirectBase(s.URL)

	// Step 1: start the flow; the state cookie travels with the callback
	r := s.Post(t, "/api/auth/sign-in/social", map[string]any{"provider": "fakeprov", "disableRedirect": true})
	if r.Status != http.StatusOK {
		t.Fatalf("sign-in/social = %d: %s", r.Status, r.Body)
	}
	expectNoMethod(t, r)
	var start struct{ URL string }
	r.JSON(t, &start)
	var cookies []string
	for _, c := range (&http.Response{Header: r.Header}).Cookies() {
		cookies = append(cookies, c.Name+"="+c.Value)
	}
	// Step 2: the provider redirects back to /callback/fakeprov
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get(start.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cb := strings.TrimPrefix(resp.Header.Get("Location"), s.URL)
	r = s.Get(t, cb, map[string]string{"Cookie": strings.Join(cookies, "; ")})
	if r.Status != http.StatusFound {
		t.Fatalf("callback = %d: %s", r.Status, r.Body)
	}
	expectMethod(t, r, "fakeprov")
}

// ─── database ────────────────────────────────────────────────────────────────

// columnOf returns where the lastLoginMethod field lives: SetupGoAuth's migrator created the column from the
// plugin's SchemaProvider declaration.
func columnOf(t *testing.T, s *compattest.Server, fieldName string) (table, column string) {
	t.Helper()
	reg := s.Auth.Schema()
	table, column = reg.Table(schema.ModelUser), reg.Column(schema.ModelUser, llmconfig.FieldLastLoginMethod)
	if fieldName != "" && column != fieldName {
		t.Fatalf("column = %q, want %q", column, fieldName)
	}
	if !s.DB.Migrator().HasColumn(table, column) {
		t.Fatalf("the migrator did not create %s.%s", table, column)
	}
	return table, column
}

func storedMethod(t *testing.T, s *compattest.Server, table, column, email string) string {
	t.Helper()
	var v *string
	if err := s.DB.Raw(`SELECT "`+column+`" FROM "`+table+`" WHERE email = ?`, email).Scan(&v).Error; err != nil {
		t.Fatal(err)
	}
	if v == nil {
		return ""
	}
	return *v
}

func TestSchema(t *testing.T) {
	if lastloginmethod.New(llmconfig.LastLoginMethodConfig{}).Schema() != nil {
		t.Fatal("schema without storeInDatabase")
	}
	sc := lastloginmethod.New(llmconfig.LastLoginMethodConfig{StoreInDatabase: true}).Schema()
	f, ok := sc[schema.ModelUser].Fields["lastLoginMethod"]
	if !ok || f.Type != schema.String || f.Required || f.Input == nil || *f.Input {
		t.Fatalf("schema = %+v", sc)
	}
}

func TestStoreInDatabase(t *testing.T) {
	var mu sync.Mutex
	var link string
	ml := magiclink.New(magiclinkconfig.MagicLinkConfig{SendMagicLink: func(d magiclinkconfig.SendMagicLinkData, _ *http.Request) error {
		mu.Lock()
		link = d.URL
		mu.Unlock()
		return nil
	}})
	s := newServer(t, nil, ml, lastloginmethod.New(llmconfig.LastLoginMethodConfig{StoreInDatabase: true}))
	table, column := columnOf(t, s, "")
	if column != "last_login_method" {
		t.Fatalf("column = %q", column)
	}

	// Step 1: sign-up stores "email" (user.create.before + session.create.after)
	signUp(t, s, "db@example.com")
	if got := storedMethod(t, s, table, column, "db@example.com"); got != "email" {
		t.Fatalf("after sign-up = %q", got)
	}
	// Step 2: a magic-link sign-in of the same user overwrites it
	if r := s.Post(t, "/api/auth/sign-in/magic-link", map[string]any{"email": "db@example.com"}); r.Status != http.StatusOK {
		t.Fatalf("magic-link = %d: %s", r.Status, r.Body)
	}
	mu.Lock()
	u, _ := url.Parse(link)
	mu.Unlock()
	expectMethod(t, s.Get(t, u.Path+"?"+u.RawQuery), "magic-link")
	if got := storedMethod(t, s, table, column, "db@example.com"); got != "magic-link" {
		t.Fatalf("after magic link = %q", got)
	}
	// Step 3: a failed sign-in changes nothing
	s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "db@example.com", "password": "nope-nope-nope"})
	if got := storedMethod(t, s, table, column, "db@example.com"); got != "magic-link" {
		t.Fatalf("after failed sign-in = %q", got)
	}
}

func TestStoreInDatabaseWithoutSession(t *testing.T) {
	// autoSignIn off: no session, the user.create.before hook alone stores the method
	off := false
	s := newServer(t, func(c *config.AuthConfig) { c.EmailAndPassword.AutoSignIn = &off },
		lastloginmethod.New(llmconfig.LastLoginMethodConfig{StoreInDatabase: true, FieldName: "login_method_custom"}))
	table, column := columnOf(t, s, "login_method_custom")
	r := signUp(t, s, "nosession@example.com")
	expectNoMethod(t, r)
	if got := storedMethod(t, s, table, column, "nosession@example.com"); got != "email" {
		t.Fatalf("stored = %q", got)
	}
}

func TestStoreInDatabaseMissingColumn(t *testing.T) {
	// without the migrated column the sign-up still works (better-auth logs "Failed to update lastLoginMethod")
	s := newServer(t, nil, lastloginmethod.New(llmconfig.LastLoginMethodConfig{StoreInDatabase: true}))
	r := signUp(t, s, "nocolumn@example.com")
	expectMethod(t, r, "email")
	r = s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "nocolumn@example.com", "password": password})
	if r.Status != http.StatusOK {
		t.Fatalf("sign-in = %d: %s", r.Status, r.Body)
	}
}

func TestConcurrentSignIns(t *testing.T) {
	s := newServer(t, nil, lastloginmethod.New(llmconfig.LastLoginMethodConfig{StoreInDatabase: true}))
	table, column := columnOf(t, s, "")
	signUp(t, s, "conc@example.com")
	var wg sync.WaitGroup
	errs := make(chan string, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "conc@example.com", "password": password})
			if c := r.Cookie(cookieName); r.Status != http.StatusOK || c == nil || c.Value != "email" {
				errs <- string(r.Body)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatalf("bad sign-in: %s", e)
	}
	if got := storedMethod(t, s, table, column, "conc@example.com"); got != "email" {
		t.Fatalf("stored = %q", got)
	}
}
