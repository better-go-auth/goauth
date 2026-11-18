package coreopts

import (
	"context"
	"net/http"
	"strings"
	"testing"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/app/repository/memory"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/social"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
)

const (
	oauthBase   = "http://localhost:3000"
	oauthID     = "client-id"
	oauthSecret = "client-secret"
)

// fakeProvider is a generic provider "fake" pointed at the fake OAuth server.
func fakeProvider(fake *socialtest.Provider, id string) providers.Provider {
	return providers.Generic(providers.GenericOptions{
		ProviderID: id,
		Issuer:     fake.Issuer,
		ProviderOptions: providers.ProviderOptions{
			ClientID: oauthID, ClientSecret: oauthSecret,
			AuthorizationEndpoint: fake.AuthorizationEndpoint(), TokenEndpoint: fake.TokenEndpoint(),
			UserInfoEndpoint: fake.UserInfoEndpoint(), JWKSEndpoint: fake.JWKSEndpoint(),
		},
	})
}

// oauthFlow runs /sign-in/social → provider authorize → /callback and returns the callback response.
func oauthFlow(t *testing.T, s *compattest.Server, provider string) *compattest.Response {
	t.Helper()
	// Step 1: start the flow (the state cookie binds it to this "browser")
	start := call(t, s, http.MethodPost, "/api/auth/sign-in/social", map[string]any{"provider": provider, "callbackURL": "/dashboard", "disableRedirect": true}, map[string]string{"Origin": oauthBase})
	if start.Status != http.StatusOK {
		t.Fatalf("sign-in/social: %d %s", start.Status, start.Body)
	}
	var body struct {
		URL string `json:"url"`
	}
	start.JSON(t, &body)
	// Step 2: the provider redirects back to the test server
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noRedirect.Get(body.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	cb := strings.TrimPrefix(resp.Header.Get("Location"), s.URL)
	// Step 3: the callback with the state cookie
	return call(t, s, http.MethodGet, cb, nil, map[string]string{"Cookie": cookieHeader(start)})
}

func TestSocialProvidersInCoreConfig(t *testing.T) {
	fake := socialtest.New(oauthID, oauthSecret)
	t.Cleanup(fake.Close)
	fake.SetUser(socialtest.Profile{Sub: "fake-sub-1", Email: "oauth@example.com", EmailVerified: true, Name: "OAuth User"})

	// Step 1: better-auth's `socialProviders` + `account` options, no social plugin passed
	s := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) {
		c.BaseURL = oauthBase
		c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*")
		c.SocialProviders = []providers.Provider{fakeProvider(fake, "fake")}
		c.Account.EncryptOAuthTokens = true
		c.Account.StoreAccountCookie = true
	}))
	fake.SetRedirectBase(s.URL)
	p, ok := goauth.GetPlugin[*social.Plugin](s.Auth, social.PluginID)
	if !ok || !p.Config().EncryptOAuthTokens || len(p.Config().Providers) != 1 {
		t.Fatalf("social plugin not installed from the core config: %v", ok)
	}

	// Step 2: the OAuth flow signs the user in and stores the account in the encrypted account_data cookie
	cb := oauthFlow(t, s, "fake")
	if cb.Status != http.StatusFound || cb.Header.Get("Location") != "/dashboard" {
		t.Fatalf("callback: %d %s %s", cb.Status, cb.Header.Get("Location"), cb.Body)
	}
	account := setCookie(cb, "better-auth.account_data")
	if account == nil || strings.Count(account.Value, ".") != 4 || account.MaxAge != 300 || !account.HttpOnly {
		t.Fatalf("account_data cookie: %+v", account)
	}
	cookie := cookieHeader(cb)
	if got := sessionEmail(t, s, cookie); got != "oauth@example.com" {
		t.Fatalf("session: %q", got)
	}
	// tokens are encrypted at rest (account.encryptOAuthTokens)
	var acc models.Account
	if err := s.DB.Where(&models.Account{ProviderID: "fake"}).First(&acc).Error; err != nil {
		t.Fatal(err)
	}
	if acc.AccessToken == nil || fake.IsAccessToken(*acc.AccessToken) {
		t.Fatalf("access token must be stored encrypted: %v", acc.AccessToken)
	}

	// Step 3: /account-info without accountId uses the account cookie (better-auth's storeAccountCookie)
	info := call(t, s, http.MethodGet, "/api/auth/account-info", nil, map[string]string{"Cookie": cookie})
	if info.Status != http.StatusOK {
		t.Fatalf("account-info: %d %s", info.Status, info.Body)
	}
	var out struct {
		User struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
	}
	info.JSON(t, &out)
	if out.User.ID != "fake-sub-1" || out.User.Email != "oauth@example.com" {
		t.Fatalf("account-info: %s", info.Body)
	}
	// without the account cookie and without accountId the account is unknown
	sessionOnly := "better-auth.session_token=" + setCookie(cb, "better-auth.session_token").Value
	expectCode(t, call(t, s, http.MethodGet, "/api/auth/account-info", nil, map[string]string{"Cookie": sessionOnly}), http.StatusBadRequest, "ACCOUNT_NOT_FOUND")

	// Step 4: /get-access-token reads the account from the cookie and decrypts the token
	at := call(t, s, http.MethodPost, "/api/auth/get-access-token", map[string]any{"providerId": "fake"}, map[string]string{"Cookie": cookie, "Origin": oauthBase})
	var token struct {
		AccessToken string `json:"accessToken"`
	}
	at.JSON(t, &token)
	if at.Status != http.StatusOK || !fake.IsAccessToken(token.AccessToken) {
		t.Fatalf("get-access-token: %d %s", at.Status, at.Body)
	}

	// Step 5: sign-out deletes the account cookie with the session cookies
	out2 := call(t, s, http.MethodPost, "/api/auth/sign-out", nil, map[string]string{"Cookie": cookie, "Origin": oauthBase})
	if del := setCookie(out2, "better-auth.account_data"); del == nil || del.MaxAge >= 0 {
		t.Fatalf("sign-out must expire account_data: %+v", del)
	}
}

func TestSocialProvidersMergeAndConflict(t *testing.T) {
	fake := socialtest.New(oauthID, oauthSecret)
	t.Cleanup(fake.Close)
	setup := func(core []providers.Provider, plugin *social.Plugin) (*goauth.GoAuth, error) {
		api := humago.New(http.NewServeMux(), huma.DefaultConfig("t", "1"))
		return goauth.SetupGoAuth(context.Background(), api, goauth.GoAuthOptions{
			AuthConfig:   config.AuthConfig{BaseURL: oauthBase, Secret: compattest.TestSecret, SocialProviders: core},
			Repositories: memory.New(),
			Plugins:      []plugins.Plugin{plugin},
		})
	}
	// Step 1: the same provider id in AuthConfig.SocialProviders and in the social plugin is a clear error
	_, err := setup([]providers.Provider{fakeProvider(fake, "fake")}, social.New(socialconfig.SocialConfig{Providers: []providers.Provider{fakeProvider(fake, "fake")}}))
	if err == nil || !strings.Contains(err.Error(), "SocialProviders conflicts with the social plugin") || !strings.Contains(err.Error(), `"fake"`) {
		t.Fatalf("expected a conflict error, got %v", err)
	}
	// Step 2: different ids are merged into the plugin that was passed
	plugin := social.New(socialconfig.SocialConfig{Providers: []providers.Provider{fakeProvider(fake, "other")}})
	a, err := setup([]providers.Provider{fakeProvider(fake, "fake")}, plugin)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := goauth.GetPlugin[*social.Plugin](a, social.PluginID)
	if got != plugin || !got.HasProvider("fake") || !got.HasProvider("other") {
		t.Fatalf("providers not merged: %+v", got.Config().Providers)
	}
	// Step 3: without providers anywhere no social plugin is installed
	api := humago.New(http.NewServeMux(), huma.DefaultConfig("t", "1"))
	b, err := goauth.SetupGoAuth(context.Background(), api, goauth.GoAuthOptions{
		AuthConfig: config.AuthConfig{BaseURL: oauthBase, Secret: compattest.TestSecret}, Repositories: memory.New(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := goauth.GetPlugin[*social.Plugin](b, social.PluginID); ok {
		t.Fatal("no social plugin expected without providers")
	}
}
