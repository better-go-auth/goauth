package configparity

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	authlog "github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/social"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// TestErrorPage: GET /error is better-auth's error route: safe codes only, ErrorURL redirect, production
// redirect to "/", HTML page otherwise.
func TestErrorPage(t *testing.T) {
	t.Run("html page", func(t *testing.T) {
		s := compattest.NewServer(t)
		res := s.Get(t, "/api/auth/error?error=INVALID_TOKEN&error_description=The+link+expired")
		if res.Status != http.StatusOK || !strings.HasPrefix(res.Header.Get("Content-Type"), "text/html") ||
			!strings.Contains(string(res.Body), "INVALID_TOKEN") || !strings.Contains(string(res.Body), "The link expired") {
			t.Fatalf("page: %d %s", res.Status, res.Body)
		}
		res = s.Get(t, "/api/auth/error?error=%3Cscript%3E")
		if strings.Contains(string(res.Body), "<script>") || !strings.Contains(string(res.Body), "UNKNOWN") {
			t.Fatalf("unsafe code not replaced: %s", res.Body)
		}
	})
	t.Run("ErrorURL redirect", func(t *testing.T) {
		s := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) {
			c.OnAPIError.ErrorURL = "https://app.example.com/auth-error"
		}))
		res := s.Get(t, "/api/auth/error?error=access_denied&error_description=no+consent")
		if res.Status != http.StatusFound || res.Header.Get("Location") != "https://app.example.com/auth-error?error=access_denied&error_description=no+consent" {
			t.Fatalf("redirect: %d %q", res.Status, res.Header.Get("Location"))
		}
		res = s.Get(t, "/api/auth/error?error=bad%20code")
		if res.Header.Get("Location") != "https://app.example.com/auth-error?error=UNKNOWN" {
			t.Fatalf("unsafe code: %q", res.Header.Get("Location"))
		}
	})
	t.Run("ErrorURL with a query", func(t *testing.T) {
		s := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) {
			c.OnAPIError.ErrorURL = "/login?tab=errors"
		}))
		if loc := s.Get(t, "/api/auth/error?error=X").Header.Get("Location"); loc != "/login?tab=errors&error=X" {
			t.Fatalf("Location = %q", loc)
		}
	})
	t.Run("production redirects home", func(t *testing.T) {
		t.Setenv("GOAUTH_ENV", "production")
		s := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) {
			c.Secret = prodSecret
			c.RateLimit.Enabled = new(false)
		}))
		res := s.Get(t, "/api/auth/error?error=state_mismatch")
		if res.Status != http.StatusFound || res.Header.Get("Location") != "/?error=state_mismatch" {
			t.Fatalf("production: %d %q", res.Status, res.Header.Get("Location"))
		}
	})
}

// TestErrorURLOnOAuthCallback: a failing social callback redirects to OnAPIError.ErrorURL instead of
// <baseURL>/error (better-auth's defaultErrorURL).
func TestErrorURLOnOAuthCallback(t *testing.T) {
	provider := providers.Generic(providers.GenericOptions{
		ProviderID: "fake",
		ProviderOptions: providers.ProviderOptions{
			ClientID: "id", ClientSecret: "secret",
			AuthorizationEndpoint: "https://idp.invalid/authorize", TokenEndpoint: "https://idp.invalid/token",
			UserInfoEndpoint: "https://idp.invalid/userinfo",
		},
	})
	for _, tc := range []struct {
		name, errorURL, wantPrefix string
	}{
		{"default error page", "", "http://127.0.0.1:8080/api/auth/error?"},
		{"OnAPIError.ErrorURL", "https://app.example.com/oauth-error", "https://app.example.com/oauth-error?"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := compattest.NewServer(t,
				compattest.WithPlugin(social.New(socialconfig.SocialConfig{Providers: []providers.Provider{provider}})),
				compattest.WithConfig(func(c *config.AuthConfig) { c.OnAPIError.ErrorURL = tc.errorURL }))
			res := s.Get(t, "/api/auth/callback/fake?code=abc&state=unknown-state")
			loc := res.Header.Get("Location")
			if res.Status != http.StatusFound || !strings.HasPrefix(loc, tc.wantPrefix) {
				t.Fatalf("callback: %d %q", res.Status, loc)
			}
			u, _ := url.Parse(loc)
			if u.Query().Get("error") == "" {
				t.Fatalf("no error code in %q", loc)
			}
		})
	}
}

// TestOnAPIErrorOnError: unexpected errors and errors raised before the endpoint (origin check) reach
// OnError; errors endpoints return on purpose do not. With OnError set goauth does not log them.
func TestOnAPIErrorOnError(t *testing.T) {
	var reported []error
	var logged []string
	s := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) {
		c.OnAPIError.OnError = func(err error, r *http.Request) { reported = append(reported, err) }
		c.Logger.Log = func(level authlog.Level, msg string, args ...any) { logged = append(logged, string(level)+" "+msg) }
		c.Hooks.Before = func(c *endpointhooks.Context) (*endpointhooks.Response, error) {
			if c.Path == "/ok" && c.Query.Get("boom") != "" {
				return nil, errors.New("database exploded")
			}
			return nil, nil
		}
	}))
	signUp(t, s, "onerror@example.com")

	// Step 1: an expected error (wrong password) is not reported
	if res := signIn(t, s, "onerror@example.com", "wrong", "10.0.0.1"); res.Status != http.StatusUnauthorized {
		t.Fatalf("sign-in: %d", res.Status)
	}
	if len(reported) != 0 {
		t.Fatalf("expected API error reported: %v", reported)
	}
	// Step 2: the origin check runs before the endpoint: reported
	res := s.Post(t, "/api/auth/sign-out", map[string]any{}, map[string]string{"Origin": "https://evil.example.com"})
	if res.Status != http.StatusForbidden {
		t.Fatalf("untrusted origin: %d %s", res.Status, res.Body)
	}
	if len(reported) != 1 || autherr.AsAuthError(reported[0]) == nil || autherr.AsAuthError(reported[0]).Code != "INVALID_ORIGIN" {
		t.Fatalf("reported = %v", reported)
	}
	// Step 3: an unexpected error: 500 for the client, the cause for OnError, nothing logged
	res = s.Get(t, "/api/auth/ok?boom=1")
	if res.Status != http.StatusInternalServerError || strings.Contains(string(res.Body), "exploded") {
		t.Fatalf("internal: %d %s", res.Status, res.Body)
	}
	var re *autherr.ReportedError
	if len(reported) != 2 || !errors.As(reported[1], &re) || re.Err.Error() != "database exploded" {
		t.Fatalf("reported = %v", reported)
	}
	for _, l := range logged {
		if strings.Contains(l, "internal error") {
			t.Fatalf("internal error logged although OnError is set: %v", logged)
		}
	}
}

// TestOnAPIErrorThrow: Throw re-raises the error as a panic (for an app's recovery middleware).
func TestOnAPIErrorThrow(t *testing.T) {
	s := compattest.NewServer(t, compattest.WithConfig(func(c *config.AuthConfig) {
		c.OnAPIError.Throw = true
		c.OnAPIError.OnError = func(error, *http.Request) { t.Error("OnError must not run when Throw is set") }
		c.Hooks.Before = func(c *endpointhooks.Context) (*endpointhooks.Response, error) {
			if c.Path == "/ok" {
				return nil, errors.New("thrown")
			}
			return nil, nil
		}
	}))
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		s.Mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/auth/ok", nil))
	}()
	err, ok := recovered.(error)
	if !ok || !strings.Contains(err.Error(), "thrown") {
		t.Fatalf("recovered %v", recovered)
	}
	// expected errors are still answered normally
	if res := s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "nobody@example.com", "password": "nope-nope"}); res.Status != http.StatusUnauthorized {
		t.Fatalf("sign-in: %d", res.Status)
	}
}
