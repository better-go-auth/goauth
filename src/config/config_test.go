package config

import (
	"strings"
	"testing"
)

func TestSetDefaults(t *testing.T) {
	t.Setenv(SecretEnvVar, "")

	t.Run("defaults", func(t *testing.T) {
		c := AuthConfig{Secret: "app-secret"}
		c.SetDefaults()

		if c.AppName != DefaultAppName || c.BasePath != "/api/auth" || c.Advanced.CookiePrefix != DefaultCookiePrefix {
			t.Errorf("unexpected defaults: %q %q %q", c.AppName, c.BasePath, c.Advanced.CookiePrefix)
		}
		if c.Advanced.IPAddress.IPv6Subnet != DefaultIPv6Subnet {
			t.Errorf("IPv6Subnet = %d", c.Advanced.IPAddress.IPv6Subnet)
		}
		if c.EmailAndPassword.MinPasswordLength != 8 || c.EmailAndPassword.MaxPasswordLength != 128 {
			t.Errorf("password length defaults = %d/%d", c.EmailAndPassword.MinPasswordLength, c.EmailAndPassword.MaxPasswordLength)
		}
		if len(c.Session.GoAuth.UpdatableFields) == 0 {
			t.Errorf("expected UpdatableFields to be set")
		}
	})

	t.Run("DeriveKey produces deterministic unique keys", func(t *testing.T) {
		k1 := DeriveKey("secret", "purpose1")
		k2 := DeriveKey("secret", "purpose2")
		if k1 == "" || k2 == "" || k1 == k2 {
			t.Fatalf("derived keys must be non-empty and differ: %q %q", k1, k2)
		}
	})

	t.Run("secret from env", func(t *testing.T) {
		t.Setenv(SecretEnvVar, "env-secret")
		c := AuthConfig{}
		c.SetDefaults()
		if c.Secret != "env-secret" {
			t.Errorf("Secret = %q, want env-secret", c.Secret)
		}
	})

	t.Run("base url from BETTER_AUTH_URL env", func(t *testing.T) {
		t.Setenv(BaseURLEnvVar, "https://env.example.com")
		c := AuthConfig{}
		c.SetDefaults()
		if c.BaseURL != "https://env.example.com" {
			t.Errorf("BaseURL = %q, want https://env.example.com", c.BaseURL)
		}
	})

	t.Run("base url from NEXT_PUBLIC_BETTER_AUTH_URL env fallback", func(t *testing.T) {
		t.Setenv(BaseURLEnvVar, "")
		t.Setenv(NextBaseURLEnvVar, "https://next.example.com")
		c := AuthConfig{}
		c.SetDefaults()
		if c.BaseURL != "https://next.example.com" {
			t.Errorf("BaseURL = %q, want https://next.example.com", c.BaseURL)
		}
	})

	t.Run("explicit values are kept", func(t *testing.T) {
		c := AuthConfig{AppName: "My App", BasePath: "/auth", Secret: "x", BaseURL: "https://explicit.com", Advanced: Advanced{CookiePrefix: "my"}}
		c.SetDefaults()
		if c.AppName != "My App" || c.BasePath != "/auth" || c.Secret != "x" || c.BaseURL != "https://explicit.com" || c.Advanced.CookiePrefix != "my" {
			t.Errorf("explicit values overwritten: %+v", c)
		}
	})
}

func TestValidate(t *testing.T) {
	t.Setenv(SecretEnvVar, "")
	t.Setenv(AuthSecretEnvVar, "")
	t.Setenv(BaseURLEnvVar, "")
	t.Setenv(NextBaseURLEnvVar, "")
	longSecret := strings.Repeat("s", 32)

	cases := []struct {
		name    string
		cfg     AuthConfig
		wantErr string
	}{
		{"valid config", AuthConfig{Secret: longSecret, BaseURL: "https://example.com"}, ""},
		{"missing secret with RequireSecret", AuthConfig{BaseURL: "https://example.com", Advanced: Advanced{GoAuth: AdvancedGoAuth{RequireSecret: true}}}, "Secret"},
		{"missing base url", AuthConfig{Secret: longSecret}, "BaseURL"},
		{"relative base url", AuthConfig{Secret: longSecret, BaseURL: "example.com"}, "absolute"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.SetDefaults()
			err := tc.cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestCookieHelpers(t *testing.T) {
	off := false
	cases := []struct {
		name       string
		cfg        AuthConfig
		wantSecure bool
		wantDomain string
	}{
		{"http base url", AuthConfig{BaseURL: "http://localhost:3000"}, false, ""},
		{"https base url", AuthConfig{BaseURL: "https://auth.example.com"}, true, ""},
		{"explicit override", AuthConfig{BaseURL: "https://auth.example.com", Advanced: Advanced{UseSecureCookies: &off}}, false, ""},
		{"cross subdomain from base url", AuthConfig{BaseURL: "https://auth.example.com",
			Advanced: Advanced{CrossSubDomainCookies: CrossSubDomainCookies{Enabled: true}}}, true, "auth.example.com"},
		{"cross subdomain explicit", AuthConfig{BaseURL: "https://auth.example.com",
			Advanced: Advanced{CrossSubDomainCookies: CrossSubDomainCookies{Enabled: true, Domain: "example.com"}}}, true, "example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.SecureCookies(); got != tc.wantSecure {
				t.Errorf("SecureCookies = %v, want %v", got, tc.wantSecure)
			}
			if got := tc.cfg.CookieDomain(); got != tc.wantDomain {
				t.Errorf("CookieDomain = %q, want %q", got, tc.wantDomain)
			}
		})
	}
}

// TestSecretFallback follows better-auth: outside production a missing secret falls back to the public
// development default; in production that default is refused.
func TestSecretFallback(t *testing.T) {
	t.Setenv(SecretEnvVar, "")
	t.Setenv(AuthSecretEnvVar, "")
	for _, k := range productionEnvVars {
		t.Setenv(k, "")
	}

	// Step 1: development: DefaultDevSecret is used
	cfg := AuthConfig{BaseURL: "https://example.com"}
	cfg.SetDefaults()
	if cfg.Secret != DefaultDevSecret {
		t.Fatalf("secret = %q, want the development default", cfg.Secret)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("development fallback should be valid: %v", err)
	}

	// Step 2: $AUTH_SECRET is read after $BETTER_AUTH_SECRET
	t.Setenv(AuthSecretEnvVar, "from-auth-secret-0123456789abcdef0123")
	cfg = AuthConfig{BaseURL: "https://example.com"}
	cfg.SetDefaults()
	if cfg.Secret != "from-auth-secret-0123456789abcdef0123" {
		t.Fatalf("secret = %q, want $AUTH_SECRET", cfg.Secret)
	}
	t.Setenv(AuthSecretEnvVar, "")

	// Step 3: production refuses the default
	t.Setenv("NODE_ENV", "production")
	cfg = AuthConfig{BaseURL: "https://example.com"}
	cfg.SetDefaults()
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "default secret") {
		t.Fatalf("production with the default secret: err = %v", err)
	}
}
