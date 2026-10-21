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

		if c.GoAuth.Mode != ModeLegacy {
			t.Errorf("Mode = %q, want legacy", c.GoAuth.Mode)
		}
		if c.AppName != DefaultAppName || c.BasePath != "/api/auth" || c.Advanced.CookiePrefix != DefaultCookiePrefix {
			t.Errorf("unexpected defaults: %q %q %q", c.AppName, c.BasePath, c.Advanced.CookiePrefix)
		}
		if c.Advanced.IPAddress.IPv6Subnet != DefaultIPv6Subnet {
			t.Errorf("IPv6Subnet = %d", c.Advanced.IPAddress.IPv6Subnet)
		}
		if c.EmailAndPassword.MinPasswordLength != 8 || c.EmailAndPassword.MaxPasswordLength != 128 {
			t.Errorf("password length defaults = %d/%d", c.EmailAndPassword.MinPasswordLength, c.EmailAndPassword.MaxPasswordLength)
		}
		if len(c.GoAuth.Session.UpdatableFields) == 0 {
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

	t.Run("explicit values are kept", func(t *testing.T) {
		c := AuthConfig{AppName: "My App", BasePath: "/auth", Secret: "x", Advanced: Advanced{CookiePrefix: "my"}}
		c.SetDefaults()
		if c.AppName != "My App" || c.BasePath != "/auth" || c.Secret != "x" || c.Advanced.CookiePrefix != "my" {
			t.Errorf("explicit values overwritten: %+v", c)
		}
	})
}

func TestValidate(t *testing.T) {
	t.Setenv(SecretEnvVar, "")
	longSecret := strings.Repeat("s", 32)
	compat := GoAuthConfig{Mode: ModeCompat}

	cases := []struct {
		name    string
		cfg     AuthConfig
		wantErr string
	}{
		{"legacy ok", AuthConfig{Secret: "secret"}, ""},
		{"legacy missing secret", AuthConfig{}, "Secret"},
		{"compat ok", AuthConfig{GoAuth: compat, Secret: longSecret, BaseURL: "https://example.com"}, ""},
		{"compat missing secret", AuthConfig{GoAuth: compat, BaseURL: "https://example.com"}, "Secret"},
		{"compat missing base url", AuthConfig{GoAuth: compat, Secret: longSecret}, "BaseURL"},
		{"relative base url", AuthConfig{GoAuth: compat, Secret: longSecret, BaseURL: "example.com"}, "absolute"},
		{"unknown mode", AuthConfig{GoAuth: GoAuthConfig{Mode: "nope"}, Secret: "secret"}, "unknown Mode"},
		{"cross subdomain without domain", AuthConfig{
			Secret:   "secret",
			Advanced: Advanced{CrossSubDomainCookies: CrossSubDomainCookies{Enabled: true}},
		}, "CrossSubDomainCookies"},
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
