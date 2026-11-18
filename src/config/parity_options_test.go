package config

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseSecretsEnv(t *testing.T) {
	// Step 1: better-auth's "<version>:<secret>" list, trimmed
	got, err := ParseSecretsEnv(" 2:second-secret , 1:first:secret-with-colon ")
	if err != nil || len(got) != 2 || got[0] != (SecretVersion{2, "second-secret"}) || got[1] != (SecretVersion{1, "first:secret-with-colon"}) {
		t.Fatalf("parse: %+v %v", got, err)
	}
	// Step 2: empty is nothing; malformed entries are errors with better-auth's wording
	if got, err := ParseSecretsEnv("  "); got != nil || err != nil {
		t.Fatalf("empty: %+v %v", got, err)
	}
	for in, want := range map[string]string{"nocolon": "expected format", "x:s": "non-negative integer", "-1:s": "non-negative integer", "3:  ": "empty secret value"} {
		if _, err := ParseSecretsEnv(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%q: %v", in, err)
		}
	}
}

func TestSecretsValidationAndDefaults(t *testing.T) {
	base := func() AuthConfig { return AuthConfig{BaseURL: "http://localhost:3000"} }
	// Step 1: duplicate / negative versions and empty values are refused
	for name, secrets := range map[string][]SecretVersion{
		"duplicate": {{1, "a-secret-a-secret-a-secret-a-secret"}, {1, "b"}},
		"negative":  {{-1, "a-secret-a-secret-a-secret-a-secret"}},
		"empty":     {{1, ""}},
	} {
		c := base()
		c.Secrets = secrets
		c.SetDefaults()
		if err := c.Validate(); err == nil {
			t.Fatalf("%s: expected an error", name)
		}
	}
	// Step 2: $BETTER_AUTH_SECRETS is read when Secrets is empty; Secret keeps the legacy value
	t.Setenv(SecretsEnvVar, "5:env-current-secret-0123456789abcdef,4:env-old")
	t.Setenv(SecretEnvVar, "legacy-from-env")
	c := base()
	c.SetDefaults()
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(c.Secrets) != 2 || c.Secret != "env-current-secret-0123456789abcdef" || c.LegacySecret() != "legacy-from-env" || c.CurrentSecret() != c.Secret {
		t.Fatalf("env secrets: %+v secret=%q legacy=%q", c.Secrets, c.Secret, c.LegacySecret())
	}
	// Step 3: a malformed env value is a Validate error
	t.Setenv(SecretsEnvVar, "garbage")
	c = base()
	c.SetDefaults()
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), SecretsEnvVar) {
		t.Fatalf("bad env: %v", err)
	}
}

func dynamicConf(d DynamicBaseURL, trust *bool) AuthConfig {
	c := AuthConfig{DynamicBaseURL: &d, Secret: "s3cret-s3cret-s3cret-s3cret-s3cret"}
	c.Advanced.TrustedProxyHeaders = trust
	c.SetDefaults()
	return c
}

func req(host string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/auth/ok", nil)
	r.Host = host
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestResolveDynamicBaseURL(t *testing.T) {
	no := false
	c := dynamicConf(DynamicBaseURL{AllowedHosts: []string{"myapp.com", "*.vercel.app", "preview-*.myapp.com", "localhost:3000"}}, nil)
	cases := []struct {
		name    string
		r       *http.Request
		want    string
		wantErr bool
	}{
		{"exact host defaults to https", req("myapp.com", nil), "https://myapp.com", false},
		{"wildcard", req("pr-12.vercel.app", nil), "https://pr-12.vercel.app", false},
		{"prefix wildcard", req("preview-7.myapp.com", nil), "https://preview-7.myapp.com", false},
		{"case insensitive", req("MyApp.COM", nil), "https://MyApp.COM", false},
		{"loopback is http", req("localhost:3000", nil), "http://localhost:3000", false},
		{"x-forwarded-host and proto win (trusted by default)", req("internal:8080", map[string]string{"X-Forwarded-Host": "myapp.com", "X-Forwarded-Proto": "http"}), "http://myapp.com", false},
		{"invalid forwarded host is ignored", req("myapp.com", map[string]string{"X-Forwarded-Host": "evil..com"}), "https://myapp.com", false},
		{"not allowed", req("evil.com", nil), "", true},
		{"wildcard does not cross dots wrongly", req("vercel.app", nil), "", true},
		{"script in host", req("myapp.com<script>", nil), "", true},
	}
	for _, tc := range cases {
		got, err := c.ResolveBaseURL(tc.r)
		if tc.wantErr {
			if err == nil || !errors.Is(err, ErrHostNotAllowed) {
				t.Fatalf("%s: expected ErrHostNotAllowed, got %q %v", tc.name, got, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Fatalf("%s: got %q %v want %q", tc.name, got, err, tc.want)
		}
	}
	// TLS connections are https even on loopback; untrusted proxy headers are ignored
	tlsReq := req("localhost:3000", nil)
	tlsReq.TLS = &tls.ConnectionState{}
	if got, _ := c.ResolveBaseURL(tlsReq); got != "https://localhost:3000" {
		t.Fatalf("tls: %q", got)
	}
	strict := dynamicConf(DynamicBaseURL{AllowedHosts: []string{"myapp.com"}}, &no)
	if _, err := strict.ResolveBaseURL(req("internal", map[string]string{"X-Forwarded-Host": "myapp.com"})); err == nil {
		t.Fatal("forwarded host must be ignored when proxy headers are not trusted")
	}
}

func TestDynamicBaseURLFallbackProtocolAndDefaults(t *testing.T) {
	// Step 1: the fallback answers for unknown hosts and becomes the static BaseURL
	c := dynamicConf(DynamicBaseURL{AllowedHosts: []string{"a.com"}, Fallback: "https://main.com/some/path", Protocol: "http"}, nil)
	if c.BaseURL != "https://main.com" {
		t.Fatalf("BaseURL default: %q", c.BaseURL)
	}
	if got, err := c.ResolveBaseURL(req("evil.com", nil)); err != nil || got != "https://main.com" {
		t.Fatalf("fallback: %q %v", got, err)
	}
	// Step 2: a configured protocol wins over the forwarded one; cookies follow it
	if got, _ := c.ResolveBaseURL(req("a.com", map[string]string{"X-Forwarded-Proto": "https"})); got != "http://a.com" {
		t.Fatalf("protocol: %q", got)
	}
	if c.SecureCookies() {
		t.Fatal("protocol http means no secure cookies")
	}
	// Step 3: trusted origins derived like better-auth's getTrustedOrigins
	got := strings.Join((&DynamicBaseURL{AllowedHosts: []string{"a.com", "localhost:3000", "https://full.example"}, Fallback: "https://main.com/x", Protocol: "auto"}).DynamicTrustedOrigins(), ",")
	if got != "https://a.com,http://a.com,https://localhost:3000,http://localhost:3000,https://full.example,https://main.com" {
		t.Fatalf("trusted origins: %s", got)
	}
	got = strings.Join((&DynamicBaseURL{AllowedHosts: []string{"a.com", "localhost"}}).DynamicTrustedOrigins(), ",")
	if got != "https://a.com,https://localhost,http://localhost" {
		t.Fatalf("default protocol origins: %s", got)
	}
	// Step 4: validation
	bad := []AuthConfig{
		{DynamicBaseURL: &DynamicBaseURL{}, Secret: "x"},
		{DynamicBaseURL: &DynamicBaseURL{AllowedHosts: []string{"a"}, Protocol: "ftp"}, Secret: "x"},
		{DynamicBaseURL: &DynamicBaseURL{AllowedHosts: []string{"a"}, Fallback: "not a url"}, Secret: "x"},
	}
	for i, b := range bad {
		b.SetDefaults()
		if err := b.Validate(); err == nil {
			t.Fatalf("case %d: expected validation error", i)
		}
	}
	ok := AuthConfig{DynamicBaseURL: &DynamicBaseURL{AllowedHosts: []string{"a.com"}}, Secret: "s3cret-s3cret-s3cret-s3cret-s3cret"}
	ok.SetDefaults()
	if err := ok.Validate(); err != nil {
		t.Fatalf("dynamic config without BaseURL must validate: %v", err)
	}
}

func TestRequestBaseURLFromContext(t *testing.T) {
	c := AuthConfig{BaseURL: "https://static.example/", BasePath: "/api/auth"}
	if got := c.AuthBaseURL(context.Background()); got != "https://static.example/api/auth" {
		t.Fatalf("static: %q", got)
	}
	ctx := WithRequestBaseURL(context.Background(), "https://tenant.example")
	if got := c.AuthBaseURL(ctx); got != "https://tenant.example/api/auth" {
		t.Fatalf("per request: %q", got)
	}
}

func TestStoreIdentifierOptions(t *testing.T) {
	// Step 1: better-auth's defaultKeyHasher (SHA-256, unpadded base64url)
	if got := HashIdentifier("reset-password:abc"); got != "IMUqJ3lXuvod79AbI4EdsWmdAkZeIP5syfKs7-d5fQQ" {
		t.Fatalf("hash: %q", got)
	}
	// Step 2: overrides: the longest matching prefix wins, else the default
	v := VerificationOptions{
		StoreIdentifier: StoreIdentifierOption{Mode: StoreIdentifierHashed},
		StoreIdentifierOverrides: map[string]StoreIdentifierOption{
			"reset":           {Mode: StoreIdentifierPlain},
			"reset-password:": {Hash: func(s string) (string, error) { return "custom:" + s, nil }},
		},
	}
	if got, _ := v.IdentifierOption("reset-password:x").Process("reset-password:x"); got != "custom:reset-password:x" {
		t.Fatalf("longest prefix: %q", got)
	}
	if !v.IdentifierOption("reset-other").IsPlain() {
		t.Fatal("shorter prefix override must apply")
	}
	if got, _ := v.IdentifierOption("otp").Process("otp"); got != HashIdentifier("otp") {
		t.Fatalf("default hashed: %q", got)
	}
	if (VerificationOptions{}).HashesIdentifiers() || !v.HashesIdentifiers() {
		t.Fatal("HashesIdentifiers")
	}
}
