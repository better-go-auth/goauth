package test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/captcha"
	captchaconfig "github.com/better-go-auth/goauth/src/plugins/captcha/config"
	"github.com/better-go-auth/goauth/src/plugins/captcha/services"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

// ─── fake provider ───────────────────────────────────────────────────────────

// fakeProvider is a site-verify endpoint: it records every call and answers with the configured status and
// body (the body may depend on the token).
type fakeProvider struct {
	*httptest.Server
	mu     sync.Mutex
	calls  []call
	status int
	answer func(token string) any
	hits   atomic.Int32
}

type call struct {
	ContentType string
	Body        string
	Form        url.Values
	JSON        map[string]any
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	f := &fakeProvider{status: http.StatusOK}
	// tokens "pass", "low-score" and "high-score" succeed; everything else fails
	f.answer = func(token string) any {
		switch token {
		case "pass":
			return map[string]any{"success": true}
		case "low-score":
			return map[string]any{"success": true, "score": 0.3}
		case "high-score":
			return map[string]any{"success": true, "score": 0.9}
		}
		return map[string]any{"success": false, "error-codes": []string{"invalid-input-response"}}
	}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		raw, _ := io.ReadAll(r.Body)
		c := call{ContentType: r.Header.Get("Content-Type"), Body: string(raw)}
		var token string
		if c.ContentType == "application/json" {
			_ = json.Unmarshal(raw, &c.JSON)
			token, _ = c.JSON["response"].(string)
		} else {
			c.Form, _ = url.ParseQuery(string(raw))
			token = c.Form.Get("response")
		}
		f.mu.Lock()
		f.calls = append(f.calls, c)
		status, answer := f.status, f.answer
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(answer(token))
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeProvider) last(t *testing.T) call {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		t.Fatal("provider was not called")
	}
	return f.calls[len(f.calls)-1]
}

func (f *fakeProvider) setStatus(s int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = s
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func newServer(t *testing.T, cfg captchaconfig.CaptchaConfig, mutate ...func(*config.AuthConfig)) *compattest.Server {
	t.Helper()
	s := compattest.NewServer(t,
		compattest.WithPlugin(captcha.New(cfg)),
		compattest.WithConfig(func(c *config.AuthConfig) {
			for _, m := range mutate {
				m(c)
			}
		}),
	)
	s.Client.Jar = nil
	return s
}

func signUpBody(email string) map[string]any {
	return map[string]any{"email": email, "password": "Password123!", "name": "Captcha"}
}

func withToken(token string) map[string]string { return map[string]string{"x-captcha-response": token} }

// expectMiddlewareError checks better-auth's middlewareResponse: {message, code} as text/plain.
func expectMiddlewareError(t *testing.T, r *compattest.Response, status int, code, message string) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("status = %d, want %d (%s)", r.Status, status, r.Body)
	}
	if ct := r.Header.Get("Content-Type"); ct != "text/plain;charset=UTF-8" {
		t.Fatalf("content-type = %q", ct)
	}
	want := `{"message":"` + message + `","code":"` + code + `"}`
	if string(r.Body) != want {
		t.Fatalf("body = %s, want %s", r.Body, want)
	}
}

// ─── unit: path matching ─────────────────────────────────────────────────────

func TestProtects(t *testing.T) {
	svc := services.New(captchaconfig.CaptchaConfig{Provider: captchaconfig.CloudflareTurnstile, SecretKey: "s"}, "/api/auth", nil)
	cases := map[string]bool{
		"/api/auth/sign-up/email":          true,
		"/api/auth/sign-in/email":          true,
		"/api/auth/request-password-reset": true,
		"/api/auth/sign-in/email-otp":      false, // exempt: contains "/sign-in/email" but is email-otp
		"/api/auth/sign-in/social":         false,
		"/api/auth/get-session":            false,
		"/api/auth//sign-in/email":         true, // double slashes are normalized like better-auth
		"/other/sign-in/email":             true, // substring match, like better-auth's pathname.includes
	}
	for path, want := range cases {
		if got := svc.Protects(path); got != want {
			t.Errorf("Protects(%q) = %v, want %v", path, got, want)
		}
	}

	// an explicitly listed exempt path is protected
	svc = services.New(captchaconfig.CaptchaConfig{Endpoints: []string{"/sign-in/email-otp"}}, "/auth", nil)
	if !svc.Protects("/auth/sign-in/email-otp") {
		t.Fatal("listed /sign-in/email-otp should be protected")
	}
	if svc.Protects("/auth/sign-in/email") {
		t.Fatal("custom endpoints replace the defaults")
	}
}

// ─── unit: provider requests ─────────────────────────────────────────────────

func TestVerifyRequestShapes(t *testing.T) {
	f := newFakeProvider(t)
	ctx := context.Background()
	verify := func(cfg captchaconfig.CaptchaConfig, token, ip string) (bool, error) {
		cfg.SecretKey = "secret-key"
		cfg.SiteVerifyURLOverride = f.URL
		return services.New(cfg, "/api/auth", nil).Verify(ctx, token, ip)
	}

	t.Run("turnstile sends JSON with remoteip", func(t *testing.T) {
		ok, err := verify(captchaconfig.CaptchaConfig{Provider: captchaconfig.CloudflareTurnstile}, "pass", "10.0.0.1")
		if err != nil || !ok {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
		c := f.last(t)
		if c.ContentType != "application/json" || c.JSON["secret"] != "secret-key" || c.JSON["response"] != "pass" || c.JSON["remoteip"] != "10.0.0.1" {
			t.Fatalf("request = %+v", c)
		}
		// no IP → no remoteip key
		_, _ = verify(captchaconfig.CaptchaConfig{Provider: captchaconfig.CloudflareTurnstile}, "pass", "")
		if _, has := f.last(t).JSON["remoteip"]; has {
			t.Fatal("remoteip sent without an IP")
		}
	})
	t.Run("recaptcha sends a form", func(t *testing.T) {
		ok, err := verify(captchaconfig.CaptchaConfig{Provider: captchaconfig.GoogleRecaptcha}, "pass", "10.0.0.2")
		if err != nil || !ok {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
		c := f.last(t)
		if c.ContentType != "application/x-www-form-urlencoded" || c.Body != "secret=secret-key&response=pass&remoteip=10.0.0.2" {
			t.Fatalf("request = %+v", c)
		}
	})
	t.Run("hcaptcha sends sitekey", func(t *testing.T) {
		_, _ = verify(captchaconfig.CaptchaConfig{Provider: captchaconfig.HCaptcha, SiteKey: "site"}, "pass", "10.0.0.3")
		if c := f.last(t); c.Body != "secret=secret-key&response=pass&sitekey=site&remoteip=10.0.0.3" {
			t.Fatalf("body = %s", c.Body)
		}
		_, _ = verify(captchaconfig.CaptchaConfig{Provider: captchaconfig.HCaptcha}, "pass", "")
		if c := f.last(t); c.Body != "secret=secret-key&response=pass" {
			t.Fatalf("body = %s", c.Body)
		}
	})
	t.Run("captchafox spells remoteIp", func(t *testing.T) {
		_, _ = verify(captchaconfig.CaptchaConfig{Provider: captchaconfig.CaptchaFox, SiteKey: "fox"}, "pass", "10.0.0.4")
		if c := f.last(t); c.Body != "secret=secret-key&response=pass&sitekey=fox&remoteIp=10.0.0.4" {
			t.Fatalf("body = %s", c.Body)
		}
	})
	t.Run("recaptcha v3 score", func(t *testing.T) {
		if ok, _ := verify(captchaconfig.CaptchaConfig{Provider: captchaconfig.GoogleRecaptcha}, "low-score", ""); ok {
			t.Fatal("0.3 < default 0.5 must fail")
		}
		if ok, _ := verify(captchaconfig.CaptchaConfig{Provider: captchaconfig.GoogleRecaptcha}, "high-score", ""); !ok {
			t.Fatal("0.9 must pass")
		}
		low := 0.2
		if ok, _ := verify(captchaconfig.CaptchaConfig{Provider: captchaconfig.GoogleRecaptcha, MinScore: &low}, "low-score", ""); !ok {
			t.Fatal("0.3 >= 0.2 must pass")
		}
		// scores are only checked for reCAPTCHA
		if ok, _ := verify(captchaconfig.CaptchaConfig{Provider: captchaconfig.HCaptcha}, "low-score", ""); !ok {
			t.Fatal("hcaptcha ignores score")
		}
	})
	t.Run("rejected token", func(t *testing.T) {
		ok, err := verify(captchaconfig.CaptchaConfig{Provider: captchaconfig.CloudflareTurnstile}, "bad", "")
		if err != nil || ok {
			t.Fatalf("ok=%v err=%v", ok, err)
		}
	})
	t.Run("provider error status is service unavailable", func(t *testing.T) {
		f.setStatus(http.StatusBadGateway)
		defer f.setStatus(http.StatusOK)
		if _, err := verify(captchaconfig.CaptchaConfig{Provider: captchaconfig.CloudflareTurnstile}, "pass", ""); err == nil {
			t.Fatal("want error")
		}
	})
}

// ─── end to end ──────────────────────────────────────────────────────────────

func TestCaptchaEndToEnd(t *testing.T) {
	f := newFakeProvider(t)
	s := newServer(t, captchaconfig.CaptchaConfig{
		Provider: captchaconfig.CloudflareTurnstile, SecretKey: "secret-key", SiteVerifyURLOverride: f.URL,
	})

	t.Run("missing header", func(t *testing.T) {
		r := s.Post(t, "/api/auth/sign-up/email", signUpBody("missing@example.com"))
		expectMiddlewareError(t, r, http.StatusBadRequest, "MISSING_RESPONSE", "Missing CAPTCHA response")
	})
	t.Run("rejected token", func(t *testing.T) {
		r := s.Post(t, "/api/auth/sign-up/email", signUpBody("rejected@example.com"), withToken("bad"))
		expectMiddlewareError(t, r, http.StatusForbidden, "VERIFICATION_FAILED", "Captcha verification failed")
		// nothing was created
		r = s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "rejected@example.com", "password": "Password123!"}, withToken("pass"))
		if r.Status != http.StatusUnauthorized {
			t.Fatalf("sign-in status = %d: %s", r.Status, r.Body)
		}
	})
	t.Run("valid token", func(t *testing.T) {
		r := s.Post(t, "/api/auth/sign-up/email", signUpBody("valid@example.com"), withToken("pass"))
		if r.Status != http.StatusOK {
			t.Fatalf("sign-up = %d: %s", r.Status, r.Body)
		}
		// the client IP goes to the provider (x-forwarded-for, like the rate limiter)
		r = s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "valid@example.com", "password": "Password123!"},
			map[string]string{"x-captcha-response": "pass", "X-Forwarded-For": "203.0.113.7"})
		if r.Status != http.StatusOK {
			t.Fatalf("sign-in = %d: %s", r.Status, r.Body)
		}
		if ip := f.last(t).JSON["remoteip"]; ip != "203.0.113.7" {
			t.Fatalf("remoteip = %v", ip)
		}
	})
	t.Run("request-password-reset is protected", func(t *testing.T) {
		r := s.Post(t, "/api/auth/request-password-reset", map[string]any{"email": "valid@example.com"})
		expectMiddlewareError(t, r, http.StatusBadRequest, "MISSING_RESPONSE", "Missing CAPTCHA response")
	})
	t.Run("other routes are not", func(t *testing.T) {
		before := f.hits.Load()
		r := s.Get(t, "/api/auth/get-session")
		if r.Status != http.StatusOK {
			t.Fatalf("get-session = %d: %s", r.Status, r.Body)
		}
		if f.hits.Load() != before {
			t.Fatal("provider called for an unprotected route")
		}
	})
	t.Run("runs before body validation and the origin check", func(t *testing.T) {
		// an invalid body and an untrusted origin still get the captcha error first (better-auth's onRequest)
		r := s.Post(t, "/api/auth/sign-in/email", map[string]any{"nope": true},
			map[string]string{"Origin": "https://evil.example", "Cookie": "a=b"})
		expectMiddlewareError(t, r, http.StatusBadRequest, "MISSING_RESPONSE", "Missing CAPTCHA response")
	})
	t.Run("provider down is UNKNOWN_ERROR", func(t *testing.T) {
		f.setStatus(http.StatusInternalServerError)
		defer f.setStatus(http.StatusOK)
		r := s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "valid@example.com", "password": "Password123!"}, withToken("pass"))
		expectMiddlewareError(t, r, http.StatusInternalServerError, "UNKNOWN_ERROR", "Something went wrong")
	})
}

func TestCaptchaMissingSecretKey(t *testing.T) {
	f := newFakeProvider(t)
	s := newServer(t, captchaconfig.CaptchaConfig{Provider: captchaconfig.HCaptcha, SiteVerifyURLOverride: f.URL})
	// the secret is checked before the header, like better-auth
	r := s.Post(t, "/api/auth/sign-up/email", signUpBody("nosecret@example.com"))
	expectMiddlewareError(t, r, http.StatusInternalServerError, "UNKNOWN_ERROR", "Something went wrong")
	if f.hits.Load() != 0 {
		t.Fatal("provider must not be called")
	}
}

func TestCaptchaUnreachableProvider(t *testing.T) {
	s := newServer(t, captchaconfig.CaptchaConfig{
		Provider: captchaconfig.CaptchaFox, SecretKey: "k", SiteVerifyURLOverride: "http://127.0.0.1:1/siteverify",
	})
	r := s.Post(t, "/api/auth/sign-up/email", signUpBody("down@example.com"), withToken("pass"))
	expectMiddlewareError(t, r, http.StatusInternalServerError, "UNKNOWN_ERROR", "Something went wrong")
}

func TestCaptchaRecaptchaScoreEndToEnd(t *testing.T) {
	f := newFakeProvider(t)
	s := newServer(t, captchaconfig.CaptchaConfig{Provider: captchaconfig.GoogleRecaptcha, SecretKey: "k", SiteVerifyURLOverride: f.URL})
	r := s.Post(t, "/api/auth/sign-up/email", signUpBody("low@example.com"), withToken("low-score"))
	expectMiddlewareError(t, r, http.StatusForbidden, "VERIFICATION_FAILED", "Captcha verification failed")
	r = s.Post(t, "/api/auth/sign-up/email", signUpBody("high@example.com"), withToken("high-score"))
	if r.Status != http.StatusOK {
		t.Fatalf("sign-up = %d: %s", r.Status, r.Body)
	}
}

func TestCaptchaCustomEndpointsAndBasePath(t *testing.T) {
	f := newFakeProvider(t)
	s := newServer(t, captchaconfig.CaptchaConfig{
		Provider: captchaconfig.CloudflareTurnstile, SecretKey: "k", SiteVerifyURLOverride: f.URL,
		Endpoints: []string{"/get-session"},
	}, func(c *config.AuthConfig) { c.BasePath = "/auth" })
	// sign-up is no longer protected
	r := s.Post(t, "/auth/sign-up/email", signUpBody("custom@example.com"))
	if r.Status != http.StatusOK {
		t.Fatalf("sign-up = %d: %s", r.Status, r.Body)
	}
	// get-session is
	r = s.Get(t, "/auth/get-session")
	expectMiddlewareError(t, r, http.StatusBadRequest, "MISSING_RESPONSE", "Missing CAPTCHA response")
	r = s.Get(t, "/auth/get-session", withToken("pass"))
	if r.Status != http.StatusOK {
		t.Fatalf("get-session = %d: %s", r.Status, r.Body)
	}
}

func TestCaptchaBeforeRateLimiter(t *testing.T) {
	f := newFakeProvider(t)
	enabled := true
	s := newServer(t, captchaconfig.CaptchaConfig{Provider: captchaconfig.CloudflareTurnstile, SecretKey: "k", SiteVerifyURLOverride: f.URL},
		func(c *config.AuthConfig) { c.RateLimit.Enabled = &enabled })
	// sign-in allows 3 requests per 10 s; captcha rejections answer before the limiter counts them
	for i := 0; i < 5; i++ {
		r := s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "x@example.com", "password": "Password123!"},
			map[string]string{"X-Forwarded-For": "198.51.100.1"})
		expectMiddlewareError(t, r, http.StatusBadRequest, "MISSING_RESPONSE", "Missing CAPTCHA response")
	}
	r := s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "x@example.com", "password": "Password123!"},
		map[string]string{"X-Forwarded-For": "198.51.100.1", "x-captcha-response": "pass"})
	if r.Status != http.StatusUnauthorized {
		t.Fatalf("sign-in = %d: %s", r.Status, r.Body)
	}
}

func TestCaptchaConcurrent(t *testing.T) {
	f := newFakeProvider(t)
	s := newServer(t, captchaconfig.CaptchaConfig{Provider: captchaconfig.CloudflareTurnstile, SecretKey: "k", SiteVerifyURLOverride: f.URL})
	var wg sync.WaitGroup
	var failures atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			token := "pass"
			want := http.StatusUnauthorized
			if i%2 == 1 {
				token, want = "bad", http.StatusForbidden
			}
			r := s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "nobody@example.com", "password": "Password123!"}, withToken(token))
			if r.Status != want {
				failures.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d requests got the wrong status", failures.Load())
	}
}

func TestOnRequestDirect(t *testing.T) {
	svc := services.New(captchaconfig.CaptchaConfig{Provider: captchaconfig.CloudflareTurnstile, SecretKey: "k"}, "/api/auth", nil)
	r := httptest.NewRequest(http.MethodPost, "/api/auth/sign-in/email", nil)
	res, err := svc.OnRequest(r)
	if err != nil || res == nil || res.Status != http.StatusBadRequest {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	var _ endpointhooks.RequestFunc = svc.OnRequest
	if res, _ := svc.OnRequest(httptest.NewRequest(http.MethodGet, "/api/auth/ok", nil)); res != nil {
		t.Fatal("unprotected path answered")
	}
}
