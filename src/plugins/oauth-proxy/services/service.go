// Package services implements better-auth's oauth-proxy plugin: the endpoint hooks that route the OAuth
// callback of preview deployments through the production deployment, and GET /oauth-proxy-callback, which
// signs the user in on the preview deployment from the encrypted profile production sends back.
//
// The flow (preview = the deployment the user is on, production = ProductionURL):
//
//  1. preview POST /sign-in/social: a before hook rewrites callbackURL to
//     "<preview>/api/auth/oauth-proxy-callback?callbackURL=<original>" and switches the request's base URL to
//     production, so the provider's redirect_uri is "<production>/api/auth/callback/<id>"; an after hook
//     replaces the `state` of the returned authorization URL with an encrypted state package carrying the
//     preview's OAuth state (PKCE verifier, callback URLs).
//  2. production GET /callback/<id>: a before hook decrypts the state package, exchanges the code, fetches
//     the user and redirects to the preview's /oauth-proxy-callback with the encrypted profile.
//  3. preview GET /oauth-proxy-callback: the profile is decrypted, checked (maxAge), the user is signed in or
//     signed up like a normal OAuth callback, and the browser is redirected to the original callbackURL.
//
// Everything is encrypted with better-auth's symmetricEncrypt (XChaCha20-Poly1305, key SHA-256(secret)), so
// a goauth deployment and a better-auth one sharing the secret interoperate.
package services

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/config"
	proxyconfig "github.com/better-go-auth/goauth/src/plugins/oauth-proxy/config"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	socialservices "github.com/better-go-auth/goauth/src/plugins/social/services"
)

// SkipProxyHeader skips the proxy for a request when set (better-auth's x-skip-oauth-proxy).
const SkipProxyHeader = "x-skip-oauth-proxy"

// errInvalidURL is returned for relative URLs where better-auth's new URL(...) throws.
var errInvalidURL = errors.New("invalid URL")

// SocialService returns the social plugin's service (nil before the social plugin is initialized).
type SocialService func() *socialservices.Service

// Service holds the oauth-proxy runtime.
type Service struct {
	kit    *pluginkit.Kit
	cfg    proxyconfig.OAuthProxyConfig
	social SocialService
}

// New builds the service. social resolves the social plugin's service at request time.
func New(kit *pluginkit.Kit, cfg proxyconfig.OAuthProxyConfig, social SocialService) *Service {
	return &Service{kit: kit, cfg: cfg.WithDefaults(), social: social}
}

// Kit returns the plugin kit.
func (s *Service) Kit() *pluginkit.Kit { return s.kit }

// Config returns the effective configuration.
func (s *Service) Config() proxyconfig.OAuthProxyConfig { return s.cfg }

// key is the encryption key: the plugin secret, else the auth secret (better-auth's opts.secret ??
// ctx.context.secretConfig).
func (s *Service) key() string {
	if s.cfg.Secret != "" {
		return s.cfg.Secret
	}
	return s.kit.Conf.Secret
}

// socialService returns the social service, or nil when the social plugin is missing.
func (s *Service) socialService() *socialservices.Service {
	if s.social == nil {
		return nil
	}
	return s.social()
}

// ─── URL helpers (better-auth's oauth-proxy/utils.ts) ────────────────────────

// stripTrailingSlash removes trailing slashes ("" stays "").
func stripTrailingSlash(u string) string { return strings.TrimRight(u, "/") }

// originOf is better-auth's getOrigin: "<scheme>://<host>" of an absolute URL, "" when it has none.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	// like URL.origin: lower-case scheme and host, the scheme's default port dropped
	scheme, host := strings.ToLower(u.Scheme), strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" && !(scheme == "http" && port == "80") && !(scheme == "https" && port == "443") {
		host += ":" + port
	}
	return scheme + "://" + host
}

// vendorBaseURL is better-auth's getVendorBaseURL: the deployment URL hosting platforms expose.
func vendorBaseURL() string {
	if v := os.Getenv("VERCEL_URL"); v != "" {
		return "https://" + v
	}
	for _, name := range []string{"NETLIFY_URL", "RENDER_URL", "AWS_LAMBDA_FUNCTION_NAME", "GOOGLE_CLOUD_FUNCTION_NAME", "AZURE_FUNCTION_NAME"} {
		if v := os.Getenv(name); v != "" {
			return v
		}
	}
	return ""
}

// requestURL is the absolute URL of the request (better-auth's ctx.request.url). The scheme comes from
// X-Forwarded-Proto, else from BaseURL when it names the same host, else http.
func (s *Service) requestURL(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	if r.URL.IsAbs() {
		return r.URL.String()
	}
	// Step 1: the host the client used
	host := r.Host
	if host == "" {
		return ""
	}
	// Step 2: the scheme
	scheme := "http"
	if p := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]); p != "" {
		scheme = strings.ToLower(p)
	} else if base, err := url.Parse(s.kit.Conf.BaseURL); err == nil && base.Scheme != "" && strings.EqualFold(base.Host, host) {
		scheme = base.Scheme
	}
	u := *r.URL
	u.Scheme, u.Host = scheme, host
	return u.String()
}

// checkSkipProxy is better-auth's checkSkipProxy: the proxy is skipped with the x-skip-oauth-proxy header and
// when the current deployment is the production deployment.
func (s *Service) checkSkipProxy(c *endpointhooks.Context) bool {
	// Step 1: explicit opt-out
	if c.Headers.Get(SkipProxyHeader) != "" {
		return true
	}
	// Step 2: production URL (option, $BETTER_AUTH_URL, the base URL)
	productionURL := s.cfg.ProductionURL
	if productionURL == "" {
		productionURL = os.Getenv(config.BaseURLEnvVar)
	}
	if productionURL == "" {
		productionURL = s.kit.RequestBaseURL(c.Ctx)
	}
	if productionURL == "" {
		return false
	}
	// Step 3: current URL (option, the request URL, the vendor URL)
	currentURL := s.cfg.CurrentURL
	if currentURL == "" {
		currentURL = s.requestURL(c.Request)
	}
	if currentURL == "" {
		currentURL = vendorBaseURL()
	}
	if currentURL == "" {
		return false
	}
	return originOf(productionURL) == originOf(currentURL)
}

// resolveCurrentURL is better-auth's resolveCurrentURL: currentURL option, request URL, vendor URL, base URL.
func (s *Service) resolveCurrentURL(c *endpointhooks.Context) (*url.URL, error) {
	raw := s.cfg.CurrentURL
	if raw == "" {
		raw = s.requestURL(c.Request)
	}
	if raw == "" {
		raw = vendorBaseURL()
	}
	if raw == "" {
		raw = s.kit.RequestBaseURL(c.Ctx)
	}
	return parseAbsoluteURL(raw)
}

// parseAbsoluteURL parses raw like the WHATWG URL constructor: it must be absolute.
func parseAbsoluteURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || (u.Host == "" && u.Opaque == "") {
		return nil, &url.Error{Op: "parse", URL: raw, Err: errInvalidURL}
	}
	return u, nil
}

// encodeURIComponent is JavaScript's encodeURIComponent.
func encodeURIComponent(s string) string {
	const unreserved = "-_.!~*'()"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || strings.IndexByte(unreserved, ch) >= 0 {
			b.WriteByte(ch)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", ch)
	}
	return b.String()
}

// setSearchParam is URLSearchParams.set: the first key=value pair is replaced in place, later duplicates are
// dropped and a missing key is appended; the other pairs keep their order.
func setSearchParam(u *url.URL, key, value string) {
	pair := url.QueryEscape(key) + "=" + url.QueryEscape(value)
	var parts []string
	found := false
	for _, kv := range strings.Split(u.RawQuery, "&") {
		if kv == "" {
			continue
		}
		k, _, _ := strings.Cut(kv, "=")
		if dk, err := url.QueryUnescape(k); err == nil {
			k = dk
		}
		if k == key {
			if !found {
				parts = append(parts, pair)
				found = true
			}
			continue
		}
		parts = append(parts, kv)
	}
	if !found {
		parts = append(parts, pair)
	}
	u.RawQuery = strings.Join(parts, "&")
}

// redirectOnError is better-auth's redirectOnError: <errorURL>?error=<code>[&error_description=...].
func redirectOnError(errorURL, code, description string, cookies []http.Cookie) *endpointhooks.Response {
	r := socialservices.ErrorRedirect(errorURL, code, description, cookies)
	return redirectResponse(r.Location, r.Cookies)
}

// redirectResponse is a 302 to location with cookies.
func redirectResponse(location string, cookies []http.Cookie) *endpointhooks.Response {
	res := endpointhooks.Redirect(location)
	for i := range cookies {
		res.SetCookie(&cookies[i])
	}
	return res
}

// withBaseURL returns ctx with the per-request base URL (better-auth's ctx.context.baseURL = ...).
func withBaseURL(ctx context.Context, baseURL string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return pluginkit.WithBaseURL(ctx, baseURL)
}
