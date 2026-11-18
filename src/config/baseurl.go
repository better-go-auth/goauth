package config

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// DynamicBaseURL is better-auth's dynamic baseURL config ({allowedHosts, fallback, protocol}): the base URL is
// derived from each request's host, which must match AllowedHosts.
type DynamicBaseURL struct {
	// AllowedHosts are host patterns (e.g. "myapp.com", "*.vercel.app", "preview-*.myapp.com", "localhost:3000").
	// "*" matches any characters except "/", "?" one character. Entries with "://" are full origins.
	AllowedHosts []string
	// Fallback is used when the request host is missing or not allowed (e.g. "https://myapp.com"). Without it
	// such requests are rejected.
	Fallback string
	// Protocol is "http", "https" or "auto" (default): auto takes X-Forwarded-Proto (when proxy headers are
	// trusted), then the connection (TLS), and defaults to https (http for loopback hosts).
	Protocol string
}

// ErrHostNotAllowed is returned by ResolveBaseURL when the request host matches no allowed host and there is
// no fallback.
var ErrHostNotAllowed = errors.New("host is not in the allowed hosts list")

// TrustProxyHeaders reports whether X-Forwarded-Host / X-Forwarded-Proto are honored when deriving the base URL
// (better-auth's advanced.trustedProxyHeaders; default true with a DynamicBaseURL, false otherwise).
func (opts AuthConfig) TrustProxyHeaders() bool {
	if opts.Advanced.TrustedProxyHeaders != nil {
		return *opts.Advanced.TrustedProxyHeaders
	}
	return opts.DynamicBaseURL != nil
}

// ResolveBaseURL is better-auth's resolveDynamicBaseURL: the origin ("https://host") of r when its host is in
// DynamicBaseURL.AllowedHosts, else the fallback origin. Without DynamicBaseURL it returns BaseURL.
func (opts AuthConfig) ResolveBaseURL(r *http.Request) (string, error) {
	// Step 1: static base URL
	d := opts.DynamicBaseURL
	if d == nil {
		return strings.TrimRight(opts.BaseURL, "/"), nil
	}
	// Step 2: the request host (X-Forwarded-Host first when proxy headers are trusted)
	trust := opts.TrustProxyHeaders()
	host := RequestHost(r, trust)
	if host != "" {
		for _, pattern := range d.AllowedHosts {
			if MatchesHostPattern(host, pattern) {
				return RequestProtocol(r, d.Protocol, trust) + "://" + host, nil
			}
		}
	}
	// Step 3: not allowed (or no host): the fallback, or an error
	if d.Fallback != "" {
		return strings.TrimRight(originOf(d.Fallback), "/"), nil
	}
	if host == "" {
		return "", fmt.Errorf("%w: could not determine host from request headers", ErrHostNotAllowed)
	}
	return "", fmt.Errorf("%w: %q", ErrHostNotAllowed, host)
}

// DynamicTrustedOrigins are the origins better-auth's getTrustedOrigins derives from a dynamic base URL: every
// allowed host as https:// (protocol https/auto) and http:// (protocol http/auto, or a loopback host), plus the
// fallback origin.
func (d DynamicBaseURL) DynamicTrustedOrigins() []string {
	var out []string
	for _, host := range d.AllowedHosts {
		if strings.Contains(host, "://") {
			out = append(out, host)
			continue
		}
		proto := d.Protocol
		if proto == "" || proto == "https" || proto == "auto" {
			out = append(out, "https://"+host)
		}
		if proto == "http" || proto == "auto" || isLoopbackHost(host) {
			out = append(out, "http://"+host)
		}
	}
	if d.Fallback != "" {
		if o := originOf(d.Fallback); o != "" {
			out = append(out, o)
		}
	}
	return out
}

// RequestHost is better-auth's getHostFromSource: X-Forwarded-Host (only with trustProxy), then the Host
// header, each validated; "" when none is usable.
func RequestHost(r *http.Request, trustProxy bool) string {
	if r == nil {
		return ""
	}
	if trustProxy {
		if fh := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); fh != "" && validProxyHost(fh) {
			return fh
		}
	}
	host := r.Host
	if host == "" {
		host = r.Header.Get("Host")
	}
	if host != "" && validProxyHost(host) {
		return host
	}
	if r.URL != nil && r.URL.Host != "" && validProxyHost(r.URL.Host) {
		return r.URL.Host
	}
	return ""
}

// RequestProtocol is better-auth's getProtocolFromSource: the configured "http"/"https", else X-Forwarded-Proto
// (only with trustProxy), else the connection (TLS or an absolute request URL), else http for loopback hosts
// and https otherwise.
func RequestProtocol(r *http.Request, configured string, trustProxy bool) string {
	if configured == "http" || configured == "https" {
		return configured
	}
	if r == nil {
		return "https"
	}
	if trustProxy {
		if p := r.Header.Get("X-Forwarded-Proto"); p == "http" || p == "https" {
			return p
		}
	}
	if r.TLS != nil {
		return "https"
	}
	if r.URL != nil && (r.URL.Scheme == "http" || r.URL.Scheme == "https") {
		return r.URL.Scheme
	}
	if isLoopbackHost(RequestHost(r, trustProxy)) {
		return "http"
	}
	return "https"
}

// MatchesHostPattern is better-auth's matchesHostPattern: a case-insensitive exact or wildcard host match
// (schemes and paths are ignored on both sides).
func MatchesHostPattern(host, pattern string) bool {
	if host == "" || pattern == "" {
		return false
	}
	norm := func(s string) string {
		s = strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(s), "https://"), "http://")
		s, _, _ = strings.Cut(s, "/")
		return s
	}
	h, p := norm(host), norm(pattern)
	if !strings.ContainsAny(p, "*?") {
		return h == p
	}
	var b strings.Builder
	b.WriteString("^")
	for _, c := range p {
		switch c {
		case '*':
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	return err == nil && re.MatchString(h)
}

// hostHeaderRe are better-auth's validateProxyHeader host shapes: DNS names, IPv4, bracketed IPv6, localhost,
// each with an optional port.
var hostHeaderRe = []*regexp.Regexp{
	regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*(:[0-9]{1,5})?$`),
	regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}(:[0-9]{1,5})?$`),
	regexp.MustCompile(`^\[[0-9a-fA-F:]+\](:[0-9]{1,5})?$`),
	regexp.MustCompile(`(?i)^localhost(:[0-9]{1,5})?$`),
}

// suspiciousHost are better-auth's rejected host header patterns.
var suspiciousHost = regexp.MustCompile(`(?i)\.\.|\x00|\s|^\.|[<>'"]|javascript:|file:|data:`)

// validProxyHost is better-auth's validateProxyHeader(header, "host").
func validProxyHost(h string) bool {
	if strings.TrimSpace(h) == "" || suspiciousHost.MatchString(h) {
		return false
	}
	for _, re := range hostHeaderRe {
		if re.MatchString(h) {
			return true
		}
	}
	return false
}

// isLoopbackHost reports whether host (with optional port) is localhost, *.localhost, ::1 or 127.x.
func isLoopbackHost(host string) bool {
	h := strings.ToLower(host)
	if hh, _, err := net.SplitHostPort(h); err == nil {
		h = hh
	}
	h = strings.Trim(h, "[]")
	return h == "localhost" || strings.HasSuffix(h, ".localhost") || h == "::1" || strings.HasPrefix(h, "127.")
}

// originOf returns "scheme://host" of raw ("" when raw is not absolute).
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

type baseURLKey struct{}

// WithRequestBaseURL stores the base URL origin resolved for the current request (set by goauth's middleware
// when DynamicBaseURL is configured).
func WithRequestBaseURL(ctx context.Context, origin string) context.Context {
	return context.WithValue(ctx, baseURLKey{}, origin)
}

// RequestBaseURL returns the base URL origin of the current request: the one resolved from DynamicBaseURL, else
// BaseURL (without trailing slash). Append BasePath for better-auth's ctx.context.baseURL.
func (opts AuthConfig) RequestBaseURL(ctx context.Context) string {
	if ctx != nil {
		if v, ok := ctx.Value(baseURLKey{}).(string); ok && v != "" {
			return v
		}
	}
	return strings.TrimRight(opts.BaseURL, "/")
}

// AuthBaseURL is better-auth's ctx.context.baseURL for the current request: RequestBaseURL + BasePath.
func (opts AuthConfig) AuthBaseURL(ctx context.Context) string {
	base := opts.BasePath
	if base == "" {
		base = "/api/auth"
	}
	return opts.RequestBaseURL(ctx) + strings.TrimSuffix(base, "/")
}
