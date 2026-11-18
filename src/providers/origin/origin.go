// Package origin decides whether a URL or Origin header is trusted, like better-auth's trustedOrigins.
package origin

import (
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/better-go-auth/goauth/src/config"
)

// TrustedOriginsEnvVar adds comma-separated trusted origins, as in better-auth.
const TrustedOriginsEnvVar = "BETTER_AUTH_TRUSTED_ORIGINS"

// Checker holds the trusted origin patterns: the BaseURL origin (or the DynamicBaseURL allowed hosts),
// config.TrustedOrigins, the env var, and config.TrustedOriginsFunc evaluated per request.
type Checker struct {
	patterns []string
	compiled map[string]*regexp.Regexp
	// fn is config.TrustedOriginsFunc (better-auth's trustedOrigins as a function of the request)
	fn func(r *http.Request) []string
}

// New builds the trusted origin list from conf, like better-auth's getTrustedOrigins.
func New(conf config.AuthConfig) *Checker {
	// Step 1: the base URL: every allowed host of a dynamic base URL, else the static BaseURL origin
	var patterns []string
	if d := conf.DynamicBaseURL; d != nil {
		patterns = append(patterns, d.DynamicTrustedOrigins()...)
	} else if o := originOf(conf.BaseURL); o != "" {
		patterns = append(patterns, o)
	}
	// Step 2: the static list and $BETTER_AUTH_TRUSTED_ORIGINS
	patterns = append(patterns, conf.TrustedOrigins...)
	for _, p := range strings.Split(os.Getenv(TrustedOriginsEnvVar), ",") {
		if p = strings.TrimSpace(p); p != "" {
			patterns = append(patterns, p)
		}
	}
	compiled := make(map[string]*regexp.Regexp, len(patterns))
	for _, pat := range patterns {
		if strings.ContainsAny(pat, "*?") {
			if re := wildcard(pat); re != nil {
				compiled[pat] = re
			}
		}
	}
	return &Checker{patterns: patterns, compiled: compiled, fn: conf.TrustedOriginsFunc}
}

// IsTrusted reports whether raw matches a trusted pattern. Relative paths ("/dashboard") are
// accepted only with allowRelative, and never protocol-relative or encoded-slash paths.
// TrustedOriginsFunc is called with a nil request; use IsTrustedFor inside a request.
func (c *Checker) IsTrusted(raw string, allowRelative bool) bool {
	return c.IsTrustedFor(nil, raw, allowRelative)
}

// IsTrustedFor is IsTrusted for request r: the origins TrustedOriginsFunc returns for r are trusted too.
func (c *Checker) IsTrustedFor(r *http.Request, raw string, allowRelative bool) bool {
	// Step 1: the static patterns
	for _, p := range c.patterns {
		if c.matchesCached(raw, p, allowRelative) {
			return true
		}
	}
	// Step 2: origins computed for this request (empty entries ignored, like better-auth's filter(Boolean))
	if c.fn == nil {
		return false
	}
	for _, p := range c.fn(r) {
		if p != "" && c.matchesCached(raw, p, allowRelative) {
			return true
		}
	}
	return false
}

func (c *Checker) matchesCached(raw, pattern string, allowRelative bool) bool {
	if strings.HasPrefix(raw, "/") {
		return Matches(raw, pattern, allowRelative)
	}
	if strings.ContainsAny(pattern, "*?") {
		re, ok := c.compiled[pattern]
		if !ok {
			re = wildcard(pattern)
		}
		if re == nil {
			return false
		}
		if strings.Contains(pattern, "://") {
			target := originOf(raw)
			if target == "" {
				target = raw
			}
			return re.MatchString(target)
		}
		host := hostOf(raw)
		return host != "" && re.MatchString(host)
	}
	return Matches(raw, pattern, allowRelative)
}

var relativePath = regexp.MustCompile(`^/[\w\-.+/@]*(?:\?[\w\-.+/=&%@]*)?$`)

// Matches is better-auth's matchesOriginPattern.
func Matches(raw, pattern string, allowRelative bool) bool {
	if strings.HasPrefix(raw, "/") {
		if !allowRelative {
			return false
		}
		rest := strings.ToLower(raw[1:])
		if strings.HasPrefix(rest, "/") || strings.HasPrefix(rest, `\`) ||
			strings.HasPrefix(rest, "%2f") || strings.HasPrefix(rest, "%5c") {
			return false
		}
		return relativePath.MatchString(raw)
	}
	if strings.ContainsAny(pattern, "*?") {
		re := wildcard(pattern)
		if re == nil {
			return false
		}
		if strings.Contains(pattern, "://") {
			target := originOf(raw)
			if target == "" {
				target = raw
			}
			return re.MatchString(target)
		}
		host := hostOf(raw)
		return host != "" && re.MatchString(host)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	if u.Scheme == "" || u.Scheme == "http" || u.Scheme == "https" {
		return pattern == originOf(raw)
	}
	// custom schemes (e.g. exp://, myapp://) match by prefix
	return strings.HasPrefix(raw, pattern)
}

func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// wildcard compiles a glob: "**" matches anything, "*" anything but "/", "?" one character.
// Returns nil if compilation fails.
func wildcard(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch c := pattern[i]; {
		case c == '*' && i+1 < len(pattern) && pattern[i+1] == '*':
			b.WriteString(".*")
			i++
		case c == '*':
			b.WriteString("[^/]*")
		case c == '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	return re
}
