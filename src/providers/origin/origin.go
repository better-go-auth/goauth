// Package origin decides whether a URL or Origin header is trusted, like better-auth's trustedOrigins.
package origin

import (
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/better-go-auth/goauth/src/config"
)

// TrustedOriginsEnvVar adds comma-separated trusted origins, as in better-auth.
const TrustedOriginsEnvVar = "BETTER_AUTH_TRUSTED_ORIGINS"

// Checker holds the trusted origin patterns: the BaseURL origin, config.TrustedOrigins and the env var.
type Checker struct {
	patterns []string
}

// New builds the trusted origin list from conf.
func New(conf config.AuthConfig) *Checker {
	var patterns []string
	if o := originOf(conf.BaseURL); o != "" {
		patterns = append(patterns, o)
	}
	patterns = append(patterns, conf.TrustedOrigins...)
	for _, p := range strings.Split(os.Getenv(TrustedOriginsEnvVar), ",") {
		if p = strings.TrimSpace(p); p != "" {
			patterns = append(patterns, p)
		}
	}
	return &Checker{patterns: patterns}
}

// IsTrusted reports whether raw matches a trusted pattern. Relative paths ("/dashboard") are
// accepted only with allowRelative, and never protocol-relative or encoded-slash paths.
func (c *Checker) IsTrusted(raw string, allowRelative bool) bool {
	for _, p := range c.patterns {
		if Matches(raw, p, allowRelative) {
			return true
		}
	}
	return false
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
		if strings.Contains(pattern, "://") {
			target := originOf(raw)
			if target == "" {
				target = raw
			}
			return wildcard(pattern).MatchString(target)
		}
		host := hostOf(raw)
		return host != "" && wildcard(pattern).MatchString(host)
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
	return regexp.MustCompile(b.String())
}
