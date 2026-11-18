package ratelimit

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

// WildcardMatch compiles a glob pattern like better-auth's wildcardMatch (utils/wildcard.ts) with its
// default "/" separator: `*` matches within one path segment, `**` matches any number of segments,
// `?` matches one character, `\` escapes the next character. An invalid pattern matches nothing.
func WildcardMatch(pattern string) func(path string) bool {
	re, err := regexp.Compile("^" + wildcardRegexp(pattern) + "$")
	if err != nil {
		return func(string) bool { return false }
	}
	return re.MatchString
}

// wildcardRegexp is better-auth's transform(pattern, separator = true).
func wildcardRegexp(pattern string) string {
	const (
		separatorMatcher = `[/\\]`
		wildcard         = `[^/\\]`
	)
	requiredSeparator := separatorMatcher + "+?"
	optionalSeparator := separatorMatcher + "*?"
	segments := strings.Split(pattern, "/")
	var b strings.Builder
	for s, segment := range segments {
		// Step 1: empty segments (repeated slashes) after the first are skipped
		if segment == "" && s > 0 {
			continue
		}
		// Step 2: the separator that follows this segment
		var currentSeparator string
		switch {
		case s == len(segments)-1:
			currentSeparator = optionalSeparator
		case segments[s+1] != "**":
			currentSeparator = requiredSeparator
		}
		// Step 3: "**" spans any number of segments
		if segment == "**" {
			if currentSeparator != "" {
				if s != 0 {
					b.WriteString(currentSeparator)
				}
				b.WriteString("(?:" + wildcard + "*?" + currentSeparator + ")*?")
			}
			continue
		}
		// Step 4: literal characters, `?`, `*` and escapes
		runes := []rune(segment)
		for c := 0; c < len(runes); c++ {
			switch ch := runes[c]; ch {
			case '\\':
				if c < len(runes)-1 {
					b.WriteString(escapeRegexpChar(runes[c+1]))
					c++
				}
			case '?':
				b.WriteString(wildcard)
			case '*':
				b.WriteString(wildcard + "*?")
			default:
				b.WriteString(escapeRegexpChar(ch))
			}
		}
		b.WriteString(currentSeparator)
	}
	return b.String()
}

// escapeRegexpChar escapes the characters better-auth's escapeRegExpChar escapes.
func escapeRegexpChar(ch rune) string {
	switch ch {
	case '-', '^', '$', '+', '.', '(', ')', '|', '[', ']', '{', '}', '*', '?', '\\':
		return `\` + string(ch)
	}
	return regexp.QuoteMeta(string(ch))
}

// NormalizeIP is better-auth's normalizeIP: IPv4 addresses (and IPv4-mapped IPv6 addresses) become the
// dotted IPv4 form; other IPv6 addresses are expanded to eight 4-digit groups and masked to their
// ipv6Subnet prefix (default 64), so all addresses of one /64 share a rate limit. Anything else is lower-cased.
func NormalizeIP(ip string, ipv6Subnet int) string {
	// Step 1: plain IPv4
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return strings.ToLower(ip)
	}
	if !strings.Contains(ip, ":") {
		return strings.ToLower(ip)
	}
	// Step 2: IPv4-mapped IPv6 → IPv4
	if v4 := parsed.To4(); v4 != nil {
		return v4.String()
	}
	// Step 3: expanded IPv6 masked to the subnet prefix
	if ipv6Subnet <= 0 {
		ipv6Subnet = 64
	}
	v6 := parsed.To16()
	if ipv6Subnet < 128 {
		v6 = v6.Mask(net.CIDRMask(ipv6Subnet, 128))
	}
	groups := make([]string, 8)
	for i := range groups {
		groups[i] = fmt.Sprintf("%02x%02x", v6[2*i], v6[2*i+1])
	}
	return strings.Join(groups, ":")
}

// sortedKeys orders custom-rule keys: exact paths first, then patterns, each lexically.
func sortedKeys(m map[string]CustomRule) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		wi, wj := strings.Contains(keys[i], "*"), strings.Contains(keys[j], "*")
		if wi != wj {
			return !wi
		}
		return keys[i] < keys[j]
	})
	return keys
}
