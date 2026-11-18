// Package ratelimit is a port of better-auth's api/rate-limiter: one limiter for every core and plugin
// route, keyed by client IP and request path.
//
// Rule resolution for a request path (relative to BasePath) follows better-auth exactly:
//
//  1. the global rule (RateLimit.Window / Max, default 10 s / 100);
//  2. the special rules (sign-in, sign-up, change-password, change-email: 3 per 10 s; password reset and
//     verification e-mails: 3 per 60 s), see SpecialRules;
//  3. plugin rules (first plugin rule whose matcher accepts the path), see Limiter.AddPluginRules;
//  4. RateLimit.CustomRules (exact path or wildcard pattern), which can also turn limiting off.
//
// A request is rejected with 429 when the stored record for "<ip>|<path>" saw at least max requests and the
// last one was less than a window ago. Every answered request updates the record afterwards (better-auth's
// onResponseRateLimit): the count restarts at 1 when the last request is older than the window.
package ratelimit

import (
	"context"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Rule is a window and the number of requests allowed in it.
type Rule struct {
	Window time.Duration
	Max    int
}

// Valid reports whether the rule limits anything.
func (r Rule) Valid() bool { return r.Window > 0 && r.Max > 0 }

// PathRule is a plugin rate-limit rule, better-auth's plugin `rateLimit` entry {pathMatcher, window, max}.
// PathMatcher receives the request path relative to BasePath (e.g. "/two-factor/verify-totp").
type PathRule struct {
	PathMatcher func(path string) bool
	Window      time.Duration
	Max         int
}

// CustomRule is a RateLimit.CustomRules value (better-auth's customRules entry).
//
//   - Window / Max replace the rule resolved so far (a zero field keeps the current value);
//   - Disabled turns rate limiting off for matching paths (better-auth's `false`);
//   - Resolve computes the rule per request (better-auth's function form). It receives the rule resolved so
//     far; returning ok=false turns limiting off for this request. Window, Max and Disabled are ignored when
//     Resolve is set.
type CustomRule struct {
	Window   time.Duration
	Max      int
	Disabled bool
	Resolve  func(r *http.Request, current Rule) (rule Rule, ok bool)
}

// Record is better-auth's rate-limit record (the `rateLimit` table row and the JSON value written to
// secondary storage). LastRequest is a Unix time in milliseconds.
type Record struct {
	Key         string `json:"key"`
	Count       int    `json:"count"`
	LastRequest int64  `json:"lastRequest"`
}

// Storage stores rate-limit records (better-auth's rateLimit.customStorage interface).
//
// Get returns nil (and no error) when there is no record for key. Set writes value; update is true when a
// record was read before (better-auth's `_update` flag: a database storage updates the row instead of
// inserting one). window is the window of the rule that applies to the key, usable as a TTL.
type Storage interface {
	Get(ctx context.Context, key string) (*Record, error)
	Set(ctx context.Context, key string, value Record, update bool, window time.Duration) error
}

// Options configure a Limiter.
type Options struct {
	// Enabled turns the limiter on.
	Enabled bool
	// Global is the default rule (better-auth: 10 s / 100).
	Global Rule
	// CustomRules are RateLimit.CustomRules: exact paths or wildcard patterns ("/sign-in/*", "/admin/**").
	CustomRules map[string]CustomRule
	// Storage keeps the records (required when Enabled).
	Storage Storage
	// BasePath is stripped from request paths before rules are matched (default "/api/auth").
	BasePath string
	// Now overrides the clock (tests).
	Now func() time.Time
	// OnError is called when the storage fails; the request is then let through.
	OnError func(err error)
}

// Defaults of better-auth's rate limiter.
const (
	DefaultWindow = 10 * time.Second
	DefaultMax    = 100
)

// TooManyRequestsMessage is better-auth's 429 message.
const TooManyRequestsMessage = "Too many requests. Please try again later."

// RetryAfterHeader is the header carrying the seconds until the client may retry.
const RetryAfterHeader = "X-Retry-After"

// SpecialRules are better-auth's getDefaultSpecialRules, applied before plugin and custom rules.
func SpecialRules() []PathRule {
	return []PathRule{
		{
			PathMatcher: func(path string) bool {
				return strings.HasPrefix(path, "/sign-in") || strings.HasPrefix(path, "/sign-up") ||
					strings.HasPrefix(path, "/change-password") || strings.HasPrefix(path, "/change-email")
			},
			Window: 10 * time.Second,
			Max:    3,
		},
		{
			PathMatcher: func(path string) bool {
				return path == "/request-password-reset" || path == "/send-verification-email" ||
					strings.HasPrefix(path, "/forget-password") || path == "/email-otp/send-verification-otp" ||
					path == "/email-otp/request-password-reset"
			},
			Window: 60 * time.Second,
			Max:    3,
		},
	}
}

// customRule is a CustomRules entry with its compiled matcher.
type customRule struct {
	pattern string
	match   func(string) bool
	rule    CustomRule
}

// Limiter is the rate limiter shared by every goauth route. It is safe for concurrent use.
type Limiter struct {
	enabled bool
	global  Rule
	custom  []customRule
	storage Storage
	base    string
	now     func() time.Time
	onError func(error)
	special []PathRule

	mu          sync.RWMutex
	pluginRules []PathRule

	locks keyLocks
}

// New builds a Limiter. Missing Global fields default to 10 s / 100.
func New(opts Options) *Limiter {
	// Step 1: defaults like better-auth's context (window || 10, max || 100)
	if opts.Global.Window <= 0 {
		opts.Global.Window = DefaultWindow
	}
	if opts.Global.Max <= 0 {
		opts.Global.Max = DefaultMax
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	base := strings.TrimRight(opts.BasePath, "/")
	if opts.BasePath == "" {
		base = "/api/auth"
	}
	l := &Limiter{
		enabled: opts.Enabled && opts.Storage != nil,
		global:  opts.Global,
		storage: opts.Storage,
		base:    base,
		now:     opts.Now,
		onError: opts.OnError,
		special: SpecialRules(),
	}
	// Step 2: compile the custom rules once; better-auth takes the first matching key in insertion order,
	// Go maps have none, so exact paths win over patterns and patterns are tried in lexical order
	for _, pattern := range sortedKeys(opts.CustomRules) {
		cr := customRule{pattern: pattern, rule: opts.CustomRules[pattern]}
		if strings.Contains(pattern, "*") {
			cr.match = WildcardMatch(pattern)
		} else {
			p := pattern
			cr.match = func(path string) bool { return path == p }
		}
		l.custom = append(l.custom, cr)
	}
	return l
}

// Enabled reports whether the limiter enforces anything.
func (l *Limiter) Enabled() bool { return l != nil && l.enabled }

// Storage returns the record storage.
func (l *Limiter) Storage() Storage {
	if l == nil {
		return nil
	}
	return l.storage
}

// AddPluginRules appends plugin rules (better-auth's plugin `rateLimit` arrays, in plugin order). Rules with
// a nil matcher or an invalid window/max are ignored. Safe on a nil Limiter.
func (l *Limiter) AddPluginRules(rules ...PathRule) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range rules {
		if r.PathMatcher != nil && r.Window > 0 && r.Max > 0 {
			l.pluginRules = append(l.pluginRules, r)
		}
	}
}

// Path returns the request path relative to BasePath without trailing slashes, like better-auth's
// normalizePathname ("/api/auth/sign-in/email/" → "/sign-in/email").
func (l *Limiter) Path(urlPath string) string {
	p := strings.TrimRight(urlPath, "/")
	if p == "" {
		p = "/"
	}
	if l.base == "" || l.base == "/" {
		return p
	}
	if p == l.base {
		return "/"
	}
	if strings.HasPrefix(p, l.base+"/") {
		rel := strings.TrimRight(p[len(l.base):], "/")
		if rel == "" {
			return "/"
		}
		return rel
	}
	return p
}

// Key is better-auth's createRateLimitKey: "<ip>|<path>".
func Key(ip, path string) string { return ip + "|" + path }

// Resolve is better-auth's resolveRateLimitConfig: the storage key and rule for a request from ip
// (already normalized, see NormalizeIP). ok is false when the request is not limited (no IP, or a custom
// rule turned limiting off).
func (l *Limiter) Resolve(r *http.Request, ip string) (key string, rule Rule, ok bool) {
	// Step 1: without a client IP better-auth skips rate limiting
	if l == nil || ip == "" || r == nil || r.URL == nil {
		return "", Rule{}, false
	}
	path := l.Path(r.URL.Path)
	key = Key(ip, path)
	rule = l.global
	// Step 2: special rules
	for _, sr := range l.special {
		if sr.PathMatcher(path) {
			rule = Rule{Window: sr.Window, Max: sr.Max}
			break
		}
	}
	// Step 3: the first matching plugin rule
	l.mu.RLock()
	for _, pr := range l.pluginRules {
		if pr.PathMatcher(path) {
			rule = Rule{Window: pr.Window, Max: pr.Max}
			break
		}
	}
	l.mu.RUnlock()
	// Step 4: custom rules (rule, disabled, or per-request function)
	for _, cr := range l.custom {
		if !cr.match(path) {
			continue
		}
		if cr.rule.Resolve != nil {
			next, enabled := cr.rule.Resolve(r, rule)
			if !enabled {
				return "", Rule{}, false
			}
			rule = mergeRule(rule, next.Window, next.Max)
			break
		}
		if cr.rule.Disabled {
			return "", Rule{}, false
		}
		rule = mergeRule(rule, cr.rule.Window, cr.rule.Max)
		break
	}
	return key, rule, true
}

// mergeRule replaces the non-zero fields of current.
func mergeRule(current Rule, window time.Duration, max int) Rule {
	if window > 0 {
		current.Window = window
	}
	if max > 0 {
		current.Max = max
	}
	return current
}

// Check is better-auth's onRequestRateLimit: it reports whether the request must be rejected and the
// seconds until the client may retry (the X-Retry-After value).
func (l *Limiter) Check(ctx context.Context, key string, rule Rule) (limited bool, retryAfter int) {
	// Step 1: read the stored record; storage errors let the request through
	rec, err := l.storage.Get(ctx, key)
	if err != nil {
		l.reportError(err)
		return false, 0
	}
	if rec == nil {
		return false, 0
	}
	// Step 2: better-auth's shouldRateLimit: inside the window and at the limit
	now := l.now().UnixMilli()
	windowMs := rule.Window.Milliseconds()
	if now-rec.LastRequest < windowMs && rec.Count >= rule.Max {
		// Step 3: getRetryAfter: whole seconds until the window of the last request ends (rounded up)
		return true, int(math.Ceil(float64(rec.LastRequest+windowMs-now) / 1000))
	}
	return false, 0
}

// Hit is better-auth's onResponseRateLimit: it records an answered request.
func (l *Limiter) Hit(ctx context.Context, key string, rule Rule) {
	// Step 1: serialize updates of one key inside this process (better-auth reads and writes without a lock)
	unlock := l.locks.lock(key)
	defer unlock()
	// Step 2: read the current record
	rec, err := l.storage.Get(ctx, key)
	if err != nil {
		l.reportError(err)
		return
	}
	now := l.now().UnixMilli()
	// Step 3: first request, a request after the window (count restarts), or one more inside it
	switch {
	case rec == nil:
		err = l.storage.Set(ctx, key, Record{Key: key, Count: 1, LastRequest: now}, false, rule.Window)
	case now-rec.LastRequest > rule.Window.Milliseconds():
		next := *rec
		next.Count, next.LastRequest = 1, now
		err = l.storage.Set(ctx, key, next, true, rule.Window)
	default:
		next := *rec
		next.Count, next.LastRequest = rec.Count+1, now
		err = l.storage.Set(ctx, key, next, true, rule.Window)
	}
	if err != nil {
		l.reportError(err)
	}
}

// reportError hands a storage error to Options.OnError.
func (l *Limiter) reportError(err error) {
	if l.onError != nil {
		l.onError(err)
	}
}

// keyLocks is a small set of per-key mutexes (released entries are removed).
type keyLocks struct {
	mu    sync.Mutex
	locks map[string]*keyLock
}

type keyLock struct {
	mu   sync.Mutex
	refs int
}

// lock locks key and returns its unlock function.
func (k *keyLocks) lock(key string) func() {
	k.mu.Lock()
	if k.locks == nil {
		k.locks = map[string]*keyLock{}
	}
	kl := k.locks[key]
	if kl == nil {
		kl = &keyLock{}
		k.locks[key] = kl
	}
	kl.refs++
	k.mu.Unlock()
	kl.mu.Lock()
	return func() {
		kl.mu.Unlock()
		k.mu.Lock()
		kl.refs--
		if kl.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}
