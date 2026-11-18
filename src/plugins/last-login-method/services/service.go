// Package services implements the last-login-method plugin: method resolution (better-auth's
// defaultResolveMethod), the after hook setting the cookie, and the optional database writes.
package services

import (
	"context"
	"net/http"
	"strings"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	llmconfig "github.com/better-go-auth/goauth/src/plugins/last-login-method/config"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"gorm.io/gorm"
)

// Deps are the runtime dependencies of the service.
type Deps struct {
	// BasePath is the auth BasePath (default "/api/auth").
	BasePath string
	// Cookies builds the cookie with the session cookie's attributes and knows the session cookie name.
	Cookies *cookies.Manager
	// Repos writes the lastLoginMethod field (StoreInDatabase).
	Repos repo_interfaces.IAuthRepos
	// UpdateKey is the key UpdateUser receives for the field: the registry field name for repositories over
	// the schema registry (adapterrepo), the physical column for GORM repositories.
	UpdateKey string
	// DB is set for GORM repositories, which don't store runtime fields on insert: AfterUserCreate then
	// writes the field with an update.
	DB *gorm.DB
}

// Service resolves login methods and records them.
type Service struct {
	cfg  llmconfig.LastLoginMethodConfig
	deps Deps
}

// New builds the service.
func New(cfg llmconfig.LastLoginMethodConfig, deps Deps) *Service {
	deps.BasePath = strings.TrimSuffix(deps.BasePath, "/")
	if deps.BasePath == "" {
		deps.BasePath = "/api/auth"
	}
	return &Service{cfg: cfg.WithDefaults(), deps: deps}
}

// Config returns the effective configuration.
func (s *Service) Config() llmconfig.LastLoginMethodConfig { return s.cfg }

// ─── resolution ──────────────────────────────────────────────────────────────

// DefaultResolveMethod is better-auth's defaultResolveMethod. path is the endpoint path (a route template
// or the request path), urlPath the request path relative to BasePath (for the provider id of callbacks):
//
//	/callback/:id, /oauth2/callback/:providerId → the provider id
//	/sign-in/email, /sign-up/email            → "email"
//	paths containing "siwe"                   → "siwe"
//	paths containing /passkey/verify-authentication → "passkey"
//	/magic-link/verify...                     → "magic-link"
//
// Anything else (including email-otp, phone-number, username and one-tap sign-ins) resolves to "".
func DefaultResolveMethod(path, urlPath string) string {
	switch {
	case path == "":
		return ""
	case strings.HasPrefix(path, "/callback/") || strings.HasPrefix(path, "/oauth2/callback/"):
		// the provider id is the last segment of the request path (better-auth's params.id / params.providerId)
		p := urlPath
		if p == "" {
			p = path
		}
		return p[strings.LastIndex(p, "/")+1:]
	case path == "/sign-in/email" || path == "/sign-up/email":
		return "email"
	case strings.Contains(path, "siwe"):
		return "siwe"
	case strings.Contains(path, "/passkey/verify-authentication"):
		return "passkey"
	case strings.HasPrefix(path, "/magic-link/verify"):
		return "magic-link"
	}
	return ""
}

// Resolve returns the login method of the request (CustomResolveMethod, then the default rules).
func (s *Service) Resolve(c *endpointhooks.Context) string {
	if c == nil {
		return ""
	}
	// Step 1: the user's resolver wins unless it defers
	if s.cfg.CustomResolveMethod != nil {
		if m, ok := s.cfg.CustomResolveMethod(c); ok {
			return m
		}
	}
	// Step 2: better-auth's rules on the endpoint path
	return DefaultResolveMethod(c.Path, s.relativePath(c.Request))
}

// relativePath is the request path without BasePath.
func (s *Service) relativePath(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	return strings.TrimPrefix(r.URL.Path, s.deps.BasePath)
}

// contextFromRequest builds the resolve context of a database hook from the request stored in ctx (nil
// outside HTTP, like better-auth's hooks without an endpoint context).
func (s *Service) contextFromRequest(ctx context.Context) *endpointhooks.Context {
	req := config.GetHTTPRequest(ctx)
	if req == nil {
		return nil
	}
	return endpointhooks.NewContext(ctx, s.relativePath(req), req.Method, req, nil)
}

// ─── after hook: the cookie ──────────────────────────────────────────────────

// AfterHook is better-auth's after hook (matcher: every endpoint): when the request resolves to a login
// method and the response sets the session cookie, it sets the last-login-method cookie. With
// StoreInDatabase the new session's user gets the method too (better-auth's session.create.after hook).
func (s *Service) AfterHook(c *endpointhooks.Context) (*endpointhooks.Response, error) {
	// Step 1: only requests with a login method
	method := s.Resolve(c)
	if method == "" || c.Returned == nil {
		return nil, nil
	}
	// Step 2: the response must set the session cookie (better-auth checks the raw Set-Cookie strings)
	sessionName := s.deps.Cookies.Name(cookies.CookieSessionToken)
	setsSession := false
	for _, raw := range c.Returned.Header.Values("Set-Cookie") {
		if strings.Contains(raw, sessionName) {
			setsSession = true
			break
		}
	}
	if setsSession {
		c.Returned.SetCookie(s.Cookie(method))
	}
	// Step 3: remember the method on the user of the session the request created
	if s.cfg.StoreInDatabase {
		if sw := c.NewSession(); sw != nil {
			s.store(c.Ctx, sw.Session.UserID, method)
		}
	}
	return nil, nil
}

// Cookie returns the last-login-method cookie: the session cookie's attributes, MaxAge and not HttpOnly.
func (s *Service) Cookie(method string) *http.Cookie {
	ck := s.deps.Cookies.Cookie(cookies.CookieSessionToken, method, int(s.cfg.MaxAge.Seconds()))
	ck.Name = s.cfg.CookieName
	ck.HttpOnly = false
	return &ck
}

// ─── database hooks (StoreInDatabase) ────────────────────────────────────────

// BeforeUserCreate is better-auth's user.create.before hook: a user created by a sign-in request gets the
// method in its lastLoginMethod field.
func (s *Service) BeforeUserCreate(ctx context.Context, user *models.User) error {
	if !s.cfg.StoreInDatabase || user == nil {
		return nil
	}
	if method := s.Resolve(s.contextFromRequest(ctx)); method != "" {
		user.SetExtra(llmconfig.FieldLastLoginMethod, method)
	}
	return nil
}

// AfterUserCreate writes the field set by BeforeUserCreate for GORM repositories, which do not store
// runtime fields on insert (repositories over the schema registry already did).
func (s *Service) AfterUserCreate(ctx context.Context, user *models.User) error {
	if !s.cfg.StoreInDatabase || user == nil || s.deps.DB == nil {
		return nil
	}
	if v, ok := user.GetExtra(llmconfig.FieldLastLoginMethod); ok {
		if method, _ := v.(string); method != "" {
			s.store(ctx, user.ID, method)
		}
	}
	return nil
}

// store writes the method on the user; failures are logged like better-auth's "Failed to update
// lastLoginMethod". The column exists: SetupGoAuth's migrator creates the plugin's schema field (auto
// mode), and verify mode refuses to start without it.
func (s *Service) store(ctx context.Context, userID, method string) {
	if _, err := s.deps.Repos.UpdateUser(ctx, userID, map[string]interface{}{s.deps.UpdateKey: method}); err != nil {
		logger.Error("Failed to update lastLoginMethod", "error", err)
	}
}
