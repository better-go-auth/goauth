// Package pluginkit bundles what a better-auth style plugin needs to expose HTTP endpoints that behave
// exactly like goauth's core endpoints: base path and disabled-route handling, the origin/CSRF check,
// session resolution, better-auth's rate limiter, auth cookies, session creation and user-creation hooks.
//
// A plugin builds one Kit in Init and registers its routes with Register:
//
//	kit, err := pluginkit.New(ictx)
//	pluginkit.Register(kit, ictx.Api, pluginkit.Route{
//		OperationID: "signInMagicLink", Method: http.MethodPost, Path: "/sign-in/magic-link",
//		Access: pluginkit.Form, RateLimit: &ratelimit.Rule{Window: time.Minute, Max: 5},
//	}, handler.SignIn)
package pluginkit

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	svcint "github.com/better-go-auth/goauth/src/app/services/interfaces"
	sessionsvc "github.com/better-go-auth/goauth/src/app/services/session"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/better-go-auth/goauth/src/providers/origin"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
	"github.com/danielgtaylor/huma/v2"
	"gorm.io/gorm"
)

// Kit is the shared runtime of a plugin's HTTP endpoints. All fields are set by New.
type Kit struct {
	Conf      config.AuthConfig
	BasePath  string
	Repos     repo_interfaces.IAuthRepos
	Sessions  *sessionsvc.Manager
	Cookies   *cookies.Manager
	Resolver  *humaadapter.Resolver
	Origins   *origin.Checker
	Hooks     plugins.HookRegistry
	Tx        interfaces.ITransactionManager
	Passwords *authcrypto.Passwords
	Store     sec_storage.SecondaryStorage
	DB        *gorm.DB
	// Limiter is goauth's global rate limiter (InitContext.RateLimiter); Route.RateLimit adds rules to it.
	Limiter *ratelimit.Limiter

	generateID func() string
}

// New builds a Kit from the plugin init context.
func New(ictx *plugins.InitContext) (*Kit, error) {
	// Step 1: validate the dependencies every endpoint relies on
	if ictx == nil {
		return nil, errors.New("pluginkit: init context is required")
	}
	if ictx.IAuthRepos == nil {
		return nil, errors.New("pluginkit: repositories are required")
	}
	mgr, ok := ictx.SessionManager.(*sessionsvc.Manager)
	if !ok || mgr == nil {
		return nil, errors.New("pluginkit: a *session.Manager is required")
	}

	// Step 2: share the core cookie manager so names, attributes and the signing secret match
	cm := ictx.CookieManager
	if cm == nil {
		cm = cookies.New(ictx.Config)
	}

	// Step 3: resolve the base path the core routes use
	basePath := strings.TrimSuffix(ictx.Config.BasePath, "/")
	if ictx.Config.BasePath == "" {
		basePath = "/api/auth"
	}

	return &Kit{
		Conf:       ictx.Config,
		BasePath:   basePath,
		Repos:      ictx.IAuthRepos,
		Sessions:   mgr,
		Cookies:    cm,
		Resolver:   humaadapter.NewResolver(mgr, cm),
		Origins:    origin.New(ictx.Config),
		Hooks:      ictx.Hooks,
		Tx:         ictx.TxManager,
		Passwords:  newPasswords(ictx),
		Store:      ictx.SecondaryStorage,
		DB:         ictx.DB,
		Limiter:    ictx.RateLimiter,
		generateID: ictx.GenerateID,
	}, nil
}

// newPasswords builds the configured password hasher; new passwords go through the password-hash hooks
// (plugins.HookRegistry.OnPasswordHash) when hashed with Passwords.HashContext.
func newPasswords(ictx *plugins.InitContext) *authcrypto.Passwords {
	p := authcrypto.NewPasswords(ictx.Config)
	if ictx.Hooks != nil {
		p = p.WithBeforeHash(ictx.Hooks.TriggerPasswordHash)
	}
	return p
}

// Access selects the middlewares an endpoint runs behind (same levels as the core routes).
type Access int

const (
	// Public endpoints: mutating requests carrying cookies get the origin check.
	Public Access = iota
	// Form endpoints (sign-in style): origin check plus the Fetch-Metadata CSRF check for cookieless browsers.
	Form
	// OptionalSession attaches the session to ctx when there is one.
	OptionalSession
	// Session requires a valid session (401 UNAUTHORIZED otherwise).
	Session
	// FreshSession requires a session younger than Session.FreshAge (better-auth's sensitiveSessionMiddleware).
	FreshSession
)

// Route describes one plugin endpoint. Path is relative to BasePath (e.g. "/two-factor/enable").
type Route struct {
	OperationID string
	Method      string
	Path        string
	Summary     string
	Tags        []string
	Access      Access
	// FormCSRF applies the sign-in CSRF check (origin required for cookieless browser requests) to
	// non-Form access levels, e.g. an optional-session endpoint that also signs users in.
	FormCSRF bool
	// RateLimit adds a plugin rate-limit rule for this route's path to goauth's global limiter (it applies
	// while AuthConfig.RateLimit is enabled). Prefer plugins.RateLimitProvider for better-auth style
	// prefix rules.
	RateLimit *ratelimit.Rule
	// SkipOriginCheck disables the origin check (GET callbacks validate their own redirect targets).
	SkipOriginCheck bool
	// Hidden keeps the operation out of the OpenAPI document.
	Hidden bool
}

// Path returns the full mount path of a route path ("/sign-in/x" → "/api/auth/sign-in/x").
func (k *Kit) Path(p string) string { return k.BasePath + p }

// Disabled reports whether the route was turned off with DisabledPaths or DisabledOps.
func (k *Kit) Disabled(r Route) bool {
	if slices.Contains(k.Conf.DisabledPaths, r.Path) {
		return true
	}
	return config.OperationSet(k.Conf.DisabledOps)[r.OperationID]
}

// Middlewares returns the middleware chain for a route: origin/CSRF → session resolution. Rate limiting is
// done by goauth's global limiter, which runs before every route.
func (k *Kit) Middlewares(r Route) huma.Middlewares {
	var mws huma.Middlewares
	// Step 1: (rate limiting moved to the global limiter, see Register)
	// Step 2: origin / CSRF check for mutating requests
	if !r.SkipOriginCheck {
		mws = append(mws, humaadapter.OriginCheck(k.Conf, k.Origins, r.Access == Form || r.FormCSRF))
	}
	// Step 3: session resolution
	switch r.Access {
	case OptionalSession:
		mws = append(mws, k.Resolver.Optional())
	case Session:
		mws = append(mws, k.Resolver.Require())
	case FreshSession:
		mws = append(mws, k.Resolver.RequireFresh())
	}
	return mws
}

// Register mounts a plugin endpoint with goauth's error format, raw JSON bodies and the access middlewares.
// Disabled routes are skipped.
func Register[I, O any](k *Kit, api huma.API, r Route, handler func(context.Context, *I) (*O, error)) {
	if api == nil || k.Disabled(r) {
		return
	}
	// a per-route rule becomes a plugin rule of the global limiter (path parameters match one segment)
	if r.RateLimit != nil {
		k.Limiter.AddPluginRules(ratelimit.PathRule{
			PathMatcher: routeMatcher(r.Path), Window: r.RateLimit.Window, Max: r.RateLimit.Max,
		})
	}
	huma.Register(api, huma.Operation{
		OperationID: r.OperationID,
		Method:      r.Method,
		Path:        k.Path(r.Path),
		Summary:     r.Summary,
		Tags:        r.Tags,
		Hidden:      r.Hidden,
		Metadata:    map[string]any{types.RawBodyMetaKey: true},
		Middlewares: k.Middlewares(r),
	}, handler)
}

// routeMatcher matches request paths against a route path whose {param} segments match any one segment.
func routeMatcher(path string) func(string) bool {
	if !strings.Contains(path, "{") {
		return func(p string) bool { return p == path }
	}
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}") {
			segs[i] = "*"
		}
	}
	return ratelimit.WildcardMatch(strings.Join(segs, "/"))
}

// ─── Request helpers ─────────────────────────────────────────────────────────

// Request returns the incoming *http.Request (nil outside HTTP).
func (k *Kit) Request(ctx context.Context) *http.Request { return config.GetHTTPRequest(ctx) }

// Meta returns the IP and user agent to store on new sessions.
func (k *Kit) Meta(ctx context.Context) svcint.Meta { return humaadapter.SessionMeta(k.Conf, ctx) }

// Current returns the session attached by the route's session middleware.
func (k *Kit) Current(ctx context.Context) *dtos.SessionWithUser {
	sw, _ := humaadapter.FromContext(ctx)
	return sw
}

// CurrentOrResolve returns the attached session, or resolves it from the request cookies / bearer token.
func (k *Kit) CurrentOrResolve(ctx context.Context) *dtos.SessionWithUser {
	if sw := k.Current(ctx); sw != nil {
		return sw
	}
	var cookieHeader string
	if req := k.Request(ctx); req != nil {
		cookieHeader = req.Header.Get("Cookie")
	}
	sw, err := k.Resolver.Resolve(ctx, cookieHeader)
	if err != nil {
		return nil
	}
	return sw
}

// ReadSignedCookie returns the verified value of auth cookie base (e.g. "two_factor") from the request.
func (k *Kit) ReadSignedCookie(ctx context.Context, base string) (string, bool) {
	req := k.Request(ctx)
	if req == nil {
		return "", false
	}
	return k.Cookies.ReadSigned(req.Header.Get("Cookie"), base)
}

// ─── Session helpers ─────────────────────────────────────────────────────────

// CreateSession starts a session for user. Errors from BeforeSessionCreate hooks (e.g. BANNED_USER) are
// returned unchanged; anything else becomes FAILED_TO_CREATE_SESSION.
func (k *Kit) CreateSession(ctx context.Context, user *models.User, dontRemember bool) (*dtos.SessionWithUser, error) {
	sw, err := k.Sessions.Create(ctx, user, k.Meta(ctx), sessionsvc.CreateOptions{DontRemember: dontRemember})
	if err != nil {
		if ae := autherr.AsAuthError(err); ae != nil {
			return nil, ae
		}
		return nil, autherr.ErrFailedToCreateSession
	}
	// goauth extra: remember when and from where the user last signed in (best effort, like core sign-in)
	update := map[string]interface{}{"LastLoginAt": models.TimeNow()}
	if meta := k.Meta(ctx); meta.IPAddress != "" {
		update["LastLoginIP"] = meta.IPAddress
	}
	_, _ = k.Repos.UpdateUser(ctx, user.ID, update)
	return sw, nil
}

// ReplaceSession is better-auth's "createSession(userId, false, oldSession) + deleteSession(old)": the user
// gets a new session (carrying the old session's organization context) and the old one is revoked. It is used
// after security-relevant user changes (two-factor enabled/disabled) so the session cookie holds fresh data.
func (k *Kit) ReplaceSession(ctx context.Context, current *dtos.SessionWithUser, user *models.User) (*dtos.SessionWithUser, error) {
	if current == nil || user == nil {
		return nil, autherr.ErrFailedToCreateSession
	}
	// Step 1: carry over the organization context of the replaced session
	opts := sessionsvc.CreateOptions{
		ActiveOrganizationID:   current.Session.ActiveOrganizationID,
		ActiveOrganizationRole: current.Session.ActiveOrganizationRole,
		ActiveOrganizationType: current.Session.ActiveOrganizationType,
		ImpersonatedBy:         current.Session.ImpersonatedBy,
	}
	// Step 2: create the replacement
	sw, err := k.Sessions.Create(ctx, user, k.Meta(ctx), opts)
	if err != nil {
		if ae := autherr.AsAuthError(err); ae != nil {
			return nil, ae
		}
		return nil, autherr.ErrFailedToCreateSession
	}
	// Step 3: revoke the old session
	_ = k.Sessions.Delete(ctx, current.Session.Token)
	return sw, nil
}

// SessionCookies returns the Set-Cookie entries for sw (session_token, plus session_data with the cookie cache).
func (k *Kit) SessionCookies(sw *dtos.SessionWithUser, dontRemember bool) []http.Cookie {
	return k.Cookies.SessionCookiesWithData(sw, dontRemember)
}

// ExpireSessionCookies deletes session_token and session_data (and dont_remember unless keepDontRemember).
func (k *Kit) ExpireSessionCookies(keepDontRemember bool) []http.Cookie {
	out := []http.Cookie{
		k.Cookies.ExpireCookie(cookies.CookieSessionToken),
		k.Cookies.ExpireCookie(cookies.CookieSessionData),
	}
	if !keepDontRemember {
		out = append(out, k.Cookies.ExpireCookie(cookies.CookieDontRemember))
	}
	return out
}

// RefreshUser rewrites the cached user copy inside the user's sessions (secondary storage).
func (k *Kit) RefreshUser(ctx context.Context, user *models.User) {
	if user != nil {
		k.Sessions.RefreshUser(ctx, user)
	}
}

// ─── User helpers ────────────────────────────────────────────────────────────

// NewID returns a new record ID (Advanced.Database.GenerateID or the default generator).
func (k *Kit) NewID() string {
	if k.generateID != nil {
		return k.generateID()
	}
	return models.NewID()
}

// CreateUser inserts user, running BeforeUserCreate and AfterUserCreate hooks like core sign-up does.
// Hook errors are returned unchanged; repository errors become FAILED_TO_CREATE_USER.
func (k *Kit) CreateUser(ctx context.Context, user *models.User) (*models.User, error) {
	// Step 1: fill the ID and better-auth defaults
	if user.ID == "" {
		user.ID = k.NewID()
	}
	// Step 2: plugins may adjust or veto the user
	if k.Hooks != nil {
		if err := k.Hooks.TriggerBeforeUserCreate(ctx, user); err != nil {
			return nil, err
		}
	}
	// Step 3: insert
	created, err := k.Repos.CreateUser(ctx, user)
	if err != nil {
		return nil, autherr.ErrFailedToCreateUser
	}
	// Step 4: after-create hooks (e.g. email-otp sending a verification code)
	if k.Hooks != nil {
		if err := k.Hooks.TriggerAfterUserCreate(ctx, created); err != nil {
			return nil, err
		}
	}
	return created, nil
}

// InTx runs fn in a transaction when a transaction manager is configured.
func (k *Kit) InTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if k.Tx == nil {
		return fn(ctx)
	}
	return k.Tx.Transaction(ctx, fn)
}

// VerifyUserPassword checks password against the user's credential account (better-auth's validatePassword).
// It returns false when the user has no password.
func (k *Kit) VerifyUserPassword(ctx context.Context, userID, password string) (bool, error) {
	acc, err := AcceptNotFound(k.Repos.FindAccountByUserAndProvider(ctx, userID, models.ProvCredential))
	if err != nil {
		return false, err
	}
	if acc == nil || acc.Password == nil || *acc.Password == "" {
		return false, nil
	}
	ok, _, err := k.Passwords.Verify(*acc.Password, password)
	if err != nil {
		return false, nil
	}
	return ok, nil
}

// HasPassword reports whether the user has a credential account with a password
// (better-auth's shouldRequirePassword for allowPasswordless).
func (k *Kit) HasPassword(ctx context.Context, userID string) bool {
	acc, err := AcceptNotFound(k.Repos.FindAccountByUserAndProvider(ctx, userID, models.ProvCredential))
	return err == nil && acc != nil && acc.Password != nil && *acc.Password != ""
}

// ─── Redirect helpers ────────────────────────────────────────────────────────

// IsTrustedURL reports whether a client-supplied redirect target is allowed (relative paths are).
func (k *Kit) IsTrustedURL(raw string) bool {
	if raw == "" || k.Conf.Advanced.DisableOriginCheck {
		return true
	}
	return k.Origins.IsTrusted(raw, true)
}

// CheckURL returns invalid when raw is not a trusted redirect target.
func (k *Kit) CheckURL(raw string, invalid *autherr.AuthError) error {
	if !k.IsTrustedURL(raw) {
		return invalid
	}
	return nil
}

// BaseURL returns "<BaseURL><BasePath>" (better-auth's ctx.context.baseURL).
func (k *Kit) BaseURL() string { return strings.TrimRight(k.Conf.BaseURL, "/") + k.BasePath }

// baseURLKey is the context key of the per-request base URL (WithBaseURL).
type baseURLKey struct{}

// WithBaseURL returns ctx carrying a per-request base URL ("<origin><basePath>"), better-auth's
// `ctx.context.baseURL = ...` in a before hook (e.g. oauth-proxy switching the OAuth redirect_uri to the
// production deployment). A before hook sets it on endpointhooks.Context.Ctx; RequestBaseURL reads it.
func WithBaseURL(ctx context.Context, baseURL string) context.Context {
	return context.WithValue(ctx, baseURLKey{}, strings.TrimRight(baseURL, "/"))
}

// RequestBaseURL returns the per-request base URL set with WithBaseURL, or BaseURL().
func (k *Kit) RequestBaseURL(ctx context.Context) string {
	if ctx != nil {
		if v, ok := ctx.Value(baseURLKey{}).(string); ok && v != "" {
			return v
		}
	}
	return k.BaseURL()
}

// ResolveURL resolves a (possibly relative) callback URL against the app's BaseURL origin, like
// better-auth's new URL(callbackURL, ctx.context.baseURL).
func (k *Kit) ResolveURL(raw string) string {
	if raw == "" {
		raw = "/"
	}
	base, err := parseURL(k.BaseURL())
	if err != nil {
		return raw
	}
	u, err := base.Parse(raw)
	if err != nil {
		return raw
	}
	return u.String()
}

// WithQuery appends query parameters to a URL, keeping the existing ones.
func WithQuery(raw string, params map[string]string) string {
	u, err := parseURL(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	for key, v := range params {
		q.Set(key, v)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// ─── Error helpers ───────────────────────────────────────────────────────────

// IsNotFound reports whether err is a repository "not found".
func IsNotFound(err error) bool {
	ae := autherr.AsAuthError(err)
	return ae != nil && ae.StatusCode == http.StatusNotFound
}

// AcceptNotFound turns a repository "not found" into (nil, nil).
func AcceptNotFound[T any](v *T, err error) (*T, error) {
	if err != nil {
		if IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return v, nil
}

// Code returns err's better-auth code, or INTERNAL_SERVER_ERROR.
func Code(err error) string {
	if ae := autherr.AsAuthError(err); ae != nil {
		return string(ae.Code)
	}
	return "INTERNAL_SERVER_ERROR"
}

// NewError builds a plugin error without touching the global code registry, so two plugins can use the
// same code with their own message (better-auth's per-plugin $ERROR_CODES).
func NewError(status int, code, message string) *autherr.AuthError {
	return autherr.New(autherr.RespCode(code), message, status)
}

func parseURL(raw string) (*url.URL, error) { return url.Parse(raw) }
