package services

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	socialservices "github.com/better-go-auth/goauth/src/plugins/social/services"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
	"github.com/better-go-auth/goauth/src/providers/cookies"
)

// CallbackPath is the social callback route as goauth's endpoint hooks see it (better-auth's "/callback/:id").
const CallbackPath = "/callback/{id}"

// isSignInPath matches better-auth's path.startsWith("/sign-in/social") || path.startsWith("/sign-in/oauth2").
func isSignInPath(c *endpointhooks.Context) bool {
	return strings.HasPrefix(c.Path, "/sign-in/social") || strings.HasPrefix(c.Path, "/sign-in/oauth2")
}

// isCallbackPath matches better-auth's path === "/callback/:id".
func isCallbackPath(c *endpointhooks.Context) bool { return c.Path == CallbackPath }

// Hooks returns the plugin's endpoint hooks (better-auth's oauth-proxy `hooks`).
func (s *Service) Hooks() endpointhooks.Hooks {
	return endpointhooks.Hooks{
		Before: []endpointhooks.BeforeHook{
			{Matcher: isSignInPath, Handler: s.beforeSignIn},
			{Matcher: isCallbackPath, Handler: s.beforeCallback},
		},
		After: []endpointhooks.AfterHook{
			{Matcher: isSignInPath, Handler: s.afterSignIn},
			{Matcher: isCallbackPath, Handler: s.afterCallback},
		},
	}
}

// ─── before /sign-in/social, /sign-in/oauth2 ─────────────────────────────────

// beforeSignIn sends the provider's callback to production and the user back to this deployment's
// /oauth-proxy-callback: callbackURL becomes "<current origin><basePath>/oauth-proxy-callback?callbackURL=<original>"
// and, with ProductionURL, the request's base URL (so the OAuth redirect_uri) becomes production's.
func (s *Service) beforeSignIn(c *endpointhooks.Context) (*endpointhooks.Response, error) {
	// Step 1: production itself (or an explicit opt-out) uses the normal flow
	if s.checkSkipProxy(c) {
		return nil, nil
	}
	currentURL, err := s.resolveCurrentURL(c)
	if err != nil {
		return nil, err
	}
	// Step 2: the callback the user asked for (default: the base URL)
	originalCallbackURL := s.kit.RequestBaseURL(c.Ctx)
	if cb, ok := c.Body["callbackURL"].(string); ok && cb != "" {
		originalCallbackURL = cb
	}
	// Step 3: the provider must redirect to production (better-auth's ctx.context.baseURL = productionBaseURL)
	if s.cfg.ProductionURL != "" {
		c.Ctx = withBaseURL(c.Ctx, stripTrailingSlash(s.cfg.ProductionURL)+s.kit.BasePath)
	}
	// Step 4: the user comes back through this deployment's proxy callback
	origin := stripTrailingSlash(originOf(currentURL.String()))
	newCallbackURL := origin + s.kit.BasePath + "/oauth-proxy-callback?callbackURL=" + encodeURIComponent(originalCallbackURL)
	if c.Body == nil {
		return nil, nil
	}
	c.Body["callbackURL"] = newCallbackURL
	return nil, nil
}

// ─── after /sign-in/social, /sign-in/oauth2 ──────────────────────────────────

// afterSignIn wraps the provider URL's state in an encrypted state package carrying this deployment's OAuth
// state, so the production callback can finish the code exchange without access to our storage.
func (s *Service) afterSignIn(c *endpointhooks.Context) (*endpointhooks.Response, error) {
	// Step 1: only proxied sign-ins that answered {url, ...}
	if s.checkSkipProxy(c) {
		return nil, nil
	}
	res := c.Returned
	if res == nil || res.Status >= http.StatusBadRequest {
		return nil, nil
	}
	body := res.JSONBody()
	providerURL, ok := body["url"].(string)
	if !ok {
		return nil, nil
	}
	oauthURL, err := url.Parse(providerURL)
	if err != nil {
		return nil, nil
	}
	originalState := oauthURL.Query().Get("state")
	if originalState == "" {
		return nil, nil
	}
	// Step 2: the plaintext state payload: the encrypted oauth_state cookie (cookie strategy) or the
	// verification row (database strategy)
	plaintextState, err := s.plaintextState(c, res, originalState)
	if err != nil {
		logger.Error("Failed to prepare OAuth proxy state:", "error", err)
		return nil, nil
	}
	if plaintextState == "" {
		logger.Warn("No OAuth state found for proxy")
		return nil, nil
	}
	// Step 3: encrypt the package and put it in place of the state
	encrypted, err := s.encryptStatePackage(originalState, plaintextState)
	if err != nil {
		logger.Error("Failed to prepare OAuth proxy state:", "error", err)
		return nil, nil
	}
	setSearchParam(oauthURL, "state", encrypted)
	if next, ok := replaceJSONField(res.Body, "url", oauthURL.String()); ok {
		res.Body = next
	}
	return nil, nil
}

// plaintextState returns the OAuth state payload the sign-in stored: the oauth_state cookie it set when the
// state lives in a cookie, else the verification row keyed by the state.
func (s *Service) plaintextState(c *endpointhooks.Context, res *endpointhooks.Response, state string) (string, error) {
	// Step 1: cookie strategy: the response sets the encrypted oauth_state cookie
	name := s.kit.Cookies.Name(socialservices.OAuthStateCookie)
	var encrypted string
	for _, ck := range res.Cookies() {
		if ck.Name == name && ck.Value != "" && ck.MaxAge >= 0 {
			encrypted = cookies.DecodeCookieValue(ck.Value)
		}
	}
	if encrypted != "" {
		return authcrypto.SymmetricDecrypt(s.kit.Conf.Secret, encrypted)
	}
	// Step 2: database strategy
	v, err := s.kit.Repos.FindVerificationValue(c.Ctx, state)
	if err != nil || v == nil {
		return "", nil
	}
	return v.Value, nil
}

// encryptStatePackage builds and encrypts the state package for state.
func (s *Service) encryptStatePackage(state, plaintextState string) (string, error) {
	stateCookie, err := authcrypto.SymmetricEncrypt(s.key(), plaintextState)
	if err != nil {
		return "", err
	}
	raw, err := marshalJSON(StatePackage{State: state, StateCookie: stateCookie, IsOAuthProxy: true})
	if err != nil {
		return "", err
	}
	return authcrypto.SymmetricEncrypt(s.key(), raw)
}

// ─── before /callback/{id} ───────────────────────────────────────────────────

// callbackParams merges the callback query and JSON body (query wins, like defu(ctx.query, ctx.body)).
func callbackParams(c *endpointhooks.Context, key string) string {
	if v := c.Query.Get(key); v != "" {
		return v
	}
	if v, ok := c.Body[key].(string); ok {
		return v
	}
	return ""
}

// beforeCallback runs on the production deployment: when the state is an oauth-proxy state package it
// finishes the OAuth exchange here and redirects to the preview's /oauth-proxy-callback with the encrypted
// profile. Any other state falls through to the normal callback.
func (s *Service) beforeCallback(c *endpointhooks.Context) (*endpointhooks.Response, error) {
	// Step 1: decrypt the state package; anything else is a regular callback
	state := callbackParams(c, "state")
	if state == "" {
		return nil, nil
	}
	pkg, ok := s.decryptStatePackage(state)
	if !ok {
		logger.Debug("OAuth proxy: could not decrypt state package, falling back to regular callback")
		return nil, nil
	}
	if !pkg.IsOAuthProxy || pkg.State == "" || pkg.StateCookie == "" {
		logger.Warn("Invalid OAuth proxy state package")
		return nil, nil
	}
	code, providerError := callbackParams(c, "code"), callbackParams(c, "error")
	// Step 2: the preview's state payload (PKCE verifier, callback URLs)
	plain, err := authcrypto.SymmetricDecrypt(s.key(), pkg.StateCookie)
	var stateData ProxyStateData
	if err == nil {
		err = json.Unmarshal([]byte(plain), &stateData)
	}
	if err != nil {
		logger.Error("Failed to decrypt OAuth proxy state cookie:", "error", err)
		return nil, nil
	}
	errorURL := stateData.ErrorURL
	if errorURL == "" {
		errorURL = s.kit.Conf.OnAPIError.ErrorURL
	}
	if errorURL == "" {
		errorURL = s.kit.RequestBaseURL(c.Ctx) + "/error"
	}
	// Step 3: the package must belong to the state it carries
	if stateData.OAuthState != nil && *stateData.OAuthState != pkg.State {
		logger.Error("OAuth proxy state binding mismatch")
		return redirectOnError(errorURL, "state_mismatch", "", nil), nil
	}
	// Step 4: provider errors and missing codes
	if providerError != "" {
		return redirectOnError(errorURL, providerError, "", nil), nil
	}
	if code == "" {
		logger.Error("OAuth callback missing authorization code")
		return redirectOnError(errorURL, "no_code", "", nil), nil
	}
	// Step 5: the provider of this callback
	providerID := callbackProviderID(c, s.kit.BasePath)
	var provider providers.Provider
	if social := s.socialService(); social != nil {
		provider, _ = social.Provider(providerID)
	}
	if provider == nil {
		logger.Error("OAuth provider not found", "provider", providerID)
		return redirectOnError(errorURL, "oauth_provider_not_found", "", nil), nil
	}
	// Step 6: exchange the code with the preview's PKCE verifier and production's redirect URI
	tokens, err := provider.ValidateAuthorizationCode(c.Ctx, providers.ValidateCodeInput{
		Code:         code,
		CodeVerifier: stateData.CodeVerifier,
		RedirectURI:  s.kit.RequestBaseURL(c.Ctx) + "/callback/" + provider.ID(),
	})
	if err != nil {
		logger.Error("Failed to validate authorization code", "error", err)
		return redirectOnError(errorURL, "invalid_code", "", nil), nil
	}
	if tokens == nil {
		return redirectOnError(errorURL, "invalid_code", "", nil), nil
	}
	// Step 7: the provider user
	info, err := provider.GetUserInfo(c.Ctx, providers.UserInfoInput{OAuth2Tokens: *tokens})
	if err != nil || info == nil {
		logger.Error("Unable to get user info from provider")
		return redirectOnError(errorURL, "unable_to_get_user_info", "", nil), nil
	}
	if info.User.Email == "" {
		logger.Error("Provider did not return email")
		return redirectOnError(errorURL, "email_not_found", "", nil), nil
	}
	// Step 8: the encrypted profile for the preview's /oauth-proxy-callback
	proxyCallbackURL, err := parseAbsoluteURL(stateData.CallbackURL)
	if err != nil {
		return nil, err
	}
	finalCallbackURL := proxyCallbackURL.Query().Get("callbackURL")
	if finalCallbackURL == "" {
		finalCallbackURL = stateData.CallbackURL
	}
	payload := s.profilePayload(provider, info.User, tokens, pkg.State, finalCallbackURL, stateData)
	raw, err := marshalJSON(payload)
	if err != nil {
		return nil, err
	}
	encrypted, err := authcrypto.SymmetricEncrypt(s.key(), raw)
	if err != nil {
		return nil, err
	}
	setSearchParam(proxyCallbackURL, "profile", encrypted)
	return redirectResponse(proxyCallbackURL.String(), nil), nil
}

// decryptStatePackage decrypts and decodes a state package (ok is false for any other state).
func (s *Service) decryptStatePackage(state string) (*StatePackage, bool) {
	plain, err := authcrypto.SymmetricDecrypt(s.key(), state)
	if err != nil {
		return nil, false
	}
	var pkg StatePackage
	if err := json.Unmarshal([]byte(plain), &pkg); err != nil {
		return nil, false
	}
	return &pkg, true
}

// callbackProviderID is the {id} of /callback/{id} (better-auth's ctx.params.id).
func callbackProviderID(c *endpointhooks.Context, basePath string) string {
	if c.Request == nil || c.Request.URL == nil {
		return ""
	}
	id := path.Base(strings.TrimPrefix(c.Request.URL.Path, basePath))
	if dec, err := url.PathUnescape(id); err == nil {
		id = dec
	}
	return id
}

// profilePayload builds better-auth's oauth-proxy payload from the provider user and tokens.
func (s *Service) profilePayload(p providers.Provider, user providers.UserInfo, tokens *providers.OAuth2Tokens, state, callbackURL string, stateData ProxyStateData) ProfilePayload {
	// Step 1: the user
	info := &ProfileUserInfo{ID: user.ID, Email: user.Email, Name: user.Name, EmailVerified: user.EmailVerified}
	if user.Image != "" {
		img := user.Image
		info.Image = &img
	}
	// Step 2: the account ({...tokens, scope: tokens.scopes?.join(",")})
	account := &ProfileAccount{
		ProviderID: p.ID(), AccountID: user.ID,
		AccessToken: tokens.AccessToken, RefreshToken: tokens.RefreshToken, IDToken: tokens.IDToken,
		AccessTokenExpiresAt: tokens.AccessTokenExpiresAt, RefreshTokenExpiresAt: tokens.RefreshTokenExpiresAt,
	}
	if tokens.Scopes != nil {
		scope := strings.Join(tokens.Scopes, ",")
		account.Scope = &scope
	}
	// Step 3: the sign-up policy of the provider (disableImplicitSignUp && !requestSignUp || disableSignUp)
	opts := p.Options()
	requestSignUp := stateData.RequestSignUp != nil && *stateData.RequestSignUp
	ts := float64(time.Now().UnixMilli())
	return ProfilePayload{
		UserInfo:      info,
		Account:       account,
		State:         state,
		CallbackURL:   callbackURL,
		NewUserURL:    stateData.NewUserURL,
		ErrorURL:      stateData.ErrorURL,
		DisableSignUp: (opts.DisableImplicitSignUp && !requestSignUp) || opts.DisableSignUp,
		Timestamp:     &ts,
	}
}

// ─── after /callback/{id} ────────────────────────────────────────────────────

// afterCallback handles a regular callback that ended on production's own /oauth-proxy-callback: the
// redirect goes straight to the inner callbackURL.
func (s *Service) afterCallback(c *endpointhooks.Context) (*endpointhooks.Response, error) {
	// Step 1: only redirects to an absolute oauth-proxy callback URL
	if c.Returned == nil {
		return nil, nil
	}
	location := c.Returned.Header.Get("Location")
	if !strings.Contains(location, "/oauth-proxy-callback?callbackURL") || !strings.HasPrefix(location, "http") {
		return nil, nil
	}
	// Step 2: production's origin (ProductionURL, BaseURL, the request base URL)
	production := s.cfg.ProductionURL
	if production == "" {
		production = s.kit.Conf.BaseURL
	}
	if production == "" {
		production = s.kit.RequestBaseURL(c.Ctx)
	}
	locationURL, err := url.Parse(location)
	if err != nil {
		return nil, nil
	}
	// Step 3: same origin: skip the proxy hop
	if originOf(location) == originOf(production) {
		next := locationURL.Query().Get("callbackURL")
		if next == "" {
			return nil, nil
		}
		c.Returned.Header.Set("Location", next)
		return nil, nil
	}
	logger.Warn("OAuth proxy: cross-origin callback reached after hook unexpectedly")
	return nil, nil
}

// userInfoFromProfile converts the profile user to the social plugin's provider user.
func userInfoFromProfile(u *ProfileUserInfo) providers.UserInfo {
	out := providers.UserInfo{ID: u.ID, Email: u.Email, Name: u.Name, EmailVerified: u.EmailVerified}
	if u.Image != nil {
		out.Image = *u.Image
	}
	return out
}

// accountFromProfile converts the profile account to the social plugin's account data.
func accountFromProfile(a *ProfileAccount) socialservices.AccountData {
	return socialservices.AccountData{
		ProviderID: a.ProviderID, AccountID: a.AccountID,
		AccessToken: a.AccessToken, RefreshToken: a.RefreshToken, IDToken: a.IDToken,
		AccessTokenExpiresAt: a.AccessTokenExpiresAt, RefreshTokenExpiresAt: a.RefreshTokenExpiresAt,
		Scope: a.Scope,
	}
}
