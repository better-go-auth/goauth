package services

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	socialsvc "github.com/better-go-auth/goauth/src/plugins/social/services"
	"github.com/better-go-auth/goauth/src/plugins/sso/config"
	ssodtos "github.com/better-go-auth/goauth/src/plugins/sso/dtos"
)

// defaultScopes are requested when neither the request nor the provider config has scopes.
var defaultScopes = []string{"openid", "email", "profile", "offline_access"}

// StartResult is the {url, redirect} body of /sign-in/sso plus the state cookies to set.
type StartResult struct {
	Body    ssodtos.SSORedirectResponse
	Cookies []http.Cookie
}

// Redirect is a 302 answer of the callbacks.
type Redirect = socialsvc.Redirect

// ─── POST /sign-in/sso ───────────────────────────────────────────────────────

// SignIn is better-auth's signInSSO: find the provider (providerId, organization slug, email domain or
// defaultSSO) and answer the IdP authorization (OIDC) or AuthnRequest (SAML) URL.
func (s *Service) SignIn(ctx context.Context, in ssodtos.SSOSignInInput) (*StartResult, error) {
	// Step 1: something to find the provider by
	if len(s.cfg.DefaultSSO) == 0 && in.Email == "" && in.OrganizationSlug == "" && in.Domain == "" && in.ProviderID == "" {
		return nil, ErrSignInTargetRequired
	}
	domain := in.Domain
	if domain == "" && in.Email != "" {
		if parts := strings.SplitN(in.Email, "@", 2); len(parts) == 2 {
			domain = parts[1]
		}
	}
	orgID := ""
	if in.OrganizationSlug != "" {
		if orgs := s.orgs(); orgs != nil {
			id, err := orgs.FindOrganizationIDBySlug(ctx, in.OrganizationSlug)
			if err != nil {
				return nil, errorf("find organization: %w", err)
			}
			orgID = id
		}
	}

	// Step 2: defaultSSO (by providerId, else by domain), then the database
	var provider *config.Provider
	if len(s.cfg.DefaultSSO) > 0 {
		provider = s.defaultProvider(func(d config.DefaultProvider) bool {
			if in.ProviderID != "" {
				return d.ProviderID == in.ProviderID
			}
			return d.Domain == domain
		}, "")
	}
	if in.ProviderID == "" && orgID == "" && domain == "" {
		return nil, ErrSignInTargetMissing
	}
	if provider == nil {
		p, err := s.lookupProvider(ctx, in.ProviderID, orgID, domain)
		if err != nil {
			return nil, err
		}
		provider = p
	}
	if provider == nil {
		return nil, ErrNoProviderForIssuer
	}

	// Step 3: the requested protocol must be configured, and the domain verified when required
	if in.ProviderType == "oidc" && provider.OIDCConfig == nil {
		return nil, ErrOIDCNotConfigured
	}
	if in.ProviderType == "saml" && provider.SAMLConfig == nil {
		return nil, ErrSAMLNotConfigured
	}
	if s.cfg.DomainVerification.Enabled && !provider.IsDomainVerified() {
		return nil, ErrDomainNotVerified
	}

	// Step 4: OIDC (unless SAML was asked for), else SAML
	if provider.OIDCConfig != nil && in.ProviderType != "saml" {
		return s.signInOIDC(ctx, provider, in)
	}
	if provider.SAMLConfig != nil {
		return s.signInSAML(ctx, provider, in)
	}
	return nil, ErrInvalidSSOProvider
}

// lookupProvider finds a stored provider by providerId, organization id, or email domain (exact match first,
// then comma-separated lists and subdomains).
func (s *Service) lookupProvider(ctx context.Context, providerID, orgID, domain string) (*config.Provider, error) {
	// Step 1: providerId or organizationId
	if providerID != "" || orgID != "" {
		field, value := "providerId", providerID
		if providerID == "" {
			field, value = "organizationId", orgID
		}
		r, err := s.store.FindOne(ctx, Model, whereEq(field, value))
		if err != nil {
			return nil, ignoreNotFound(err)
		}
		return providerFromRecord(r), nil
	}
	if domain == "" {
		return nil, nil
	}
	// Step 2: exact domain
	if r, err := s.store.FindOne(ctx, Model, whereEq("domain", domain)); err == nil {
		return providerFromRecord(r), nil
	} else if err = ignoreNotFound(err); err != nil {
		return nil, err
	}
	// Step 3: domain lists and subdomains
	all, err := s.listProviderRecords(ctx, nil)
	if err != nil {
		return nil, errorf("list providers: %w", err)
	}
	for _, r := range all {
		if p := providerFromRecord(r); domainMatches(domain, p.Domain) {
			return p, nil
		}
	}
	return nil, nil
}

// signInOIDC is the OIDC branch of signInSSO.
func (s *Service) signInOIDC(ctx context.Context, provider *config.Provider, in ssodtos.SSOSignInInput) (*StartResult, error) {
	// Step 1: complete the config with discovery when endpoints are missing
	cfg, err := s.ensureRuntimeDiscovery(ctx, provider.OIDCConfig, provider.Issuer, s.isTrustedOrigin(ctx))
	if err != nil {
		return nil, mapDiscoveryError(err)
	}
	if cfg.AuthorizationEndpoint == "" {
		return nil, ErrAuthorizationURLNotFound
	}
	// Step 2: state + PKCE verifier (the shared redirect URI needs the provider id in the state)
	var additional map[string]any
	if strings.TrimSpace(s.cfg.RedirectURI) != "" {
		additional = map[string]any{"ssoProviderId": provider.ProviderID}
	}
	st, err := s.oauth.GenerateState(ctx, nil, socialsvc.StateRequest{
		CallbackURL:      in.CallbackURL,
		ErrorCallbackURL: in.ErrorCallbackURL,
		NewUserURL:       in.NewUserCallbackURL,
		RequestSignUp:    in.RequestSignUp,
		AdditionalData:   additional,
	})
	if err != nil {
		return nil, err
	}
	// Step 3: the authorization URL
	scopes := in.Scopes
	if scopes == nil {
		scopes = cfg.Scopes
	}
	if scopes == nil {
		scopes = defaultScopes
	}
	verifier := ""
	if cfg.PKCEEnabled() {
		verifier = st.CodeVerifier
	}
	u, err := providers.BuildAuthorizationURL(providers.AuthURLParams{
		Endpoint:     cfg.AuthorizationEndpoint,
		ClientID:     cfg.ClientID,
		State:        st.State,
		CodeVerifier: verifier,
		Scopes:       scopes,
		RedirectURI:  s.redirectURI(ctx, provider.ProviderID),
		LoginHint:    pick(in.LoginHint, in.Email),
	})
	if err != nil {
		return nil, autherr.Internal(ctx, err)
	}
	return &StartResult{Body: ssodtos.SSORedirectResponse{URL: u.String(), Redirect: true}, Cookies: st.Cookies}, nil
}

// ─── GET /sso/callback/{providerId} ──────────────────────────────────────────

// CallbackParams are the OIDC callback query fields.
type CallbackParams struct {
	Code             string
	State            string
	Error            string
	ErrorDescription string
	// HasError / HasErrorDescription tell an absent parameter from an empty one (JavaScript prints
	// undefined for absent ones in the error redirect).
	HasError            bool
	HasErrorDescription bool
}

// stateFailure turns a state parsing error into better-auth's redirect (state_security_mismatch → state_mismatch).
func (s *Service) stateFailure(ctx context.Context, err error, cookies []http.Cookie) *Redirect {
	code, target := "internal_server_error", s.oauth.DefaultErrorURL(ctx)
	var se *socialsvc.StateError
	if errors.As(err, &se) {
		code = se.Code
		if se.ErrorURL != "" {
			target = se.ErrorURL
		}
	}
	return socialsvc.ErrorRedirect(target, code, "", cookies)
}

// CallbackShared is better-auth's callbackSSOShared (GET /sso/callback): the provider id comes from the state.
func (s *Service) CallbackShared(ctx context.Context, q CallbackParams) (*Redirect, error) {
	// Step 1: the state
	state, cookies, err := s.oauth.ParseState(ctx, q.State)
	if err != nil {
		return s.stateFailure(ctx, err, cookies), nil
	}
	// Step 2: the provider id stored at sign-in
	providerID := str(state.AdditionalData["ssoProviderId"])
	if providerID == "" {
		target := pick(state.ErrorURL, state.CallbackURL)
		return &Redirect{Location: target + "?error=invalid_state&error_description=missing_provider_id", Cookies: cookies}, nil
	}
	return s.handleOIDCCallback(ctx, providerID, q, state, cookies)
}

// Callback is better-auth's callbackSSO (GET /sso/callback/{providerId}).
func (s *Service) Callback(ctx context.Context, providerID string, q CallbackParams) (*Redirect, error) {
	state, cookies, err := s.oauth.ParseState(ctx, q.State)
	if err != nil {
		return s.stateFailure(ctx, err, cookies), nil
	}
	return s.handleOIDCCallback(ctx, providerID, q, state, cookies)
}

// jsValue prints an optional query value like a JavaScript template literal (absent → "undefined").
func jsValue(v string, present bool) string {
	if !present {
		return "undefined"
	}
	return v
}

// handleOIDCCallback is better-auth's handleOIDCCallback: exchange the code, read the user (userinfo endpoint
// or verified id_token), then sign in / link / sign up and redirect.
func (s *Service) handleOIDCCallback(ctx context.Context, providerID string, q CallbackParams, state *socialsvc.StateData, cookies []http.Cookie) (*Redirect, error) {
	errorURL := state.ErrorURL
	if errorURL == "" {
		errorURL = s.oauth.DefaultErrorURL(ctx)
	}
	base := pick(errorURL, state.CallbackURL)
	fail := func(code, description string) (*Redirect, error) {
		return &Redirect{Location: base + "?error=" + code + "&error_description=" + description, Cookies: cookies}, nil
	}

	// Step 1: the provider reported an error, or there is no code
	if q.Code == "" || q.Error != "" {
		return fail(jsValue(q.Error, q.HasError), jsValue(q.ErrorDescription, q.HasErrorDescription))
	}

	// Step 2: the provider (defaultSSO first)
	provider := s.defaultProvider(func(d config.DefaultProvider) bool { return d.ProviderID == providerID }, "oidc")
	if provider == nil {
		p, _, err := s.findStoredProvider(ctx, providerID)
		if err != nil {
			return nil, errorf("find provider: %w", err)
		}
		provider = p
	}
	if provider == nil {
		return fail("invalid_provider", "provider not found")
	}
	if s.cfg.DomainVerification.Enabled && !provider.IsDomainVerified() {
		return nil, ErrDomainNotVerified
	}
	if provider.OIDCConfig == nil {
		return fail("invalid_provider", "provider not found")
	}

	// Step 3: runtime discovery for incomplete configs
	cfg, err := s.ensureRuntimeDiscovery(ctx, provider.OIDCConfig, provider.Issuer, s.isTrustedOrigin(ctx))
	if err != nil {
		var de *DiscoveryError
		if errors.As(err, &de) {
			return fail("discovery_failed", encodeURIComponent(de.Message))
		}
		return fail("discovery_failed", "unexpected_discovery_error")
	}
	if cfg.TokenEndpoint == "" {
		return fail("invalid_provider", "token_endpoint_not_found")
	}

	// Step 4: exchange the authorization code
	verifier := ""
	if cfg.PKCEEnabled() {
		verifier = state.CodeVerifier
	}
	auth := providers.AuthBasic
	if cfg.TokenEndpointAuthentication == "client_secret_post" {
		auth = providers.AuthPost
	}
	tokens, err := providers.ExchangeCode(ctx, s.cfg.HTTPClient, providers.CodeExchange{
		TokenEndpoint: cfg.TokenEndpoint, Code: q.Code, CodeVerifier: verifier,
		RedirectURI: s.redirectURI(ctx, provider.ProviderID), ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret,
		Authentication: auth,
	})
	if err != nil {
		logger.Error("Error validating authorization code", "error", err)
		var he *providers.HTTPError
		if errors.As(err, &he) {
			return fail("invalid_provider", http.StatusText(he.Status))
		}
		tokens = nil
	}
	if tokens == nil {
		return fail("invalid_provider", "token_response_not_found")
	}

	// Step 5: the user (userinfo endpoint, else the verified id_token)
	mapping := config.OIDCMapping{}
	if cfg.Mapping != nil {
		mapping = *cfg.Mapping
	}
	var raw map[string]any
	if cfg.UserInfoEndpoint != "" {
		if err := providers.GetJSON(ctx, s.cfg.HTTPClient, cfg.UserInfoEndpoint, map[string]string{"Authorization": "Bearer " + tokens.AccessToken}, &raw); err != nil {
			desc := err.Error()
			var he *providers.HTTPError
			if errors.As(err, &he) {
				desc = http.StatusText(he.Status)
			}
			return fail("invalid_provider", desc)
		}
	} else if tokens.IDToken != "" {
		if cfg.JWKSEndpoint == "" {
			return fail("invalid_provider", "jwks_endpoint_not_found")
		}
		claims, err := providers.VerifyJWT(ctx, s.cfg.HTTPClient, tokens.IDToken, providers.IDTokenCheck{
			JWKSEndpoint: cfg.JWKSEndpoint, Issuers: []string{provider.Issuer}, Audiences: []string{cfg.ClientID},
		})
		if err != nil {
			logger.Error("sso: id token verification failed", "error", err)
			return fail("invalid_provider", "token_not_verified")
		}
		raw = map[string]any(claims)
	} else {
		return fail("invalid_provider", "user_info_endpoint_not_found")
	}
	info := mapOIDCUserInfo(raw, mapping, s.cfg.TrustEmailVerified)
	if str(info["email"]) == "" || str(info["id"]) == "" {
		return fail("invalid_provider", "missing_user_info")
	}

	// Step 6: sign in, link or sign up
	email := str(info["email"])
	emailVerified := s.cfg.TrustEmailVerified && truthy(info["emailVerified"])
	result, err := s.oauth.HandleOAuthUserInfo(ctx, socialsvc.OAuthUserInput{
		UserInfo: providers.UserInfo{
			ID: str(info["id"]), Email: email, Name: str(info["name"]), Image: str(info["image"]), EmailVerified: emailVerified,
		},
		Account:                socialsvc.AccountFromTokens(provider.ProviderID, str(info["id"]), tokens),
		CallbackURL:            state.CallbackURL,
		DisableSignUp:          s.cfg.DisableImplicitSignUp && !(state.RequestSignUp != nil && *state.RequestSignUp),
		OverrideUserInfo:       cfg.OverrideUserInfo != nil && *cfg.OverrideUserInfo,
		IsTrustedProvider:      provider.IsDomainVerified() && validateEmailDomain(email, provider.Domain),
		IgnoreTrustedProviders: true,
	})
	if err != nil {
		if ae := autherr.AsAuthError(err); ae != nil && ae.Code != "" {
			return &Redirect{Location: withParams(base, url.Values{"error": {string(ae.Code)}, "error_description": {ae.Message}}), Cookies: cookies}, nil
		}
		return nil, err
	}
	if result.Error != "" {
		return &Redirect{Location: withParams(base, url.Values{"error": {result.Error}}), Cookies: cookies}, nil
	}

	// Step 7: provisioning, organization membership, session cookie
	if s.cfg.ProvisionUser != nil && (result.IsRegister || s.cfg.ProvisionUserOnEveryLogin) {
		if err := s.cfg.ProvisionUser(ctx, config.ProvisionUserData{User: result.User, UserInfo: info, Token: tokens, Provider: provider}); err != nil {
			return nil, err
		}
	}
	if err := s.assignOrganizationFromProvider(ctx, result.User, provider, info, tokens); err != nil {
		return nil, err
	}
	target := state.CallbackURL
	if result.IsRegister && state.NewUserURL != "" {
		target = state.NewUserURL
	}
	return &Redirect{Location: target, Cookies: append(cookies, s.oauth.SignInCookies(ctx, result)...)}, nil
}

// mapOIDCUserInfo applies the provider mapping to the raw claims (extra fields first, then the standard ones).
func mapOIDCUserInfo(raw map[string]any, m config.OIDCMapping, trustEmailVerified bool) map[string]any {
	info := map[string]any{}
	for key, field := range m.ExtraFields {
		if f, ok := field.(string); ok {
			info[key] = raw[f]
		}
	}
	info["id"] = raw[pick(m.ID, "sub")]
	info["email"] = raw[pick(m.Email, "email")]
	if trustEmailVerified {
		info["emailVerified"] = raw[pick(m.EmailVerified, "email_verified")]
	} else {
		info["emailVerified"] = false
	}
	info["name"] = raw[pick(m.Name, "name")]
	info["image"] = raw[pick(m.Image, "picture")]
	return info
}

// truthy is JavaScript truthiness for claim values.
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0
	}
	return true
}

// withParams appends URLSearchParams to base ("?" or "&").
func withParams(base string, params url.Values) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + params.Encode()
}
