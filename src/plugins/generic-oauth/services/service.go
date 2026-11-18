// Package services implements better-auth's generic-oauth endpoints (POST /sign-in/oauth2,
// GET /oauth2/callback/{providerId}, POST /oauth2/link) on top of the social plugin's OAuth machinery:
// state + PKCE storage, handleOAuthUserInfo (sign in / implicit linking / sign up), account token storage
// and error redirects all come from social/services.
package services

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins/generic-oauth/config"
	godtos "github.com/better-go-auth/goauth/src/plugins/generic-oauth/dtos"
	gproviders "github.com/better-go-auth/goauth/src/plugins/generic-oauth/providers"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	socialproviders "github.com/better-go-auth/goauth/src/plugins/social/providers"
	socialsvc "github.com/better-go-auth/goauth/src/plugins/social/services"
)

// Service runs the generic-oauth flows.
type Service struct {
	kit       *pluginkit.Kit
	cfg       config.Config
	oauth     *socialsvc.Service
	providers map[string]*gproviders.Provider
}

// New builds the service. The first provider wins when several share an id (better-auth only warns).
func New(kit *pluginkit.Kit, cfg config.Config, ps []*gproviders.Provider) (*Service, error) {
	// Step 1: index the providers
	s := &Service{kit: kit, cfg: cfg, providers: map[string]*gproviders.Provider{}}
	for _, p := range ps {
		if p == nil {
			continue
		}
		if p.ID() == "" {
			return nil, fmt.Errorf("generic-oauth: provider without providerId")
		}
		if _, dup := s.providers[p.ID()]; !dup {
			s.providers[p.ID()] = p
		}
	}
	// Step 2: the shared OAuth machinery (state, account linking, token storage) of the social plugin
	oauth, err := socialsvc.New(kit, cfg.SocialConfig())
	if err != nil {
		return nil, err
	}
	s.oauth = oauth
	return s, nil
}

// Kit exposes the plugin kit.
func (s *Service) Kit() *pluginkit.Kit { return s.kit }

// Provider returns the provider with id.
func (s *Service) Provider(id string) (*gproviders.Provider, bool) {
	p, ok := s.providers[id]
	return p, ok
}

// callbackURI is "<baseURL>/oauth2/callback/<providerId>": the per-request base URL of pluginkit.WithBaseURL
// when set, else the (possibly dynamic) base URL of the request.
func (s *Service) callbackURI(ctx context.Context, providerID string) string {
	return s.kit.RequestBaseURL(ctx) + "/oauth2/callback/" + providerID
}

// ─── POST /sign-in/oauth2 ────────────────────────────────────────────────────

// StartResult is the outcome of SignIn and Link: the {url, redirect} body and the state cookies.
type StartResult struct {
	Body    godtos.RedirectResponse
	Cookies []http.Cookie
}

// SignIn is better-auth's signInWithOAuth2.
func (s *Service) SignIn(ctx context.Context, in godtos.SignInOAuth2Input) (*StartResult, error) {
	// Step 1: the provider config
	p, ok := s.Provider(in.ProviderID)
	if !ok {
		return nil, errProviderConfigNotFound(in.ProviderID)
	}
	cfg := p.Config()

	// Step 2: endpoints: the discovery document wins over the configured URLs
	authURL, tokenURL := cfg.AuthorizationURL, cfg.TokenURL
	if doc := p.Discover(ctx); doc != nil {
		if doc.AuthorizationEndpoint != "" {
			authURL = doc.AuthorizationEndpoint
		}
		if doc.TokenEndpoint != "" {
			tokenURL = doc.TokenEndpoint
		}
	}
	if authURL == "" || tokenURL == "" {
		return nil, ErrInvalidOAuthConfiguration
	}

	// Step 3: state + PKCE verifier (stored with the callback URLs and requestSignUp)
	st, err := s.oauth.GenerateState(ctx, nil, socialsvc.StateRequest{
		CallbackURL:      in.CallbackURL,
		ErrorCallbackURL: in.ErrorCallbackURL,
		NewUserURL:       in.NewUserCallbackURL,
		RequestSignUp:    in.RequestSignUp,
		AdditionalData:   in.AdditionalData,
	})
	if err != nil {
		return nil, err
	}

	// Step 4: the authorization URL (request scopes first, then the configured ones)
	scopes := append([]string{}, cfg.Scopes...)
	if in.Scopes != nil {
		scopes = append(append([]string{}, in.Scopes...), cfg.Scopes...)
	}
	u, err := p.BuildAuthorizationURL(authURL, gproviders.AuthURLRequest{
		State:        st.State,
		CodeVerifier: st.CodeVerifier,
		RedirectURI:  s.callbackURI(ctx, cfg.ProviderID),
		Scopes:       scopes,
		Prompt:       cfg.Prompt,
		AccessType:   cfg.AccessType,
		ResponseType: cfg.ResponseType,
		ResponseMode: cfg.ResponseMode,
		Additional:   p.AuthorizationParams(ctx),
	})
	if err != nil {
		return nil, ErrInvalidOAuthConfiguration
	}
	return &StartResult{Body: godtos.RedirectResponse{URL: u.String(), Redirect: !in.DisableRedirect}, Cookies: st.Cookies}, nil
}

// ─── POST /oauth2/link ───────────────────────────────────────────────────────

// Link is better-auth's oAuth2LinkAccount: the authorization URL to link a provider account to the session user.
func (s *Service) Link(ctx context.Context, current *dtos.SessionWithUser, in godtos.OAuth2LinkInput) (*StartResult, error) {
	// Step 1: session and provider
	if current == nil {
		return nil, ErrSessionRequired
	}
	p, ok := s.Provider(in.ProviderID)
	if !ok {
		return nil, autherr.ErrProviderNotFound
	}
	cfg := p.Config()

	// Step 2: the authorization endpoint (configured first, discovery only as a fallback)
	authURL := cfg.AuthorizationURL
	if authURL == "" {
		if cfg.DiscoveryURL == "" {
			return nil, ErrInvalidOAuthConfiguration
		}
		if doc := p.Discover(ctx); doc != nil {
			authURL = doc.AuthorizationEndpoint
		}
	}
	if authURL == "" {
		return nil, ErrInvalidOAuthConfiguration
	}

	// Step 3: the state carries the user to link to
	st, err := s.oauth.GenerateState(ctx, &socialsvc.StateLink{UserID: current.User.ID, Email: current.User.Email}, socialsvc.StateRequest{
		CallbackURL:      in.CallbackURL,
		ErrorCallbackURL: in.ErrorCallbackURL,
	})
	if err != nil {
		return nil, err
	}

	// Step 4: the authorization URL (request scopes replace the configured ones)
	scopes := cfg.Scopes
	if in.Scopes != nil {
		scopes = in.Scopes
	}
	u, err := p.BuildAuthorizationURL(authURL, gproviders.AuthURLRequest{
		State:        st.State,
		CodeVerifier: st.CodeVerifier,
		RedirectURI:  s.callbackURI(ctx, cfg.ProviderID),
		Scopes:       scopes,
		Prompt:       cfg.Prompt,
		AccessType:   cfg.AccessType,
		Additional:   p.AuthorizationParams(ctx),
	})
	if err != nil {
		return nil, ErrInvalidOAuthConfiguration
	}
	return &StartResult{Body: godtos.RedirectResponse{URL: u.String(), Redirect: true}, Cookies: st.Cookies}, nil
}

// ─── GET /oauth2/callback/{providerId} ───────────────────────────────────────

// CallbackParams are the callback query fields.
type CallbackParams struct {
	Code             string
	Error            string
	ErrorDescription string
	State            string
	Iss              string
}

// Callback is better-auth's oAuth2Callback. Every outcome is a redirect except the configuration errors
// (unknown provider), which better-auth throws as 400 JSON errors.
func (s *Service) Callback(ctx context.Context, providerID string, q CallbackParams) (*socialsvc.Redirect, error) {
	defaultErrorURL := s.oauth.DefaultErrorURL(ctx)

	// Step 1: provider error or missing code: straight to the default error URL (the state is not read)
	if q.Error != "" || q.Code == "" {
		code := q.Error
		if code == "" {
			code = "oAuth_code_missing"
		}
		return socialsvc.ErrorRedirect(defaultErrorURL, code, q.ErrorDescription, nil), nil
	}

	// Step 2: the provider config
	if providerID == "" {
		return nil, ErrProviderIDRequired
	}
	p, ok := s.Provider(providerID)
	if !ok {
		return nil, errProviderConfigNotFound(providerID)
	}
	cfg := p.Config()

	// Step 3: the state (PKCE verifier, callback URLs, link target); state errors redirect
	state, cookies, err := s.oauth.ParseState(ctx, q.State)
	if err != nil {
		code, target := "internal_server_error", defaultErrorURL
		if se, ok := err.(*socialsvc.StateError); ok {
			code = se.Code
			if se.ErrorURL != "" {
				target = se.ErrorURL
			}
		}
		return socialsvc.ErrorRedirect(target, code, "", cookies), nil
	}
	errorURL := state.ErrorURL
	if errorURL == "" {
		errorURL = defaultErrorURL
	}
	fail := func(code string, description ...string) *socialsvc.Redirect {
		d := ""
		if len(description) > 0 {
			d = description[0]
		}
		return socialsvc.ErrorRedirect(errorURL, code, d, cookies)
	}

	// Step 4: endpoints and the expected issuer (discovery wins over the configured URLs)
	tokenURL, userInfoURL, issuer := cfg.TokenURL, cfg.UserInfoURL, cfg.Issuer
	if doc := p.Discover(ctx); doc != nil {
		if doc.TokenEndpoint != "" {
			tokenURL = doc.TokenEndpoint
		}
		if doc.UserInfoEndpoint != "" {
			userInfoURL = doc.UserInfoEndpoint
		}
		if issuer == "" {
			issuer = doc.Issuer
		}
	}

	// Step 5: RFC 9207 issuer identification
	if issuer != "" {
		if q.Iss != "" {
			if q.Iss != issuer {
				return fail("issuer_mismatch"), nil
			}
		} else if cfg.RequireIssuerValidation {
			return fail("issuer_missing"), nil
		}
	}

	// Step 6: exchange the code (getToken override or the token endpoint)
	tokens, err := p.ExchangeCode(ctx, gproviders.ExchangeRequest{
		TokenURL:     tokenURL,
		Code:         q.Code,
		CodeVerifier: state.CodeVerifier,
		RedirectURI:  s.callbackURI(ctx, cfg.ProviderID),
		Extra:        p.TokenParams(ctx),
	})
	if err != nil || tokens == nil {
		return fail("oauth_code_verification_failed"), nil
	}

	// Step 7: the provider user (mapProfileToUser applied, email / id / name required)
	info, code := s.userInfo(ctx, p, *tokens, userInfoURL)
	if code != "" {
		return fail(code), nil
	}

	// Step 8: link flow (/oauth2/link)
	if state.Link != nil {
		return s.callbackLink(ctx, cfg.ProviderID, state, info, tokens, fail, cookies), nil
	}

	// Step 9: sign in, implicit link or sign up
	requestSignUp := state.RequestSignUp != nil && *state.RequestSignUp
	result, err := s.oauth.HandleOAuthUserInfo(ctx, socialsvc.OAuthUserInput{
		UserInfo:         info,
		Account:          socialsvc.AccountFromTokens(cfg.ProviderID, info.ID, tokens),
		CallbackURL:      state.CallbackURL,
		DisableSignUp:    (cfg.DisableImplicitSignUp && !requestSignUp) || cfg.DisableSignUp,
		OverrideUserInfo: cfg.OverrideUserInfo,
	})
	if err != nil {
		if ae := autherr.AsAuthError(err); ae != nil {
			return fail(string(ae.Code), ae.Message), nil
		}
		return nil, err
	}
	if result.Error != "" {
		return fail(strings.Join(strings.Split(result.Error, " "), "_")), nil
	}

	// Step 10: session cookie, then the app (new users go to newUserURL when set)
	target := state.CallbackURL
	if result.IsRegister && state.NewUserURL != "" {
		target = state.NewUserURL
	}
	return &socialsvc.Redirect{Location: target, Cookies: append(cookies, s.oauth.SignInCookies(ctx, result)...)}, nil
}

// userInfo is the handleUserInfo step of better-auth's callback: the profile, mapProfileToUser on top, and the
// required email / id / name. It returns the redirect error code on failure.
func (s *Service) userInfo(ctx context.Context, p *gproviders.Provider, tokens socialproviders.OAuth2Tokens, userInfoURL string) (socialproviders.UserInfo, string) {
	// Step 1: the profile (getUserInfo override, id_token claims or the userinfo endpoint)
	profile := p.FetchProfile(ctx, tokens, userInfoURL)
	if profile == nil {
		return socialproviders.UserInfo{}, "user_info_is_missing"
	}
	// Step 2: mapProfileToUser (defaults to the profile itself)
	mapped := profile
	cfg := p.Config()
	if cfg.MapProfileToUser != nil {
		if m := cfg.MapProfileToUser(profile); m != nil {
			mapped = m
		} else {
			mapped = map[string]any{}
		}
	}
	pick := func(key string) any {
		if v, ok := mapped[key]; ok && v != nil && gproviders.StringOf(v) != "" {
			return v
		}
		return profile[key]
	}
	// Step 3: the required fields (email is lower-cased)
	info := socialproviders.UserInfo{
		Email: strings.ToLower(gproviders.StringOf(pick("email"))),
		ID:    gproviders.StringOf(pick("id")),
		Name:  gproviders.StringOf(pick("name")),
		Image: gproviders.StringOf(pick("image")),
	}
	if v, ok := mapped["emailVerified"]; ok {
		info.EmailVerified = gproviders.BoolOf(v)
	} else {
		info.EmailVerified = gproviders.BoolOf(profile["emailVerified"])
	}
	if info.Email == "" {
		return info, "email_is_missing"
	}
	if info.ID == "" {
		return info, "id_is_missing"
	}
	if info.Name == "" {
		return info, "name_is_missing"
	}
	// Step 4: the extra user fields returned by mapProfileToUser (firstName, username, ...)
	if cfg.MapProfileToUser != nil {
		for k, v := range mapped {
			switch k {
			case "id", "name", "email", "image", "emailVerified":
			default:
				if info.Extra == nil {
					info.Extra = map[string]any{}
				}
				info.Extra[k] = v
			}
		}
	}
	return info, ""
}

// callbackLink is the link branch of better-auth's oAuth2Callback.
func (s *Service) callbackLink(ctx context.Context, providerID string, state *socialsvc.StateData, info socialproviders.UserInfo, tokens *socialproviders.OAuth2Tokens, fail func(string, ...string) *socialsvc.Redirect, cookies []http.Cookie) *socialsvc.Redirect {
	// Step 1: the provider email must match the user's unless allowDifferentEmails
	if !s.cfg.AccountLinking.AllowDifferentEmails && !strings.EqualFold(state.Link.Email, info.Email) {
		return fail("email_doesn't_match")
	}
	// Step 2: an existing account: the same user refreshes its tokens, another user is refused
	data := socialsvc.AccountFromTokens(providerID, info.ID, tokens)
	existing, err := pluginkit.AcceptNotFound(s.kit.Repos.FindAccountByProviderID(ctx, models.Providers(providerID), info.ID))
	if err != nil {
		return fail("unable_to_link_account")
	}
	if existing != nil {
		if existing.UserID != state.Link.UserID {
			return fail("account_already_linked_to_different_user")
		}
		if update, err := s.oauth.TokenUpdate(data); err == nil && len(update) > 0 {
			_, _ = s.kit.Repos.UpdateAccount(ctx, existing.ID, update)
		}
	} else {
		// Step 3: a new account for the linking user
		acc, err := s.oauth.NewAccount(state.Link.UserID, data)
		if err == nil {
			_, err = s.kit.Repos.CreateAccount(ctx, acc)
		}
		if err != nil {
			return fail("unable_to_link_account")
		}
	}
	// Step 4: optional profile sync (accountLinking.updateUserInfoOnLink), then back to the app
	s.oauth.ApplyUpdateUserInfoOnLink(ctx, state.Link.UserID, info)
	return &socialsvc.Redirect{Location: state.CallbackURL, Cookies: cookies}
}
