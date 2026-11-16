// Package services implements better-auth's social sign-in flows: /sign-in/social, /callback/{id},
// /link-social and the account token endpoints.
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	socialdtos "github.com/better-go-auth/goauth/src/plugins/social/dtos"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
)

// Service runs the social sign-in flows on top of a pluginkit.Kit.
type Service struct {
	kit       *pluginkit.Kit
	cfg       socialconfig.SocialConfig
	providers map[string]providers.Provider
}

// New builds the service. Providers with an empty or duplicate id are rejected.
func New(kit *pluginkit.Kit, cfg socialconfig.SocialConfig) (*Service, error) {
	s := &Service{kit: kit, cfg: cfg, providers: map[string]providers.Provider{}}
	for _, p := range cfg.Providers {
		if p == nil {
			continue
		}
		if p.ID() == "" {
			return nil, fmt.Errorf("social: provider without id")
		}
		if _, dup := s.providers[p.ID()]; dup {
			return nil, fmt.Errorf("social: duplicate provider %q", p.ID())
		}
		s.providers[p.ID()] = p
	}
	return s, nil
}

// Provider returns the configured provider with id.
func (s *Service) Provider(id string) (providers.Provider, bool) {
	p, ok := s.providers[id]
	return p, ok
}

// Kit exposes the plugin kit (handlers build cookies with it).
func (s *Service) Kit() *pluginkit.Kit { return s.kit }

// redirectURI is "<baseURL>/callback/<id>".
func (s *Service) redirectURI(p providers.Provider) string {
	return s.kit.BaseURL() + "/callback/" + p.ID()
}

// disableSignUp is `provider.disableImplicitSignUp && !requestSignUp || provider.disableSignUp`.
func disableSignUp(p providers.Provider, requestSignUp bool) bool {
	o := p.Options()
	return (o.DisableImplicitSignUp && !requestSignUp) || o.DisableSignUp
}

// ─── POST /sign-in/social ────────────────────────────────────────────────────

// SignInResult is the outcome of SignInSocial.
type SignInResult struct {
	Body socialdtos.SignInSocialResponse
	// Location is set when the client should be redirected (redirect branch without disableRedirect).
	Location string
	Cookies  []http.Cookie
}

// SignInSocial is better-auth's signInSocial.
func (s *Service) SignInSocial(ctx context.Context, in socialdtos.SignInSocialInput) (*SignInResult, error) {
	// Step 1: the provider must be configured
	p, ok := s.Provider(in.Provider)
	if !ok {
		return nil, autherr.ErrProviderNotFound
	}

	// Step 2: id_token branch: verify the token, then sign in / sign up without a redirect
	if in.IDToken != nil {
		return s.signInWithIDToken(ctx, p, in)
	}

	// Step 3: redirect branch: state + PKCE, then the provider's authorization URL
	st, err := s.generateState(ctx, nil, stateRequest{
		CallbackURL:      in.CallbackURL,
		ErrorCallbackURL: in.ErrorCallbackURL,
		NewUserURL:       in.NewUserCallbackURL,
		RequestSignUp:    in.RequestSignUp,
		AdditionalData:   in.AdditionalData,
	})
	if err != nil {
		return nil, err
	}
	u, err := p.CreateAuthorizationURL(ctx, providers.AuthorizationURLInput{
		State:        st.State,
		CodeVerifier: st.CodeVerifier,
		RedirectURI:  s.redirectURI(p),
		Scopes:       in.Scopes,
		LoginHint:    in.LoginHint,
	})
	if err != nil {
		return nil, pluginkit.NewError(http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", err.Error())
	}
	res := &SignInResult{Body: socialdtos.SignInSocialResponse{URL: u.String(), Redirect: !in.DisableRedirect}, Cookies: st.Cookies}
	if !in.DisableRedirect {
		res.Location = u.String()
	}
	return res, nil
}

// signInWithIDToken is the idToken branch of signInSocial.
func (s *Service) signInWithIDToken(ctx context.Context, p providers.Provider, in socialdtos.SignInSocialInput) (*SignInResult, error) {
	// Step 1: the provider must support id_token sign-in
	verifier, ok := providers.AsIDTokenVerifier(p)
	if !ok {
		return nil, autherr.ErrIDTokenNotSupported
	}
	// Step 2: verify the token (signature, issuer, audience, nonce)
	if valid, err := verifier.VerifyIDToken(ctx, in.IDToken.Token, in.IDToken.Nonce); err != nil || !valid {
		return nil, ErrInvalidIDToken
	}
	// Step 3: the user behind the token
	info, err := p.GetUserInfo(ctx, providers.UserInfoInput{
		OAuth2Tokens: providers.OAuth2Tokens{IDToken: in.IDToken.Token, AccessToken: in.IDToken.AccessToken, RefreshToken: in.IDToken.RefreshToken},
		User:         appleUser(in.IDToken.User),
	})
	if err != nil || info == nil {
		return nil, autherr.ErrFailedToGetUserInfo
	}
	if info.User.Email == "" {
		return nil, autherr.ErrUserEmailNotFound
	}
	// Step 4: sign in, link or sign up
	res, err := s.handleOAuthUserInfo(ctx, oauthUserInput{
		UserInfo: info.User,
		Account: accountData{
			ProviderID:  p.ID(),
			AccountID:   info.User.ID,
			AccessToken: in.IDToken.AccessToken,
		},
		CallbackURL:   in.CallbackURL,
		DisableSignUp: disableSignUp(p, in.RequestSignUp),
	})
	if err != nil {
		return nil, err
	}
	if res.Error != "" {
		return nil, errOAuthLink(res.Error)
	}
	// Step 5: session cookie + {redirect:false, token, user}
	user := dtos.UserFromModel(res.User)
	return &SignInResult{
		Body:    socialdtos.SignInSocialResponse{Redirect: false, Token: res.Session.Session.Token, User: &user},
		Cookies: s.kit.SessionCookies(res.Session, false),
	}, nil
}

func appleUser(u *socialdtos.IDTokenUser) *providers.AppleUser {
	if u == nil {
		return nil
	}
	out := &providers.AppleUser{Email: u.Email}
	if u.Name != nil {
		out.Name = &providers.AppleUserName{FirstName: u.Name.FirstName, LastName: u.Name.LastName}
	}
	return out
}

// ─── POST /link-social ───────────────────────────────────────────────────────

// LinkResult is the outcome of LinkSocial.
type LinkResult struct {
	Body     socialdtos.LinkSocialResponse
	Location string
	Cookies  []http.Cookie
}

// LinkSocial is better-auth's linkSocialAccount for the signed-in user.
func (s *Service) LinkSocial(ctx context.Context, current *dtos.SessionWithUser, in socialdtos.LinkSocialInput) (*LinkResult, error) {
	// Step 1: the provider must be configured
	p, ok := s.Provider(in.Provider)
	if !ok {
		return nil, autherr.ErrProviderNotFound
	}
	if in.IDToken != nil {
		return s.linkWithIDToken(ctx, current, p, in)
	}
	// Step 2: redirect branch: the state carries the user to link to
	st, err := s.generateState(ctx, &StateLink{UserID: current.User.ID, Email: current.User.Email}, stateRequest{
		CallbackURL:      in.CallbackURL,
		ErrorCallbackURL: in.ErrorCallbackURL,
		RequestSignUp:    in.RequestSignUp,
		AdditionalData:   in.AdditionalData,
	})
	if err != nil {
		return nil, err
	}
	u, err := p.CreateAuthorizationURL(ctx, providers.AuthorizationURLInput{
		State:        st.State,
		CodeVerifier: st.CodeVerifier,
		RedirectURI:  s.redirectURI(p),
		Scopes:       in.Scopes,
	})
	if err != nil {
		return nil, pluginkit.NewError(http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", err.Error())
	}
	res := &LinkResult{Body: socialdtos.LinkSocialResponse{URL: u.String(), Redirect: !in.DisableRedirect}, Cookies: st.Cookies}
	if !in.DisableRedirect {
		res.Location = u.String()
	}
	return res, nil
}

// linkWithIDToken is the idToken branch of linkSocialAccount.
func (s *Service) linkWithIDToken(ctx context.Context, current *dtos.SessionWithUser, p providers.Provider, in socialdtos.LinkSocialInput) (*LinkResult, error) {
	done := &LinkResult{Body: socialdtos.LinkSocialResponse{URL: "", Status: socialconfig.Bool(true), Redirect: false}}
	// Step 1: verify the token
	verifier, ok := providers.AsIDTokenVerifier(p)
	if !ok {
		return nil, autherr.ErrIDTokenNotSupported
	}
	if valid, err := verifier.VerifyIDToken(ctx, in.IDToken.Token, in.IDToken.Nonce); err != nil || !valid {
		return nil, ErrInvalidIDToken
	}
	// Step 2: the provider user
	info, err := p.GetUserInfo(ctx, providers.UserInfoInput{OAuth2Tokens: providers.OAuth2Tokens{
		IDToken: in.IDToken.Token, AccessToken: in.IDToken.AccessToken, RefreshToken: in.IDToken.RefreshToken,
	}})
	if err != nil || info == nil {
		return nil, autherr.ErrFailedToGetUserInfo
	}
	if info.User.Email == "" {
		return nil, autherr.ErrUserEmailNotFound
	}
	// Step 3: already linked: nothing to do
	accounts, err := s.kit.Repos.FindAccounts(ctx, current.User.ID)
	if err != nil {
		return nil, err
	}
	for _, a := range accounts {
		if string(a.ProviderID) == p.ID() && a.AccountID == info.User.ID {
			return done, nil
		}
	}
	// Step 4: linking policy
	if (!s.isTrustedProvider(p.ID()) && !info.User.EmailVerified) || !s.cfg.LinkingEnabled() {
		return nil, ErrLinkingNotAllowed
	}
	if !strings.EqualFold(info.User.Email, current.User.Email) && !s.cfg.AccountLinking.AllowDifferentEmails {
		return nil, ErrLinkingDifferentEmails
	}
	// Step 5: create the account
	var scope *string
	if in.IDToken.Scopes != nil {
		sc := strings.Join(in.IDToken.Scopes, ",")
		scope = &sc
	}
	acc, err := s.newAccount(current.User.ID, accountData{
		ProviderID: p.ID(), AccountID: info.User.ID, AccessToken: in.IDToken.AccessToken,
		RefreshToken: in.IDToken.RefreshToken, IDToken: in.IDToken.Token, Scope: scope,
	})
	if err == nil {
		_, err = s.kit.Repos.CreateAccount(ctx, acc)
	}
	if err != nil {
		return nil, ErrLinkingFailed
	}
	s.applyUpdateUserInfoOnLink(ctx, current.User.ID, info.User)
	return done, nil
}

// ─── GET|POST /callback/{id} ─────────────────────────────────────────────────

// CallbackParams are the callback query (or form_post body) fields.
type CallbackParams struct {
	Code             string `json:"code,omitempty"`
	Error            string `json:"error,omitempty"`
	DeviceID         string `json:"device_id,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	State            string `json:"state,omitempty"`
	User             string `json:"user,omitempty"`
}

// Redirect is a 302 answer: every callback outcome is one.
type Redirect struct {
	Location string
	Cookies  []http.Cookie
}

// errorRedirect is better-auth's redirectOnError: <errorURL>?error=<code>[&error_description=...].
func errorRedirect(errorURL, code, description string, cookies []http.Cookie) *Redirect {
	q := url.Values{}
	q.Set("error", code)
	if description != "" {
		q.Set("error_description", description)
	}
	sep := "?"
	if strings.Contains(errorURL, "?") {
		sep = "&"
	}
	return &Redirect{Location: errorURL + sep + q.Encode(), Cookies: cookies}
}

// defaultErrorURL is onAPIError.errorURL or "<baseURL>/error".
func (s *Service) defaultErrorURL() string {
	if s.cfg.ErrorURL != "" {
		return s.cfg.ErrorURL
	}
	return s.kit.BaseURL() + "/error"
}

// PostCallbackRedirect is the POST /callback/{id} (form_post) answer: merge body and query, then redirect to the
// GET callback so the cookies (SameSite=Lax) are sent.
func (s *Service) PostCallbackRedirect(providerID string, body, query CallbackParams) *Redirect {
	// Step 1: query values win over body values
	merged := body
	for _, kv := range []struct {
		dst *string
		v   string
	}{{&merged.Code, query.Code}, {&merged.Error, query.Error}, {&merged.DeviceID, query.DeviceID}, {&merged.ErrorDescription, query.ErrorDescription}, {&merged.State, query.State}, {&merged.User, query.User}} {
		if kv.v != "" {
			*kv.dst = kv.v
		}
	}
	// Step 2: re-encode in better-auth's schema order
	var parts []string
	for _, kv := range [][2]string{{"code", merged.Code}, {"error", merged.Error}, {"device_id", merged.DeviceID}, {"error_description", merged.ErrorDescription}, {"state", merged.State}, {"user", merged.User}} {
		if kv[1] != "" {
			parts = append(parts, url.QueryEscape(kv[0])+"="+url.QueryEscape(kv[1]))
		}
	}
	return &Redirect{Location: s.kit.BaseURL() + "/callback/" + providerID + "?" + strings.Join(parts, "&")}
}

// Callback is better-auth's callbackOAuth (GET): every outcome, success or failure, is a redirect.
func (s *Service) Callback(ctx context.Context, providerID string, q CallbackParams) *Redirect {
	defaultErrorURL := s.defaultErrorURL()

	// Step 1: the state (PKCE verifier, callback URLs, link target)
	state, cookies, err := s.parseState(ctx, q.State)
	if err != nil {
		se, _ := err.(*StateError)
		code, target := "internal_server_error", defaultErrorURL
		if se != nil {
			code = se.Code
			if se.ErrorURL != "" {
				target = se.ErrorURL
			}
		}
		return errorRedirect(target, code, "", cookies)
	}
	errorURL := state.ErrorURL
	if errorURL == "" {
		errorURL = defaultErrorURL
	}
	fail := func(code string, description ...string) *Redirect {
		d := ""
		if len(description) > 0 {
			d = description[0]
		}
		return errorRedirect(errorURL, code, d, cookies)
	}

	// Step 2: the provider reported an error (e.g. access_denied)
	if q.Error != "" {
		return fail(q.Error, q.ErrorDescription)
	}
	if q.Code == "" {
		return fail("no_code")
	}
	p, ok := s.Provider(providerID)
	if !ok {
		return fail("oauth_provider_not_found")
	}

	// Step 3: exchange the code (with the PKCE verifier)
	tokens, err := p.ValidateAuthorizationCode(ctx, providers.ValidateCodeInput{
		Code:         q.Code,
		CodeVerifier: state.CodeVerifier,
		DeviceID:     q.DeviceID,
		RedirectURI:  s.redirectURI(p),
	})
	if err != nil || tokens == nil {
		return fail("invalid_code")
	}

	// Step 4: the provider user
	var apple *providers.AppleUser
	if q.User != "" {
		var u providers.AppleUser
		if json.Unmarshal([]byte(q.User), &u) == nil {
			apple = &u
		}
	}
	res, err := p.GetUserInfo(ctx, providers.UserInfoInput{OAuth2Tokens: *tokens, User: apple})
	if err != nil || res == nil || res.User.ID == "" {
		return fail("unable_to_get_user_info")
	}
	info := res.User
	if state.CallbackURL == "" {
		return fail("no_callback_url")
	}

	// Step 5: link flow (/link-social): attach the account to the user stored in the state
	if state.Link != nil {
		return s.callbackLink(ctx, p, state, info, tokens, fail, cookies)
	}

	// Step 6: sign-in flow
	if info.Email == "" {
		return fail("email_not_found")
	}
	result, err := s.handleOAuthUserInfo(ctx, oauthUserInput{
		UserInfo:         info,
		Account:          accountFromTokens(p.ID(), info.ID, tokens),
		CallbackURL:      state.CallbackURL,
		DisableSignUp:    disableSignUp(p, state.RequestSignUp != nil && *state.RequestSignUp),
		OverrideUserInfo: p.Options().OverrideUserInfoOnSignIn,
	})
	if err != nil {
		if ae := autherr.AsAuthError(err); ae != nil {
			return fail(string(ae.Code), ae.Message)
		}
		return fail("internal_server_error")
	}
	if result.Error != "" {
		return fail(strings.Join(strings.Split(result.Error, " "), "_"))
	}

	// Step 7: session cookie + redirect (new users go to newUserURL when set)
	target := state.CallbackURL
	if result.IsRegister && state.NewUserURL != "" {
		target = state.NewUserURL
	}
	return &Redirect{Location: target, Cookies: append(cookies, s.kit.SessionCookies(result.Session, false)...)}
}

// callbackLink is the link branch of callbackOAuth.
func (s *Service) callbackLink(ctx context.Context, p providers.Provider, state *StateData, info providers.UserInfo, tokens *providers.OAuth2Tokens, fail func(string, ...string) *Redirect, cookies []http.Cookie) *Redirect {
	// Step 1: linking policy
	if (!s.isTrustedProvider(p.ID()) && !info.EmailVerified) || !s.cfg.LinkingEnabled() {
		return fail("unable_to_link_account")
	}
	if !strings.EqualFold(info.Email, state.Link.Email) && !s.cfg.AccountLinking.AllowDifferentEmails {
		return fail("email_doesn't_match")
	}
	// Step 2: existing account: same user refreshes its tokens, another user is refused
	data := accountFromTokens(p.ID(), info.ID, tokens)
	existing, err := pluginkit.AcceptNotFound(s.kit.Repos.FindAccountByProviderID(ctx, models.Providers(p.ID()), info.ID))
	if err != nil {
		return fail("unable_to_link_account")
	}
	if existing != nil {
		if existing.UserID != state.Link.UserID {
			return fail("account_already_linked_to_different_user")
		}
		update, err := s.tokenUpdate(data)
		if err == nil && len(update) > 0 {
			_, _ = s.kit.Repos.UpdateAccount(ctx, existing.ID, update)
		}
	} else {
		// Step 3: new account for the linking user
		acc, err := s.newAccount(state.Link.UserID, data)
		if err == nil {
			_, err = s.kit.Repos.CreateAccount(ctx, acc)
		}
		if err != nil {
			return fail("unable_to_link_account")
		}
	}
	// Step 4: optional profile sync, then back to the app
	s.applyUpdateUserInfoOnLink(ctx, state.Link.UserID, info)
	return &Redirect{Location: state.CallbackURL, Cookies: cookies}
}
