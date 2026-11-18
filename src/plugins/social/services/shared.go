package services

import (
	"context"
	"net/http"

	"github.com/better-go-auth/goauth/src/models"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
)

// This file exports the OAuth machinery of the social plugin (state + PKCE, handleOAuthUserInfo, account
// token storage, error redirects) so other OAuth plugins (e.g. generic-oauth) share one implementation
// instead of re-porting better-auth's src/oauth2 helpers. The exported names are thin wrappers or aliases
// around the unexported implementation used by the social endpoints themselves.

// StateRequest are the request fields stored in the OAuth state (better-auth reads them from ctx.body).
type StateRequest = stateRequest

// GeneratedState is the result of GenerateState: the state value, the PKCE verifier and the cookies to set.
type GeneratedState = generatedState

// AccountData is the provider account passed to HandleOAuthUserInfo (tokens in clear text).
type AccountData = accountData

// OAuthUserInput is HandleOAuthUserInfo's options.
type OAuthUserInput = oauthUserInput

// OAuthUserResult is HandleOAuthUserInfo's result.
type OAuthUserResult = oauthUserResult

// Config returns the effective social configuration (account linking, token storage, state strategy).
func (s *Service) Config() socialconfig.SocialConfig { return s.cfg }

// GenerateState is better-auth's generateState: it stores the state payload (database or cookie strategy)
// and returns the state value, the PKCE code verifier and the cookies to set.
func (s *Service) GenerateState(ctx context.Context, link *StateLink, in StateRequest) (*GeneratedState, error) {
	return s.generateState(ctx, link, in)
}

// ParseState is better-auth's parseGenericState: it loads and consumes the state, returning the cookies to
// set (the expired state cookie) and a *StateError on failure.
func (s *Service) ParseState(ctx context.Context, state string) (*StateData, []http.Cookie, error) {
	return s.parseState(ctx, state)
}

// ParseStateSkipCookieCheck is better-auth's parseGenericState(ctx, state, {skipStateCookieCheck: true}): the
// signed `state` cookie of the database strategy is not required (oauth-proxy callbacks).
func (s *Service) ParseStateSkipCookieCheck(ctx context.Context, state string) (*StateData, []http.Cookie, error) {
	return s.parseStateWith(ctx, state, true)
}

// HandleOAuthUserInfo is better-auth's handleOAuthUserInfo (sign in, implicit link or sign up + session).
func (s *Service) HandleOAuthUserInfo(ctx context.Context, in OAuthUserInput) (*OAuthUserResult, error) {
	return s.handleOAuthUserInfo(ctx, in)
}

// AccountFromTokens builds AccountData from a token response ({...tokens, scope: scopes.join(",")}).
func AccountFromTokens(providerID, accountID string, t *providers.OAuth2Tokens) AccountData {
	return accountFromTokens(providerID, accountID, t)
}

// NewAccount builds the account row for userID, encrypting the tokens when EncryptOAuthTokens is on.
func (s *Service) NewAccount(userID string, a AccountData) (*models.Account, error) {
	return s.newAccount(userID, a)
}

// TokenUpdate is the account update for fresh tokens, skipping unknown values.
func (s *Service) TokenUpdate(a AccountData) (map[string]interface{}, error) {
	return s.tokenUpdate(a)
}

// ApplyUpdateUserInfoOnLink copies the linked provider's profile onto the user when
// AccountLinking.UpdateUserInfoOnLink is on (nil when nothing changed).
func (s *Service) ApplyUpdateUserInfoOnLink(ctx context.Context, userID string, info providers.UserInfo) *models.User {
	return s.applyUpdateUserInfoOnLink(ctx, userID, info)
}

// DefaultErrorURL is onAPIError.errorURL (SocialConfig.ErrorURL) or "<baseURL>/error".
func (s *Service) DefaultErrorURL(ctx context.Context) string { return s.defaultErrorURL(ctx) }

// ErrorRedirect is better-auth's redirectOnError: <errorURL>?error=<code>[&error_description=...].
func ErrorRedirect(errorURL, code, description string, cookies []http.Cookie) *Redirect {
	return errorRedirect(errorURL, code, description, cookies)
}
