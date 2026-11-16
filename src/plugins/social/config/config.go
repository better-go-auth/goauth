// Package config holds the social sign-in plugin options: the providers plus better-auth's `account`
// options that core AuthConfig.Account does not model (account linking policy, token storage, OAuth state).
package config

import "github.com/better-go-auth/goauth/src/plugins/social/providers"

// StateStrategy selects where the OAuth state lives between sign-in and callback
// (better-auth's account.storeStateStrategy).
type StateStrategy string

const (
	// StateDatabase stores the state in a verification row keyed by the state, plus a signed `state`
	// cookie (maxAge 300) binding it to the browser. Default.
	StateDatabase StateStrategy = "database"
	// StateCookie stores the whole state encrypted in the `oauth_state` cookie (maxAge 600).
	StateCookie StateStrategy = "cookie"
)

// AccountLinking mirrors better-auth's account.accountLinking (AllowUnlinkingAll stays in core config).
type AccountLinking struct {
	// Enabled turns account linking on (default true). With false, implicit linking and /link-social fail.
	Enabled *bool
	// TrustedProviders may link even when the provider reports an unverified email.
	TrustedProviders []string
	// AllowDifferentEmails lets /link-social link an account whose email differs from the user's.
	AllowDifferentEmails bool
	// DisableImplicitLinking stops sign-in from linking a provider account to an existing user by email.
	DisableImplicitLinking bool
	// UpdateUserInfoOnLink copies the provider profile (name, image, ...) onto the user when linking.
	UpdateUserInfoOnLink bool
	// RequireLocalEmailVerified (default true) only links implicitly when the local user's email is verified.
	RequireLocalEmailVerified *bool
}

// SocialConfig configures the social sign-in plugin.
type SocialConfig struct {
	// Providers are the enabled social providers (providers.Google(...), providers.Generic(...), ...).
	Providers []providers.Provider

	// AccountLinking is the account linking policy.
	AccountLinking AccountLinking
	// EncryptOAuthTokens stores access/refresh tokens encrypted with the auth secret (XChaCha20-Poly1305).
	EncryptOAuthTokens bool
	// UpdateAccountOnSignIn refreshes the stored tokens on every sign-in (default true).
	UpdateAccountOnSignIn *bool
	// StoreStateStrategy is StateDatabase (default) or StateCookie.
	StoreStateStrategy StateStrategy
	// SkipStateCookieCheck skips the signed `state` cookie check of the database strategy
	// (for flows where the callback lands in a different browser context, e.g. mobile).
	SkipStateCookieCheck bool
	// ErrorURL is better-auth's onAPIError.errorURL: where callback errors redirect when the flow has no
	// errorCallbackURL (default "<baseURL><basePath>/error").
	ErrorURL string
}

// LinkingEnabled reports accountLinking.enabled (default true).
func (c SocialConfig) LinkingEnabled() bool {
	return c.AccountLinking.Enabled == nil || *c.AccountLinking.Enabled
}

// RequireLocalEmailVerified reports accountLinking.requireLocalEmailVerified (default true).
func (c SocialConfig) RequireLocalEmailVerified() bool {
	return c.AccountLinking.RequireLocalEmailVerified == nil || *c.AccountLinking.RequireLocalEmailVerified
}

// UpdateAccountOnSignInEnabled reports updateAccountOnSignIn (default true).
func (c SocialConfig) UpdateAccountOnSignInEnabled() bool {
	return c.UpdateAccountOnSignIn == nil || *c.UpdateAccountOnSignIn
}

// Strategy returns the configured state strategy (default StateDatabase).
func (c SocialConfig) Strategy() StateStrategy {
	if c.StoreStateStrategy == "" {
		return StateDatabase
	}
	return c.StoreStateStrategy
}

// Bool returns a pointer to b, for the optional boolean options.
func Bool(b bool) *bool { return &b }
