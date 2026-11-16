// Package config holds the options of the passkey (WebAuthn) plugin. They mirror the options of
// better-auth's @better-auth/passkey plugin (v1.6.16).
package config

import (
	"context"
	"net/http"
)

// DefaultWebAuthnChallengeCookie is better-auth's advanced.webAuthnChallengeCookie default; the cookie is
// created with the auth cookie prefix ("better-auth.better-auth-passkey").
const DefaultWebAuthnChallengeCookie = "better-auth-passkey"

// DefaultChallengeMaxAgeSeconds is how long a generated challenge (and its cookie) stays valid (better-auth: 300s).
const DefaultChallengeMaxAgeSeconds = 300

// AuthenticatorSelection mirrors WebAuthn's AuthenticatorSelectionCriteria. Empty fields keep better-auth's
// defaults (residentKey "preferred", userVerification "preferred").
type AuthenticatorSelection struct {
	// AuthenticatorAttachment is "platform" or "cross-platform" (empty: any authenticator).
	AuthenticatorAttachment string
	// ResidentKey is "discouraged", "preferred" or "required".
	ResidentKey string
	// UserVerification is "discouraged", "preferred" or "required".
	UserVerification string
}

// RegistrationUser is the WebAuthn user a passkey is registered for (better-auth's resolveUser result).
type RegistrationUser struct {
	ID          string
	Name        string
	DisplayName string
}

// ResolveUserInput is passed to Registration.ResolveUser.
type ResolveUserInput struct {
	// Request is the incoming generate-register-options request.
	Request *http.Request
	// Context is the optional `context` query parameter sent by the client (nil when absent).
	Context *string
}

// RegistrationVerification carries the verified registration to Registration.AfterVerification.
type RegistrationVerification struct {
	Request *http.Request
	// User is the user the challenge was generated for.
	User RegistrationUser
	// CredentialID is the base64url credential ID, PublicKey the raw COSE key.
	CredentialID string
	PublicKey    []byte
	AAGUID       string
	// ClientData is the raw registration response the client posted.
	ClientData map[string]any
	// Context is the `context` query parameter of the options request.
	Context *string
}

// RegistrationResult lets Registration.AfterVerification move the passkey to another user or name it.
type RegistrationResult struct {
	UserID string
	Name   string
}

// AuthenticationVerification carries the verified assertion to Authentication.AfterVerification.
type AuthenticationVerification struct {
	Request      *http.Request
	CredentialID string
	UserID       string
	NewCounter   uint32
	ClientData   map[string]any
}

// ExtensionsFunc returns the WebAuthn extensions to put in generated options (better-auth's extensions callback).
type ExtensionsFunc func(ctx context.Context, req *http.Request) (map[string]any, error)

// RegistrationConfig mirrors better-auth's `registration` option.
type RegistrationConfig struct {
	// RequireSession (default true) requires a fresh session to register a passkey. When false, registration
	// can run without a session for the user returned by ResolveUser (passkey-first sign-up flows).
	RequireSession *bool
	// ResolveUser returns the user to register a passkey for when RequireSession is false and no session exists.
	ResolveUser func(ctx context.Context, in ResolveUserInput) (*RegistrationUser, error)
	// AfterVerification runs after the registration response was verified, before the passkey is stored.
	AfterVerification func(ctx context.Context, v RegistrationVerification) (*RegistrationResult, error)
	// Extensions are added to the registration options (credProps is always requested).
	Extensions map[string]any
	// ExtensionsFunc computes the extensions per request; it wins over Extensions.
	ExtensionsFunc ExtensionsFunc
}

// AuthenticationConfig mirrors better-auth's `authentication` option.
type AuthenticationConfig struct {
	// AfterVerification runs after the assertion was verified; returning an error aborts the sign-in.
	AfterVerification func(ctx context.Context, v AuthenticationVerification) error
	// Extensions are added to the authentication options.
	Extensions map[string]any
	// ExtensionsFunc computes the extensions per request; it wins over Extensions.
	ExtensionsFunc ExtensionsFunc
}

// AdvancedConfig mirrors better-auth's `advanced` option.
type AdvancedConfig struct {
	// WebAuthnChallengeCookie is the base name of the signed challenge cookie (default "better-auth-passkey").
	WebAuthnChallengeCookie string
}

// PasskeyConfig mirrors better-auth's passkey plugin options.
type PasskeyConfig struct {
	// RPID is the relying party ID (default: hostname of AuthConfig.BaseURL, or "localhost").
	RPID string
	// RPName is the relying party name shown by authenticators (default: AuthConfig.AppName).
	RPName string
	// Origin lists the origins the WebAuthn responses must come from (default: the request's Origin header).
	Origin []string
	// AuthenticatorSelection overrides the registration authenticator selection criteria.
	AuthenticatorSelection *AuthenticatorSelection
	Registration           RegistrationConfig
	Authentication         AuthenticationConfig
	Advanced               AdvancedConfig
}

// RequireSession reports whether registration needs a (fresh) session (better-auth default true).
func (c PasskeyConfig) RequireSession() bool {
	return c.Registration.RequireSession == nil || *c.Registration.RequireSession
}

// ChallengeCookie returns the configured challenge cookie base name.
func (c PasskeyConfig) ChallengeCookie() string {
	if c.Advanced.WebAuthnChallengeCookie == "" {
		return DefaultWebAuthnChallengeCookie
	}
	return c.Advanced.WebAuthnChallengeCookie
}

// Bool is a helper for optional boolean options such as Registration.RequireSession.
func Bool(v bool) *bool { return &v }
