// Package config holds the options of the scim plugin (better-auth's SCIMOptions, @better-auth/scim 1.6.16).
package config

import (
	"context"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins"
)

// Provider is a SCIM provider connection (better-auth's SCIMProvider): a stored scimProvider row or a
// DefaultSCIM entry.
type Provider struct {
	ID             string
	ProviderID     string
	OrganizationID string
	// SCIMToken is the stored token (plain, hashed or encrypted per StoreSCIMToken; plain for DefaultSCIM).
	SCIMToken string
	// UserID is the owner when ProviderOwnership is enabled.
	UserID string
}

// LinkExistingUsers is better-auth's linkExistingUsers object form: every constraint set must pass.
type LinkExistingUsers struct {
	// All links any existing user that matches by email (better-auth's `true`).
	All bool
	// TrustedDomains links only emails of these domains (case-insensitive).
	TrustedDomains []string
	// RequireExistingOrgMembership links only users already in the token's organization.
	RequireExistingOrgMembership bool
	// ShouldLinkUser decides per user.
	ShouldLinkUser func(ctx context.Context, data LinkUserData) (bool, error)
}

// LinkUserData is passed to ShouldLinkUser.
type LinkUserData struct {
	User     *models.User
	Email    string
	Provider Provider
}

// TokenPayload is passed to BeforeSCIMTokenGenerated / AfterSCIMTokenGenerated.
type TokenPayload struct {
	// User is the session user generating the token.
	User *models.User
	// Member is the user's membership of the token's organization (nil for personal tokens).
	Member *plugins.OrganizationMember
	// SCIMToken is the token returned to the client.
	SCIMToken string
	// Provider is the stored provider (AfterSCIMTokenGenerated only).
	Provider *Provider
}

// CanGenerateTokenData is passed to CanGenerateToken.
type CanGenerateTokenData struct {
	User           *models.User
	ProviderID     string
	OrganizationID string
	Member         *plugins.OrganizationMember
}

// TokenStorage is better-auth's storeSCIMToken: "plain" (default), "hashed" (SHA-256, base64url),
// "encrypted" (the auth secret) or custom functions.
type TokenStorage struct {
	// Mode is "plain", "hashed" or "encrypted" (ignored when Hash or Encrypt is set).
	Mode string
	// Hash stores hash(token) and compares hashes.
	Hash func(token string) (string, error)
	// Encrypt / Decrypt store an encrypted token and compare the decrypted one.
	Encrypt func(token string) (string, error)
	Decrypt func(stored string) (string, error)
}

// Storage modes of TokenStorage.Mode.
const (
	StorePlain     = "plain"
	StoreHashed    = "hashed"
	StoreEncrypted = "encrypted"
)

// SCIMConfig mirrors better-auth's SCIMOptions.
type SCIMConfig struct {
	// ProviderOwnership links each provider connection to the user who generated its token (userId column).
	ProviderOwnership bool
	// RequiredRole are the organization roles allowed to manage SCIM connections (default
	// ["admin", organization creatorRole or "owner"]).
	RequiredRole []string
	// DefaultSCIM are provider connections configured in code (they win over the database).
	DefaultSCIM []Provider
	// LinkExistingUsers allows SCIM provisioning to attach to a pre-existing user with the same email
	// (nil: such users are a 409 conflict).
	LinkExistingUsers *LinkExistingUsers
	// BeforeSCIMTokenGenerated runs before a token is stored (after the role checks).
	BeforeSCIMTokenGenerated func(ctx context.Context, p TokenPayload) error
	// AfterSCIMTokenGenerated runs after the token is stored.
	AfterSCIMTokenGenerated func(ctx context.Context, p TokenPayload) error
	// CanGenerateToken may refuse token generation (it cannot loosen the built-in checks).
	CanGenerateToken func(ctx context.Context, d CanGenerateTokenData) (bool, error)
	// StoreSCIMToken selects how tokens are stored (default plain).
	StoreSCIMToken TokenStorage
}

// WithDefaults returns cfg with better-auth's defaults.
func (cfg SCIMConfig) WithDefaults() SCIMConfig {
	if cfg.StoreSCIMToken.Mode == "" {
		cfg.StoreSCIMToken.Mode = StorePlain
	}
	return cfg
}
