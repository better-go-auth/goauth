// Package config holds the options of the siwe plugin (better-auth's SIWEPluginOptions).
package config

import (
	"context"
	"time"

	"github.com/better-go-auth/goauth/src/plugins/siwe/eip4361"
)

// NonceTTL is how long a nonce from /siwe/nonce is valid (better-auth: 15 minutes).
const NonceTTL = 15 * time.Minute

// VerifyMessageArgs are the arguments of VerifyMessage (better-auth's SIWEVerifyMessageArgs).
type VerifyMessageArgs = eip4361.VerifyArgs

// Cacao is the CAIP-74 object in VerifyMessageArgs.
type Cacao = eip4361.Cacao

// GetNonceFunc returns a new nonce (EIP-4361: at least 8 alphanumeric characters).
type GetNonceFunc func(ctx context.Context) (string, error)

// VerifyMessageFunc reports whether a signed SIWE message is valid. An error is reported to the client as
// better-auth's 401 "Something went wrong. Please try again later." (with the error text).
type VerifyMessageFunc func(ctx context.Context, args VerifyMessageArgs) (bool, error)

// ENSLookupArgs are the arguments of ENSLookup.
type ENSLookupArgs struct {
	WalletAddress string `json:"walletAddress"`
}

// ENSLookupResult is the ENS name and avatar used for a new user's name and image.
type ENSLookupResult struct {
	Name   string `json:"name"`
	Avatar string `json:"avatar"`
}

// ENSLookupFunc resolves a wallet's ENS name and avatar (nil result = none).
type ENSLookupFunc func(ctx context.Context, args ENSLookupArgs) (*ENSLookupResult, error)

// SIWEConfig holds the options of the siwe plugin.
type SIWEConfig struct {
	// Domain is the RFC 3986 authority the SIWE messages must be issued for ("example.com",
	// "localhost:3000"); it is compared without scheme, path and case. Empty = the host of the configured
	// BaseURL (better-auth requires it).
	Domain string
	// EmailDomainName is the domain of the placeholder email of new users ("<address>@<EmailDomainName>").
	// Empty = the origin of the base URL, like better-auth ("<address>@http://localhost:3000").
	EmailDomainName string
	// Anonymous allows sign-ins without an email (default true). With false, /siwe/verify requires email.
	Anonymous *bool
	// GetNonce generates nonces. Default: 32 random alphanumeric characters (better-auth requires it).
	GetNonce GetNonceFunc
	// VerifyMessage checks the signed message. Default: eip4361.Verify, which parses the EIP-4361 message
	// and recovers the EIP-191 personal_sign signer with secp256k1 (externally owned accounts only;
	// smart-contract wallets need an EIP-1271 verifier that calls the chain). better-auth requires it.
	VerifyMessage VerifyMessageFunc
	// ENSLookup resolves the name and avatar of new users.
	ENSLookup ENSLookupFunc
	// ModelName renames the walletAddress table (better-auth's schema.walletAddress.modelName).
	ModelName string
	// FieldNames renames columns of the walletAddress table: logical field name → column.
	FieldNames map[string]string
}

// IsAnonymous reports whether sign-ins without an email are allowed (default true).
func (c SIWEConfig) IsAnonymous() bool { return c.Anonymous == nil || *c.Anonymous }
