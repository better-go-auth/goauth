package services

import (
	"net/http"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// ErrorCodes are better-auth's GENERIC_OAUTH_ERROR_CODES (code → message).
var ErrorCodes = map[string]string{
	"INVALID_OAUTH_CONFIGURATION": "Invalid OAuth configuration",
	"TOKEN_URL_NOT_FOUND":         "Invalid OAuth configuration. Token URL not found.",
	"PROVIDER_CONFIG_NOT_FOUND":   "No config found for provider",
	"PROVIDER_ID_REQUIRED":        "Provider ID is required",
	"INVALID_OAUTH_CONFIG":        "Invalid OAuth configuration.",
	"SESSION_REQUIRED":            "Session is required",
	"ISSUER_MISMATCH":             "OAuth issuer mismatch. The authorization server issuer does not match the expected value (RFC 9207).",
	"ISSUER_MISSING":              "OAuth issuer parameter missing. The authorization server did not include the required iss parameter (RFC 9207).",
}

func codeErr(status int, code string) *autherr.AuthError {
	return pluginkit.NewError(status, code, ErrorCodes[code])
}

var (
	// ErrInvalidOAuthConfiguration is thrown when no authorization (or token) endpoint can be resolved.
	ErrInvalidOAuthConfiguration = codeErr(http.StatusBadRequest, "INVALID_OAUTH_CONFIGURATION")
	// ErrProviderIDRequired is thrown by the callback without provider id.
	ErrProviderIDRequired = codeErr(http.StatusBadRequest, "PROVIDER_ID_REQUIRED")
	// ErrSessionRequired is thrown by /oauth2/link without session.
	ErrSessionRequired = codeErr(http.StatusUnauthorized, "SESSION_REQUIRED")
)

// errProviderConfigNotFound is better-auth's `${PROVIDER_CONFIG_NOT_FOUND} ${providerId}` (400).
func errProviderConfigNotFound(providerID string) error {
	return pluginkit.NewError(http.StatusBadRequest, "PROVIDER_CONFIG_NOT_FOUND", ErrorCodes["PROVIDER_CONFIG_NOT_FOUND"]+" "+providerID)
}
