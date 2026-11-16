package services

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// Error codes thrown inline by better-auth's social endpoints (not part of BASE_ERROR_CODES, so they are
// built with pluginkit.NewError and never touch the global registry).
var (
	// ErrInvalidIDToken is BASE_ERROR_CODES.INVALID_TOKEN thrown as UNAUTHORIZED by the id_token branches.
	ErrInvalidIDToken = pluginkit.NewError(http.StatusUnauthorized, "INVALID_TOKEN", "Invalid token")
	// ErrLinkingNotAllowed is /link-social's untrusted provider / disabled linking error.
	ErrLinkingNotAllowed = pluginkit.NewError(http.StatusUnauthorized, "LINKING_NOT_ALLOWED", "Account not linked - linking not allowed")
	// ErrLinkingDifferentEmails is /link-social's email mismatch error.
	ErrLinkingDifferentEmails = pluginkit.NewError(http.StatusUnauthorized, "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED", "Account not linked - different emails not allowed")
	// ErrLinkingFailed is /link-social's account creation failure.
	ErrLinkingFailed = pluginkit.NewError(http.StatusExpectationFailed, "LINKING_FAILED", "Account not linked - unable to create account")
	// ErrUnableToCreateVerification is generateState's storage failure.
	ErrUnableToCreateVerification = pluginkit.NewError(http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "Unable to create verification")
	// ErrUserIDOrSessionRequired is resolveUserId's error without session or userId.
	ErrUserIDOrSessionRequired = pluginkit.NewError(http.StatusBadRequest, "USER_ID_OR_SESSION_REQUIRED", "Either userId or session is required")
	// ErrFailedToGetAccessToken wraps any failure of getValidAccessToken.
	ErrFailedToGetAccessToken = pluginkit.NewError(http.StatusBadRequest, "FAILED_TO_GET_ACCESS_TOKEN", "Failed to get a valid access token")
	// ErrRefreshTokenNotFound is /refresh-token on an account without refresh token.
	ErrRefreshTokenNotFound = pluginkit.NewError(http.StatusBadRequest, "REFRESH_TOKEN_NOT_FOUND", "Refresh token not found")
	// ErrFailedToRefreshAccessToken wraps any failure of the provider refresh in /refresh-token.
	ErrFailedToRefreshAccessToken = pluginkit.NewError(http.StatusBadRequest, "FAILED_TO_REFRESH_ACCESS_TOKEN", "Failed to refresh access token")
	// ErrAmbiguousAccount is /account-info when several providers share the account id.
	ErrAmbiguousAccount = pluginkit.NewError(http.StatusBadRequest, "AMBIGUOUS_ACCOUNT", "Multiple accounts share this account ID. Pass a providerId to disambiguate.")
	// ErrProviderNotConfigured is /account-info for an account whose provider is not configured.
	ErrProviderNotConfigured = pluginkit.NewError(http.StatusBadRequest, "PROVIDER_NOT_CONFIGURED", "Account is not associated with a configured social provider.")
	// ErrAccessTokenNotFound is /account-info for an account without access token.
	ErrAccessTokenNotFound = pluginkit.NewError(http.StatusBadRequest, "ACCESS_TOKEN_NOT_FOUND", "Access token not found")
)

// errProviderNotSupported is getValidAccessToken / refresh-token's unknown provider error.
func errProviderNotSupported(providerID string) error {
	return pluginkit.NewError(http.StatusBadRequest, "PROVIDER_NOT_SUPPORTED", "Provider "+providerID+" is not supported.")
}

// errTokenRefreshNotSupported is /refresh-token for a provider without refresh support.
func errTokenRefreshNotSupported(providerID string) error {
	return pluginkit.NewError(http.StatusBadRequest, "TOKEN_REFRESH_NOT_SUPPORTED", "Provider "+providerID+" does not support token refreshing.")
}

// errOAuthLink is the id_token sign-in's wrapper of a handleOAuthUserInfo error.
func errOAuthLink(message string) error {
	return pluginkit.NewError(http.StatusUnauthorized, "OAUTH_LINK_ERROR", message)
}
