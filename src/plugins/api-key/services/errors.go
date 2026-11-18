package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// ErrorCodes are @better-auth/api-key's API_KEY_ERROR_CODES (code → message).
var ErrorCodes = map[string]string{
	"INVALID_METADATA_TYPE":                  "metadata must be an object or undefined",
	"REFILL_AMOUNT_AND_INTERVAL_REQUIRED":    "refillAmount is required when refillInterval is provided",
	"REFILL_INTERVAL_AND_AMOUNT_REQUIRED":    "refillInterval is required when refillAmount is provided",
	"USER_BANNED":                            "User is banned",
	"UNAUTHORIZED_SESSION":                   "Unauthorized or invalid session",
	"KEY_NOT_FOUND":                          "API Key not found",
	"KEY_DISABLED":                           "API Key is disabled",
	"KEY_EXPIRED":                            "API Key has expired",
	"USAGE_EXCEEDED":                         "API Key has reached its usage limit",
	"KEY_NOT_RECOVERABLE":                    "API Key is not recoverable",
	"EXPIRES_IN_IS_TOO_SMALL":                "The expiresIn is smaller than the predefined minimum value.",
	"EXPIRES_IN_IS_TOO_LARGE":                "The expiresIn is larger than the predefined maximum value.",
	"INVALID_REMAINING":                      "The remaining count is either too large or too small.",
	"INVALID_PREFIX_LENGTH":                  "The prefix length is either too large or too small.",
	"INVALID_NAME_LENGTH":                    "The name length is either too large or too small.",
	"METADATA_DISABLED":                      "Metadata is disabled.",
	"RATE_LIMIT_EXCEEDED":                    "Rate limit exceeded.",
	"NO_VALUES_TO_UPDATE":                    "No values to update.",
	"KEY_DISABLED_EXPIRATION":                "Custom key expiration values are disabled.",
	"INVALID_API_KEY":                        "Invalid API key.",
	"INVALID_USER_ID_FROM_API_KEY":           "The user id from the API key is invalid.",
	"INVALID_REFERENCE_ID_FROM_API_KEY":      "The reference id from the API key is invalid.",
	"INVALID_API_KEY_GETTER_RETURN_TYPE":     "API Key getter returned an invalid key type. Expected string.",
	"SERVER_ONLY_PROPERTY":                   "The property you're trying to set can only be set from the server auth instance only.",
	"FAILED_TO_UPDATE_API_KEY":               "Failed to update API key",
	"NAME_REQUIRED":                          "API Key name is required.",
	"ORGANIZATION_ID_REQUIRED":               "Organization ID is required for organization-owned API keys.",
	"USER_NOT_MEMBER_OF_ORGANIZATION":        "You are not a member of the organization that owns this API key.",
	"INSUFFICIENT_API_KEY_PERMISSIONS":       "You do not have permission to perform this action on organization API keys.",
	"NO_DEFAULT_API_KEY_CONFIGURATION_FOUND": "No default api-key configuration found.",
	"ORGANIZATION_PLUGIN_REQUIRED":           "Organization plugin is required for organization-owned API keys. Please install and configure the organization plugin.",
}

// apiKeyErr builds a plugin error with this plugin's message for code (better-auth's APIError.from).
func apiKeyErr(status int, code string) *autherr.AuthError {
	return pluginkit.NewError(status, code, ErrorCodes[code])
}

// Errors with the HTTP status better-auth throws them with. Some codes are thrown with several statuses
// (e.g. KEY_NOT_FOUND: 404 on get/update/delete, 401 from verify); use WithStatus for the others.
var (
	ErrInvalidMetadataType           = apiKeyErr(http.StatusBadRequest, "INVALID_METADATA_TYPE")
	ErrRefillAmountAndIntervalReq    = apiKeyErr(http.StatusBadRequest, "REFILL_AMOUNT_AND_INTERVAL_REQUIRED")
	ErrRefillIntervalAndAmountReq    = apiKeyErr(http.StatusBadRequest, "REFILL_INTERVAL_AND_AMOUNT_REQUIRED")
	ErrUserBanned                    = apiKeyErr(http.StatusUnauthorized, "USER_BANNED")
	ErrUnauthorizedSession           = apiKeyErr(http.StatusUnauthorized, "UNAUTHORIZED_SESSION")
	ErrKeyNotFound                   = apiKeyErr(http.StatusNotFound, "KEY_NOT_FOUND")
	ErrKeyDisabled                   = apiKeyErr(http.StatusUnauthorized, "KEY_DISABLED")
	ErrKeyExpired                    = apiKeyErr(http.StatusUnauthorized, "KEY_EXPIRED")
	ErrUsageExceeded                 = apiKeyErr(http.StatusTooManyRequests, "USAGE_EXCEEDED")
	ErrExpiresInTooSmall             = apiKeyErr(http.StatusBadRequest, "EXPIRES_IN_IS_TOO_SMALL")
	ErrExpiresInTooLarge             = apiKeyErr(http.StatusBadRequest, "EXPIRES_IN_IS_TOO_LARGE")
	ErrInvalidPrefixLength           = apiKeyErr(http.StatusBadRequest, "INVALID_PREFIX_LENGTH")
	ErrInvalidNameLength             = apiKeyErr(http.StatusBadRequest, "INVALID_NAME_LENGTH")
	ErrMetadataDisabled              = apiKeyErr(http.StatusBadRequest, "METADATA_DISABLED")
	ErrNoValuesToUpdate              = apiKeyErr(http.StatusBadRequest, "NO_VALUES_TO_UPDATE")
	ErrKeyDisabledExpiration         = apiKeyErr(http.StatusBadRequest, "KEY_DISABLED_EXPIRATION")
	ErrInvalidAPIKey                 = apiKeyErr(http.StatusUnauthorized, "INVALID_API_KEY")
	ErrInvalidReferenceIDFromAPIKey  = apiKeyErr(http.StatusUnauthorized, "INVALID_REFERENCE_ID_FROM_API_KEY")
	ErrServerOnlyProperty            = apiKeyErr(http.StatusBadRequest, "SERVER_ONLY_PROPERTY")
	ErrFailedToUpdateAPIKey          = apiKeyErr(http.StatusInternalServerError, "FAILED_TO_UPDATE_API_KEY")
	ErrNameRequired                  = apiKeyErr(http.StatusBadRequest, "NAME_REQUIRED")
	ErrOrganizationIDRequired        = apiKeyErr(http.StatusBadRequest, "ORGANIZATION_ID_REQUIRED")
	ErrUserNotMemberOfOrganization   = apiKeyErr(http.StatusForbidden, "USER_NOT_MEMBER_OF_ORGANIZATION")
	ErrInsufficientAPIKeyPermissions = apiKeyErr(http.StatusForbidden, "INSUFFICIENT_API_KEY_PERMISSIONS")
	ErrNoDefaultConfigurationFound   = apiKeyErr(http.StatusBadRequest, "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND")
	ErrOrganizationPluginRequired    = apiKeyErr(http.StatusInternalServerError, "ORGANIZATION_PLUGIN_REQUIRED")
)

// RateLimitedCode is the code of the per-key rate-limit error (better-auth throws it with code
// "RATE_LIMITED", not RATE_LIMIT_EXCEEDED, and the message of RATE_LIMIT_EXCEEDED).
const RateLimitedCode = "RATE_LIMITED"

// RateLimitedError is better-auth's per-key rate-limit error: 429 with
// {"message":"Rate limit exceeded.","code":"RATE_LIMITED","details":{"tryAgainIn":<ms>}}.
type RateLimitedError struct {
	// TryAgainIn is the number of milliseconds until the window resets.
	TryAgainIn int64
}

// Error implements error.
func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("[%s] %s (try again in %d ms)", RateLimitedCode, ErrorCodes["RATE_LIMIT_EXCEEDED"], e.TryAgainIn)
}

// GetStatus implements huma.StatusError (429).
func (e *RateLimitedError) GetStatus() int { return http.StatusTooManyRequests }

// MarshalJSON writes better-auth's body.
func (e *RateLimitedError) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.Body())
}

// Body returns the error body as better-auth sends it.
func (e *RateLimitedError) Body() map[string]any {
	return map[string]any{
		"message": ErrorCodes["RATE_LIMIT_EXCEEDED"],
		"code":    RateLimitedCode,
		"details": map[string]any{"tryAgainIn": e.TryAgainIn},
	}
}

// ErrorBody returns the JSON body (and status) of an error as better-auth sends it: {code, message} for
// API errors, the details body for RATE_LIMITED. Other errors are not API errors (ok=false).
func ErrorBody(err error) (body map[string]any, status int, ok bool) {
	var rl *RateLimitedError
	if errors.As(err, &rl) {
		return rl.Body(), rl.GetStatus(), true
	}
	if ae := autherr.AsAuthError(err); ae != nil {
		b := map[string]any{"message": ae.Message}
		if ae.Code != "" {
			b["code"] = string(ae.Code)
		}
		return b, ae.StatusCode, true
	}
	return nil, 0, false
}
