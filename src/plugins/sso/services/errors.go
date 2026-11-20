package services

import (
	"net/http"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// apiError is better-auth's `new APIError(status, { message })`: a body with only a message (no code).
func apiError(status int, message string) *autherr.AuthError {
	return pluginkit.NewError(status, "", message)
}

// codedError is `new APIError(status, { message, code })`.
func codedError(status int, code, message string) *autherr.AuthError {
	return pluginkit.NewError(status, code, message)
}

// SAMLErrorCodes are better-auth's SAML_ERROR_CODES (code → message).
var SAMLErrorCodes = map[string]string{
	"SINGLE_LOGOUT_NOT_ENABLED": "Single Logout is not enabled",
	"INVALID_LOGOUT_RESPONSE":   "Invalid LogoutResponse",
	"INVALID_LOGOUT_REQUEST":    "Invalid LogoutRequest",
	"LOGOUT_FAILED_AT_IDP":      "Logout failed at IdP",
	"IDP_SLO_NOT_SUPPORTED":     "IdP does not support Single Logout Service",
	"SAML_PROVIDER_NOT_FOUND":   "SAML provider not found",
}

// samlError is `APIError.from(status, SAML_ERROR_CODES[code])`.
func samlError(status int, code string) *autherr.AuthError {
	return codedError(status, code, SAMLErrorCodes[code])
}

// Errors of the sso endpoints (messages and statuses of @better-auth/sso 1.6.16).
var (
	ErrRegistrationDisabled       = apiError(http.StatusForbidden, "SSO provider registration is disabled")
	ErrProvidersLimitReached      = apiError(http.StatusForbidden, "You have reached the maximum number of SSO providers")
	ErrInvalidIssuer              = apiError(http.StatusBadRequest, "Invalid issuer. Must be a valid URL")
	ErrNotOrganizationMember      = apiError(http.StatusBadRequest, "You are not a member of the organization")
	ErrNotOrganizationAdmin       = apiError(http.StatusForbidden, "You must be an organization owner or admin to register SSO providers")
	ErrReservedProviderID         = apiError(http.StatusUnprocessableEntity, "This providerId is reserved and cannot be used for an SSO provider")
	ErrProviderIDExists           = apiError(http.StatusUnprocessableEntity, "SSO provider with this providerId already exists")
	ErrSAMLEntryPointRequired     = apiError(http.StatusBadRequest, "SAML configuration requires either idpMetadata.metadata (IdP metadata XML), idpMetadata.singleSignOnService, or a valid entryPoint URL")
	ErrSignInTargetRequired       = apiError(http.StatusBadRequest, "email, organizationSlug, domain or providerId is required")
	ErrSignInTargetMissing        = apiError(http.StatusBadRequest, "providerId, orgId or domain is required")
	ErrNoProviderForIssuer        = apiError(http.StatusNotFound, "No provider found for the issuer")
	ErrOIDCNotConfigured          = apiError(http.StatusBadRequest, "OIDC provider is not configured")
	ErrSAMLNotConfigured          = apiError(http.StatusBadRequest, "SAML provider is not configured")
	ErrDomainNotVerified          = apiError(http.StatusUnauthorized, "Provider domain has not been verified")
	ErrAuthorizationURLNotFound   = apiError(http.StatusBadRequest, "Invalid OIDC configuration. Authorization URL not found.")
	ErrInvalidSAMLConfiguration   = apiError(http.StatusBadRequest, "Invalid SAML configuration")
	ErrAuthnRequestsSignedNoKey   = apiError(http.StatusBadRequest, "authnRequestsSigned is enabled but no privateKey provided in spMetadata or samlConfig")
	ErrInvalidSAMLRequest         = apiError(http.StatusBadRequest, "Invalid SAML request")
	ErrInvalidSSOProvider         = apiError(http.StatusBadRequest, "Invalid SSO provider")
	ErrCallbackURLRequired        = apiError(http.StatusBadRequest, "callbackURL is required")
	ErrRelayStateCreate           = apiError(http.StatusInternalServerError, "State error: Unable to create verification for relay state")
	ErrProviderNotFound           = apiError(http.StatusNotFound, "Provider not found")
	ErrProviderNotFoundAfterWrite = apiError(http.StatusNotFound, "Provider not found after update")
	ErrNoProviderAccess           = apiError(http.StatusForbidden, "You don't have access to this provider")
	ErrNoFieldsToUpdate           = apiError(http.StatusBadRequest, "No fields provided for update")
	ErrNoSAMLProviderFound        = apiError(http.StatusNotFound, "No SAML provider found")
	ErrNoProviderForProviderID    = apiError(http.StatusNotFound, "No provider found for the given providerId")
	ErrSAMLResponseRequired       = apiError(http.StatusBadRequest, "SAMLResponse is required for POST requests")
	ErrMissingUserInfoSAML        = apiError(http.StatusBadRequest, "Unable to extract user ID or email from SAML response")

	// Domain verification (codes are better-auth's, including its INSUFICCIENT_ACCESS spelling).
	ErrDomainProviderNotFound   = codedError(http.StatusNotFound, "PROVIDER_NOT_FOUND", "Provider not found")
	ErrDomainInsufficientAccess = codedError(http.StatusForbidden, "INSUFICCIENT_ACCESS", "User must be owner of or belong to the SSO provider organization")
	ErrDomainVerified           = codedError(http.StatusConflict, "DOMAIN_VERIFIED", "Domain has already been verified")
	ErrIdentifierTooLong        = codedError(http.StatusBadRequest, "IDENTIFIER_TOO_LONG", "Verification identifier exceeds the DNS label limit of 63 characters")
	ErrNoPendingVerification    = codedError(http.StatusNotFound, "NO_PENDING_VERIFICATION", "No pending domain verification exists")
	ErrInvalidDomain            = codedError(http.StatusBadRequest, "INVALID_DOMAIN", "Invalid domain")
	ErrDomainVerificationFailed = codedError(http.StatusBadGateway, "DOMAIN_VERIFICATION_FAILED", "Unable to verify domain ownership. Try again later")
)

// errMetadataTooLarge is the idpMetadata size error.
func errMetadataTooLarge(limit int) *autherr.AuthError {
	return apiError(http.StatusBadRequest, "IdP metadata exceeds maximum allowed size ("+itoa(limit)+" bytes)")
}

// errResponseTooLarge is the SAMLResponse size error.
func errResponseTooLarge(limit int) *autherr.AuthError {
	return apiError(http.StatusBadRequest, "SAML response exceeds maximum allowed size ("+itoa(limit)+" bytes)")
}

// errCannotUpdateConfig is parseAndValidateConfig's error.
func errCannotUpdateConfig(kind string) *autherr.AuthError {
	return apiError(http.StatusBadRequest, "Cannot update "+kind+" config for a provider that doesn't have "+kind+" configured")
}
