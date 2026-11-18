package humasso

import (
	"net/http"
	"time"

	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
	"github.com/danielgtaylor/huma/v2"
)

// Operation IDs (better-auth's openapi operationId, else the endpoint key).
const (
	OpSPMetadata                = "getSSOServiceProviderMetadata"
	OpRegisterSSOProvider       = "registerSSOProvider"
	OpSignInWithSSO             = "signInWithSSO"
	OpHandleSSOCallback         = "handleSSOCallback"
	OpHandleSSOCallbackShared   = "handleSSOCallbackShared"
	OpHandleSAMLCallback        = "handleSAMLCallback"
	OpHandleSAMLCallbackGet     = "handleSAMLCallbackGet"
	OpHandleSAMLACS             = "handleSAMLAssertionConsumerService"
	OpSLOEndpoint               = "sloEndpoint"
	OpSLOEndpointGet            = "sloEndpointGet"
	OpInitiateSLO               = "initiateSLO"
	OpListSSOProviders          = "listSSOProviders"
	OpGetSSOProvider            = "getSSOProvider"
	OpUpdateSSOProvider         = "updateSSOProvider"
	OpDeleteSSOProvider         = "deleteSSOProvider"
	OpRequestDomainVerification = "requestDomainVerification"
	OpVerifyDomain              = "verifyDomain"
)

// Register mounts the sso endpoints. The domain verification endpoints exist only with domain verification
// enabled. The SAML endpoints receive cross-site POSTs from the IdP, so they skip the origin check (better-auth's
// skipOriginCheck paths).
func Register(kit *pluginkit.Kit, api huma.API, h *Handler, domainVerification bool) {
	tags := []string{"sso"}
	// better-auth's default special rule for /sign-in/*: 3 requests per 10 seconds
	signInLimit := &ratelimit.Rule{Window: 10 * time.Second, Max: 3}

	// Step 1: metadata, registration and sign-in
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpSPMetadata, Method: http.MethodGet, Path: "/sso/saml2/sp/metadata",
		Summary: "Get Service Provider metadata", Tags: tags, Access: pluginkit.Public,
	}, h.SPMetadata)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpRegisterSSOProvider, Method: http.MethodPost, Path: "/sso/register",
		Summary: "Register an OIDC provider", Tags: tags, Access: pluginkit.Session, ValidateFirst: true,
	}, h.Register)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpSignInWithSSO, Method: http.MethodPost, Path: "/sign-in/sso",
		Summary: "Sign in with SSO provider", Tags: tags, Access: pluginkit.Public, RateLimit: signInLimit,
	}, h.SignIn)

	// Step 2: OIDC callbacks
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpHandleSSOCallback, Method: http.MethodGet, Path: "/sso/callback/{providerId}",
		Summary: "Callback URL for SSO provider", Tags: tags, Access: pluginkit.Public, SkipOriginCheck: true, Hidden: true,
	}, h.Callback)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpHandleSSOCallbackShared, Method: http.MethodGet, Path: "/sso/callback",
		Summary: "Shared callback URL for all SSO providers", Tags: tags, Access: pluginkit.Public, SkipOriginCheck: true, Hidden: true,
	}, h.CallbackShared)

	// Step 3: SAML callback, ACS and Single Logout
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpHandleSAMLCallbackGet, Method: http.MethodGet, Path: "/sso/saml2/callback/{providerId}",
		Summary: "Callback URL for SAML provider", Tags: tags, Access: pluginkit.OptionalSession, SkipOriginCheck: true, Hidden: true,
	}, h.SAMLCallbackGet)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpHandleSAMLCallback, Method: http.MethodPost, Path: "/sso/saml2/callback/{providerId}",
		Summary: "Callback URL for SAML provider", Tags: tags, Access: pluginkit.Public, SkipOriginCheck: true, Hidden: true,
	}, h.SAMLCallbackPost)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpHandleSAMLACS, Method: http.MethodPost, Path: "/sso/saml2/sp/acs/{providerId}",
		Summary: "SAML Assertion Consumer Service", Tags: tags, Access: pluginkit.Public, SkipOriginCheck: true, Hidden: true,
	}, h.ACS)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpSLOEndpointGet, Method: http.MethodGet, Path: "/sso/saml2/sp/slo/{providerId}",
		Summary: "SAML Single Logout", Tags: tags, Access: pluginkit.OptionalSession, SkipOriginCheck: true, Hidden: true,
	}, h.SLOGet)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpSLOEndpoint, Method: http.MethodPost, Path: "/sso/saml2/sp/slo/{providerId}",
		Summary: "SAML Single Logout", Tags: tags, Access: pluginkit.OptionalSession, SkipOriginCheck: true, Hidden: true,
	}, h.SLO)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpInitiateSLO, Method: http.MethodPost, Path: "/sso/saml2/logout/{providerId}",
		Summary: "Start SAML Single Logout", Tags: tags, Access: pluginkit.Session, Hidden: true,
	}, h.InitiateSLO)

	// Step 4: provider management
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpListSSOProviders, Method: http.MethodGet, Path: "/sso/providers",
		Summary: "List SSO providers", Tags: tags, Access: pluginkit.Session,
	}, h.ListProviders)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpGetSSOProvider, Method: http.MethodGet, Path: "/sso/get-provider",
		Summary: "Get SSO provider details", Tags: tags, Access: pluginkit.Session, ValidateFirst: true,
	}, h.GetProvider)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpUpdateSSOProvider, Method: http.MethodPost, Path: "/sso/update-provider",
		Summary: "Update SSO provider", Tags: tags, Access: pluginkit.Session, ValidateFirst: true,
	}, h.UpdateProvider)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpDeleteSSOProvider, Method: http.MethodPost, Path: "/sso/delete-provider",
		Summary: "Delete SSO provider", Tags: tags, Access: pluginkit.Session, ValidateFirst: true,
	}, h.DeleteProvider)

	// Step 5: domain verification
	if domainVerification {
		pluginkit.Register(kit, api, pluginkit.Route{
			OperationID: OpRequestDomainVerification, Method: http.MethodPost, Path: "/sso/request-domain-verification",
			Summary: "Request a domain verification", Tags: tags, Access: pluginkit.Session, ValidateFirst: true,
		}, h.RequestDomainVerification)
		pluginkit.Register(kit, api, pluginkit.Route{
			OperationID: OpVerifyDomain, Method: http.MethodPost, Path: "/sso/verify-domain",
			Summary: "Verify the provider domain ownership", Tags: tags, Access: pluginkit.Session, ValidateFirst: true,
		}, h.VerifyDomain)
	}
}
