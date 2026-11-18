package humapasskey

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/danielgtaylor/huma/v2"
)

// SetupRoutes registers better-auth's passkey endpoints. requireSession mirrors
// registration.requireSession: registration then runs behind the fresh-session middleware.
func SetupRoutes(api huma.API, kit *pluginkit.Kit, h *Handler, requireSession bool) {
	// Step 1: registration needs a fresh session unless passkey-first registration is enabled
	regAccess := pluginkit.FreshSession
	if !requireSession {
		regAccess = pluginkit.OptionalSession
	}
	tags := []string{"passkey"}

	// Step 2: ceremony endpoints
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: "generatePasskeyRegistrationOptions", Method: http.MethodGet, Path: "/passkey/generate-register-options",
		Summary: "Generate registration options for a new passkey", Tags: tags, Access: regAccess, ValidateFirst: true,
	}, h.GenerateRegisterOptions)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: "passkeyGenerateAuthenticateOptions", Method: http.MethodGet, Path: "/passkey/generate-authenticate-options",
		Summary: "Generate authentication options for a passkey", Tags: tags, Access: pluginkit.OptionalSession,
	}, h.GenerateAuthenticateOptions)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: "passkeyVerifyRegistration", Method: http.MethodPost, Path: "/passkey/verify-registration",
		Summary: "Verify registration of a new passkey", Tags: tags, Access: regAccess, ValidateFirst: true,
	}, h.VerifyRegistration)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: "passkeyVerifyAuthentication", Method: http.MethodPost, Path: "/passkey/verify-authentication",
		Summary: "Verify authentication of a passkey", Tags: tags, Access: pluginkit.Public,
	}, h.VerifyAuthentication)

	// Step 3: management endpoints (session required)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: "listPasskeys", Method: http.MethodGet, Path: "/passkey/list-user-passkeys",
		Summary: "List all passkeys for the authenticated user", Tags: tags, Access: pluginkit.Session,
	}, h.ListUserPasskeys)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: "deletePasskey", Method: http.MethodPost, Path: "/passkey/delete-passkey",
		Summary: "Delete a specific passkey", Tags: tags, Access: pluginkit.Session, ValidateFirst: true,
	}, h.DeletePasskey)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: "updatePasskey", Method: http.MethodPost, Path: "/passkey/update-passkey",
		Summary: "Update a specific passkey's name", Tags: tags, Access: pluginkit.Session, ValidateFirst: true,
	}, h.UpdatePasskey)
}
