package humasiwe

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/danielgtaylor/huma/v2"
)

// Operation IDs (better-auth's endpoint keys), usable in AuthConfig.DisabledOps.
const (
	OpGetSiweNonce      = "getSiweNonce"
	OpGetNonce          = "getNonce"
	OpVerifySiweMessage = "verifySiweMessage"
)

// RegisterRoutes mounts the siwe endpoints under the kit's base path.
func RegisterRoutes(api huma.API, kit *pluginkit.Kit, h *Handler) {
	tags := []string{"siwe"}
	// Step 1: the nonce endpoint and its alias
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpGetSiweNonce, Method: http.MethodPost, Path: "/siwe/nonce",
		Summary: "Get a SIWE nonce for a wallet address", Tags: tags, Access: pluginkit.Public,
	}, h.Nonce)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpGetNonce, Method: http.MethodPost, Path: "/siwe/get-nonce",
		Summary: "Get a SIWE nonce for a wallet address (alias of /siwe/nonce)", Tags: tags, Access: pluginkit.Public,
	}, h.Nonce)
	// Step 2: the sign-in (sign-in CSRF checks, like /sign-in/email)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpVerifySiweMessage, Method: http.MethodPost, Path: "/siwe/verify",
		Summary: "Verify a signed SIWE message and sign in", Tags: tags, Access: pluginkit.Form,
	}, h.Verify)
}
