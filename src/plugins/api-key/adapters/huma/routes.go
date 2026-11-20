package humaapikey

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/danielgtaylor/huma/v2"
)

// Operation IDs (better-auth's endpoint keys), usable in AuthConfig.DisabledOps.
const (
	OpCreateAPIKey = "createApiKey"
	OpGetAPIKey    = "getApiKey"
	OpUpdateAPIKey = "updateApiKey"
	OpDeleteAPIKey = "deleteApiKey"
	OpListAPIKeys  = "listApiKeys"
)

// RegisterRoutes mounts the api-key endpoints under the kit's base path. create and update resolve the
// session themselves (server-only fields and the owner rules depend on it); get, delete and list require
// one (better-auth's sessionMiddleware, after body / query validation).
func RegisterRoutes(api huma.API, kit *pluginkit.Kit, h *Handler) {
	tags := []string{"api-key"}
	// Step 1: create and update (session optional at the route level)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpCreateAPIKey, Method: http.MethodPost, Path: "/api-key/create",
		Summary: "Create a new API key for a user", Tags: tags, Access: pluginkit.Public,
	}, h.Create)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpUpdateAPIKey, Method: http.MethodPost, Path: "/api-key/update",
		Summary: "Update an existing API key by ID", Tags: tags, Access: pluginkit.Public,
	}, h.Update)
	// Step 2: read, delete and list (session required)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpGetAPIKey, Method: http.MethodGet, Path: "/api-key/get",
		Summary: "Retrieve an existing API key by ID", Tags: tags, Access: pluginkit.Session, ValidateFirst: true,
	}, h.Get)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpDeleteAPIKey, Method: http.MethodPost, Path: "/api-key/delete",
		Summary: "Delete an existing API key", Tags: tags, Access: pluginkit.Session, ValidateFirst: true,
	}, h.Delete)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpListAPIKeys, Method: http.MethodGet, Path: "/api-key/list",
		Summary: "List all API keys for the authenticated user or for a specific organization", Tags: tags,
		Access: pluginkit.Session, ValidateFirst: true,
	}, h.List)
}
