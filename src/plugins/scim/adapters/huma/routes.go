package humascim

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/danielgtaylor/huma/v2"
)

// Operation IDs (better-auth's openapi operationId, else the endpoint key).
const (
	OpGenerateSCIMToken            = "generateSCIMToken"
	OpListSCIMProviderConnections  = "listSCIMProviderConnections"
	OpGetSCIMProviderConnection    = "getSCIMProviderConnection"
	OpDeleteSCIMProviderConnection = "deleteSCIMProviderConnection"
	OpCreateSCIMUser               = "createSCIMUser"
	OpListSCIMUsers                = "listSCIMUsers"
	OpGetSCIMUser                  = "getSCIMUser"
	OpUpdateSCIMUser               = "updateSCIMUser"
	OpPatchSCIMUser                = "patchSCIMUser"
	OpDeleteSCIMUser               = "deleteSCIMUser"
	OpGetSCIMServiceProviderConfig = "getSCIMServiceProviderConfig"
	OpGetSCIMSchemas               = "getSCIMSchemas"
	OpGetSCIMSchema                = "getSCIMSchema"
	OpGetSCIMResourceTypes         = "getSCIMResourceTypes"
	OpGetSCIMResourceType          = "getSCIMResourceType"
)

// Register mounts the scim endpoints. The /scim/v2 endpoints authenticate with the SCIM bearer token, are
// called server to server by identity providers and are hidden from the OpenAPI document
// like better-auth's HIDE_METADATA.
func Register(kit *pluginkit.Kit, api huma.API, h *Handler) {
	tags := []string{"scim"}

	// Step 1: provider connection management (session)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpGenerateSCIMToken, Method: http.MethodPost, Path: "/scim/generate-token",
		Summary: "Generates a new SCIM token for the given provider", Tags: tags, Access: pluginkit.Session, ValidateFirst: true,
	}, h.GenerateToken)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpListSCIMProviderConnections, Method: http.MethodGet, Path: "/scim/list-provider-connections",
		Summary: "List SCIM providers", Tags: tags, Access: pluginkit.Session,
	}, h.ListConnections)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpGetSCIMProviderConnection, Method: http.MethodGet, Path: "/scim/get-provider-connection",
		Summary: "Get SCIM provider details", Tags: tags, Access: pluginkit.Session, ValidateFirst: true,
	}, h.GetConnection)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpDeleteSCIMProviderConnection, Method: http.MethodPost, Path: "/scim/delete-provider-connection",
		Summary: "Delete SCIM provider", Tags: tags, Access: pluginkit.Session, ValidateFirst: true,
	}, h.DeleteConnection)

	// Step 2: SCIM users (bearer SCIM token)
	user := func(op, method, path, summary string) pluginkit.Route {
		return pluginkit.Route{OperationID: op, Method: method, Path: path, Summary: summary, Tags: tags, Access: pluginkit.Public, Hidden: true}
	}
	pluginkit.Register(kit, api, user(OpCreateSCIMUser, http.MethodPost, "/scim/v2/Users", "Create SCIM user."), h.CreateUser)
	pluginkit.Register(kit, api, user(OpListSCIMUsers, http.MethodGet, "/scim/v2/Users", "List SCIM users"), h.ListUsers)
	pluginkit.Register(kit, api, user(OpGetSCIMUser, http.MethodGet, "/scim/v2/Users/{userId}", "Get SCIM user details"), h.GetUser)
	pluginkit.Register(kit, api, user(OpUpdateSCIMUser, http.MethodPut, "/scim/v2/Users/{userId}", "Update SCIM user."), h.UpdateUser)
	pluginkit.Register(kit, api, user(OpPatchSCIMUser, http.MethodPatch, "/scim/v2/Users/{userId}", "Patch SCIM user"), h.PatchUser)
	pluginkit.Register(kit, api, user(OpDeleteSCIMUser, http.MethodDelete, "/scim/v2/Users/{userId}", "Delete SCIM user"), h.DeleteUser)

	// Step 3: SCIM metadata (public)
	pluginkit.Register(kit, api, user(OpGetSCIMServiceProviderConfig, http.MethodGet, "/scim/v2/ServiceProviderConfig", "SCIM Service Provider Configuration"), h.ServiceProviderConfig)
	pluginkit.Register(kit, api, user(OpGetSCIMSchemas, http.MethodGet, "/scim/v2/Schemas", "SCIM Service Provider Configuration Schemas"), h.Schemas)
	pluginkit.Register(kit, api, user(OpGetSCIMSchema, http.MethodGet, "/scim/v2/Schemas/{schemaId}", "SCIM a Service Provider Configuration Schema"), h.Schema)
	pluginkit.Register(kit, api, user(OpGetSCIMResourceTypes, http.MethodGet, "/scim/v2/ResourceTypes", "SCIM Service Provider Supported Resource Types"), h.ResourceTypes)
	pluginkit.Register(kit, api, user(OpGetSCIMResourceType, http.MethodGet, "/scim/v2/ResourceTypes/{resourceTypeId}", "SCIM Service Provider Supported Resource Type"), h.ResourceType)
}
