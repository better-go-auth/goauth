package humamultisession

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/danielgtaylor/huma/v2"
)

// Operation IDs (better-auth's endpoint keys), usable in AuthConfig.DisabledOps.
const (
	OpListDeviceSessions  = "listDeviceSessions"
	OpSetActiveSession    = "setActiveSession"
	OpRevokeDeviceSession = "revokeDeviceSession"
)

// RegisterRoutes mounts the multi-session endpoints under the kit's base path.
func RegisterRoutes(api huma.API, kit *pluginkit.Kit, h *Handler) {
	tags := []string{"multi-session"}
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpListDeviceSessions, Method: http.MethodGet, Path: "/multi-session/list-device-sessions",
		Summary: "List the device's sessions", Tags: tags, Access: pluginkit.Public,
	}, h.ListDeviceSessions)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpSetActiveSession, Method: http.MethodPost, Path: "/multi-session/set-active",
		Summary: "Set the active session", Tags: tags, Access: pluginkit.Public,
	}, h.SetActive)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpRevokeDeviceSession, Method: http.MethodPost, Path: "/multi-session/revoke",
		Summary: "Revoke a device session", Tags: tags, Access: pluginkit.Session,
	}, h.Revoke)
}
