package humadevice

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/danielgtaylor/huma/v2"
)

// Operation IDs (better-auth's endpoint keys), usable in AuthConfig.DisabledOps.
const (
	OpDeviceCode    = "deviceCode"
	OpDeviceToken   = "deviceToken"
	OpDeviceVerify  = "deviceVerify"
	OpDeviceApprove = "deviceApprove"
	OpDeviceDeny    = "deviceDeny"
)

// RegisterRoutes mounts the device-authorization endpoints under the kit's base path.
func RegisterRoutes(api huma.API, kit *pluginkit.Kit, h *Handler) {
	tags := []string{"device-authorization"}
	// Step 1: the device's endpoints (no session; RFC 8628 clients may post forms)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpDeviceCode, Method: http.MethodPost, Path: "/device/code",
		Summary: "Request a device and user code (RFC 8628 §3.2)", Tags: tags, Access: pluginkit.Public, AcceptForm: true,
	}, h.DeviceCode)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpDeviceToken, Method: http.MethodPost, Path: "/device/token",
		Summary: "Exchange a device code for an access token (RFC 8628 §3.4)", Tags: tags, Access: pluginkit.Public, AcceptForm: true,
	}, h.DeviceToken)
	// Step 2: the user's endpoints (the session is optional in the middleware; approve / deny answer
	// better-auth's own 401 {error: "unauthorized"} without one)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpDeviceVerify, Method: http.MethodGet, Path: "/device",
		Summary: "Verify a user code and get the device authorization status", Tags: tags, Access: pluginkit.OptionalSession,
	}, h.DeviceVerify)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpDeviceApprove, Method: http.MethodPost, Path: "/device/approve",
		Summary: "Approve a device authorization", Tags: tags, Access: pluginkit.OptionalSession,
	}, h.DeviceApprove)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpDeviceDeny, Method: http.MethodPost, Path: "/device/deny",
		Summary: "Deny a device authorization", Tags: tags, Access: pluginkit.OptionalSession,
	}, h.DeviceDeny)
}
