package humaonetimetoken

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/danielgtaylor/huma/v2"
)

// Operation IDs (better-auth's endpoint keys), usable in AuthConfig.DisabledOps.
const (
	OpGenerateOneTimeToken = "generateOneTimeToken"
	OpVerifyOneTimeToken   = "verifyOneTimeToken"
)

// RegisterRoutes mounts the one-time-token endpoints under the kit's base path.
func RegisterRoutes(api huma.API, kit *pluginkit.Kit, h *Handler) {
	tags := []string{"one-time-token"}
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpGenerateOneTimeToken, Method: http.MethodGet, Path: "/one-time-token/generate",
		Summary: "Generate a one-time token for the current session", Tags: tags, Access: pluginkit.Session,
	}, h.Generate)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpVerifyOneTimeToken, Method: http.MethodPost, Path: "/one-time-token/verify",
		Summary: "Verify a one-time token and return its session", Tags: tags, Access: pluginkit.Public,
	}, h.Verify)
}
