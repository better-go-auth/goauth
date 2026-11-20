package humajwt

import (
	"net/http"
	"strings"

	"github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/danielgtaylor/huma/v2"
)

// Operation IDs (better-auth's endpoint keys), usable in AuthConfig.DisabledOps.
const (
	OpGetJWKS     = "getJSONWebKeySet"
	OpGetJWKSRoot = "getJSONWebKeySetRoot"
	OpGetToken    = "getJSONWebToken"
)

// RegisterRoutes registers the JWT plugin endpoints through pluginkit (GET <BasePath><jwksPath> and
// GET <BasePath>/token), plus GET <jwksPath> at the server root when jwksPath is not below BasePath.
func RegisterRoutes(api huma.API, kit *pluginkit.Kit, jwksPath string, handler *JWTHandler) {
	if api == nil {
		return
	}
	if jwksPath == "" {
		jwksPath = "/jwks"
	}
	if !strings.HasPrefix(jwksPath, "/") {
		jwksPath = "/" + jwksPath
	}
	tags := []string{"JWT"}

	// Step 1: GET /jwks (public, under BasePath)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpGetJWKS, Method: http.MethodGet, Path: jwksPath,
		Summary: "Get the JSON Web Key Set", Description: "Get the JSON Web Key Set", Tags: tags,
		Access: pluginkit.Public,
	}, handler.GetJWKS)

	// Step 2: the same key set at the server root (well-known style), outside goauth's base path
	rootDisabled := pluginkit.Route{OperationID: OpGetJWKSRoot, Path: jwksPath}
	if kit.BasePath != "" && !strings.HasPrefix(jwksPath, kit.BasePath) && !kit.Disabled(rootDisabled) {
		huma.Register(api, huma.Operation{
			OperationID: OpGetJWKSRoot,
			Method:      http.MethodGet,
			Path:        jwksPath,
			Summary:     "Get the JSON Web Key Set (Root)",
			Description: "Get the JSON Web Key Set at root path",
			Tags:        tags,
			Metadata:    map[string]any{types.RawBodyMetaKey: true},
		}, handler.GetJWKS)
	}

	// Step 3: GET /token (session required)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpGetToken, Method: http.MethodGet, Path: "/token",
		Summary: "Get a JWT token", Description: "Get a JWT token for the current session", Tags: tags,
		Access: pluginkit.Session,
	}, handler.GetToken)

	// POST /sign-jwt and POST /verify-jwt are SERVER_ONLY in better-auth and are deliberately not
	// registered: they are available from Go through the plugin's SignJWT / VerifyJWT methods.
}
