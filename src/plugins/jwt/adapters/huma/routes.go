package humajwt

import (
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

// RegisterRoutes registers the JWT plugin endpoints onto the Huma API.
func RegisterRoutes(api huma.API, basePath string, jwksPath string, handler *JWTHandler) {
	if basePath == "" {
		basePath = "/api/auth"
	}
	basePath = strings.TrimSuffix(basePath, "/")
	if jwksPath == "" {
		jwksPath = "/jwks"
	}
	if !strings.HasPrefix(jwksPath, "/") {
		jwksPath = "/" + jwksPath
	}

	// 1. GET /jwks (primary path under basePath)
	huma.Register(api, huma.Operation{
		OperationID: "getJSONWebKeySet",
		Method:      http.MethodGet,
		Path:        basePath + jwksPath,
		Summary:     "Get the JSON Web Key Set",
		Description: "Get the JSON Web Key Set",
		Tags:        []string{"JWT"},
	}, handler.GetJWKS)

	// Also register on root jwksPath if basePath is non-empty and jwksPath doesn't already start with basePath
	if basePath != "" && !strings.HasPrefix(jwksPath, basePath) {
		huma.Register(api, huma.Operation{
			OperationID: "getJSONWebKeySetRoot",
			Method:      http.MethodGet,
			Path:        jwksPath,
			Summary:     "Get the JSON Web Key Set (Root)",
			Description: "Get the JSON Web Key Set at root path",
			Tags:        []string{"JWT"},
		}, handler.GetJWKS)
	}

	// 2. GET /token
	huma.Register(api, huma.Operation{
		OperationID: "getJSONWebToken",
		Method:      http.MethodGet,
		Path:        basePath + "/token",
		Summary:     "Get a JWT token",
		Description: "Get a JWT token for the current session",
		Tags:        []string{"JWT"},
	}, handler.GetToken)

	// 3. POST /sign-jwt
	huma.Register(api, huma.Operation{
		OperationID: "signJWT",
		Method:      http.MethodPost,
		Path:        basePath + "/sign-jwt",
		Summary:     "Sign a JWT token",
		Description: "Sign a JWT token with custom payload",
		Tags:        []string{"JWT"},
	}, handler.SignJWT)

	// 4. POST /verify-jwt
	huma.Register(api, huma.Operation{
		OperationID: "verifyJWT",
		Method:      http.MethodPost,
		Path:        basePath + "/verify-jwt",
		Summary:     "Verify a JWT token",
		Description: "Verify a JWT token using stored public keys",
		Tags:        []string{"JWT"},
	}, handler.VerifyJWT)
}
