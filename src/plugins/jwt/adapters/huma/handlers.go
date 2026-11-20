package humajwt

import (
	"context"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/plugins/jwt/models"
	"github.com/better-go-auth/goauth/src/plugins/jwt/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/danielgtaylor/huma/v2"
)

// JWTHandler handles HTTP requests for JWKS and JWT operations.
type JWTHandler struct {
	service *services.JWTService
	kit     *pluginkit.Kit
}

// NewJWTHandler creates a new JWTHandler; kit provides the session the routes resolve.
func NewJWTHandler(service *services.JWTService, kit *pluginkit.Kit) *JWTHandler {
	return &JWTHandler{service: service, kit: kit}
}

type getJWKSOutput struct {
	Body models.JWKSResponse
}

// GetJWKS handles GET /jwks.
func (h *JWTHandler) GetJWKS(ctx context.Context, _ *struct{}) (*getJWKSOutput, error) {
	keys, err := h.service.GetJWKS(ctx)
	if err != nil {
		return nil, huma.Error404NotFound("Not found")
	}
	return &getJWKSOutput{
		Body: models.JWKSResponse{Keys: keys},
	}, nil
}

type getTokenOutput struct {
	Body struct {
		Token string `json:"token"`
	}
}

// GetToken handles GET /token (the route requires a session; pluginkit's resolver attaches it).
func (h *JWTHandler) GetToken(ctx context.Context, _ *struct{}) (*getTokenOutput, error) {
	session := h.kit.Current(ctx)
	if session == nil {
		return nil, autherr.ErrUnauthorized
	}

	token, err := h.service.GetJWTToken(ctx, session)
	if err != nil {
		return nil, err
	}

	out := &getTokenOutput{}
	out.Body.Token = token
	return out, nil
}

// Signing and verifying arbitrary JWTs (better-auth's /sign-jwt and /verify-jwt) are server-only and have
// no HTTP handler: an unauthenticated caller could otherwise mint a valid token for any subject. Use
// JWTService.SignJWT / VerifyJWT (or the plugin's SignJWT / VerifyJWT) from Go instead.
