package humajwt

import (
	"context"

	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/plugins/jwt/models"
	"github.com/better-go-auth/goauth/src/plugins/jwt/services"
	"github.com/danielgtaylor/huma/v2"
)

// JWTHandler handles HTTP requests for JWKS and JWT operations.
type JWTHandler struct {
	service  *services.JWTService
	resolver *humaadapter.Resolver
}

// NewJWTHandler creates a new JWTHandler.
func NewJWTHandler(service *services.JWTService, resolver *humaadapter.Resolver) *JWTHandler {
	return &JWTHandler{
		service:  service,
		resolver: resolver,
	}
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

type getTokenInput struct {
	Cookie        string `header:"Cookie"`
	Authorization string `header:"Authorization"`
}

type getTokenOutput struct {
	Body struct {
		Token string `json:"token"`
	}
}

// GetToken handles GET /token (requires active session).
func (h *JWTHandler) GetToken(ctx context.Context, in *getTokenInput) (*getTokenOutput, error) {
	session, _ := humaadapter.FromContext(ctx)
	if session == nil && h.resolver != nil {
		s, err := h.resolver.Resolve(ctx, in.Cookie)
		if err == nil && s != nil {
			session = s
		}
	}
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

type signJWTInput struct {
	Body struct {
		Payload         map[string]any `json:"payload"`
		OverrideOptions map[string]any `json:"overrideOptions,omitempty"`
	}
}

type signJWTOutput struct {
	Body struct {
		Token string `json:"token"`
	}
}

// SignJWT handles POST /sign-jwt.
func (h *JWTHandler) SignJWT(ctx context.Context, in *signJWTInput) (*signJWTOutput, error) {
	if in.Body.Payload == nil {
		in.Body.Payload = map[string]any{}
	}
	tok, err := h.service.SignJWT(ctx, in.Body.Payload, in.Body.OverrideOptions)
	if err != nil {
		return nil, err
	}
	out := &signJWTOutput{}
	out.Body.Token = tok
	return out, nil
}

type verifyJWTInput struct {
	Body struct {
		Token  string `json:"token"`
		Issuer string `json:"issuer,omitempty"`
	}
}

type verifyJWTOutput struct {
	Body struct {
		Payload map[string]any `json:"payload"`
	}
}

// VerifyJWT handles POST /verify-jwt.
func (h *JWTHandler) VerifyJWT(ctx context.Context, in *verifyJWTInput) (*verifyJWTOutput, error) {
	payload, err := h.service.VerifyJWT(ctx, in.Body.Token, in.Body.Issuer)
	out := &verifyJWTOutput{}
	if err != nil || payload == nil {
		// Better Auth returns { payload: null } when token is invalid
		out.Body.Payload = nil
		return out, nil
	}
	out.Body.Payload = payload
	return out, nil
}
