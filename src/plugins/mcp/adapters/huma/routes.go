// Package humamcp mounts the mcp endpoints on a Huma API.
package humamcp

import (
	"context"
	"net/http"

	"github.com/better-go-auth/goauth/src/plugins/mcp/services"
	humaoidc "github.com/better-go-auth/goauth/src/plugins/oidc-provider/adapters/huma"
	oidc "github.com/better-go-auth/goauth/src/plugins/oidc-provider/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/danielgtaylor/huma/v2"
)

// Operation IDs (better-auth's endpoint keys), usable in AuthConfig.DisabledOps.
const (
	OpConsent                = "oauth2Consent"
	OpOAuthConfig            = "getMcpOAuthConfig"
	OpProtectedResource      = "getMCPProtectedResource"
	OpAuthorize              = "mcpOAuthAuthorize"
	OpToken                  = "mcpOAuthToken"
	OpRegister               = "registerMcpClient"
	OpGetSession             = "getMcpSession"
	OAuthConfigPath          = "/.well-known/oauth-authorization-server"
	ProtectedResourcePath    = "/.well-known/oauth-protected-resource"
	AuthorizePath            = "/mcp/authorize"
	TokenPath                = "/mcp/token"
	RegisterPath             = "/mcp/register"
	GetSessionPath           = "/mcp/get-session"
	mcpTag                   = "mcp"
	requestNotFoundError     = "request not found"
	requestNotFoundErrorCode = "invalid_request"
)

// Handler serves the mcp endpoints.
type Handler struct {
	Service *services.Service
}

// RegisterRoutes mounts the mcp endpoints (and the oidc-provider's /oauth2/consent) under the kit's base path.
func RegisterRoutes(api huma.API, kit *pluginkit.Kit, h *Handler) {
	tags := []string{mcpTag}
	consent := &humaoidc.Handler{Service: h.Service.Provider}
	// Step 1: consent (the oidc-provider's endpoint)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpConsent, Method: http.MethodPost, Path: humaoidc.ConsentPath, Summary: "Handle OAuth2 consent",
		Tags: tags, Access: pluginkit.OptionalSession, OptionalBody: true,
	}, consent.Consent)
	// Step 2: discovery documents
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpOAuthConfig, Method: http.MethodGet, Path: OAuthConfigPath, Tags: tags, Hidden: true,
	}, h.OAuthConfig)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpProtectedResource, Method: http.MethodGet, Path: ProtectedResourcePath, Tags: tags, Hidden: true,
	}, h.ProtectedResource)
	// Step 3: the OAuth endpoints
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpAuthorize, Method: http.MethodGet, Path: AuthorizePath, Summary: "Authorize an OAuth2 request using MCP",
		Tags: tags, Access: pluginkit.OptionalSession,
	}, h.Authorize)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpToken, Method: http.MethodPost, Path: TokenPath, Tags: tags, Hidden: true, OptionalBody: true,
	}, h.Token)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpRegister, Method: http.MethodPost, Path: RegisterPath, Summary: "Register an OAuth2 application",
		Tags: tags, Access: pluginkit.OptionalSession, OptionalBody: true,
	}, h.Register)
	// Step 4: the access token lookup for resource servers
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpGetSession, Method: http.MethodGet, Path: GetSessionPath, Summary: "Get the MCP session of a bearer access token",
		Tags: tags,
	}, h.GetSession)
}

type rawBodyInput struct {
	RawBody []byte
}

// OAuthConfig is GET /.well-known/oauth-authorization-server.
func (h *Handler) OAuthConfig(ctx context.Context, _ *struct{}) (*huma.StreamResponse, error) {
	return humaoidc.Stream(oidc.JSON(http.StatusOK, h.Service.Metadata(ctx))), nil
}

// ProtectedResource is GET /.well-known/oauth-protected-resource.
func (h *Handler) ProtectedResource(ctx context.Context, _ *struct{}) (*huma.StreamResponse, error) {
	return humaoidc.Stream(oidc.JSON(http.StatusOK, h.Service.ProtectedResourceMetadata(ctx))), nil
}

// Authorize is GET /mcp/authorize.
func (h *Handler) Authorize(ctx context.Context, _ *struct{}) (*huma.StreamResponse, error) {
	kit := h.Service.Provider.Kit()
	r := kit.Request(ctx)
	if r == nil {
		return humaoidc.Stream(oidc.OAuthError(http.StatusUnauthorized, requestNotFoundErrorCode, requestNotFoundError)), nil
	}
	q, raw := humaoidc.Query(r)
	return humaoidc.Stream(h.Service.Authorize(ctx, oidc.AuthorizeRequest{
		Query: q, RawQuery: raw, Headers: r.Header, Session: kit.CurrentOrResolve(ctx),
	})), nil
}

// Token is POST /mcp/token.
func (h *Handler) Token(ctx context.Context, in *rawBodyInput) (*huma.StreamResponse, error) {
	req := oidc.TokenRequest{Body: in.RawBody}
	if r := h.Service.Provider.Kit().Request(ctx); r != nil {
		req.ContentType = r.Header.Get("Content-Type")
		req.Authorization = r.Header.Get("Authorization")
	}
	return humaoidc.Respond(h.Service.Token(ctx, req))
}

// Register is POST /mcp/register.
func (h *Handler) Register(ctx context.Context, in *rawBodyInput) (*huma.StreamResponse, error) {
	userID := ""
	if sw := h.Service.Provider.Kit().CurrentOrResolve(ctx); sw != nil {
		userID = sw.Session.UserID
	}
	return humaoidc.Respond(h.Service.Register(ctx, in.RawBody, userID))
}

// GetSession is GET /mcp/get-session.
func (h *Handler) GetSession(ctx context.Context, _ *struct{}) (*huma.StreamResponse, error) {
	auth := ""
	if r := h.Service.Provider.Kit().Request(ctx); r != nil {
		auth = r.Header.Get("Authorization")
	}
	return humaoidc.Respond(h.Service.GetSession(ctx, auth))
}
