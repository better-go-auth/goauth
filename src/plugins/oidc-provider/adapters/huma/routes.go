// Package humaoidc mounts the oidc-provider endpoints on a Huma API.
package humaoidc

import (
	"context"
	"net/http"
	"strings"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/plugins/oidc-provider/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/danielgtaylor/huma/v2"
)

// Operation IDs (better-auth's operationId / endpoint keys), usable in AuthConfig.DisabledOps.
const (
	OpGetOpenIDConfig    = "getOpenIdConfig"
	OpAuthorize          = "oauth2Authorize"
	OpConsent            = "oauth2Consent"
	OpToken              = "oauth2Token"
	OpUserInfo           = "oauth2Userinfo"
	OpRegister           = "registerOAuthApplication"
	OpGetClient          = "getOAuthClient"
	OpEndSession         = "endSession"
	OpEndSessionPost     = "endSessionPost"
	OpenIDConfigPath     = "/.well-known/openid-configuration"
	AuthorizePath        = "/oauth2/authorize"
	ConsentPath          = "/oauth2/consent"
	TokenPath            = "/oauth2/token"
	UserInfoPath         = "/oauth2/userinfo"
	RegisterPath         = "/oauth2/register"
	ClientPath           = "/oauth2/client/{id}"
	EndSessionPath       = "/oauth2/endsession"
	oidcTag              = "oidc-provider"
	requestNotFoundError = "request not found"
)

// Handler serves the oidc-provider endpoints.
type Handler struct {
	Service *services.Service
}

// RegisterRoutes mounts the oidc-provider endpoints under the kit's base path.
func RegisterRoutes(api huma.API, kit *pluginkit.Kit, h *Handler) {
	tags := []string{oidcTag}
	// Step 1: discovery
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpGetOpenIDConfig, Method: http.MethodGet, Path: OpenIDConfigPath, Tags: tags, Hidden: true,
	}, h.OpenIDConfig)
	// Step 2: the authorization endpoint and consent
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpAuthorize, Method: http.MethodGet, Path: AuthorizePath, Summary: "Authorize an OAuth2 request",
		Tags: tags, Access: pluginkit.OptionalSession,
	}, h.Authorize)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpConsent, Method: http.MethodPost, Path: ConsentPath, Summary: "Handle OAuth2 consent",
		Tags: tags, Access: pluginkit.OptionalSession, OptionalBody: true,
	}, h.Consent)
	// Step 3: token and userinfo (client and bearer authentication, no session)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpToken, Method: http.MethodPost, Path: TokenPath, Tags: tags, Hidden: true, OptionalBody: true,
	}, h.Token)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpUserInfo, Method: http.MethodGet, Path: UserInfoPath, Tags: tags, Hidden: true,
	}, h.UserInfo)
	// Step 4: dynamic client registration and public client info
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpRegister, Method: http.MethodPost, Path: RegisterPath, Summary: "Register an OAuth2 application",
		Tags: tags, Access: pluginkit.OptionalSession, OptionalBody: true,
	}, h.Register)
	pluginkit.Register(kit, api, pluginkit.Route{
		OperationID: OpGetClient, Method: http.MethodGet, Path: ClientPath, Summary: "Get OAuth2 client details",
		Tags: tags, Access: pluginkit.Session,
	}, h.GetClient)
	// Step 5: RP-initiated logout (GET and POST, parameters in the query)
	for _, m := range []struct{ op, method string }{{OpEndSession, http.MethodGet}, {OpEndSessionPost, http.MethodPost}} {
		pluginkit.Register(kit, api, pluginkit.Route{
			OperationID: m.op, Method: m.method, Path: EndSessionPath, Tags: tags, Hidden: true,
			Access: pluginkit.OptionalSession,
		}, h.EndSession)
	}
}

// Stream writes res as the HTTP response (status, every header, raw body).
func Stream(res *endpointhooks.Response) *huma.StreamResponse {
	return &huma.StreamResponse{Body: func(hctx huma.Context) {
		for k, vs := range res.Header {
			for _, v := range vs {
				hctx.AppendHeader(k, v)
			}
		}
		status := res.Status
		if status == 0 {
			status = http.StatusOK
		}
		hctx.SetStatus(status)
		if len(res.Body) > 0 {
			_, _ = hctx.BodyWriter().Write(res.Body)
		}
	}}
}

// Respond converts a service result into the handler result.
func Respond(res *endpointhooks.Response, err error) (*huma.StreamResponse, error) {
	if err != nil {
		return nil, err
	}
	return Stream(res), nil
}

// Query returns the request's first query values and its raw query (nil when the URL has no '?').
func Query(r *http.Request) (map[string]string, *string) {
	q := map[string]string{}
	if r == nil || r.URL == nil {
		return q, nil
	}
	// Step 1: the first value of every parameter ('+' is a space, like URLSearchParams)
	sp := services.ParseSearchParams(r.URL.RawQuery)
	vals := sp.Values()
	for i, k := range sp.Keys() {
		if _, seen := q[k]; !seen {
			q[k] = vals[i]
		}
	}
	// Step 2: the raw query for the login page redirect
	var raw *string
	if r.URL.RawQuery != "" || r.URL.ForceQuery || strings.Contains(r.RequestURI, "?") {
		v := r.URL.RawQuery
		raw = &v
	}
	return q, raw
}

// ─── handlers ────────────────────────────────────────────────────────────────

type idInput struct {
	ID string `path:"id"`
}

type rawBodyInput struct {
	RawBody []byte
}

// OpenIDConfig is GET /.well-known/openid-configuration.
func (h *Handler) OpenIDConfig(ctx context.Context, _ *struct{}) (*huma.StreamResponse, error) {
	return Stream(services.JSON(http.StatusOK, h.Service.Metadata(ctx))), nil
}

// Authorize is GET /oauth2/authorize.
func (h *Handler) Authorize(ctx context.Context, _ *struct{}) (*huma.StreamResponse, error) {
	kit := h.Service.Kit()
	r := kit.Request(ctx)
	if r == nil {
		return Stream(services.OAuthError(http.StatusUnauthorized, "invalid_request", requestNotFoundError)), nil
	}
	q, raw := Query(r)
	return Stream(h.Service.Authorize(ctx, services.AuthorizeRequest{
		Query: q, RawQuery: raw, Headers: r.Header, Session: kit.CurrentOrResolve(ctx),
	})), nil
}

// Consent is POST /oauth2/consent.
func (h *Handler) Consent(ctx context.Context, in *rawBodyInput) (*huma.StreamResponse, error) {
	kit := h.Service.Kit()
	cookieHeader := ""
	if r := kit.Request(ctx); r != nil {
		cookieHeader = r.Header.Get("Cookie")
	}
	return Respond(h.Service.Consent(ctx, services.ConsentRequest{
		Body: in.RawBody, CookieHeader: cookieHeader, Session: kit.CurrentOrResolve(ctx),
	}))
}

// Token is POST /oauth2/token.
func (h *Handler) Token(ctx context.Context, in *rawBodyInput) (*huma.StreamResponse, error) {
	r := h.Service.Kit().Request(ctx)
	req := services.TokenRequest{Body: in.RawBody}
	if r != nil {
		req.ContentType = r.Header.Get("Content-Type")
		req.Authorization = r.Header.Get("Authorization")
	}
	return Respond(h.Service.Token(ctx, req))
}

// UserInfo is GET /oauth2/userinfo.
func (h *Handler) UserInfo(ctx context.Context, _ *struct{}) (*huma.StreamResponse, error) {
	r := h.Service.Kit().Request(ctx)
	if r == nil {
		return Stream(services.OAuthError(http.StatusUnauthorized, "invalid_request", requestNotFoundError)), nil
	}
	return Respond(h.Service.UserInfo(ctx, r.Header.Get("Authorization")))
}

// Register is POST /oauth2/register.
func (h *Handler) Register(ctx context.Context, in *rawBodyInput) (*huma.StreamResponse, error) {
	return Respond(h.Service.Register(ctx, in.RawBody, h.Service.Kit().CurrentOrResolve(ctx)))
}

// GetClient is GET /oauth2/client/{id}.
func (h *Handler) GetClient(ctx context.Context, in *idInput) (*huma.StreamResponse, error) {
	return Stream(h.Service.ClientInfo(ctx, in.ID)), nil
}

// EndSession is GET|POST /oauth2/endsession.
func (h *Handler) EndSession(ctx context.Context, _ *struct{}) (*huma.StreamResponse, error) {
	kit := h.Service.Kit()
	q := map[string]string{}
	if r := kit.Request(ctx); r != nil {
		q, _ = Query(r)
	}
	return Respond(h.Service.EndSession(ctx, services.EndSessionRequest{
		IDTokenHint: q["id_token_hint"], ClientID: q["client_id"], PostLogoutRedirectURI: q["post_logout_redirect_uri"],
		State: q["state"], Session: kit.CurrentOrResolve(ctx),
	}))
}
