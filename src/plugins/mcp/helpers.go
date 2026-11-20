package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	oidc "github.com/better-go-auth/goauth/src/plugins/oidc-provider/services"
)

// Session is the access token an MCP request was authenticated with (better-auth's getMcpSession
// result): the user, the client and the granted scopes.
type Session = oidc.AccessTokenRecord

// sessionKey is the context key of the MCP session.
type sessionKey struct{}

// SessionFromContext returns the MCP session Middleware attached to the request context.
func SessionFromContext(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(sessionKey{}).(*Session)
	return s, ok && s != nil
}

// unauthorizedBody is the JSON-RPC error withMcpAuth answers with.
type unauthorizedBody struct {
	JSONRPC string            `json:"jsonrpc"`
	Error   unauthorizedError `json:"error"`
	ID      any               `json:"id"`
}

type unauthorizedError struct {
	Code            int    `json:"code"`
	Message         string `json:"message"`
	WWWAuthenticate string `json:"www-authenticate"`
}

// WWWAuthenticate is the challenge of an unauthenticated MCP request:
// `Bearer resource_metadata="<baseURL><basePath>/.well-known/oauth-protected-resource"` ("Bearer" when the
// base URL cannot be resolved for the request).
func (p *Plugin) WWWAuthenticate(r *http.Request) string {
	if p.service == nil {
		return "Bearer"
	}
	kit := p.service.Provider.Kit()
	origin, err := kit.Conf.ResolveBaseURL(r)
	if err != nil || origin == "" {
		return "Bearer"
	}
	return `Bearer resource_metadata="` + origin + kit.BasePath + `/.well-known/oauth-protected-resource"`
}

// Authenticate returns the session of the request's bearer access token, or nil when the token is missing,
// unknown or expired. (better-auth's withMcpAuth does not check the expiry; goauth rejects expired tokens.)
func (p *Plugin) Authenticate(r *http.Request) *Session {
	if p.service == nil {
		return nil
	}
	rec, err := p.service.Session(r.Context(), r.Header.Get("Authorization"))
	if err != nil || rec == nil {
		return nil
	}
	s := oidc.AccessTokenFromRecord(rec)
	if s.AccessTokenExpiresAt.Before(time.Now()) {
		return nil
	}
	return s
}

// writeUnauthorized writes withMcpAuth's 401: the JSON-RPC error and the WWW-Authenticate challenge.
func (p *Plugin) writeUnauthorized(w http.ResponseWriter, r *http.Request) {
	www := p.WWWAuthenticate(r)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", www)
	w.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(unauthorizedBody{
		JSONRPC: "2.0",
		Error:   unauthorizedError{Code: -32000, Message: "Unauthorized: Authentication required", WWWAuthenticate: www},
		ID:      nil,
	})
}

// WithMcpAuth is better-auth's withMcpAuth: handler runs with the session of a valid bearer access token;
// other requests get 401 with the JSON-RPC error {"jsonrpc":"2.0","error":{"code":-32000,...},"id":null} and
// the WWW-Authenticate header pointing MCP clients at the protected resource metadata.
func (p *Plugin) WithMcpAuth(handler func(w http.ResponseWriter, r *http.Request, session *Session)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := p.Authenticate(r)
		if s == nil {
			p.writeUnauthorized(w, r)
			return
		}
		handler(w, r, s)
	})
}

// Middleware is WithMcpAuth as net/http middleware: the session is available through SessionFromContext.
func (p *Plugin) Middleware(next http.Handler) http.Handler {
	return p.WithMcpAuth(func(w http.ResponseWriter, r *http.Request, s *Session) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, s)))
	})
}

// writeMetadata writes a discovery document with the CORS headers of better-auth's helpers.
func writeMetadata(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(v)
}

// requestContext carries the request (and, with a dynamic base URL, its resolved origin) like goauth's
// own middleware does, so the metadata URLs match the request host.
func (p *Plugin) requestContext(r *http.Request) context.Context {
	ctx := config.WithHTTPRequest(r.Context(), r)
	conf := p.service.Provider.Kit().Conf
	if conf.DynamicBaseURL != nil {
		if origin, err := conf.ResolveBaseURL(r); err == nil && origin != "" {
			ctx = config.WithRequestBaseURL(ctx, origin)
		}
	}
	return ctx
}

// OAuthDiscoveryMetadata is better-auth's oAuthDiscoveryMetadata: a handler for the app's own
// /.well-known/oauth-authorization-server (MCP clients look for it at the origin).
func (p *Plugin) OAuthDiscoveryMetadata() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.service == nil {
			http.Error(w, "mcp: not initialized", http.StatusServiceUnavailable)
			return
		}
		writeMetadata(w, p.service.Metadata(p.requestContext(r)))
	})
}

// OAuthProtectedResourceMetadata is better-auth's oAuthProtectedResourceMetadata: a handler for the
// app's own /.well-known/oauth-protected-resource.
func (p *Plugin) OAuthProtectedResourceMetadata() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p.service == nil {
			http.Error(w, "mcp: not initialized", http.StatusServiceUnavailable)
			return
		}
		writeMetadata(w, p.service.ProtectedResourceMetadata(p.requestContext(r)))
	})
}
