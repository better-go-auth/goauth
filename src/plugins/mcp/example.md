# MCP plugin

Makes goauth the OAuth authorization server of an MCP (Model Context Protocol) server. MCP clients
(Claude, the MCP inspector, IDEs, ...) discover goauth from the MCP server's 401, register themselves,
run the authorization code flow with PKCE and call the MCP server with the access token. It is the Go
version of better-auth's `mcp()` plugin (v1.6.16) plus the server helpers `withMcpAuth`,
`oAuthDiscoveryMetadata` and `oAuthProtectedResourceMetadata`; better-auth's resource-server client
`createMcpAuthClient` (`better-auth/plugins/mcp/client`) works against it.

Runnable example: [src/example/mcp](../../example/mcp/main.go)

```sh
go run ./src/example/mcp    # MCP endpoint at http://localhost:8080/mcp
go test ./src/example/mcp   # an MCP client end to end
```

## Setup

```go
import (
	"github.com/better-go-auth/goauth/src/plugins/mcp"
	mcpconfig "github.com/better-go-auth/goauth/src/plugins/mcp/config"
)

p := mcp.New(mcpconfig.Config{
	LoginPage: "/login", // required: where signed-out users go (with the authorization query)
	// Resource: "https://api.example.com/mcp",              // default: the BaseURL origin
	// OIDCConfig: oidcconfig.Config{ConsentPage: "/consent"}, // token lifetimes, scopes, PKCE, claims, ...
})
auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{Conn: db, AuthConfig: cfg, Plugins: []plugin.Plugin{p}})

// your MCP endpoint, protected by the access token
mux.Handle("/mcp", p.WithMcpAuth(func(w http.ResponseWriter, r *http.Request, s *mcp.Session) {
	// s.UserID, s.ClientID, s.Scopes, s.AccessTokenExpiresAt ...
}))
// or as middleware: p.Middleware(next), then mcp.SessionFromContext(r.Context())

// discovery where MCP clients look for it (the origin)
mux.Handle("/.well-known/oauth-authorization-server", p.OAuthDiscoveryMetadata())
mux.Handle("/.well-known/oauth-protected-resource", p.OAuthProtectedResourceMetadata())
```

The plugin uses the oidc-provider's tables (`oauthApplication`, `oauthAccessToken`, `oauthConsent`).
Install either `mcp` or `oidc-provider`, not both (they share `/oauth2/consent`, as in better-auth).

## What an MCP client sees

1. `POST /mcp` without a token → `401` with
   `WWW-Authenticate: Bearer resource_metadata="<BaseURL>/api/auth/.well-known/oauth-protected-resource"`,
   `Access-Control-Expose-Headers: WWW-Authenticate` and the JSON-RPC body
   `{"jsonrpc":"2.0","error":{"code":-32000,"message":"Unauthorized: Authentication required","www-authenticate":"…"},"id":null}`.
2. The protected resource metadata names the authorization server (the origin); its
   `/.well-known/oauth-authorization-server` lists `/api/auth/mcp/authorize`, `/mcp/token`, `/mcp/register`.
3. `POST /api/auth/mcp/register` (open, no session): `token_endpoint_auth_method: "none"` registers a public
   client (no secret); otherwise a confidential client with `client_secret`.
4. `GET /api/auth/mcp/authorize?...&code_challenge=…&code_challenge_method=S256` → login page (signed
   `oidc_login_prompt` cookie) → the sign-in response redirects to the client with `?code=…&state=…`
   (consent only with `prompt=consent` and `OIDCConfig.ConsentPage`).
5. `POST /api/auth/mcp/token` (`authorization_code` with `code_verifier`, `refresh_token`).
6. `POST /mcp` with `Authorization: Bearer <access_token>`.

## Endpoints (under `/api/auth`)

| Method | Path | Operation ID | Notes |
|---|---|---|---|
| GET | `/.well-known/oauth-authorization-server` | `getMcpOAuthConfig` | RFC 8414 (null without a BaseURL) |
| GET | `/.well-known/oauth-protected-resource` | `getMCPProtectedResource` | RFC 9728 |
| GET | `/mcp/authorize` | `mcpOAuthAuthorize` | Always redirects; CORS headers |
| POST | `/mcp/token` | `mcpOAuthToken` | Refresh answers `token_type: "bearer"` |
| POST | `/mcp/register` | `registerMcpClient` | Open registration, CORS headers |
| GET | `/mcp/get-session` | `getMcpSession` | The `oauthAccessToken` record of the bearer token, or `null` |
| POST | `/oauth2/consent` | `oauth2Consent` | The oidc-provider's consent endpoint |

## Notes and differences from better-auth

* `/mcp/userinfo` and `/mcp/jwks` appear in the metadata but, as in better-auth, are not served.
* The mcp id_token is signed with a throwaway HMAC key (MCP clients use the access token).
* `WithMcpAuth` / `Middleware` reject expired access tokens; better-auth's `withMcpAuth` and
  `/mcp/get-session` do not look at the expiry (the endpoint keeps better-auth's behaviour).
