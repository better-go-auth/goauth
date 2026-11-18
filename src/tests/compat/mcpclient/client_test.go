// Package mcpclient runs src/tests/compat/client/test-mcp.mjs (an MCP client plus better-auth's
// createMcpAuthClient from better-auth/plugins/mcp/client) against goauth's mcp plugin.
package mcpclient

import (
	"encoding/json"
	"net/http"
	"testing"

	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/mcp"
	mcpconfig "github.com/better-go-auth/goauth/src/plugins/mcp/config"
	"github.com/better-go-auth/goauth/src/plugins/oidc-provider/oidctest"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

func TestOfficialClientMCP(t *testing.T) {
	// Step 1: goauth with the mcp plugin
	p := mcp.New(mcpconfig.Config{LoginPage: "/login"})
	srv := oidctest.NewServer(t, oidctest.Options{Plugins: []plugin.Plugin{p}})
	// Step 2: the MCP server's routes: the protected endpoint and the discovery documents at the origin
	srv.Mux.Handle("/mcp", p.WithMcpAuth(func(w http.ResponseWriter, _ *http.Request, s *mcp.Session) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"userId": s.UserID}})
	}))
	srv.Mux.Handle("/.well-known/oauth-authorization-server", p.OAuthDiscoveryMetadata())
	srv.Mux.Handle("/.well-known/oauth-protected-resource", p.OAuthProtectedResourceMetadata())
	// Step 3: the official client script
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-mcp.mjs", srv.URL)
}
