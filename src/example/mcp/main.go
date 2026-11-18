// Command mcp runs goauth as the OAuth authorization server of an MCP (Model Context Protocol) server.
// The MCP endpoint /mcp only answers requests with a valid access token; MCP clients (Claude, the MCP
// inspector, ...) find everything else on their own: the 401 points at the protected resource metadata,
// which points at the authorization server metadata, where they register and run the OAuth flow.
//
//	go run ./src/example/mcp    # http://localhost:8080/mcp
//	go test ./src/example/mcp   # an MCP client end to end
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/mcp"
	mcpconfig "github.com/better-go-auth/goauth/src/plugins/mcp/config"
)

// loginHTML is the login page /mcp/authorize sends signed-out users to, with the authorization query.
// goauth answers the sign-in with the redirect to the MCP client (a fetch cannot follow it across origins),
// so once signed in the page simply opens /mcp/authorize again with the same query.
const loginHTML = `<!doctype html><title>Sign in</title>
<form id="f"><input name="email" placeholder="email"> <input name="password" type="password" placeholder="password"> <button>Sign in</button></form>
<script>
f.onsubmit = async (e) => {
  e.preventDefault();
  const res = await fetch("/api/auth/sign-in/email", {method: "POST", headers: {"content-type": "application/json"}, redirect: "manual",
    body: JSON.stringify({email: f.email.value, password: f.password.value})});
  if (res.ok || res.type === "opaqueredirect") location.href = "/api/auth/mcp/authorize" + location.search;
  else document.body.append(await res.text());
};
</script>`

// rpcRequest is the part of a JSON-RPC request the example reads.
type rpcRequest struct {
	ID     any    `json:"id"`
	Method string `json:"method"`
}

// mcpHandler is a tiny MCP endpoint: "whoami" returns the user and client behind the access token.
func mcpHandler(w http.ResponseWriter, r *http.Request, s *mcp.Session) {
	var req rpcRequest
	_ = json.NewDecoder(r.Body).Decode(&req)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0", "id": req.ID,
		"result": map[string]any{"method": req.Method, "userId": s.UserID, "clientId": s.ClientID, "scopes": s.Scopes},
	})
}

// newApp builds the example server. dbPath "" uses an in-memory database (tests).
func newApp(dbPath string) (*exkit.App, *mcp.Plugin, error) {
	// Step 1: open the database
	db, err := exkit.OpenDB(dbPath)
	if err != nil {
		return nil, nil, err
	}
	// Step 2: the mcp plugin (its LoginPage is where signed-out users go)
	p := mcp.New(mcpconfig.Config{LoginPage: "/login"})
	app, err := exkit.New(context.Background(), exkit.Options{DB: db, Plugins: []plugin.Plugin{p}})
	if err != nil {
		return nil, nil, err
	}
	// Step 3: the MCP endpoint behind WithMcpAuth, the discovery documents at the origin, the login page
	app.Mux.Handle("/mcp", p.WithMcpAuth(mcpHandler))
	app.Mux.Handle("GET /.well-known/oauth-authorization-server", p.OAuthDiscoveryMetadata())
	app.Mux.Handle("GET /.well-known/oauth-protected-resource", p.OAuthProtectedResourceMetadata())
	app.Mux.HandleFunc("GET /login", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(loginHTML))
	})
	return app, p, nil
}

func main() {
	dbPath := os.Getenv("SQLITE_DB")
	if dbPath == "" {
		dbPath = "mcp_example.db"
	}
	app, _, err := newApp(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	exkit.Serve(app.Mux)
}
