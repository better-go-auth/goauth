package test

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/migration"
	"github.com/better-go-auth/goauth/src/plugins"
	onetimetoken "github.com/better-go-auth/goauth/src/plugins/one-time-token"
	ottconfig "github.com/better-go-auth/goauth/src/plugins/one-time-token/config"
	openapi "github.com/better-go-auth/goauth/src/plugins/open-api"
	openapiconfig "github.com/better-go-auth/goauth/src/plugins/open-api/config"
	"github.com/better-go-auth/goauth/src/plugins/open-api/services"
	"github.com/better-go-auth/goauth/src/plugins/username"
	usernameconfig "github.com/better-go-auth/goauth/src/plugins/username/config"
	"github.com/better-go-auth/goauth/src/schema"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
	"github.com/danielgtaylor/huma/v2"
)

const baseURL = "http://localhost:3000"

// auditPlugin is a plugin that only declares a schema (a new model) for components.schemas.
type auditPlugin struct{}

func (auditPlugin) ID() string                        { return "audit" }
func (auditPlugin) Init(*plugins.InitContext) error   { return nil }
func (auditPlugin) Migrator() migration.IMigrator     { return nil }
func (auditPlugin) Services() map[string]any          { return nil }
func (auditPlugin) Routes() []plugins.RouteDescriptor { return nil }
func (auditPlugin) Schema() schema.PluginSchema {
	return schema.PluginSchema{"auditLog": schema.Model{Fields: map[string]schema.Field{
		"action":    {Type: schema.String, Required: true},
		"userId":    {Type: schema.String, Required: true, Input: schema.Bool(false)},
		"tags":      {Type: schema.StringArray},
		"createdAt": {Type: schema.Date, Required: true},
	}}}
}

func newServer(t *testing.T, opts []openapi.Option, core func(*config.AuthConfig)) *compattest.Server {
	t.Helper()
	// the open-api plugin comes first: routes of later plugins and core must still be documented
	p := openapi.New(openapiconfig.OpenAPIConfig{}, opts...)
	s := compattest.NewServer(t,
		compattest.WithPlugin(p),
		compattest.WithPlugin(onetimetoken.New(ottconfig.OneTimeTokenConfig{})),
		compattest.WithPlugin(username.New(usernameconfig.UsernameConfig{})),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = baseURL
			if core != nil {
				core(c)
			}
		}),
	)
	// an application route on the same API, outside the base path: not part of the auth document
	huma.Get(s.API, "/api/example/ping", func(context.Context, *struct{}) (*struct{ Body string }, error) {
		return &struct{ Body string }{Body: "pong"}, nil
	})
	return s
}

func getDoc(t *testing.T, s *compattest.Server) (map[string]any, []byte) {
	t.Helper()
	r := s.Get(t, "/api/auth/open-api/generate-schema")
	if r.Status != http.StatusOK {
		t.Fatalf("generate-schema: %d %s", r.Status, r.Body)
	}
	var doc map[string]any
	r.JSON(t, &doc)
	return doc, r.Body
}

// at walks a JSON value along keys.
func at(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestGenerateSchema_Envelope(t *testing.T) {
	s := newServer(t, nil, nil)
	doc, raw := getDoc(t, s)
	// Step 1: better-auth's envelope
	if doc["openapi"] != "3.1.1" || at(doc, "info", "title") != "Better Auth" || at(doc, "info", "version") != "1.1.0" ||
		at(doc, "info", "description") != "API Reference for your Better Auth Instance" {
		t.Fatalf("envelope: %v", doc["info"])
	}
	if servers := doc["servers"].([]any); len(servers) != 1 || at(servers[0], "url") != baseURL+"/api/auth" {
		t.Fatalf("servers = %v", doc["servers"])
	}
	if at(doc, "components", "securitySchemes", "bearerAuth", "scheme") != "bearer" ||
		at(doc, "components", "securitySchemes", "apiKeyCookie", "in") != "cookie" {
		t.Fatalf("securitySchemes = %v", at(doc, "components", "securitySchemes"))
	}
	if tags := doc["tags"].([]any); len(tags) != 1 || at(tags[0], "name") != "Default" {
		t.Fatalf("tags = %v", doc["tags"])
	}
	// Step 2: the document is self-contained (every Huma $ref is inlined)
	if strings.Contains(string(raw), "$ref") || strings.Contains(string(raw), "#/components/schemas") {
		t.Fatal("document still has $ref")
	}
}

// TestGenerateSchema_InstalledSchemaProvider: without WithSchemaPlugins the document comes from SetupGoAuth's
// registry, so an installed SchemaProvider plugin's model is documented (and its table was migrated).
func TestGenerateSchema_InstalledSchemaProvider(t *testing.T) {
	p := openapi.New(openapiconfig.OpenAPIConfig{})
	s := compattest.NewServer(t, compattest.WithPlugin(p), compattest.WithPlugin(auditPlugin{}),
		compattest.WithConfig(func(c *config.AuthConfig) { c.BaseURL = baseURL }))
	doc, _ := getDoc(t, s)
	schemas := at(doc, "components", "schemas").(map[string]any)
	if schemas["AuditLog"] == nil {
		t.Fatalf("missing AuditLog: %v", schemas)
	}
	if !s.DB.Migrator().HasTable("auditLog") {
		t.Fatal("the registry migrator must create the plugin table")
	}
}

func TestGenerateSchema_Components(t *testing.T) {
	s := newServer(t, []openapi.Option{openapi.WithSchemaPlugins(auditPlugin{})}, nil)
	doc, _ := getDoc(t, s)
	schemas := at(doc, "components", "schemas").(map[string]any)
	// Step 1: the four core tables (plus the extra plugin model)
	for _, name := range []string{"User", "Session", "Account", "Verification", "AuditLog"} {
		if schemas[name] == nil {
			t.Fatalf("missing schema %s: %v", name, schemas)
		}
	}
	user := schemas["User"]
	props := at(user, "properties").(map[string]any)
	// Step 2: better-auth's getFieldSchema rules
	if at(props, "id", "type") != "string" || at(props, "email", "type") != "string" {
		t.Fatalf("id/email: %v", props)
	}
	if at(props, "emailVerified", "readOnly") != true || at(props, "emailVerified", "default") != false {
		t.Fatalf("emailVerified = %v", props["emailVerified"])
	}
	if at(props, "createdAt", "format") != "date-time" || at(props, "createdAt", "type") != "string" ||
		at(props, "createdAt", "default") != "Generated at runtime" {
		t.Fatalf("createdAt = %v", props["createdAt"])
	}
	// required = required && input !== false
	req := strs(at(user, "required"))
	want := map[string]bool{"name": true, "email": true, "createdAt": true, "updatedAt": true}
	if len(req) != len(want) {
		t.Fatalf("required = %v", req)
	}
	for _, r := range req {
		if !want[r] {
			t.Fatalf("required = %v", req)
		}
	}
	// Step 3: installed plugins' fields are there, other plugins' and goauth-only columns are not
	if props["username"] == nil || props["displayUsername"] == nil {
		t.Fatalf("username fields missing: %v", props)
	}
	for _, absent := range []string{"role", "banned", "twoFactorEnabled", "phoneNumber", "firstName", "lastLoginAt", "deletedAt"} {
		if props[absent] != nil {
			t.Fatalf("unexpected field %s", absent)
		}
	}
	if at(schemas, "Session", "properties", "deviceId") != nil || at(schemas, "Session", "properties", "token") == nil {
		t.Fatalf("session = %v", schemas["Session"])
	}
	// Step 4: the extra plugin model
	audit := at(schemas, "AuditLog", "properties").(map[string]any)
	if at(audit, "tags", "type") != "array" || at(audit, "userId", "readOnly") != true {
		t.Fatalf("auditLog = %v", audit)
	}
	if r := strs(at(schemas, "AuditLog", "required")); len(r) != 2 {
		t.Fatalf("auditLog required = %v", r)
	}
}

func TestGenerateSchema_Paths(t *testing.T) {
	s := newServer(t, nil, nil)
	doc, _ := getDoc(t, s)
	paths := doc["paths"].(map[string]any)
	// Step 1: core route: tag Default, security, body, default error responses + its own 200
	signIn := at(paths, "/sign-in/email", "post")
	if signIn == nil {
		t.Fatalf("no /sign-in/email: %v", keys(paths))
	}
	if tags := strs(at(signIn, "tags")); len(tags) != 1 || tags[0] != "Default" {
		t.Fatalf("tags = %v", tags)
	}
	if at(signIn, "operationId") != "signInEmail" {
		t.Fatalf("operationId = %v", at(signIn, "operationId"))
	}
	if sec := at(signIn, "security").([]any); len(sec) != 1 || at(sec[0], "bearerAuth") == nil {
		t.Fatalf("security = %v", sec)
	}
	bodyProps, _ := at(signIn, "requestBody", "content", "application/json", "schema", "properties").(map[string]any)
	if bodyProps["email"] == nil || bodyProps["password"] == nil || bodyProps["$schema"] != nil {
		t.Fatalf("requestBody = %v", at(signIn, "requestBody"))
	}
	resp := at(signIn, "responses").(map[string]any)
	for _, code := range []string{"200", "400", "401", "403", "404", "429", "500"} {
		if resp[code] == nil {
			t.Fatalf("missing response %s: %v", code, keys(resp))
		}
	}
	if resp["default"] != nil {
		t.Fatal("Huma's default response leaked")
	}
	if at(resp, "429", "description") != "Too Many Requests. You have exceeded the rate limit. Try again later." {
		t.Fatalf("429 = %v", resp["429"])
	}
	// Step 2: GET routes have no request body; query parameters are kept, header/cookie ones are not
	getSession := at(paths, "/get-session", "get")
	if getSession == nil || at(getSession, "requestBody") != nil {
		t.Fatalf("get-session = %v", getSession)
	}
	for _, p := range at(getSession, "parameters").([]any) {
		if in := at(p, "in"); in != "query" && in != "path" {
			t.Fatalf("parameter in %v", in)
		}
	}
	// Step 3: plugin routes carry the capitalized plugin tag
	ott := at(paths, "/one-time-token/generate", "get")
	if tags := strs(at(ott, "tags")); len(tags) != 1 || tags[0] != "One-time-token" {
		t.Fatalf("ott tags = %v", tags)
	}
	if at(paths, "/sign-in/username", "post") == nil {
		t.Fatal("plugin route missing")
	}
	// Step 4: the open-api routes, hidden routes and application routes are not documented
	for p := range paths {
		if strings.HasPrefix(p, "/open-api") || p == "/reference" || strings.Contains(p, "example") || strings.HasPrefix(p, "/api/") {
			t.Fatalf("unexpected path %s", p)
		}
	}
	// Step 5: operation IDs are unique
	seen := map[string]bool{}
	for _, item := range paths {
		for _, op := range item.(map[string]any) {
			id, _ := at(op, "operationId").(string)
			if id == "" {
				continue
			}
			if seen[id] {
				t.Fatalf("duplicate operationId %s", id)
			}
			seen[id] = true
		}
	}
}

func TestGenerateSchema_DisabledPaths(t *testing.T) {
	s := newServer(t, nil, func(c *config.AuthConfig) { c.DisabledPaths = []string{"/sign-up/email"} })
	doc, _ := getDoc(t, s)
	if at(doc, "paths", "/sign-up/email") != nil {
		t.Fatal("disabled path documented")
	}
	if at(doc, "paths", "/sign-in/email") == nil {
		t.Fatal("sign-in missing")
	}
}

// keys lists a map's keys (for failure messages).
func keys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

var embedded = regexp.MustCompile(`(?s)<script\s+id="api-reference"\s+type="application/json">\s*(.*?)\s*</script>`)

func TestReferencePage(t *testing.T) {
	// Step 1: default path and theme
	s := newServer(t, nil, nil)
	r := s.Get(t, "/api/auth/reference")
	if r.Status != http.StatusOK || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("reference: %d %s", r.Status, r.Header)
	}
	page := string(r.Body)
	for _, want := range []string{
		"<title>Scalar API Reference</title>",
		`theme: "default"`,
		`favicon: "data:image/svg+xml;utf8,` + services.EncodeURIComponent(services.Logo) + `"`,
		`<script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference" ></script>`,
		`title: "Better Auth API"`,
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("page lacks %q", want[:min(len(want), 80)])
		}
	}
	// Step 2: the embedded document is the generated one
	m := embedded.FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no embedded document")
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(m[1]), &doc); err != nil {
		t.Fatalf("embedded JSON: %v", err)
	}
	live, _ := getDoc(t, s)
	if len(doc["paths"].(map[string]any)) != len(live["paths"].(map[string]any)) || doc["openapi"] != "3.1.1" {
		t.Fatal("embedded document differs")
	}

	// Step 3: custom path, theme and nonce
	s2 := newServer(t, []openapi.Option{openapi.WithPath("/docs-ref"), openapi.WithTheme("moon"), openapi.WithNonce("abc123")}, nil)
	if r := s2.Get(t, "/api/auth/reference"); r.Status != http.StatusNotFound {
		t.Fatalf("default path still served: %d", r.Status)
	}
	r = s2.Get(t, "/api/auth/docs-ref")
	page = string(r.Body)
	if r.Status != http.StatusOK || !strings.Contains(page, `theme: "moon"`) || strings.Count(page, `nonce="abc123"`) != 2 {
		t.Fatalf("custom page: %d", r.Status)
	}
}

func TestReferenceDisabled(t *testing.T) {
	s := newServer(t, []openapi.Option{openapi.WithDisableDefaultReference(true)}, nil)
	r := s.Get(t, "/api/auth/reference")
	var e struct {
		Code string `json:"code"`
	}
	r.JSON(t, &e)
	if r.Status != http.StatusNotFound || e.Code != "NOT_FOUND" {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	// the document itself is still served
	getDoc(t, s)
}

func TestOpenAPIDisabledOps(t *testing.T) {
	s := newServer(t, nil, func(c *config.AuthConfig) {
		c.DisabledPaths = []string{"/open-api/generate-schema"}
	})
	if r := s.Get(t, "/api/auth/open-api/generate-schema"); r.Status != http.StatusNotFound {
		t.Fatalf("%d", r.Status)
	}
	if r := s.Get(t, "/api/auth/reference"); r.Status != http.StatusOK {
		t.Fatalf("reference: %d", r.Status)
	}
}
