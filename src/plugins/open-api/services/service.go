// Package services implements better-auth's open-api plugin: the OpenAPI 3.1 document of the auth routes
// (GET /open-api/generate-schema) and the Scalar reference page.
//
// better-auth builds its document from the endpoints' zod schemas; goauth builds it from the document Huma
// already generates for every registered operation, reshaped like better-auth's generator:
//
//   - only operations under BasePath, with the base path stripped ("/api/auth/sign-in/email" →
//     "/sign-in/email"); hidden operations and DisabledPaths are left out, and so are the open-api
//     plugin's own routes (better-auth skips plugin "open-api");
//   - core routes (Huma tag "better-auth") get the tag "Default"; plugin routes keep their Huma tags with
//     the first letter upper-cased (better-auth's capitalized plugin id, e.g. "One-time-token");
//   - every operation gets security [{bearerAuth: []}], better-auth's default 400/401/403/404/429/500
//     responses merged with the operation's own responses, query and path parameters, and request bodies
//     (core POST/PUT/PATCH routes without a body get an empty object body, like better-auth);
//   - operation IDs are made unique like better-auth (method suffix, then a counter);
//   - every $ref into Huma's components is inlined, so the document is self-contained, and
//     components.schemas holds better-auth's table schemas (User, Session, Account, Verification, ...).
//
// The document is generated on every request, so routes mounted after the plugin are included.
package services

import (
	"context"
	"encoding/json"
	"slices"
	"sort"
	"strconv"
	"strings"

	authconfig "github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/open-api/config"
	"github.com/danielgtaylor/huma/v2"
)

// Tag is the Huma tag of the open-api plugin's own routes (they are not part of the document).
const Tag = "open-api"

// coreTag is the Huma tag goauth's core routes carry.
const coreTag = "better-auth"

// Service generates the OpenAPI document of the auth routes.
type Service struct {
	api      huma.API
	conf     authconfig.AuthConfig
	cfg      config.OpenAPIConfig
	basePath string
	baseURL  string
}

// New builds the service. api is the Huma API goauth registers its routes on; baseURL is
// "<BaseURL><BasePath>" (better-auth's ctx.context.baseURL, the document's server URL).
func New(api huma.API, conf authconfig.AuthConfig, cfg config.OpenAPIConfig, basePath, baseURL string) *Service {
	return &Service{api: api, conf: conf, cfg: cfg.WithDefaults(), basePath: basePath, baseURL: baseURL}
}

// Config returns the effective configuration.
func (s *Service) Config() config.OpenAPIConfig { return s.cfg }

// Generate returns better-auth's OpenAPI document of the auth routes.
func (s *Service) Generate(_ context.Context) (map[string]any, error) {
	// Step 1: better-auth's table schemas
	schemas, err := s.componentSchemas()
	if err != nil {
		return nil, err
	}
	// Step 2: the auth routes from Huma's document
	paths, err := s.paths()
	if err != nil {
		return nil, err
	}
	// Step 3: better-auth's document envelope
	return map[string]any{
		"openapi": "3.1.1",
		"info": map[string]any{
			"title":       "Better Auth",
			"description": "API Reference for your Better Auth Instance",
			"version":     "1.1.0",
		},
		"components": map[string]any{
			"schemas": schemas,
			"securitySchemes": map[string]any{
				"apiKeyCookie": map[string]any{
					"type": "apiKey", "in": "cookie", "name": "apiKeyCookie",
					"description": "API Key authentication via cookie",
				},
				"bearerAuth": map[string]any{
					"type": "http", "scheme": "bearer", "description": "Bearer token authentication",
				},
			},
		},
		"security": []any{map[string]any{"apiKeyCookie": []any{}, "bearerAuth": []any{}}},
		"servers":  []any{map[string]any{"url": s.baseURL}},
		"tags": []any{map[string]any{
			"name":        "Default",
			"description": "Default endpoints that are included with Better Auth by default. These endpoints are not part of any plugin.",
		}},
		"paths": paths,
	}, nil
}

// methods are the HTTP methods better-auth documents, in its order.
var methods = []string{"get", "delete", "post", "patch", "put"}

// paths turns Huma's operations under BasePath into better-auth's path items.
func (s *Service) paths() (map[string]any, error) {
	// Step 1: Huma's document as plain JSON values
	raw, err := json.Marshal(s.api.OpenAPI())
	if err != nil {
		return nil, err
	}
	var doc struct {
		Paths      map[string]map[string]any `json:"paths"`
		Components struct {
			Schemas map[string]any `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	r := &refResolver{schemas: doc.Components.Schemas}
	ids := newOperationIDs()
	// Step 2: walk the paths in a stable order (operation ID de-duplication depends on it)
	keys := make([]string, 0, len(doc.Paths))
	for p := range doc.Paths {
		keys = append(keys, p)
	}
	sort.Strings(keys)
	out := map[string]any{}
	for _, full := range keys {
		rel, ok := s.relative(full)
		if !ok {
			continue
		}
		item := map[string]any{}
		for _, method := range methods {
			op, _ := doc.Paths[full][method].(map[string]any)
			if op == nil {
				continue
			}
			tags := stringList(op["tags"])
			// the plugin's own routes are not documented (better-auth skips plugin "open-api")
			if slices.Contains(tags, Tag) {
				continue
			}
			item[method] = s.operation(op, method, tags, r, ids)
		}
		if len(item) > 0 {
			out[rel] = item
		}
	}
	return out, nil
}

// relative strips BasePath from a Huma path; ok is false for routes outside BasePath or disabled paths.
func (s *Service) relative(full string) (string, bool) {
	if !strings.HasPrefix(full, s.basePath+"/") {
		return "", false
	}
	rel := strings.TrimPrefix(full, s.basePath)
	if slices.Contains(s.conf.DisabledPaths, rel) {
		return "", false
	}
	return rel, true
}

// operation builds one better-auth operation object from a Huma operation.
func (s *Service) operation(op map[string]any, method string, tags []string, r *refResolver, ids *operationIDs) map[string]any {
	// Step 1: tags: "Default" for core routes, the capitalized plugin tags otherwise
	core := slices.Contains(tags, coreTag)
	var outTags []any
	if core || len(tags) == 0 {
		outTags = []any{"Default"}
	} else {
		for _, t := range tags {
			outTags = append(outTags, capitalize(t))
		}
	}
	// Step 2: description (Huma's description, else its summary)
	description, _ := op["description"].(string)
	if description == "" {
		description, _ = op["summary"].(string)
	}
	out := map[string]any{
		"tags":        outTags,
		"description": description,
		"security":    []any{map[string]any{"bearerAuth": []any{}}},
		"parameters":  parameters(op["parameters"], r),
		"responses":   responses(op["responses"], r),
	}
	// Step 3: a unique operation ID
	if id, _ := op["operationId"].(string); id != "" {
		out["operationId"] = ids.unique(id, method)
	}
	// Step 4: request bodies for POST / PATCH / PUT
	if method == "post" || method == "patch" || method == "put" {
		if body, ok := op["requestBody"].(map[string]any); ok {
			out["requestBody"] = r.resolve(body)
		} else if core {
			out["requestBody"] = map[string]any{"content": map[string]any{"application/json": map[string]any{
				"schema": map[string]any{"type": "object", "properties": map[string]any{}},
			}}}
		}
	}
	return out
}

// parameters keeps the query and path parameters (headers and cookies are transport details), with
// their schemas inlined.
func parameters(v any, r *refResolver) []any {
	out := []any{}
	list, _ := v.([]any)
	for _, p := range list {
		pm, _ := p.(map[string]any)
		if pm == nil {
			continue
		}
		if in, _ := pm["in"].(string); in != "query" && in != "path" {
			continue
		}
		param := map[string]any{"name": pm["name"], "in": pm["in"]}
		for _, k := range []string{"required", "description", "schema"} {
			if val, ok := pm[k]; ok {
				param[k] = r.resolve(val)
			}
		}
		out = append(out, param)
	}
	return out
}

// responses is better-auth's getResponse: the default error responses, overridden by the operation's own
// responses (Huma's catch-all "default" error response is dropped).
func responses(v any, r *refResolver) map[string]any {
	out := defaultResponses()
	own, _ := v.(map[string]any)
	for status, res := range own {
		if status == "default" {
			continue
		}
		out[status] = r.resolve(res)
	}
	return out
}

// errorResponse is one of better-auth's default error responses.
func errorResponse(description string, required bool) map[string]any {
	schema := map[string]any{"type": "object", "properties": map[string]any{"message": map[string]any{"type": "string"}}}
	if required {
		schema["required"] = []any{"message"}
	}
	return map[string]any{
		"content":     map[string]any{"application/json": map[string]any{"schema": schema}},
		"description": description,
	}
}

// defaultResponses are better-auth's default error responses of every operation.
func defaultResponses() map[string]any {
	return map[string]any{
		"400": errorResponse("Bad Request. Usually due to missing parameters, or invalid parameters.", true),
		"401": errorResponse("Unauthorized. Due to missing or invalid authentication.", true),
		"403": errorResponse("Forbidden. You do not have permission to access this resource or to perform this action.", false),
		"404": errorResponse("Not Found. The requested resource was not found.", false),
		"429": errorResponse("Too Many Requests. You have exceeded the rate limit. Try again later.", false),
		"500": errorResponse("Internal Server Error. This is a problem with the server that you cannot fix.", false),
	}
}

// operationIDs is better-auth's uniqueOperationId: a repeated ID gets the PascalCase method appended, then
// a counter.
type operationIDs struct{ seen map[string]bool }

func newOperationIDs() *operationIDs { return &operationIDs{seen: map[string]bool{}} }

func (o *operationIDs) unique(id, method string) string {
	base := id
	if o.seen[id] {
		base = id + capitalize(strings.ToLower(method))
	}
	result := base
	for n := 2; o.seen[result]; n++ {
		result = base + strconv.Itoa(n)
	}
	o.seen[result] = true
	return result
}

// refResolver inlines "#/components/schemas/<name>" references of Huma's document.
type refResolver struct {
	schemas map[string]any
	stack   []string
}

const refPrefix = "#/components/schemas/"

// resolve returns a deep copy of v with every schema reference inlined. A reference back into a schema
// being inlined (a recursive type) becomes {"type": "object"}. Huma's "$schema" link property is dropped.
func (r *refResolver) resolve(v any) any {
	switch t := v.(type) {
	case map[string]any:
		// Step 1: a reference is replaced by the referenced schema
		if ref, ok := t["$ref"].(string); ok && strings.HasPrefix(ref, refPrefix) {
			name := strings.TrimPrefix(ref, refPrefix)
			target, found := r.schemas[name]
			if !found || slices.Contains(r.stack, name) {
				return map[string]any{"type": "object"}
			}
			r.stack = append(r.stack, name)
			out := r.resolve(target)
			r.stack = r.stack[:len(r.stack)-1]
			return out
		}
		// Step 2: copy the object, resolving every value
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = r.resolve(val)
		}
		// Step 3: Huma's "$schema" link is not part of the API
		if props, ok := out["properties"].(map[string]any); ok {
			delete(props, "$schema")
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = r.resolve(val)
		}
		return out
	default:
		return v
	}
}

// stringList converts a JSON array of strings.
func stringList(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, x := range list {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
