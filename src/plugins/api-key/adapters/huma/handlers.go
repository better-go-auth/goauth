// Package humaapikey mounts the api-key plugin's endpoints on a Huma API: POST /api-key/create,
// GET /api-key/get, POST /api-key/update, POST /api-key/delete and GET /api-key/list (better-auth's
// verifyApiKey and deleteAllExpiredApiKeys are server-only and have no route).
package humaapikey

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strconv"

	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins/api-key/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// Handler adapts the service to Huma operations.
type Handler struct {
	Service *services.Service
	Kit     *pluginkit.Kit
}

// NewHandler builds the handler.
func NewHandler(svc *services.Service, kit *pluginkit.Kit) *Handler {
	return &Handler{Service: svc, Kit: kit}
}

// prefixPattern is better-auth's prefix regex.
var prefixPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// validationError is better-call's 400 VALIDATION_ERROR for one invalid field.
func validationError(location, message string) error {
	return autherr.ErrValidationError.WithMessage("[" + location + "] " + message)
}

// sessionNoCache is better-auth's getSessionFromCtx(ctx, {disableCookieCache: true}): a session attached to
// the request (an API key's), or the one of the session cookie / bearer token read from the store.
func (h *Handler) sessionNoCache(ctx context.Context) *dtos.SessionWithUser {
	// Step 1: a session already attached (API-key session)
	if sw := h.Kit.Current(ctx); sw != nil {
		return sw
	}
	// Step 2: the signed session cookie, else the bearer token, looked up in the store
	req := h.Kit.Request(ctx)
	if req == nil {
		return nil
	}
	tok, ok := h.Kit.Cookies.SessionToken(req.Header.Get("Cookie"))
	if !ok {
		tok, ok = humaadapter.FromBearerContext(ctx)
	}
	if !ok {
		return nil
	}
	sw, err := h.Kit.Sessions.Get(ctx, tok)
	if err != nil {
		return nil
	}
	return sw
}

// ─── Raw body fields ─────────────────────────────────────────────────────────

// rawFields holds the top-level members of a JSON body, so absent, null and set values can be told apart
// (zod's optional / nullable).
type rawFields map[string]json.RawMessage

// parseRaw splits a JSON object body into its members (an empty body has none).
func parseRaw(raw []byte) rawFields {
	out := rawFields{}
	if len(bytes.TrimSpace(raw)) == 0 {
		return out
	}
	_ = json.Unmarshal(raw, &out)
	return out
}

// isNull reports whether the member is present and null.
func (f rawFields) isNull(name string) bool {
	v, ok := f[name]
	return ok && bytes.Equal(bytes.TrimSpace(v), []byte("null"))
}

// has reports whether the member is present (null included).
func (f rawFields) has(name string) bool {
	_, ok := f[name]
	return ok
}

// notNull rejects null for members zod declares optional but not nullable.
func (f rawFields) notNull(names ...string) error {
	for _, n := range names {
		if f.isNull(n) {
			return validationError("body."+n, "Invalid input: expected value, received null")
		}
	}
	return nil
}

// str returns a string member (nil when absent or null).
func (f rawFields) str(name string) *string {
	var s *string
	if v, ok := f[name]; ok {
		_ = json.Unmarshal(v, &s)
	}
	return s
}

// num returns a number member (nil when absent or null).
func (f rawFields) num(name string) *float64 {
	var n *float64
	if v, ok := f[name]; ok {
		_ = json.Unmarshal(v, &n)
	}
	return n
}

// boolean returns a boolean member (nil when absent or null).
func (f rawFields) boolean(name string) *bool {
	var b *bool
	if v, ok := f[name]; ok {
		_ = json.Unmarshal(v, &b)
	}
	return b
}

// anyValue returns a member decoded as any JSON value (ok=false when absent).
func (f rawFields) anyValue(name string) (any, bool) {
	v, ok := f[name]
	if !ok {
		return nil, false
	}
	var out any
	_ = json.Unmarshal(v, &out)
	return out, true
}

// coerceString is zod's z.coerce.string(): String(value) of any member (nil when absent).
func (f rawFields) coerceString(name string) *string {
	v, ok := f.anyValue(name)
	if !ok {
		return nil
	}
	var s string
	switch x := v.(type) {
	case nil:
		s = "null"
	case string:
		s = x
	case bool:
		s = strconv.FormatBool(x)
	case float64:
		s = strconv.FormatFloat(x, 'f', -1, 64)
	case []any:
		parts := make([]string, len(x))
		for i, p := range x {
			parts[i] = fmt.Sprint(p)
		}
		s = joinComma(parts)
	default:
		s = "[object Object]"
	}
	return &s
}

// joinComma is Array.prototype.join(",").
func joinComma(parts []string) string {
	var b bytes.Buffer
	for i, p := range parts {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(p)
	}
	return b.String()
}

// permissions returns the permissions member ({resource: [actions]}); nil when absent or null.
func (f rawFields) permissions(name string) map[string][]string {
	var p map[string][]string
	if v, ok := f[name]; ok {
		_ = json.Unmarshal(v, &p)
		if p == nil && !f.isNull(name) {
			p = map[string][]string{}
		}
	}
	return p
}

// minimum checks a number member against zod's .min(n).
func minimum(name string, v *float64, n float64) error {
	if v != nil && *v < n {
		return validationError("body."+name, fmt.Sprintf("Too small: expected number to be >=%v", n))
	}
	return nil
}

// toInt converts a JSON number to the integer goauth stores (better-auth's number columns).
func toInt(v *float64) *int64 {
	if v == nil {
		return nil
	}
	n := int64(math.Round(*v))
	return &n
}

// ─── POST /api-key/create ────────────────────────────────────────────────────

// CreateAPIKeyBody is the body of POST /api-key/create.
type CreateAPIKeyBody struct {
	ConfigID            *string             `json:"configId,omitempty" doc:"The configuration ID to use for the API key. If not provided, the default configuration will be used."`
	Name                *string             `json:"name,omitempty" doc:"Name of the Api Key"`
	ExpiresIn           *float64            `json:"expiresIn,omitempty" nullable:"true" doc:"Expiration time of the Api Key in seconds"`
	Prefix              *string             `json:"prefix,omitempty" doc:"Prefix of the Api Key"`
	Remaining           *float64            `json:"remaining,omitempty" nullable:"true" doc:"Remaining number of requests. Server side only"`
	Metadata            any                 `json:"metadata,omitempty"`
	RefillAmount        *float64            `json:"refillAmount,omitempty" doc:"Amount to refill the remaining count of the Api Key. server-only. Eg: 100"`
	RefillInterval      *float64            `json:"refillInterval,omitempty" doc:"Interval to refill the Api Key in milliseconds. server-only. Eg: 1000"`
	RateLimitTimeWindow *float64            `json:"rateLimitTimeWindow,omitempty" doc:"The duration in milliseconds where each request is counted. server-only."`
	RateLimitMax        *float64            `json:"rateLimitMax,omitempty" doc:"Maximum amount of requests allowed within a window. server-only."`
	RateLimitEnabled    *bool               `json:"rateLimitEnabled,omitempty" doc:"Whether the key has rate limiting enabled. server-only."`
	Permissions         map[string][]string `json:"permissions,omitempty" doc:"Permissions of the Api Key."`
	UserID              any                 `json:"userId,omitempty" doc:"User Id of the user that the Api Key belongs to. server-only."`
	OrganizationID      any                 `json:"organizationId,omitempty" doc:"Organization Id of the organization that the Api Key belongs to."`
	_                   struct{}            `json:"-" additionalProperties:"true"`
}

type createInput struct {
	RawBody []byte
	Body    CreateAPIKeyBody
}

type createOutput struct {
	Body services.CreateAPIKeyResponse
}

// parseCreate turns the raw body into the service input (zod's createApiKeyBodySchema).
func parseCreate(raw []byte) (services.CreateInput, error) {
	f := parseRaw(raw)
	// Step 1: members that may not be null, the prefix format and number bounds
	if err := f.notNull("configId", "name", "prefix", "refillAmount", "refillInterval", "rateLimitTimeWindow",
		"rateLimitMax", "rateLimitEnabled", "permissions", "organizationId"); err != nil {
		return services.CreateInput{}, err
	}
	in := services.CreateInput{
		Name: f.str("name"), ExpiresIn: f.num("expiresIn"), Prefix: f.str("prefix"),
		RefillAmount: toInt(f.num("refillAmount")), RefillInterval: toInt(f.num("refillInterval")),
		RateLimitTimeWindow: toInt(f.num("rateLimitTimeWindow")), RateLimitMax: toInt(f.num("rateLimitMax")),
		RateLimitEnabled: f.boolean("rateLimitEnabled"), Permissions: f.permissions("permissions"),
		UserID: f.coerceString("userId"), OrganizationID: f.coerceString("organizationId"),
	}
	if id := f.str("configId"); id != nil {
		in.ConfigID = *id
	}
	if in.Prefix != nil && !prefixPattern.MatchString(*in.Prefix) {
		return in, validationError("body.prefix", "Invalid prefix format, must be alphanumeric and contain only underscores and hyphens.")
	}
	if err := minimum("expiresIn", in.ExpiresIn, 1); err != nil {
		return in, err
	}
	remaining := f.num("remaining")
	if err := minimum("remaining", remaining, 0); err != nil {
		return in, err
	}
	if err := minimum("refillAmount", f.num("refillAmount"), 1); err != nil {
		return in, err
	}
	in.Remaining = toInt(remaining)
	// Step 2: metadata as sent (any JSON value)
	if md, ok := f.anyValue("metadata"); ok {
		in.Metadata = md
	}
	return in, nil
}

// Create is POST /api-key/create.
func (h *Handler) Create(ctx context.Context, in *createInput) (*createOutput, error) {
	body, err := parseCreate(in.RawBody)
	if err != nil {
		return nil, err
	}
	res, err := h.Service.Create(ctx, body, services.Call{Client: true, Session: h.sessionNoCache(ctx)})
	if err != nil {
		return nil, err
	}
	return &createOutput{Body: *res}, nil
}

// ─── GET /api-key/get ────────────────────────────────────────────────────────

type getInput struct {
	ID       string `query:"id" required:"true" doc:"The id of the Api Key"`
	ConfigID string `query:"configId" doc:"The configuration ID to use for the API key lookup. If not provided, the default configuration will be used."`
}

type keyOutput struct {
	Body services.APIKeyResponse
}

// Get is GET /api-key/get.
func (h *Handler) Get(ctx context.Context, in *getInput) (*keyOutput, error) {
	sw := h.Kit.Current(ctx)
	res, err := h.Service.Get(ctx, in.ID, in.ConfigID, sw.User.ID)
	if err != nil {
		return nil, err
	}
	return &keyOutput{Body: *res}, nil
}

// ─── POST /api-key/update ────────────────────────────────────────────────────

// UpdateAPIKeyBody is the body of POST /api-key/update.
type UpdateAPIKeyBody struct {
	ConfigID            *string             `json:"configId,omitempty" doc:"The configuration ID to use for the API key lookup."`
	KeyID               string              `json:"keyId" doc:"The id of the Api Key"`
	UserID              any                 `json:"userId,omitempty" doc:"The id of the user which the api key belongs to. server-only."`
	Name                *string             `json:"name,omitempty" doc:"The name of the key"`
	Enabled             *bool               `json:"enabled,omitempty" doc:"Whether the Api Key is enabled or not"`
	Remaining           *float64            `json:"remaining,omitempty" doc:"The number of remaining requests"`
	RefillAmount        *float64            `json:"refillAmount,omitempty" doc:"The refill amount"`
	RefillInterval      *float64            `json:"refillInterval,omitempty" doc:"The refill interval"`
	Metadata            any                 `json:"metadata,omitempty"`
	ExpiresIn           *float64            `json:"expiresIn,omitempty" nullable:"true" doc:"Expiration time of the Api Key in seconds"`
	RateLimitEnabled    *bool               `json:"rateLimitEnabled,omitempty" doc:"Whether the key has rate limiting enabled."`
	RateLimitTimeWindow *float64            `json:"rateLimitTimeWindow,omitempty" doc:"The duration in milliseconds where each request is counted. server-only."`
	RateLimitMax        *float64            `json:"rateLimitMax,omitempty" doc:"Maximum amount of requests allowed within a window. server-only."`
	Permissions         map[string][]string `json:"permissions,omitempty" nullable:"true" doc:"Update the permissions on the API Key. server-only."`
	_                   struct{}            `json:"-" additionalProperties:"true"`
}

type updateInput struct {
	RawBody []byte
	Body    UpdateAPIKeyBody
}

// parseUpdate turns the raw body into the service input (zod's updateApiKeyBodySchema).
func parseUpdate(raw []byte) (services.UpdateInput, error) {
	f := parseRaw(raw)
	// Step 1: members that may not be null and number bounds
	if err := f.notNull("configId", "keyId", "name", "enabled", "remaining", "refillAmount", "refillInterval",
		"rateLimitEnabled", "rateLimitTimeWindow", "rateLimitMax"); err != nil {
		return services.UpdateInput{}, err
	}
	in := services.UpdateInput{
		UserID: f.coerceString("userId"), Name: f.str("name"), Enabled: f.boolean("enabled"),
		RefillAmount: toInt(f.num("refillAmount")), RefillInterval: toInt(f.num("refillInterval")),
		RateLimitEnabled: f.boolean("rateLimitEnabled"), RateLimitTimeWindow: toInt(f.num("rateLimitTimeWindow")),
		RateLimitMax: toInt(f.num("rateLimitMax")),
	}
	if id := f.str("configId"); id != nil {
		in.ConfigID = *id
	}
	if id := f.str("keyId"); id != nil {
		in.KeyID = *id
	}
	remaining := f.num("remaining")
	if err := minimum("remaining", remaining, 1); err != nil {
		return in, err
	}
	in.Remaining = toInt(remaining)
	// Step 2: nullable members (null is a value here)
	if f.has("expiresIn") {
		exp := f.num("expiresIn")
		if err := minimum("expiresIn", exp, 1); err != nil {
			return in, err
		}
		in.ExpiresIn = services.Nullable[float64]{Set: true, Value: exp}
	}
	if f.has("permissions") {
		p := f.permissions("permissions")
		in.Permissions = services.Nullable[map[string][]string]{Set: true}
		if p != nil {
			in.Permissions.Value = &p
		}
	}
	if md, ok := f.anyValue("metadata"); ok {
		in.Metadata = services.Nullable[any]{Set: true}
		if md != nil {
			in.Metadata.Value = &md
		}
	}
	return in, nil
}

// Update is POST /api-key/update.
func (h *Handler) Update(ctx context.Context, in *updateInput) (*keyOutput, error) {
	body, err := parseUpdate(in.RawBody)
	if err != nil {
		return nil, err
	}
	res, err := h.Service.Update(ctx, body, services.Call{Client: true, Session: h.Kit.CurrentOrResolve(ctx)})
	if err != nil {
		return nil, err
	}
	return &keyOutput{Body: *res}, nil
}

// ─── POST /api-key/delete ────────────────────────────────────────────────────

// DeleteAPIKeyBody is the body of POST /api-key/delete.
type DeleteAPIKeyBody struct {
	ConfigID *string  `json:"configId,omitempty" doc:"The configuration ID to use for the API key lookup."`
	KeyID    string   `json:"keyId" doc:"The id of the API key to delete"`
	_        struct{} `json:"-" additionalProperties:"true"`
}

type deleteInput struct {
	Body DeleteAPIKeyBody
}

// DeleteAPIKeySuccess is the body of POST /api-key/delete.
type DeleteAPIKeySuccess struct {
	Success bool `json:"success"`
}

type deleteOutput struct {
	Body DeleteAPIKeySuccess
}

// Delete is POST /api-key/delete.
func (h *Handler) Delete(ctx context.Context, in *deleteInput) (*deleteOutput, error) {
	sw := h.Kit.Current(ctx)
	configID := ""
	if in.Body.ConfigID != nil {
		configID = *in.Body.ConfigID
	}
	if err := h.Service.Delete(ctx, in.Body.KeyID, configID, &sw.User); err != nil {
		return nil, err
	}
	return &deleteOutput{Body: DeleteAPIKeySuccess{Success: true}}, nil
}

// ─── GET /api-key/list ───────────────────────────────────────────────────────

type listInput struct {
	ConfigID       string `query:"configId" doc:"Filter by configuration ID. If not provided, returns keys from all configurations."`
	OrganizationID string `query:"organizationId" doc:"Organization ID to list keys for. If provided, returns organization-owned keys."`
	Limit          string `query:"limit" doc:"The number of API keys to return"`
	Offset         string `query:"offset" doc:"The offset to start from"`
	SortBy         string `query:"sortBy" doc:"The field to sort by (e.g., createdAt, name, expiresAt)"`
	SortDirection  string `query:"sortDirection" doc:"The direction to sort by (asc or desc)"`
}

type listOutput struct {
	Body services.ListResult
}

// nonNegativeInt is zod's z.coerce.number().int().nonnegative() for a query parameter ("" = absent).
func nonNegativeInt(name, raw string) (*int, error) {
	if raw == "" {
		return nil, nil
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || math.IsNaN(f) {
		return nil, validationError("query."+name, "Invalid input: expected number, received NaN")
	}
	if f != math.Trunc(f) {
		return nil, validationError("query."+name, "Invalid input: expected int, received number")
	}
	if f < 0 {
		return nil, validationError("query."+name, "Too small: expected number to be >=0")
	}
	n := int(f)
	return &n, nil
}

// List is GET /api-key/list.
func (h *Handler) List(ctx context.Context, in *listInput) (*listOutput, error) {
	// Step 1: the query (zod's listApiKeysQuerySchema)
	limit, err := nonNegativeInt("limit", in.Limit)
	if err != nil {
		return nil, err
	}
	offset, err := nonNegativeInt("offset", in.Offset)
	if err != nil {
		return nil, err
	}
	if in.SortDirection != "" && in.SortDirection != "asc" && in.SortDirection != "desc" {
		return nil, validationError("query.sortDirection", `Invalid option: expected one of "asc"|"desc"`)
	}
	// Step 2: the keys of the session's user (or an organization)
	sw := h.Kit.Current(ctx)
	res, err := h.Service.List(ctx, services.ListInput{
		ConfigID: in.ConfigID, OrganizationID: in.OrganizationID, Limit: limit, Offset: offset,
		SortBy: in.SortBy, SortDirection: in.SortDirection,
	}, sw.User.ID)
	if err != nil {
		return nil, err
	}
	return &listOutput{Body: *res}, nil
}
