package services

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// Alphabets of better-auth's generateRandomString.
const (
	AlphaLower = "abcdefghijklmnopqrstuvwxyz"
	AlphaUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Digits     = "0123456789"
)

// RandomString returns n characters drawn uniformly from alphabet with crypto/rand (better-auth's
// generateRandomString(n, ...alphabets)).
func RandomString(n int, alphabet string) string {
	var b strings.Builder
	max := big.NewInt(int64(len(alphabet)))
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(fmt.Sprintf("oidc-provider: crypto/rand failed: %v", err))
		}
		b.WriteByte(alphabet[idx.Int64()])
	}
	return b.String()
}

// S256 returns base64url(SHA-256(verifier)) without padding (PKCE S256, also the "hashed" client secret).
func S256(v string) string {
	sum := sha256.Sum256([]byte(v))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ─── responses ───────────────────────────────────────────────────────────────

// JSON returns a JSON response (better-auth's ctx.json; HTML characters are not escaped).
func JSON(status int, v any) *endpointhooks.Response { return endpointhooks.JSON(status, v) }

// oauthErrorBody is the body of better-auth's `new APIError(status, {error_description, error})`.
type oauthErrorBody struct {
	ErrorDescription string `json:"error_description"`
	Error            string `json:"error"`
}

// OAuthError is better-auth's APIError with an RFC 6749 body: {"error_description": ..., "error": ...}.
func OAuthError(status int, code, description string) *endpointhooks.Response {
	return JSON(status, oauthErrorBody{ErrorDescription: description, Error: code})
}

// errorFirstBody is the body of the APIErrors that list `error` first (register, end session).
type errorFirstBody struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// OAuthErrorErrorFirst is OAuthError with the keys in the order better-auth writes them for
// /oauth2/register and /oauth2/endsession.
func OAuthErrorErrorFirst(status int, code, description string) *endpointhooks.Response {
	return JSON(status, errorFirstBody{Error: code, ErrorDescription: description})
}

// messageBody is the body of `new APIError(status, {message})`.
type messageBody struct {
	Message string `json:"message"`
}

// MessageError is better-auth's `new APIError(status, {message})`: {"message": ...} without a code.
func MessageError(status int, message string) *endpointhooks.Response {
	return JSON(status, messageBody{Message: message})
}

// providerErrorBody is the body of the oidc-provider's InvalidRequest / InvalidClient errors.
type providerErrorBody struct {
	Message          string `json:"message"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// InvalidRequest is better-auth's oidc-provider InvalidRequest error (400).
func InvalidRequest(description string) *endpointhooks.Response {
	return JSON(http.StatusBadRequest, providerErrorBody{Message: description, Error: "invalid_request", ErrorDescription: description})
}

// InvalidClient is better-auth's oidc-provider InvalidClient error (400).
func InvalidClient(description string) *endpointhooks.Response {
	return JSON(http.StatusBadRequest, providerErrorBody{Message: description, Error: "invalid_client", ErrorDescription: description})
}

// Redirect is better-auth's `throw ctx.redirect(url)`: 302 with Location.
func Redirect(location string) *endpointhooks.Response { return endpointhooks.Redirect(location) }

// redirectBody is the JSON answer of handleRedirect for browser fetch requests.
type redirectBody struct {
	Redirect bool   `json:"redirect"`
	URL      string `json:"url"`
}

// HandleRedirect is the oidc-provider's handleRedirect: browser fetch requests (Sec-Fetch-Mode: cors) get
// {"redirect": true, "url": ...} so the client can navigate, everything else a 302.
func HandleRedirect(headers http.Header, location string) *endpointhooks.Response {
	if headers != nil && headers.Get("Sec-Fetch-Mode") == "cors" {
		return JSON(http.StatusOK, redirectBody{Redirect: true, URL: location})
	}
	return Redirect(location)
}

// HTML returns a text/html response.
func HTML(page string) *endpointhooks.Response {
	return &endpointhooks.Response{Status: http.StatusOK, Header: http.Header{"Content-Type": {"text/html"}}, Body: []byte(page)}
}

// AddCookie appends a Set-Cookie entry to res.
func AddCookie(res *endpointhooks.Response, c http.Cookie) *endpointhooks.Response {
	res.SetCookie(&c)
	return res
}

// NoStore adds the token endpoint's "Cache-Control: no-store" and "Pragma: no-cache".
func NoStore(res *endpointhooks.Response) *endpointhooks.Response {
	res.Header.Set("Cache-Control", "no-store")
	res.Header.Set("Pragma", "no-cache")
	return res
}

// ValidationError is better-call's 400 {"message", "code": "VALIDATION_ERROR"} as a goauth error.
func ValidationError(message string) error {
	return pluginkit.NewError(http.StatusBadRequest, "VALIDATION_ERROR", message)
}

// ─── URLs ────────────────────────────────────────────────────────────────────

// FormatErrorURL is the oidc-provider's formatErrorURL: the values are appended as is (not encoded).
func FormatErrorURL(u, code, description string) string {
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	return u + sep + "error=" + code + "&error_description=" + description
}

// formEscape encodes like the WHATWG application/x-www-form-urlencoded serializer (URLSearchParams):
// alphanumerics and *-._ stay, space becomes '+', everything else is percent-encoded.
func formEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '*', c == '-', c == '.', c == '_':
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// EncodeURIComponent is JavaScript's encodeURIComponent (A-Z a-z 0-9 - _ . ! ~ * ' ( ) stay as is).
func EncodeURIComponent(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', strings.IndexByte("-_.!~*'()", c) >= 0:
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// SearchParams is an ordered query string with URLSearchParams semantics.
type SearchParams struct {
	keys []string
	vals []string
}

// ParseSearchParams parses a raw query (without '?') keeping the order; '+' decodes to a space.
func ParseSearchParams(raw string) *SearchParams {
	sp := &SearchParams{}
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		dk, err := url.QueryUnescape(k)
		if err != nil {
			dk = k
		}
		dv, err := url.QueryUnescape(v)
		if err != nil {
			dv = v
		}
		sp.keys = append(sp.keys, dk)
		sp.vals = append(sp.vals, dv)
	}
	return sp
}

// Keys returns the parameter names in order (repeated names included).
func (sp *SearchParams) Keys() []string { return append([]string{}, sp.keys...) }

// Values returns the parameter values, in the order of Keys.
func (sp *SearchParams) Values() []string { return append([]string{}, sp.vals...) }

// Set replaces the first value of key (removing the others) or appends it (URLSearchParams.set).
func (sp *SearchParams) Set(key, value string) {
	found := false
	keys, vals := sp.keys[:0:0], sp.vals[:0:0]
	for i, k := range sp.keys {
		if k != key {
			keys, vals = append(keys, k), append(vals, sp.vals[i])
			continue
		}
		if !found {
			keys, vals = append(keys, k), append(vals, value)
			found = true
		}
	}
	if !found {
		keys, vals = append(keys, key), append(vals, value)
	}
	sp.keys, sp.vals = keys, vals
}

// Encode serializes like URLSearchParams.toString.
func (sp *SearchParams) Encode() string {
	parts := make([]string, len(sp.keys))
	for i, k := range sp.keys {
		parts[i] = formEscape(k) + "=" + formEscape(sp.vals[i])
	}
	return strings.Join(parts, "&")
}

// Params builds URLSearchParams from ordered key/value pairs.
func Params(kv ...string) *SearchParams {
	sp := &SearchParams{}
	for i := 0; i+1 < len(kv); i += 2 {
		sp.Set(kv[i], kv[i+1])
	}
	return sp
}

// WithSearchParams is `const u = new URL(raw); u.searchParams.set(k, v)...; u.toString()`. ok is false when
// raw is not an absolute URL (new URL throws).
func WithSearchParams(raw string, kv ...string) (string, bool) {
	// Step 1: parse like new URL (absolute only); special schemes get "/" as empty path
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return "", false
	}
	if (u.Scheme == "http" || u.Scheme == "https") && u.Host == "" {
		return "", false
	}
	if (u.Scheme == "http" || u.Scheme == "https") && u.Path == "" && u.RawPath == "" {
		u.Path = "/"
	}
	// Step 2: set the parameters with URLSearchParams semantics (the query is re-serialized)
	sp := ParseSearchParams(u.RawQuery)
	for i := 0; i+1 < len(kv); i += 2 {
		sp.Set(kv[i], kv[i+1])
	}
	u.RawQuery = sp.Encode()
	u.ForceQuery = false
	return u.String(), true
}

// IsSafeURLScheme is better-auth's isSafeUrlScheme: false only for absolute javascript:, data: and
// vbscript: URLs.
func IsSafeURLScheme(v string) bool {
	u, err := url.Parse(strings.TrimSpace(v))
	if err != nil || u.Scheme == "" {
		return true
	}
	switch strings.ToLower(u.Scheme) {
	case "javascript", "data", "vbscript":
		return false
	}
	return true
}

// ─── prompt ──────────────────────────────────────────────────────────────────

// ParsePrompt is better-auth's parsePrompt: the known values of a space-separated prompt. "none" with
// anything else is an InvalidRequest (returned as the error response).
func ParsePrompt(prompt string) (map[string]bool, *endpointhooks.Response) {
	set := map[string]bool{}
	for _, p := range strings.Split(prompt, " ") {
		switch p = strings.TrimSpace(p); p {
		case "login", "consent", "select_account", "none":
			set[p] = true
		}
	}
	if set["none"] && len(set) > 1 {
		return nil, InvalidRequest("prompt none must only be used alone")
	}
	return set, nil
}

// PromptString joins a prompt set back (better-auth keeps insertion order; the order is irrelevant).
func PromptString(prompt string, drop string) string {
	var out []string
	seen := map[string]bool{}
	for _, p := range strings.Split(prompt, " ") {
		p = strings.TrimSpace(p)
		switch p {
		case "login", "consent", "select_account", "none":
			if p != drop && !seen[p] {
				out = append(out, p)
				seen[p] = true
			}
		}
	}
	return strings.Join(out, " ")
}

// ─── request bodies ──────────────────────────────────────────────────────────

// ReadTokenBody is better-call's getBody for the token endpoints (allowedMediaTypes form and JSON) followed
// by the z.record validation. It returns the fields as strings (JS toString of the JSON values).
func ReadTokenBody(contentType string, raw []byte) (map[string]string, error) {
	// Step 1: no body is `undefined`, which the record schema rejects
	if len(raw) == 0 {
		return nil, ValidationError("[body] Invalid input: expected record, received undefined")
	}
	// Step 2: only form and JSON bodies are accepted
	mt, _, _ := mime.ParseMediaType(contentType)
	mt = strings.ToLower(mt)
	switch {
	case mt == "application/x-www-form-urlencoded" || strings.Contains(mt, "application/x-www-form-urlencoded"):
		// malformed pairs are skipped, like the browser's form-data parser
		vals, _ := url.ParseQuery(string(raw))
		out := make(map[string]string, len(vals))
		for k, v := range vals {
			if len(v) > 0 {
				out[k] = v[len(v)-1]
			}
		}
		return out, nil
	case mt == "application/json" || strings.Contains(mt, "application/json"):
		obj, err := DecodeJSONObject(raw)
		if err != nil {
			return nil, err
		}
		out := make(map[string]string, len(obj))
		for k, v := range obj {
			if s, ok := JSString(v); ok {
				out[k] = s
			}
		}
		return out, nil
	case strings.TrimSpace(contentType) == "":
		return nil, pluginkit.NewError(http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE",
			"Content-Type is required. Allowed types: application/x-www-form-urlencoded, application/json")
	default:
		return nil, pluginkit.NewError(http.StatusUnsupportedMediaType, "UNSUPPORTED_MEDIA_TYPE",
			fmt.Sprintf("Content-Type %q is not allowed. Allowed types: application/x-www-form-urlencoded, application/json", contentType))
	}
}

// DecodeJSONObject decodes a JSON object body (numbers as json.Number). Invalid JSON is better-call's 400
// "Invalid JSON in request body"; another JSON type fails the record schema.
func DecodeJSONObject(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, pluginkit.NewError(http.StatusBadRequest, "BAD_REQUEST", "Invalid JSON in request body")
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, ValidationError("[body] Invalid input: expected record, received " + JSType(v))
	}
	return obj, nil
}

// JSType is zod's name of a JSON value's type ("undefined" for a missing value).
func JSType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "boolean"
	case json.Number, float64:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "unknown"
}

// JSString is a JSON value's JavaScript toString; ok is false for null (better-auth reads it as missing).
func JSString(v any) (string, bool) {
	switch t := v.(type) {
	case nil:
		return "", false
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case json.Number:
		return t.String(), true
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i], _ = JSString(e)
		}
		return strings.Join(parts, ","), true
	case map[string]any:
		return "[object Object]", true
	}
	return fmt.Sprint(v), true
}

// BasicCredentials parses an "Authorization: Basic" header like the token endpoint: base64 of
// "<urlencoded id>:<urlencoded secret>". ok is false for a malformed header (invalid_client).
func BasicCredentials(authorization string) (id, secret string, ok bool) {
	// Step 1: decode the base64 payload (padding optional, like better-auth's base64.decode)
	encoded := strings.Replace(authorization, "Basic ", "", 1)
	var decoded []byte
	var err error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err = enc.DecodeString(encoded); err == nil {
			break
		}
	}
	if err != nil {
		return "", "", false
	}
	// Step 2: split at the first colon and URL-decode both parts
	s := string(decoded)
	colon := strings.Index(s, ":")
	if colon == -1 {
		return "", "", false
	}
	if id, err = url.PathUnescape(s[:colon]); err != nil {
		return "", "", false
	}
	if secret, err = url.PathUnescape(s[colon+1:]); err != nil {
		return "", "", false
	}
	if id == "" || secret == "" {
		return "", "", false
	}
	return id, secret, true
}

// SplitScopes splits a space-separated scope list, dropping empty entries.
func SplitScopes(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, " ") {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// contains reports whether list holds v.
func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// Contains reports whether list holds v.
func Contains(list []string, v string) bool { return contains(list, v) }
