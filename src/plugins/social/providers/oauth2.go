package providers

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ─── Authorization URL ───────────────────────────────────────────────────────

// AuthURLParams mirrors the arguments of better-auth's createAuthorizationURL.
type AuthURLParams struct {
	Endpoint     string
	ClientID     string
	State        string
	CodeVerifier string
	Scopes       []string
	ScopeJoiner  string
	RedirectURI  string
	Prompt       string
	AccessType   string
	Display      string
	LoginHint    string
	HD           string
	ResponseType string
	ResponseMode string
	// Additional are appended last, in order.
	Additional [][2]string
}

// orderedQuery keeps insertion order like JavaScript's URLSearchParams.
type orderedQuery struct{ kv [][2]string }

func (q *orderedQuery) set(k, v string) {
	for i := range q.kv {
		if q.kv[i][0] == k {
			q.kv[i][1] = v
			return
		}
	}
	q.kv = append(q.kv, [2]string{k, v})
}

func (q *orderedQuery) encode() string {
	parts := make([]string, 0, len(q.kv))
	for _, p := range q.kv {
		parts = append(parts, url.QueryEscape(p[0])+"="+url.QueryEscape(p[1]))
	}
	return strings.Join(parts, "&")
}

// BuildAuthorizationURL is better-auth's createAuthorizationURL (PKCE S256 when a code verifier is given).
func BuildAuthorizationURL(p AuthURLParams) (*url.URL, error) {
	// Step 1: parse the endpoint, keeping any query it already has
	u, err := url.Parse(p.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("social: invalid authorization endpoint: %w", err)
	}
	q := &orderedQuery{}
	for k, vs := range u.Query() {
		for _, v := range vs {
			q.kv = append(q.kv, [2]string{k, v})
		}
	}
	// Step 2: the standard parameters, in better-auth's order
	q.set("response_type", pick(p.ResponseType, "code"))
	q.set("client_id", p.ClientID)
	q.set("state", p.State)
	if p.Scopes != nil {
		q.set("scope", strings.Join(p.Scopes, pick(p.ScopeJoiner, " ")))
	}
	q.set("redirect_uri", p.RedirectURI)
	optional := [][2]string{{"display", p.Display}, {"login_hint", p.LoginHint}, {"prompt", p.Prompt}, {"hd", p.HD}, {"access_type", p.AccessType}, {"response_mode", p.ResponseMode}}
	for _, kv := range optional {
		if kv[1] != "" {
			q.set(kv[0], kv[1])
		}
	}
	// Step 3: PKCE (S256)
	if p.CodeVerifier != "" {
		q.set("code_challenge_method", "S256")
		q.set("code_challenge", CodeChallenge(p.CodeVerifier))
	}
	// Step 4: provider specific extras
	for _, kv := range p.Additional {
		q.set(kv[0], kv[1])
	}
	u.RawQuery = q.encode()
	return u, nil
}

// CodeChallenge returns the PKCE S256 challenge: base64url(sha256(verifier)) without padding.
func CodeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ─── Token endpoint ──────────────────────────────────────────────────────────

// TokenAuth selects how client credentials are sent to the token endpoint.
type TokenAuth string

const (
	// AuthPost sends client_id / client_secret in the form body (default).
	AuthPost TokenAuth = "post"
	// AuthBasic sends them as HTTP Basic credentials.
	AuthBasic TokenAuth = "basic"
)

// CodeExchange describes an authorization_code grant (better-auth's createAuthorizationCodeRequest).
type CodeExchange struct {
	TokenEndpoint  string
	Code           string
	CodeVerifier   string
	RedirectURI    string
	DeviceID       string
	ClientID       string
	ClientSecret   string
	Authentication TokenAuth
	Extra          map[string]string
	// Headers are extra request headers (better-auth's authorizationHeaders); they never override the
	// client authentication header.
	Headers map[string]string
}

// ExchangeCode posts the authorization code to the token endpoint and parses the tokens.
func ExchangeCode(ctx context.Context, client *http.Client, x CodeExchange) (*OAuth2Tokens, error) {
	// Step 1: build the form body
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", x.Code)
	if x.CodeVerifier != "" {
		form.Set("code_verifier", x.CodeVerifier)
	}
	if x.DeviceID != "" {
		form.Set("device_id", x.DeviceID)
	}
	form.Set("redirect_uri", x.RedirectURI)
	// Step 2: extra headers first, then client authentication (so Basic credentials always win)
	headers := http.Header{}
	for k, v := range x.Headers {
		headers.Set(k, v)
	}
	if x.Authentication == AuthBasic {
		headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(x.ClientID+":"+x.ClientSecret)))
	} else {
		form.Set("client_id", x.ClientID)
		if x.ClientSecret != "" {
			form.Set("client_secret", x.ClientSecret)
		}
	}
	for k, v := range x.Extra {
		if !form.Has(k) {
			form.Set(k, v)
		}
	}
	// Step 3: post and parse
	data, err := postForm(ctx, client, x.TokenEndpoint, form, headers)
	if err != nil {
		return nil, err
	}
	return ParseTokens(data), nil
}

// RefreshRequest describes a refresh_token grant (better-auth's createRefreshAccessTokenRequest).
type RefreshRequest struct {
	TokenEndpoint  string
	RefreshToken   string
	ClientID       string
	ClientSecret   string
	Authentication TokenAuth
	Extra          map[string]string
}

// Refresh posts a refresh_token grant and parses the new tokens.
func Refresh(ctx context.Context, client *http.Client, r RefreshRequest) (*OAuth2Tokens, error) {
	// Step 1: build the form body
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", r.RefreshToken)
	// Step 2: client authentication
	headers := http.Header{}
	if r.Authentication == AuthBasic {
		headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(r.ClientID+":"+r.ClientSecret)))
	} else {
		form.Set("client_id", r.ClientID)
		if r.ClientSecret != "" {
			form.Set("client_secret", r.ClientSecret)
		}
	}
	for k, v := range r.Extra {
		form.Set(k, v)
	}
	// Step 3: post and parse
	data, err := postForm(ctx, client, r.TokenEndpoint, form, headers)
	if err != nil {
		return nil, err
	}
	return ParseTokens(data), nil
}

// ParseTokens is better-auth's getOAuth2Tokens.
func ParseTokens(data map[string]any) *OAuth2Tokens {
	now := time.Now()
	t := &OAuth2Tokens{
		TokenType:    stringOf(data["token_type"]),
		AccessToken:  stringOf(data["access_token"]),
		RefreshToken: stringOf(data["refresh_token"]),
		IDToken:      stringOf(data["id_token"]),
		Raw:          data,
		Scopes:       []string{},
	}
	if s := numberOf(data["expires_in"]); s > 0 {
		at := now.Add(time.Duration(s * float64(time.Second)))
		t.AccessTokenExpiresAt = &at
	}
	if s := numberOf(data["refresh_token_expires_in"]); s > 0 {
		at := now.Add(time.Duration(s * float64(time.Second)))
		t.RefreshTokenExpiresAt = &at
	}
	switch sc := data["scope"].(type) {
	case string:
		if sc != "" {
			t.Scopes = strings.Split(sc, " ")
		}
	case []any:
		for _, v := range sc {
			t.Scopes = append(t.Scopes, stringOf(v))
		}
	}
	return t
}

// ─── HTTP helpers ────────────────────────────────────────────────────────────

// HTTPError is a non-2xx provider response.
type HTTPError struct {
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("social: provider returned %d: %s", e.Status, e.Body)
}

func postForm(ctx context.Context, client *http.Client, endpoint string, form url.Values, headers http.Header) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// caller headers replace the defaults (better-auth spreads them over content-type / accept)
	for k, vs := range headers {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	var out map[string]any
	if err := doJSON(client, req, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// GetJSON GETs endpoint with headers and decodes the JSON response into out.
func GetJSON(ctx context.Context, client *http.Client, endpoint string, headers map[string]string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return doJSON(client, req, out)
}

func doJSON(client *http.Client, req *http.Request, out any) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &HTTPError{Status: resp.StatusCode, Body: string(raw)}
	}
	if err := json.Unmarshal(raw, out); err != nil {
		// some providers (old GitHub) answer form-encoded token responses
		if m, ok := out.(*map[string]any); ok {
			if vals, perr := url.ParseQuery(string(raw)); perr == nil && len(vals) > 0 {
				*m = map[string]any{}
				for k := range vals {
					(*m)[k] = vals.Get(k)
				}
				return nil
			}
		}
		return fmt.Errorf("social: decode provider response: %w", err)
	}
	return nil
}

// bearer returns the Authorization header map for an access token.
func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

// ─── Value helpers ───────────────────────────────────────────────────────────

func stringOf(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	case int:
		return strconv.Itoa(x)
	case int64:
		return strconv.FormatInt(x, 10)
	default:
		return fmt.Sprint(x)
	}
}

func boolOf(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true"
	default:
		return false
	}
}

func numberOf(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	case int64:
		return float64(x)
	case json.Number:
		f, _ := x.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(x, 64)
		return f
	default:
		return 0
	}
}

// DecodeJWT returns the claims of a JWT without verifying it (jose's decodeJwt).
func DecodeJWT(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("social: id token is not a JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, fmt.Errorf("social: decode id token payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("social: parse id token payload: %w", err)
	}
	return claims, nil
}
