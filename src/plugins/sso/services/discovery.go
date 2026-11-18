package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/plugins/sso/config"
)

// DiscoveryError is better-auth's DiscoveryError: a machine code plus a message (mapped to an API error at
// the edge by mapDiscoveryError).
type DiscoveryError struct {
	Code    string
	Message string
}

func (e *DiscoveryError) Error() string { return e.Message }

// requiredDiscoveryFields are better-auth's REQUIRED_DISCOVERY_FIELDS.
var requiredDiscoveryFields = []string{"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"}

// discoveryTimeout is DEFAULT_DISCOVERY_TIMEOUT.
const discoveryTimeout = 10 * time.Second

// discoverParams are discoverOIDCConfig's parameters.
type discoverParams struct {
	Issuer            string
	DiscoveryEndpoint string
	Existing          *config.OIDCConfig
	IsTrustedOrigin   func(string) bool
}

// discoverOIDCConfig is better-auth's discoverOIDCConfig: fetch, validate and normalize the discovery document,
// then merge it with the existing config (existing values win).
func (s *Service) discoverOIDCConfig(ctx context.Context, p discoverParams) (*config.OIDCConfig, error) {
	existing := p.Existing
	if existing == nil {
		existing = &config.OIDCConfig{}
	}
	// Step 1: the discovery URL (explicit, existing, or <issuer>/.well-known/openid-configuration)
	discoveryURL := p.DiscoveryEndpoint
	if discoveryURL == "" {
		discoveryURL = existing.DiscoveryEndpoint
	}
	if discoveryURL == "" {
		discoveryURL = computeDiscoveryURL(p.Issuer)
	}
	// Step 2: the discovery URL must be a trusted origin
	u, err := parseEndpointURL("discoveryEndpoint", discoveryURL, "")
	if err != nil {
		return nil, err
	}
	if !p.IsTrustedOrigin(u.String()) {
		return nil, &DiscoveryError{Code: "discovery_untrusted_origin", Message: fmt.Sprintf("The main discovery endpoint %q is not trusted by your trusted origins configuration.", u.String())}
	}
	// Step 3: fetch and validate
	doc, err := s.fetchDiscoveryDocument(ctx, discoveryURL)
	if err != nil {
		return nil, err
	}
	if err := validateDiscoveryDocument(doc, p.Issuer); err != nil {
		return nil, err
	}
	// Step 4: normalize the endpoints (relative ones resolve against the issuer) and check their origins
	if err := normalizeDiscoveryURLs(doc, p.Issuer, p.IsTrustedOrigin); err != nil {
		return nil, err
	}
	// Step 5: merge (existing values take precedence)
	out := &config.OIDCConfig{
		Issuer:                      pick(existing.Issuer, str(doc["issuer"])),
		DiscoveryEndpoint:           pick(existing.DiscoveryEndpoint, discoveryURL),
		AuthorizationEndpoint:       pick(existing.AuthorizationEndpoint, str(doc["authorization_endpoint"])),
		TokenEndpoint:               pick(existing.TokenEndpoint, str(doc["token_endpoint"])),
		JWKSEndpoint:                pick(existing.JWKSEndpoint, str(doc["jwks_uri"])),
		UserInfoEndpoint:            pick(existing.UserInfoEndpoint, str(doc["userinfo_endpoint"])),
		TokenEndpointAuthentication: pick(existing.TokenEndpointAuthentication, selectTokenEndpointAuthMethod(doc)),
	}
	return out, nil
}

// computeDiscoveryURL is <issuer without trailing slash>/.well-known/openid-configuration.
func computeDiscoveryURL(issuer string) string {
	return strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
}

// parseEndpointURL is better-auth's parseURL: a valid http(s) URL, optionally relative to base.
func parseEndpointURL(name, endpoint, base string) (*url.URL, error) {
	// Step 1: parse (relative to base when given)
	var (
		u   *url.URL
		err error
	)
	if base != "" {
		var b *url.URL
		if b, err = url.Parse(base); err == nil {
			u, err = b.Parse(endpoint)
		}
	} else {
		u, err = url.Parse(endpoint)
	}
	if err != nil || u == nil || u.Scheme == "" || (u.Host == "" && u.Opaque == "") {
		return nil, &DiscoveryError{Code: "discovery_invalid_url", Message: fmt.Sprintf("The url %q must be valid: %s", name, endpoint)}
	}
	// Step 2: only http and https
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, &DiscoveryError{Code: "discovery_invalid_url", Message: fmt.Sprintf("The url %q must use the http or https supported protocols: %s", name, endpoint)}
	}
	return u, nil
}

// fetchDiscoveryDocument is better-auth's fetchDiscoveryDocument.
func (s *Service) fetchDiscoveryDocument(ctx context.Context, discoveryURL string) (map[string]any, error) {
	// Step 1: GET with the discovery timeout, redirects refused
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, &DiscoveryError{Code: "discovery_unexpected_error", Message: "Unexpected error during discovery: " + err.Error()}
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, &DiscoveryError{Code: "discovery_timeout", Message: "Discovery request timed out"}
		}
		return nil, &DiscoveryError{Code: "discovery_unexpected_error", Message: "Unexpected error during discovery: " + err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	// Step 2: error statuses
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, &DiscoveryError{Code: "discovery_not_found", Message: "Discovery endpoint not found"}
	case resp.StatusCode == http.StatusRequestTimeout:
		return nil, &DiscoveryError{Code: "discovery_timeout", Message: "Discovery request timed out"}
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return nil, &DiscoveryError{Code: "discovery_unexpected_error", Message: "Unexpected discovery error: " + http.StatusText(resp.StatusCode)}
	}
	// Step 3: a JSON object
	if len(strings.TrimSpace(string(body))) == 0 {
		return nil, &DiscoveryError{Code: "discovery_invalid_json", Message: "Discovery endpoint returned an empty response"}
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil || doc == nil {
		return nil, &DiscoveryError{Code: "discovery_invalid_json", Message: "Discovery endpoint returned invalid JSON"}
	}
	return doc, nil
}

// validateDiscoveryDocument checks the required fields and that the issuer matches (trailing slash ignored).
func validateDiscoveryDocument(doc map[string]any, configuredIssuer string) error {
	// Step 1: required fields
	var missing []string
	for _, f := range requiredDiscoveryFields {
		if str(doc[f]) == "" {
			missing = append(missing, f)
		}
	}
	if len(missing) > 0 {
		return &DiscoveryError{Code: "discovery_incomplete", Message: "Discovery document is missing required fields: " + strings.Join(missing, ", ")}
	}
	// Step 2: issuer
	discovered := str(doc["issuer"])
	if strings.TrimSuffix(discovered, "/") != strings.TrimSuffix(configuredIssuer, "/") {
		return &DiscoveryError{Code: "issuer_mismatch", Message: fmt.Sprintf("Discovered issuer %q does not match configured issuer %q", discovered, configuredIssuer)}
	}
	return nil
}

// normalizeDiscoveryURLs is better-auth's normalizeDiscoveryUrls: every endpoint is made absolute (relative to
// the issuer) and must be a trusted origin.
func normalizeDiscoveryURLs(doc map[string]any, issuer string, isTrusted func(string) bool) error {
	for _, name := range []string{"token_endpoint", "authorization_endpoint", "jwks_uri", "userinfo_endpoint", "revocation_endpoint", "end_session_endpoint", "introspection_endpoint"} {
		raw := str(doc[name])
		if raw == "" {
			continue
		}
		u, err := normalizeURL(name, raw, issuer)
		if err != nil {
			return err
		}
		if !isTrusted(u) {
			return &DiscoveryError{Code: "discovery_untrusted_origin", Message: fmt.Sprintf("The %s %q is not trusted by your trusted origins configuration.", name, u)}
		}
		doc[name] = u
	}
	return nil
}

// normalizeURL is better-auth's normalizeUrl: absolute URLs as is, relative ones under the issuer's path.
func normalizeURL(name, endpoint, issuer string) (string, error) {
	if u, err := parseEndpointURL(name, endpoint, ""); err == nil {
		return u.String(), nil
	}
	iu, err := parseEndpointURL(name, issuer, "")
	if err != nil {
		return "", err
	}
	basePath := strings.TrimRight(iu.Path, "/")
	endpointPath := strings.TrimLeft(endpoint, "/")
	u, err := parseEndpointURL(name, basePath+"/"+endpointPath, iu.Scheme+"://"+iu.Host)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// selectTokenEndpointAuthMethod prefers client_secret_basic, then client_secret_post.
func selectTokenEndpointAuthMethod(doc map[string]any) string {
	supported := strs(doc["token_endpoint_auth_methods_supported"])
	for _, m := range supported {
		if m == "client_secret_basic" {
			return "client_secret_basic"
		}
	}
	for _, m := range supported {
		if m == "client_secret_post" {
			return "client_secret_post"
		}
	}
	return "client_secret_basic"
}

// needsRuntimeDiscovery reports a config missing the token, JWKS or authorization endpoint.
func needsRuntimeDiscovery(c *config.OIDCConfig) bool {
	return c == nil || c.TokenEndpoint == "" || c.JWKSEndpoint == "" || c.AuthorizationEndpoint == ""
}

// ensureRuntimeDiscovery is better-auth's ensureRuntimeDiscovery: hydrate a config missing endpoints, then
// re-check the server-side fetched endpoints against SSRF rules.
func (s *Service) ensureRuntimeDiscovery(ctx context.Context, c *config.OIDCConfig, issuer string, isTrusted func(string) bool) (*config.OIDCConfig, error) {
	// Step 1: discovery for incomplete configs
	resolved := *c
	if needsRuntimeDiscovery(c) {
		hydrated, err := s.discoverOIDCConfig(ctx, discoverParams{Issuer: issuer, Existing: c, IsTrustedOrigin: isTrusted})
		if err != nil {
			return nil, err
		}
		resolved.AuthorizationEndpoint = hydrated.AuthorizationEndpoint
		resolved.TokenEndpoint = hydrated.TokenEndpoint
		resolved.TokenEndpointAuthentication = hydrated.TokenEndpointAuthentication
		resolved.UserInfoEndpoint = hydrated.UserInfoEndpoint
		resolved.JWKSEndpoint = hydrated.JWKSEndpoint
	}
	// Step 2: token / userinfo / jwks must be public or trusted, also after DNS resolution
	for _, f := range [][2]string{{"tokenEndpoint", resolved.TokenEndpoint}, {"userInfoEndpoint", resolved.UserInfoEndpoint}, {"jwksEndpoint", resolved.JWKSEndpoint}} {
		if f[1] == "" {
			continue
		}
		if err := validateSkipDiscoveryEndpoint(f[0], f[1], isTrusted); err != nil {
			return nil, err
		}
		if err := s.assertEndpointResolvesPublic(ctx, f[0], f[1], isTrusted); err != nil {
			return nil, err
		}
	}
	return &resolved, nil
}

// validateSkipDiscoveryEndpoint is better-auth's validateSkipDiscoveryEndpoint: a URL must be http(s) and
// publicly routable, unless its origin is trusted (internal IdPs).
func validateSkipDiscoveryEndpoint(name, endpoint string, isTrusted func(string) bool) error {
	u, err := parseEndpointURL(name, endpoint, "")
	if err != nil {
		return err
	}
	if isPublicRoutableHost(u.Hostname()) || isTrusted(u.String()) {
		return nil
	}
	return &DiscoveryError{Code: "discovery_private_host", Message: fmt.Sprintf("The %s URL (%s) is not publicly routable: %s. If this is an internal IdP, add its origin to trustedOrigins.", name, u.String(), u.Hostname())}
}

// validateSkipDiscoveryEndpoints checks every endpoint present in a registration or update body.
func validateSkipDiscoveryEndpoints(c *OIDCEndpoints, isTrusted func(string) bool) error {
	if c == nil {
		return nil
	}
	for _, f := range [][2]string{{"authorizationEndpoint", c.AuthorizationEndpoint}, {"tokenEndpoint", c.TokenEndpoint}, {"userInfoEndpoint", c.UserInfoEndpoint}, {"jwksEndpoint", c.JWKSEndpoint}, {"discoveryEndpoint", c.DiscoveryEndpoint}} {
		if f[1] == "" {
			continue
		}
		if err := validateSkipDiscoveryEndpoint(f[0], f[1], isTrusted); err != nil {
			return err
		}
	}
	return nil
}

// OIDCEndpoints are the endpoint URLs of a registration or update body.
type OIDCEndpoints struct {
	AuthorizationEndpoint, TokenEndpoint, UserInfoEndpoint, JWKSEndpoint, DiscoveryEndpoint string
}

// assertEndpointResolvesPublic is better-auth's assertEndpointResolvesPublic: a host name that resolves to a
// non-public address is refused (trusted origins and IP literals are skipped; resolution errors are ignored).
func (s *Service) assertEndpointResolvesPublic(ctx context.Context, name, endpoint string, isTrusted func(string) bool) error {
	u, err := parseEndpointURL(name, endpoint, "")
	if err != nil {
		return err
	}
	if isTrusted(u.String()) || classifyHost(u.Hostname()).literal != "fqdn" {
		return nil
	}
	addrs, err := s.cfg.LookupHost(ctx, u.Hostname())
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if !isPublicRoutableHost(a) {
			return &DiscoveryError{Code: "discovery_private_host", Message: fmt.Sprintf("The %s host %q resolves to a non-publicly-routable address (%s). If this is an internal IdP, add its origin to trustedOrigins.", name, u.Hostname(), a)}
		}
	}
	return nil
}

// mapDiscoveryError is better-auth's mapDiscoveryErrorToAPIError.
func mapDiscoveryError(err error) error {
	var de *DiscoveryError
	if !errors.As(err, &de) {
		return err
	}
	switch de.Code {
	case "discovery_timeout":
		return codedError(http.StatusBadGateway, de.Code, "OIDC discovery timed out: "+de.Message)
	case "discovery_unexpected_error":
		return codedError(http.StatusBadGateway, de.Code, "OIDC discovery failed: "+de.Message)
	case "discovery_not_found":
		return codedError(http.StatusBadRequest, de.Code, "OIDC discovery endpoint not found. The issuer may not support OIDC discovery, or the URL is incorrect. "+de.Message)
	case "discovery_invalid_url":
		return codedError(http.StatusBadRequest, de.Code, "Invalid OIDC endpoint URL: "+de.Message)
	case "discovery_untrusted_origin":
		return codedError(http.StatusBadRequest, de.Code, "Untrusted OIDC discovery URL: "+de.Message)
	case "discovery_private_host":
		return codedError(http.StatusBadRequest, de.Code, de.Message)
	case "discovery_invalid_json":
		return codedError(http.StatusBadRequest, de.Code, "OIDC discovery returned invalid data: "+de.Message)
	case "discovery_incomplete":
		return codedError(http.StatusBadRequest, de.Code, "OIDC discovery document is missing required fields: "+de.Message)
	case "issuer_mismatch":
		return codedError(http.StatusBadRequest, de.Code, "OIDC issuer mismatch: "+de.Message)
	case "unsupported_token_auth_method":
		return codedError(http.StatusBadRequest, de.Code, "Incompatible OIDC provider: "+de.Message)
	}
	return codedError(http.StatusInternalServerError, "discovery_unexpected_error", "Unexpected discovery error: "+de.Message)
}

// ─── small value helpers ─────────────────────────────────────────────────────

func pick(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func str(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return fmt.Sprintf("%v", t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	}
	return ""
}

func strs(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
