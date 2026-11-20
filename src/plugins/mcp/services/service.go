// Package services implements better-auth's mcp plugin: an OAuth 2.1 authorization server for MCP
// (Model Context Protocol) clients on top of the oidc-provider: discovery (RFC 8414) and protected
// resource metadata (RFC 9728), /mcp/authorize, /mcp/token, /mcp/register (open dynamic registration,
// public clients with PKCE) and /mcp/get-session for resource servers.
package services

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/models"
	mcpconfig "github.com/better-go-auth/goauth/src/plugins/mcp/config"
	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
	oidc "github.com/better-go-auth/goauth/src/plugins/oidc-provider/services"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
	"github.com/golang-jwt/jwt/v5"
)

// Service implements the mcp endpoints; Provider is the oidc-provider service it builds on (consent,
// codes, clients, tokens).
type Service struct {
	cfg      mcpconfig.Config
	Provider *oidc.Service
}

// New builds the service around an oidc-provider service configured with cfg.ProviderConfig().
func New(cfg mcpconfig.Config, provider *oidc.Service) *Service {
	return &Service{cfg: cfg, Provider: provider}
}

// Config returns the configuration.
func (s *Service) Config() mcpconfig.Config { return s.cfg }

// opts is the provider configuration (better-auth's opts).
func (s *Service) opts() oidcconfig.Config { return s.Provider.Config() }

// cors adds the CORS headers the mcp endpoints set (Access-Control-Allow-Origin: *, ...).
func cors(res *endpointhooks.Response) *endpointhooks.Response {
	if res.Header == nil {
		res.Header = http.Header{}
	}
	res.Header.Set("Access-Control-Allow-Origin", "*")
	res.Header.Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	res.Header.Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	res.Header.Set("Access-Control-Max-Age", "86400")
	return res
}

// CORS is cors for the Go helpers.
func CORS(res *endpointhooks.Response) *endpointhooks.Response { return cors(res) }

// ─── /mcp/authorize ──────────────────────────────────────────────────────────

// Authorize is better-auth's authorizeMCPOAuth: the oidc-provider's authorization code flow without the
// stored consent (prompt=consent asks for it), always answering with redirects and CORS headers.
func (s *Service) Authorize(ctx context.Context, req oidc.AuthorizeRequest) *endpointhooks.Response {
	return cors(s.authorize(ctx, req))
}

func (s *Service) authorize(ctx context.Context, req oidc.AuthorizeRequest) *endpointhooks.Response {
	kit := s.Provider.Kit()
	opts := s.opts()
	q := req.Query
	if q == nil {
		q = map[string]string{}
	}
	// Step 1: no session: the login page with the query (kept in the signed oidc_login_prompt cookie)
	if req.Session == nil {
		raw := "undefined"
		if req.RawQuery != nil {
			raw = *req.RawQuery
		}
		res := oidc.Redirect(opts.LoginPage + "?" + raw)
		return oidc.AddCookie(res, s.Provider.SignedFlowCookie(oidc.LoginPromptCookie, oidc.QueryJSON(q)))
	}
	// Step 2: the client (database only) and its redirect_uri
	errorBase := kit.BaseURL(ctx) + "/error"
	if q["client_id"] == "" {
		return oidc.Redirect(errorBase + "?error=invalid_client")
	}
	if q["response_type"] == "" {
		return oidc.Redirect(oidc.FormatErrorURL(errorBase, "invalid_request", "response_type is required"))
	}
	client, err := s.Provider.GetStoredClient(ctx, q["client_id"])
	if err != nil || client == nil {
		return oidc.Redirect(errorBase + "?error=invalid_client")
	}
	redirectURI := q["redirect_uri"]
	if redirectURI == "" || !oidc.Contains(client.RedirectURLs, redirectURI) {
		return oidc.MessageError(http.StatusBadRequest, "Invalid redirect URI")
	}
	if client.Disabled {
		return oidc.Redirect(errorBase + "?error=client_disabled")
	}
	if q["response_type"] != "code" {
		return oidc.Redirect(errorBase + "?error=unsupported_response_type")
	}
	// Step 3: scopes and PKCE
	var scopes []string
	if raw, ok := q["scope"]; ok {
		scopes = oidc.SplitScopes(raw)
	} else {
		scopes = strings.Split(opts.DefaultScope, " ")
	}
	var invalid []string
	for _, sc := range scopes {
		if !oidc.Contains(opts.AllScopes(), sc) {
			invalid = append(invalid, sc)
		}
	}
	if len(invalid) > 0 {
		return oidc.Redirect(oidc.FormatErrorURL(redirectURI, "invalid_scope", "The following scopes are invalid: "+strings.Join(invalid, ", ")))
	}
	if (q["code_challenge"] == "" || q["code_challenge_method"] == "") && opts.RequirePKCE {
		return oidc.Redirect(oidc.FormatErrorURL(redirectURI, "invalid_request", "pkce is required"))
	}
	if q["code_challenge_method"] != "" && q["code_challenge"] == "" {
		return oidc.Redirect(oidc.FormatErrorURL(redirectURI, "invalid_request", "code_challenge_method requires code_challenge"))
	}
	if q["code_challenge"] != "" {
		method := strings.ToLower(q["code_challenge_method"])
		if method == "" && opts.AllowPlainCodeChallengeMethod {
			method = "plain"
		}
		if !(method == "s256" || (method == "plain" && opts.AllowPlainCodeChallengeMethod)) {
			return oidc.Redirect(oidc.FormatErrorURL(redirectURI, "invalid_request", "invalid code_challenge method"))
		}
		q["code_challenge_method"] = method
	}
	// Step 4: the code (prompt=consent keeps it pending until /oauth2/consent)
	code := oidc.RandomString(32, oidc.AlphaLower+oidc.AlphaUpper+oidc.Digits)
	consent := q["prompt"] == "consent"
	value := oidc.CodeValue{
		ClientID: client.ClientID, RedirectURI: redirectURI, Scope: scopes, UserID: req.Session.User.ID,
		AuthTime: time.Time(req.Session.Session.CreatedAt).UnixMilli(), RequireConsent: consent,
		CodeChallenge: q["code_challenge"], CodeChallengeMethod: q["code_challenge_method"], Nonce: q["nonce"],
	}
	if state, ok := q["state"]; ok && consent {
		value.State = &state
	}
	if err := s.Provider.StoreCode(ctx, code, value); err != nil {
		return oidc.Redirect(oidc.FormatErrorURL(redirectURI, "server_error", "An error occurred while processing the request"))
	}
	// Step 5: consent page, else the code goes to the client
	if consent && opts.ConsentPage != "" {
		res := oidc.Redirect(opts.ConsentPage + "?" + oidc.Params("consent_code", code, "client_id", client.ClientID, "scope", strings.Join(scopes, " ")).Encode())
		return oidc.AddCookie(res, s.Provider.SignedFlowCookie(oidc.ConsentPromptCookie, code))
	}
	kv := []string{"code", code}
	if st := q["state"]; st != "" {
		kv = append(kv, "state", st)
	}
	target, ok := oidc.WithSearchParams(redirectURI, kv...)
	if !ok {
		return oidc.MessageError(http.StatusBadRequest, "Invalid redirect URI")
	}
	return oidc.Redirect(target)
}

// ─── /mcp/token ──────────────────────────────────────────────────────────────

// Token is better-auth's POST /mcp/token: like /oauth2/token, but clients come from the database only,
// secrets are compared as stored, the refresh grant answers token_type "bearer" and the id_token is signed
// with a throwaway HMAC key (MCP clients use the access token, not the id_token).
func (s *Service) Token(ctx context.Context, req oidc.TokenRequest) (*endpointhooks.Response, error) {
	// Step 1: parameters and client_secret_basic
	p, res, err := oidc.ParseTokenRequest(req)
	if err != nil || res != nil {
		return res, err
	}
	opts := s.opts()
	if p.GrantType == "refresh_token" {
		return s.refresh(ctx, p)
	}
	// Step 2: authorization_code
	if p.Code == "" {
		return oidc.OAuthError(http.StatusBadRequest, "invalid_request", "code is required"), nil
	}
	if opts.RequirePKCE && p.CodeVerifier == "" {
		return oidc.OAuthError(http.StatusBadRequest, "invalid_request", "code verifier is missing"), nil
	}
	ver, err := s.Provider.Kit().Repos.ConsumeVerificationValue(ctx, p.Code)
	if err != nil || ver == nil {
		return oidc.OAuthError(http.StatusUnauthorized, "invalid_grant", "invalid code"), nil
	}
	if p.ClientID == "" {
		return oidc.OAuthError(http.StatusUnauthorized, "invalid_client", "client_id is required"), nil
	}
	if p.GrantType == "" {
		return oidc.OAuthError(http.StatusBadRequest, "invalid_request", "grant_type is required"), nil
	}
	if p.GrantType != "authorization_code" {
		return oidc.OAuthError(http.StatusBadRequest, "unsupported_grant_type", "grant_type must be 'authorization_code'"), nil
	}
	if p.RedirectURI == "" {
		return oidc.OAuthError(http.StatusBadRequest, "invalid_request", "redirect_uri is required"), nil
	}
	// Step 3: client authentication before the code is matched
	client, err := s.Provider.GetStoredClient(ctx, p.ClientID)
	if err != nil || client == nil {
		return oidc.OAuthError(http.StatusUnauthorized, "invalid_client", "invalid client_id"), nil
	}
	if res := authenticateClient(client, p); res != nil {
		return res, nil
	}
	var value oidc.CodeValue
	if err := json.Unmarshal([]byte(ver.Value), &value); err != nil {
		return nil, autherr.Internal(ctx, err)
	}
	if value.ClientID != p.ClientID {
		return oidc.OAuthError(http.StatusUnauthorized, "invalid_client", "invalid client_id"), nil
	}
	if value.RedirectURI != p.RedirectURI {
		return oidc.OAuthError(http.StatusUnauthorized, "invalid_client", "invalid redirect_uri"), nil
	}
	if value.CodeChallenge != "" && p.CodeVerifier == "" {
		return oidc.OAuthError(http.StatusBadRequest, "invalid_request", "code verifier is missing"), nil
	}
	if value.CodeChallenge != "" && !oidc.VerifyPKCE(value.CodeChallengeMethod, value.CodeChallenge, p.CodeVerifier) {
		return oidc.OAuthError(http.StatusUnauthorized, "invalid_request", "code verification failed"), nil
	}
	// Step 4: issue the tokens
	scopes := value.Scope
	if scopes == nil {
		scopes = []string{}
	}
	accessToken := oidc.RandomString(32, oidc.AlphaLower+oidc.AlphaUpper)
	refreshToken := oidc.RandomString(32, oidc.AlphaUpper+oidc.AlphaLower)
	now := time.Now()
	if err := s.Provider.CreateAccessToken(ctx, oidc.AccessTokenRecord{
		AccessToken: accessToken, RefreshToken: refreshToken,
		AccessTokenExpiresAt: now.Add(opts.AccessTokenExpiresIn), RefreshTokenExpiresAt: now.Add(opts.RefreshTokenExpiresIn),
		ClientID: p.ClientID, UserID: value.UserID, Scopes: strings.Join(scopes, " "), CreatedAt: now,
	}); err != nil {
		return nil, autherr.Internal(ctx, err)
	}
	user := s.Provider.UserByID(ctx, value.UserID)
	if user == nil {
		return oidc.OAuthError(http.StatusUnauthorized, "invalid_grant", "user not found"), nil
	}
	// Step 5: the id_token
	idToken, err := s.idToken(ctx, user, client, p.ClientID, scopes, value.Nonce)
	if err != nil {
		return nil, err
	}
	out := oidc.TokenResponse{
		AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: int64(opts.AccessTokenExpiresIn.Seconds()),
		Scope: strings.Join(scopes, " "),
	}
	if oidc.Contains(scopes, "offline_access") {
		out.RefreshToken = refreshToken
	}
	if oidc.Contains(scopes, "openid") {
		out.IDToken = idToken
	}
	return oidc.NoStore(oidc.JSON(http.StatusOK, out)), nil
}

// authenticateClient checks a disabled client and the client secret (public clients need none).
func authenticateClient(client *oidcconfig.Client, p *oidc.TokenParams) *endpointhooks.Response {
	if client.Disabled {
		return oidc.OAuthError(http.StatusUnauthorized, "invalid_client", "client is disabled")
	}
	if client.Type == oidcconfig.ClientTypePublic {
		if p.GrantType != "refresh_token" && p.CodeVerifier == "" {
			return oidc.OAuthError(http.StatusBadRequest, "invalid_request", "code verifier is required for public clients")
		}
		return nil
	}
	if client.ClientSecret == "" || p.ClientSecret == "" {
		return oidc.OAuthError(http.StatusUnauthorized, "invalid_client", "client_secret is required for confidential clients")
	}
	if !authcrypto.SecureEqual(client.ClientSecret, p.ClientSecret) {
		return oidc.OAuthError(http.StatusUnauthorized, "invalid_client", "invalid client_secret")
	}
	return nil
}

// refresh is the refresh_token grant of /mcp/token.
func (s *Service) refresh(ctx context.Context, p *oidc.TokenParams) (*endpointhooks.Response, error) {
	opts := s.opts()
	// Step 1: the refresh token
	if p.RefreshToken == "" {
		return oidc.OAuthError(http.StatusBadRequest, "invalid_request", "refresh_token is required"), nil
	}
	tok, err := s.Provider.FindAccessToken(ctx, "refreshToken", p.RefreshToken)
	if err != nil || tok == nil {
		return oidc.OAuthError(http.StatusUnauthorized, "invalid_grant", "invalid refresh token"), nil
	}
	if tok.ClientID != p.ClientID {
		return oidc.OAuthError(http.StatusUnauthorized, "invalid_client", "invalid client_id"), nil
	}
	if tok.RefreshTokenExpiresAt.Before(time.Now()) {
		return oidc.OAuthError(http.StatusUnauthorized, "invalid_grant", "refresh token expired"), nil
	}
	// Step 2: the client
	client, err := s.Provider.GetStoredClient(ctx, p.ClientID)
	if err != nil || client == nil {
		return oidc.OAuthError(http.StatusUnauthorized, "invalid_client", "invalid client_id"), nil
	}
	if res := authenticateClient(client, p); res != nil {
		return res, nil
	}
	// Step 3: the new pair
	accessToken := oidc.RandomString(32, oidc.AlphaLower+oidc.AlphaUpper)
	newRefresh := oidc.RandomString(32, oidc.AlphaLower+oidc.AlphaUpper)
	now := time.Now()
	if err := s.Provider.CreateAccessToken(ctx, oidc.AccessTokenRecord{
		AccessToken: accessToken, RefreshToken: newRefresh,
		AccessTokenExpiresAt: now.Add(opts.AccessTokenExpiresIn), RefreshTokenExpiresAt: now.Add(opts.RefreshTokenExpiresIn),
		ClientID: p.ClientID, UserID: tok.UserID, Scopes: tok.Scopes, CreatedAt: now,
	}); err != nil {
		return nil, autherr.Internal(ctx, err)
	}
	return oidc.JSON(http.StatusOK, oidc.TokenResponse{
		AccessToken: accessToken, TokenType: "bearer", ExpiresIn: int64(opts.AccessTokenExpiresIn.Seconds()),
		RefreshToken: newRefresh, Scope: tok.Scopes,
	}), nil
}

// idToken signs the mcp id_token with a random HS256 key (better-auth generates a fresh HMAC key per
// request, so the token cannot be verified; it carries the same claims as the oidc-provider's, with
// updated_at in seconds).
func (s *Service) idToken(ctx context.Context, user *models.User, client *oidcconfig.Client, clientID string, scopes []string, nonce string) (string, error) {
	// Step 1: the claims
	now := time.Now().Unix()
	claims := jwt.MapClaims{"sub": user.ID, "aud": clientID, "iat": now, "acr": "urn:mace:incommon:iap:silver",
		"exp": now + int64(s.opts().AccessTokenExpiresIn.Seconds())}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if oidc.Contains(scopes, "profile") {
		for k, v := range oidc.ProfileClaims(user) {
			claims[k] = v
		}
		claims["updated_at"] = user.UpdatedAt.Unix()
	}
	if oidc.Contains(scopes, "email") {
		claims["email"] = user.Email
		claims["email_verified"] = user.EmailVerified
	}
	if fn := s.opts().GetAdditionalUserInfoClaim; fn != nil {
		extra, err := fn(ctx, user, scopes, client)
		if err != nil {
			return "", err
		}
		for k, v := range extra {
			claims[k] = v
		}
	}
	// Step 2: sign with a throwaway key
	key := make([]byte, 64)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	delete(tok.Header, "typ")
	return tok.SignedString(key)
}

// ─── /mcp/register ───────────────────────────────────────────────────────────

// Register is better-auth's POST /mcp/register: open RFC 7591 registration (no session needed);
// token_endpoint_auth_method "none" registers a public client without a secret.
func (s *Service) Register(ctx context.Context, raw []byte, userID string) (*endpointhooks.Response, error) {
	// Step 1: validate
	b, err := oidc.ParseRegisterBody(raw)
	if err != nil {
		return nil, err
	}
	if res := oidc.CheckRegisterBody(b); res != nil {
		return cors(res), nil
	}
	// Step 2: the client (public clients get an empty secret)
	clientID := s.Provider.GenerateClientID()
	secret := s.Provider.GenerateClientSecret()
	clientType := oidcconfig.ClientTypeWeb
	if b.TokenEndpointAuthMethod == "none" {
		clientType, secret = oidcconfig.ClientTypePublic, ""
	}
	if _, err := s.Provider.Store().Create(ctx, oidcconfig.ModelOAuthApplication, oidc.ApplicationRecord(b, clientID, secret, clientType, userID)); err != nil {
		return nil, autherr.Internal(ctx, err)
	}
	// Step 3: the RFC 7591 response
	out := oidc.NewRegistrationResponse(b, clientID)
	if clientType != oidcconfig.ClientTypePublic {
		zero := int64(0)
		out.ClientSecret, out.ClientSecretExpiresAt = secret, &zero
	}
	return cors(oidc.NoStore(oidc.JSON(http.StatusCreated, out))), nil
}

// ─── /mcp/get-session ────────────────────────────────────────────────────────

// Session is the oauthAccessToken record behind a bearer access token (better-auth's getMcpSession).
func (s *Service) Session(ctx context.Context, authorization string) (adapter.Record, error) {
	token := strings.Replace(authorization, "Bearer ", "", 1)
	if token == "" {
		return nil, nil
	}
	return s.Provider.FindAccessTokenRecord(ctx, "accessToken", token)
}

// GetSession is GET /mcp/get-session: the access token record as JSON, or null.
func (s *Service) GetSession(ctx context.Context, authorization string) (*endpointhooks.Response, error) {
	rec, err := s.Session(ctx, authorization)
	if err != nil {
		return nil, autherr.Internal(ctx, err)
	}
	if rec == nil {
		return oidc.JSON(http.StatusOK, nil), nil
	}
	return oidc.JSON(http.StatusOK, RecordJSON(rec)), nil
}

// RecordJSON converts record dates to better-auth's ISO strings (millisecond precision, UTC).
func RecordJSON(rec adapter.Record) map[string]any {
	out := make(map[string]any, len(rec))
	for k, v := range rec {
		if t, ok := v.(time.Time); ok {
			out[k] = t.UTC().Format("2006-01-02T15:04:05.000Z")
			continue
		}
		out[k] = v
	}
	return out
}

// ─── metadata ────────────────────────────────────────────────────────────────

// Metadata is /.well-known/oauth-authorization-server (better-auth's getMCPProviderMetadata); nil when
// no BaseURL is configured (better-auth answers null).
func (s *Service) Metadata(ctx context.Context) map[string]any {
	kit := s.Provider.Kit()
	issuer := strings.TrimRight(kit.Conf.BaseURL, "/")
	base := kit.BaseURL(ctx)
	if issuer == "" || base == "" {
		return nil
	}
	return map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                base + "/mcp/authorize",
		"token_endpoint":                        base + "/mcp/token",
		"userinfo_endpoint":                     base + "/mcp/userinfo",
		"jwks_uri":                              base + "/mcp/jwks",
		"registration_endpoint":                 base + "/mcp/register",
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"acr_values_supported":                  []string{"urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "nbf", "iat", "jti", "email", "email_verified", "name"},
	}
}

// ProtectedResourceMetadata is /.well-known/oauth-protected-resource (better-auth's
// getMCPProtectedResourceMetadata, RFC 9728).
func (s *Service) ProtectedResourceMetadata(ctx context.Context) map[string]any {
	base := s.Provider.Kit().BaseURL(ctx)
	origin := base
	if u, err := url.Parse(base); err == nil && u.Scheme != "" {
		origin = u.Scheme + "://" + u.Host
	}
	resource := s.cfg.Resource
	if resource == "" {
		resource = origin
	}
	md := s.cfg.OIDCConfig.Metadata
	jwks := any(base + "/mcp/jwks")
	if v, ok := md["jwks_uri"]; ok && v != nil {
		jwks = v
	}
	scopes := any([]string{"openid", "profile", "email", "offline_access"})
	if v, ok := md["scopes_supported"]; ok && v != nil {
		scopes = v
	}
	return map[string]any{
		"resource":                              resource,
		"authorization_servers":                 []string{origin},
		"jwks_uri":                              jwks,
		"scopes_supported":                      scopes,
		"bearer_methods_supported":              []string{"header"},
		"resource_signing_alg_values_supported": []string{"RS256"},
	}
}
