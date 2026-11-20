package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
	"github.com/better-go-auth/goauth/src/providers/cookies"
	"github.com/golang-jwt/jwt/v5"
)

// ─── POST /oauth2/consent ────────────────────────────────────────────────────

// ConsentRequest is one POST /oauth2/consent call.
type ConsentRequest struct {
	// Body is the raw JSON body ({accept, consent_code?}).
	Body []byte
	// CookieHeader carries the oidc_consent_prompt cookie (cookie-based flow).
	CookieHeader string
	// Session is the signed-in user (required).
	Session *dtos.SessionWithUser
}

// consentBody is {accept: boolean, consent_code?: string | null}.
type consentBody struct {
	Accept      bool
	ConsentCode string
}

// parseConsentBody validates the consent body like zod (all issues joined).
func parseConsentBody(raw []byte) (*consentBody, error) {
	if len(raw) == 0 {
		return nil, ValidationError("[body] Invalid input: expected object, received undefined")
	}
	obj, err := DecodeJSONObject(raw)
	if err != nil {
		return nil, objectError(err)
	}
	var issues []string
	out := &consentBody{}
	switch v := obj["accept"].(type) {
	case bool:
		out.Accept = v
	default:
		issues = append(issues, "[body.accept] Invalid input: expected boolean, received "+jsTypeOrUndefined(obj, "accept"))
	}
	switch v := obj["consent_code"].(type) {
	case nil:
	case string:
		out.ConsentCode = v
	default:
		issues = append(issues, "[body.consent_code] Invalid input: expected string, received "+JSType(v))
	}
	if len(issues) > 0 {
		return nil, ValidationError(strings.Join(issues, "; "))
	}
	return out, nil
}

// Consent is better-auth's POST /oauth2/consent: accept turns the consent code into an authorization code
// (and records the consent), deny returns the client's redirect_uri with access_denied.
func (s *Service) Consent(ctx context.Context, req ConsentRequest) (*endpointhooks.Response, error) {
	// Step 1: the body is validated before the session is required (better-call order)
	body, err := parseConsentBody(req.Body)
	if err != nil {
		return nil, err
	}
	if req.Session == nil {
		return nil, autherr.ErrUnauthorized
	}
	// Step 2: the consent code from the body, else from the signed cookie
	consentCode := body.ConsentCode
	if consentCode == "" {
		if v, ok := s.ReadFlowCookie(req.CookieHeader, ConsentPromptCookie); ok {
			consentCode = v
		}
	}
	if consentCode == "" {
		return OAuthError(http.StatusUnauthorized, "invalid_request", "consent_code is required (either in body or cookie)"), nil
	}
	ver, err := s.deps.Kit.Repos.FindVerificationValue(ctx, consentCode)
	if err != nil || ver == nil {
		return OAuthError(http.StatusUnauthorized, "invalid_request", "Invalid code"), nil
	}
	if ver.ExpiresAt.Before(time.Now()) {
		return OAuthError(http.StatusUnauthorized, "invalid_request", "Code expired"), nil
	}
	// Step 3: the cookie is spent; the code must still wait for consent
	expire := ExpiredFlowCookie(ConsentPromptCookie)
	var value CodeValue
	if err := json.Unmarshal([]byte(ver.Value), &value); err != nil {
		return nil, autherr.Internal(ctx, err)
	}
	if !value.RequireConsent {
		return AddCookie(OAuthError(http.StatusUnauthorized, "invalid_request", "Consent not required"), expire), nil
	}
	// Step 4: denied: drop the code and send the user back with access_denied
	if !body.Accept {
		_ = s.deps.Kit.Repos.DeleteVerificationByIdentifier(ctx, consentCode)
		return AddCookie(JSON(http.StatusOK, map[string]string{
			"redirectURI": value.RedirectURI + "?error=access_denied&error_description=User denied access",
		}), expire), nil
	}
	// Step 5: accepted: the consent code becomes a fresh authorization code
	code := RandomString(32, AlphaLower+AlphaUpper+Digits)
	value.RequireConsent = false
	raw, _ := json.Marshal(value)
	if err := s.deps.Kit.Repos.DeleteVerificationByIdentifier(ctx, consentCode); err != nil {
		return nil, autherr.Internal(ctx, err)
	}
	if _, err := s.deps.Kit.Repos.UpsertVerificationValue(ctx, &models.Verification{
		Base: models.Base{ID: ver.ID}, Identifier: code, Value: string(raw), ExpiresAt: time.Now().Add(s.cfg.CodeExpiresIn),
	}); err != nil {
		return nil, autherr.Internal(ctx, err)
	}
	// Step 6: remember the consent for later authorizations
	now := time.Now()
	if _, err := s.deps.Store.Create(ctx, oidcconfig.ModelOAuthConsent, adapter.Record{
		"clientId": value.ClientID, "userId": value.UserID, "scopes": strings.Join(value.Scope, " "),
		"consentGiven": true, "createdAt": now, "updatedAt": now,
	}); err != nil {
		return nil, autherr.Internal(ctx, err)
	}
	// Step 7: the client's redirect_uri with the code (and the state saved at authorization)
	kv := []string{"code", code}
	if value.State != nil && *value.State != "" {
		kv = append(kv, "state", *value.State)
	}
	target, ok := WithSearchParams(value.RedirectURI, kv...)
	if !ok {
		return nil, autherr.Internal(ctx, fmt.Errorf("oidc-provider: invalid redirect URI %q", value.RedirectURI))
	}
	return AddCookie(JSON(http.StatusOK, map[string]string{"redirectURI": target}), expire), nil
}

// ─── GET /oauth2/userinfo ────────────────────────────────────────────────────

// UserInfo is better-auth's GET /oauth2/userinfo: the claims of the access token's scopes.
func (s *Service) UserInfo(ctx context.Context, authorization string) (*endpointhooks.Response, error) {
	// Step 1: the bearer access token must exist and be live
	if authorization == "" {
		return OAuthError(http.StatusUnauthorized, "invalid_request", "authorization header not found"), nil
	}
	token := strings.Replace(authorization, "Bearer ", "", 1)
	at, err := s.FindAccessToken(ctx, "accessToken", token)
	if err != nil || at == nil {
		return OAuthError(http.StatusUnauthorized, "invalid_token", "invalid access token"), nil
	}
	if at.AccessTokenExpiresAt.Before(time.Now()) {
		return OAuthError(http.StatusUnauthorized, "invalid_token", "The Access Token expired"), nil
	}
	client, err := s.GetClient(ctx, at.ClientID)
	if err != nil || client == nil {
		return OAuthError(http.StatusUnauthorized, "invalid_token", "client not found"), nil
	}
	user := s.UserByID(ctx, at.UserID)
	if user == nil {
		return OAuthError(http.StatusUnauthorized, "invalid_token", "user not found"), nil
	}
	// Step 2: claims of the granted scopes
	scopes := strings.Split(at.Scopes, " ")
	claims := UserInfoClaims(user, scopes)
	// Step 3: additional claims win
	if s.cfg.GetAdditionalUserInfoClaim != nil {
		extra, err := s.cfg.GetAdditionalUserInfoClaim(ctx, user, scopes, client)
		if err != nil {
			return nil, err
		}
		for k, v := range extra {
			claims[k] = v
		}
	}
	return JSON(http.StatusOK, claims), nil
}

// UserInfoClaims are better-auth's base userinfo claims: sub plus the profile and email claims of scopes
// (undefined claims are left out; picture is null for users without an image).
func UserInfoClaims(user *models.User, scopes []string) map[string]any {
	claims := map[string]any{"sub": user.ID}
	if contains(scopes, "email") {
		claims["email"] = user.Email
		claims["email_verified"] = user.EmailVerified
	}
	if contains(scopes, "profile") {
		parts := strings.Split(user.Name, " ")
		claims["name"] = user.Name
		claims["given_name"] = parts[0]
		if len(parts) > 1 {
			claims["family_name"] = parts[1]
		}
		claims["picture"] = nil
		if user.Image != nil {
			claims["picture"] = *user.Image
		}
	}
	return claims
}

// ─── POST /oauth2/register ───────────────────────────────────────────────────

// RegisterBody is the RFC 7591 client metadata of /oauth2/register (and /mcp/register).
type RegisterBody struct {
	RedirectURIs            []string
	TokenEndpointAuthMethod string
	GrantTypes              []string
	ResponseTypes           []string
	ClientName              *string
	ClientURI               *string
	LogoURI                 *string
	Scope                   *string
	Contacts                []string
	TosURI                  *string
	PolicyURI               *string
	JwksURI                 *string
	Jwks                    map[string]any
	Metadata                map[string]any
	SoftwareID              *string
	SoftwareVersion         *string
	SoftwareStatement       *string
}

var (
	authMethods   = []string{"none", "client_secret_basic", "client_secret_post"}
	grantTypeEnum = []string{"authorization_code", "implicit", "password", "client_credentials", "refresh_token",
		"urn:ietf:params:oauth:grant-type:jwt-bearer", "urn:ietf:params:oauth:grant-type:saml2-bearer"}
	responseTypeEnum = []string{"code", "token"}
)

// ParseRegisterBody validates the registration body like better-auth's zod schema (defaults applied:
// token_endpoint_auth_method client_secret_basic, grant_types [authorization_code], response_types [code]).
func ParseRegisterBody(raw []byte) (*RegisterBody, error) {
	// Step 1: the body must be a JSON object
	if len(raw) == 0 {
		return nil, ValidationError("[body] Invalid input: expected object, received undefined")
	}
	obj, err := DecodeJSONObject(raw)
	if err != nil {
		return nil, objectError(err)
	}
	b := &RegisterBody{}
	var issues []string
	// Step 2: redirect_uris (required, safe schemes)
	if arr, ok := obj["redirect_uris"].([]any); ok {
		for i, e := range arr {
			s, ok := e.(string)
			if !ok {
				issues = append(issues, fmt.Sprintf("[body.redirect_uris.%d] Invalid input: expected string, received %s", i, JSType(e)))
				continue
			}
			if !IsSafeURLScheme(s) {
				issues = append(issues, fmt.Sprintf("[body.redirect_uris.%d] redirect_uri cannot use a javascript:, data:, or vbscript: scheme", i))
			}
			b.RedirectURIs = append(b.RedirectURIs, s)
		}
		if b.RedirectURIs == nil {
			b.RedirectURIs = []string{}
		}
	} else {
		issues = append(issues, "[body.redirect_uris] Invalid input: expected array, received "+jsTypeOrUndefined(obj, "redirect_uris"))
	}
	// Step 3: enums with defaults
	b.TokenEndpointAuthMethod = "client_secret_basic"
	if v, present := obj["token_endpoint_auth_method"]; present {
		if s, ok := v.(string); ok && contains(authMethods, s) {
			b.TokenEndpointAuthMethod = s
		} else {
			issues = append(issues, "[body.token_endpoint_auth_method] "+enumMessage(authMethods))
		}
	}
	b.GrantTypes, issues = enumArray(obj, "grant_types", grantTypeEnum, []string{"authorization_code"}, issues)
	b.ResponseTypes, issues = enumArray(obj, "response_types", responseTypeEnum, []string{"code"}, issues)
	// Step 4: optional strings, arrays and records
	strField := func(key string) *string {
		v, present := obj[key]
		if !present {
			return nil
		}
		if s, ok := v.(string); ok {
			return &s
		}
		issues = append(issues, fmt.Sprintf("[body.%s] Invalid input: expected string, received %s", key, JSType(v)))
		return nil
	}
	b.ClientName = strField("client_name")
	b.ClientURI = strField("client_uri")
	b.LogoURI = strField("logo_uri")
	b.Scope = strField("scope")
	if v, present := obj["contacts"]; present {
		if arr, ok := v.([]any); ok {
			b.Contacts = []string{}
			for i, e := range arr {
				if s, ok := e.(string); ok {
					b.Contacts = append(b.Contacts, s)
				} else {
					issues = append(issues, fmt.Sprintf("[body.contacts.%d] Invalid input: expected string, received %s", i, JSType(e)))
				}
			}
		} else {
			issues = append(issues, "[body.contacts] Invalid input: expected array, received "+JSType(v))
		}
	}
	b.TosURI = strField("tos_uri")
	b.PolicyURI = strField("policy_uri")
	b.JwksURI = strField("jwks_uri")
	recField := func(key string) map[string]any {
		v, present := obj[key]
		if !present {
			return nil
		}
		if m, ok := v.(map[string]any); ok {
			return m
		}
		issues = append(issues, fmt.Sprintf("[body.%s] Invalid input: expected record, received %s", key, JSType(v)))
		return nil
	}
	b.Jwks = recField("jwks")
	b.Metadata = recField("metadata")
	b.SoftwareID = strField("software_id")
	b.SoftwareVersion = strField("software_version")
	b.SoftwareStatement = strField("software_statement")
	if len(issues) > 0 {
		return nil, ValidationError(strings.Join(issues, "; "))
	}
	return b, nil
}

// CheckRegisterBody applies the RFC 7591 consistency rules (invalid_redirect_uri, invalid_client_metadata).
func CheckRegisterBody(b *RegisterBody) *endpointhooks.Response {
	needsRedirect := b.GrantTypes == nil || contains(b.GrantTypes, "authorization_code") || contains(b.GrantTypes, "implicit")
	if needsRedirect && len(b.RedirectURIs) == 0 {
		return OAuthErrorErrorFirst(http.StatusBadRequest, "invalid_redirect_uri", "Redirect URIs are required for authorization_code and implicit grant types")
	}
	if b.GrantTypes != nil && b.ResponseTypes != nil {
		if contains(b.GrantTypes, "authorization_code") && !contains(b.ResponseTypes, "code") {
			return OAuthErrorErrorFirst(http.StatusBadRequest, "invalid_client_metadata", "When 'authorization_code' grant type is used, 'code' response type must be included")
		}
		if contains(b.GrantTypes, "implicit") && !contains(b.ResponseTypes, "token") {
			return OAuthErrorErrorFirst(http.StatusBadRequest, "invalid_client_metadata", "When 'implicit' grant type is used, 'token' response type must be included")
		}
	}
	return nil
}

// RegistrationResponse is the RFC 7591 response body (undefined members are left out).
type RegistrationResponse struct {
	ClientID                string         `json:"client_id"`
	ClientSecret            string         `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64          `json:"client_id_issued_at"`
	ClientSecretExpiresAt   *int64         `json:"client_secret_expires_at,omitempty"`
	RedirectURIs            []string       `json:"redirect_uris"`
	TokenEndpointAuthMethod string         `json:"token_endpoint_auth_method"`
	GrantTypes              []string       `json:"grant_types"`
	ResponseTypes           []string       `json:"response_types"`
	ClientName              *string        `json:"client_name,omitempty"`
	ClientURI               *string        `json:"client_uri,omitempty"`
	LogoURI                 *string        `json:"logo_uri,omitempty"`
	Scope                   *string        `json:"scope,omitempty"`
	Contacts                []string       `json:"contacts,omitempty"`
	TosURI                  *string        `json:"tos_uri,omitempty"`
	PolicyURI               *string        `json:"policy_uri,omitempty"`
	JwksURI                 *string        `json:"jwks_uri,omitempty"`
	Jwks                    map[string]any `json:"jwks,omitempty"`
	SoftwareID              *string        `json:"software_id,omitempty"`
	SoftwareVersion         *string        `json:"software_version,omitempty"`
	SoftwareStatement       *string        `json:"software_statement,omitempty"`
	Metadata                map[string]any `json:"metadata,omitempty"`
}

// NewRegistrationResponse fills the echo of the registration body.
func NewRegistrationResponse(b *RegisterBody, clientID string) RegistrationResponse {
	return RegistrationResponse{
		ClientID: clientID, ClientIDIssuedAt: time.Now().Unix(),
		RedirectURIs: b.RedirectURIs, TokenEndpointAuthMethod: b.TokenEndpointAuthMethod,
		GrantTypes: b.GrantTypes, ResponseTypes: b.ResponseTypes,
		ClientName: b.ClientName, ClientURI: b.ClientURI, LogoURI: b.LogoURI, Scope: b.Scope, Contacts: b.Contacts,
		TosURI: b.TosURI, PolicyURI: b.PolicyURI, JwksURI: b.JwksURI, Jwks: b.Jwks,
		SoftwareID: b.SoftwareID, SoftwareVersion: b.SoftwareVersion, SoftwareStatement: b.SoftwareStatement,
		Metadata: b.Metadata,
	}
}

// ApplicationRecord builds the oauthApplication row of a registration.
func ApplicationRecord(b *RegisterBody, clientID, storedSecret, clientType string, userID string) adapter.Record {
	now := time.Now()
	rec := adapter.Record{
		"clientId": clientID, "clientSecret": storedSecret, "redirectUrls": strings.Join(b.RedirectURIs, ","),
		"type": clientType, "disabled": false,
		"createdAt": now, "updatedAt": now,
	}
	if b.ClientName != nil {
		rec["name"] = *b.ClientName
	}
	if b.LogoURI != nil {
		rec["icon"] = *b.LogoURI
	}
	if b.Metadata != nil {
		raw, _ := json.Marshal(b.Metadata)
		rec["metadata"] = string(raw)
	}
	if userID != "" {
		rec["userId"] = userID
	}
	// better-auth also passes authenticationScheme, which is not a column of its schema (the adapter drops it)
	return rec
}

// Register is better-auth's POST /oauth2/register (RFC 7591 dynamic client registration). Without a
// session it needs AllowDynamicClientRegistration; the client is always a confidential "web" client.
func (s *Service) Register(ctx context.Context, raw []byte, session *dtos.SessionWithUser) (*endpointhooks.Response, error) {
	// Step 1: validate the body, then the session requirement
	b, err := ParseRegisterBody(raw)
	if err != nil {
		return nil, err
	}
	if session == nil && !s.cfg.AllowDynamicClientRegistration {
		return OAuthErrorErrorFirst(http.StatusUnauthorized, "invalid_token", "Authentication required for client registration"), nil
	}
	if res := CheckRegisterBody(b); res != nil {
		return res, nil
	}
	// Step 2: credentials (the secret is stored according to StoreClientSecret)
	clientID := s.GenerateClientID()
	clientSecret := s.GenerateClientSecret()
	stored, err := s.StoreClientSecret(ctx, clientSecret)
	if err != nil {
		return nil, autherr.Internal(ctx, err)
	}
	userID := ""
	if session != nil {
		userID = session.Session.UserID
	}
	// Step 3: insert the client
	if _, err := s.deps.Store.Create(ctx, oidcconfig.ModelOAuthApplication, ApplicationRecord(b, clientID, stored, oidcconfig.ClientTypeWeb, userID)); err != nil {
		return nil, autherr.Internal(ctx, err)
	}
	// Step 4: RFC 7591 response with the plain secret
	out := NewRegistrationResponse(b, clientID)
	out.ClientSecret = clientSecret
	zero := int64(0)
	out.ClientSecretExpiresAt = &zero
	return NoStore(JSON(http.StatusCreated, out)), nil
}

// GenerateClientID is Config.GenerateClientID or 32 random letters.
func (s *Service) GenerateClientID() string {
	if s.cfg.GenerateClientID != nil {
		if id := s.cfg.GenerateClientID(); id != "" {
			return id
		}
	}
	return RandomString(32, AlphaLower+AlphaUpper)
}

// GenerateClientSecret is Config.GenerateClientSecret or 32 random letters.
func (s *Service) GenerateClientSecret() string {
	if s.cfg.GenerateClientSecret != nil {
		if sec := s.cfg.GenerateClientSecret(); sec != "" {
			return sec
		}
	}
	return RandomString(32, AlphaLower+AlphaUpper)
}

// ─── GET /oauth2/client/{id} ─────────────────────────────────────────────────

// clientInfoBody is the public client info.
type clientInfoBody struct {
	ClientID string  `json:"clientId"`
	Name     string  `json:"name"`
	Icon     *string `json:"icon"`
}

// ClientInfo is better-auth's GET /oauth2/client/:id: the public client info for consent screens.
func (s *Service) ClientInfo(ctx context.Context, id string) *endpointhooks.Response {
	client, err := s.GetClient(ctx, id)
	if err != nil || client == nil {
		return OAuthError(http.StatusNotFound, "not_found", "client not found")
	}
	out := clientInfoBody{ClientID: client.ClientID, Name: client.Name}
	if client.Icon != "" {
		out.Icon = &client.Icon
	}
	return JSON(http.StatusOK, out)
}

// ─── GET|POST /oauth2/endsession ─────────────────────────────────────────────

// EndSessionRequest is one RP-initiated logout call.
type EndSessionRequest struct {
	IDTokenHint           string
	ClientID              string
	PostLogoutRedirectURI string
	State                 string
	// Session is the signed-in user, if any.
	Session *dtos.SessionWithUser
}

// EndSession is better-auth's /oauth2/endsession (OpenID RP-Initiated Logout): it revokes the user's
// OAuth access tokens, ends the session and redirects to a registered post_logout_redirect_uri.
func (s *Service) EndSession(ctx context.Context, req EndSessionRequest) (*endpointhooks.Response, error) {
	// Step 1: id_token_hint names the user and the client when its signature checks out
	var validatedClientID, validatedUserID string
	if req.IDTokenHint != "" {
		validatedClientID, validatedUserID = s.verifyIDTokenHint(ctx, req.IDTokenHint, req.ClientID)
	}
	// Step 2: client_id must exist and match the hint's audience
	if req.ClientID != "" {
		client, err := s.GetClient(ctx, req.ClientID)
		if err != nil || client == nil {
			return OAuthErrorErrorFirst(http.StatusBadRequest, "invalid_client", "Invalid client_id"), nil
		}
		if validatedClientID != "" && validatedClientID != req.ClientID {
			return OAuthErrorErrorFirst(http.StatusBadRequest, "invalid_request", "client_id does not match the ID Token's audience"), nil
		}
		validatedClientID = req.ClientID
	}
	// Step 3: post_logout_redirect_uri must be registered for the client
	if req.PostLogoutRedirectURI != "" {
		if validatedClientID == "" {
			return OAuthErrorErrorFirst(http.StatusBadRequest, "invalid_request", "client_id is required when using post_logout_redirect_uri without a valid id_token_hint"), nil
		}
		client, err := s.GetClient(ctx, validatedClientID)
		if err != nil || client == nil {
			return OAuthErrorErrorFirst(http.StatusBadRequest, "invalid_client", "Invalid client"), nil
		}
		if !contains(client.RedirectURLs, req.PostLogoutRedirectURI) {
			return OAuthErrorErrorFirst(http.StatusBadRequest, "invalid_request", "post_logout_redirect_uri is not registered for this client"), nil
		}
	}
	// Step 4: revoke the user's OAuth tokens and the session
	var out []http.Cookie
	userID := validatedUserID
	if userID == "" && req.Session != nil {
		userID = req.Session.User.ID
	}
	if userID != "" {
		if _, err := s.deps.Store.DeleteMany(ctx, oidcconfig.ModelOAuthAccessToken, []adapter.Where{{Field: "userId", Value: userID}}); err != nil {
			return nil, autherr.Internal(ctx, err)
		}
	}
	if req.Session != nil {
		_ = s.deps.Kit.Sessions.Delete(ctx, req.Session.Session.Token)
		out = append(out, s.deps.Kit.Cookies.ExpireCookie(cookies.CookieSessionToken))
	}
	// Step 5: redirect to the client (with its state), or a JSON confirmation
	var res *endpointhooks.Response
	if req.PostLogoutRedirectURI != "" {
		kv := []string{}
		if req.State != "" {
			kv = append(kv, "state", req.State)
		}
		target, ok := WithSearchParams(req.PostLogoutRedirectURI, kv...)
		if !ok {
			res = OAuthErrorErrorFirst(http.StatusBadRequest, "invalid_request", "Invalid post_logout_redirect_uri format")
		} else {
			res = Redirect(target)
		}
	} else {
		res = JSON(http.StatusOK, map[string]any{"success": true, "message": "Logout successful"})
	}
	for _, c := range out {
		AddCookie(res, c)
	}
	return res, nil
}

// verifyIDTokenHint returns the audience and subject of a valid id_token_hint: verified with the jwt plugin
// when UseJWTPlugin, else as HS256 with client_id's secret. Invalid hints are ignored.
func (s *Service) verifyIDTokenHint(ctx context.Context, hint, clientID string) (aud, sub string) {
	// Step 1: the jwt plugin (better-auth's verifyJWT checks iss and aud against the jwt options)
	if j := s.jwt(); j != nil && s.cfg.UseJWTPlugin {
		claims, err := j.VerifyJWT(ctx, hint, "")
		if err != nil {
			logger.Debug("Invalid id_token_hint provided to end_session endpoint")
			return "", ""
		}
		return audOf(claims["aud"]), str(claims["sub"])
	}
	// Step 2: HS256 with the client secret
	if clientID == "" {
		return "", ""
	}
	client, err := s.GetClient(ctx, clientID)
	if err != nil || client == nil || client.ClientSecret == "" {
		return "", ""
	}
	tok, err := jwt.Parse(hint, func(*jwt.Token) (any, error) { return []byte(client.ClientSecret), nil },
		jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !tok.Valid {
		logger.Debug("Invalid id_token_hint provided to end_session endpoint")
		return "", ""
	}
	claims, _ := tok.Claims.(jwt.MapClaims)
	return audOf(claims["aud"]), str(claims["sub"])
}

// audOf returns a string audience, or the first entry of an array audience.
func audOf(v any) string {
	switch a := v.(type) {
	case string:
		return a
	case []any:
		if len(a) > 0 {
			return str(a[0])
		}
	case []string:
		if len(a) > 0 {
			return a[0]
		}
	}
	return ""
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// jsTypeOrUndefined is the zod type name of obj[key], "undefined" when the key is missing.
func jsTypeOrUndefined(obj map[string]any, key string) string {
	v, ok := obj[key]
	if !ok {
		return "undefined"
	}
	return JSType(v)
}

// objectError turns DecodeJSONObject's record error into the object schema's message.
func objectError(err error) error {
	if ae := autherr.AsAuthError(err); ae != nil && ae.Code == "VALIDATION_ERROR" {
		return ValidationError(strings.Replace(ae.Message, "expected record", "expected object", 1))
	}
	return err
}

// enumMessage is zod's invalid enum option message.
func enumMessage(values []string) string {
	q := make([]string, len(values))
	for i, v := range values {
		q[i] = `"` + v + `"`
	}
	return "Invalid option: expected one of " + strings.Join(q, "|")
}

// enumArray validates an optional array of enum values with a default.
func enumArray(obj map[string]any, key string, enum, def []string, issues []string) ([]string, []string) {
	v, present := obj[key]
	if !present {
		return append([]string{}, def...), issues
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, append(issues, fmt.Sprintf("[body.%s] Invalid input: expected array, received %s", key, JSType(v)))
	}
	out := []string{}
	for i, e := range arr {
		s, ok := e.(string)
		if !ok || !contains(enum, s) {
			issues = append(issues, fmt.Sprintf("[body.%s.%d] %s", key, i, enumMessage(enum)))
			continue
		}
		out = append(out, s)
	}
	return out, issues
}
