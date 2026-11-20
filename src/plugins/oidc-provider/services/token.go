package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/models"
	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
	"github.com/golang-jwt/jwt/v5"
)

// TokenRequest is one POST /oauth2/token call.
type TokenRequest struct {
	// ContentType and Body are the raw request body (form-urlencoded or JSON).
	ContentType string
	Body        []byte
	// Authorization is the Authorization header (client_secret_basic).
	Authorization string
}

// TokenResponse is the token endpoint's success body.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
	IDToken      string `json:"id_token,omitempty"`
}

// TokenParams are the parsed token request parameters after client authentication.
type TokenParams struct {
	GrantType    string
	Code         string
	RedirectURI  string
	RefreshToken string
	CodeVerifier string
	ClientID     string
	ClientSecret string
}

// ParseTokenRequest reads the body and applies client_secret_basic (the Authorization header supplies
// client_id/client_secret when the body has no client_secret). The returned response is an error answer.
func ParseTokenRequest(req TokenRequest) (*TokenParams, *endpointhooks.Response, error) {
	// Step 1: form or JSON body
	body, err := ReadTokenBody(req.ContentType, req.Body)
	if err != nil {
		return nil, nil, err
	}
	p := &TokenParams{
		GrantType: body["grant_type"], Code: body["code"], RedirectURI: body["redirect_uri"],
		RefreshToken: body["refresh_token"], CodeVerifier: body["code_verifier"],
		ClientID: body["client_id"], ClientSecret: body["client_secret"],
	}
	// Step 2: HTTP Basic client authentication
	if req.Authorization != "" && p.ClientSecret == "" && strings.HasPrefix(req.Authorization, "Basic ") {
		id, secret, ok := BasicCredentials(req.Authorization)
		if !ok {
			return nil, OAuthError(http.StatusUnauthorized, "invalid_client", "invalid authorization header format"), nil
		}
		if p.ClientID != "" && p.ClientID != id {
			return nil, OAuthError(http.StatusUnauthorized, "invalid_client", "client_id in body does not match Authorization header"), nil
		}
		p.ClientID, p.ClientSecret = id, secret
	}
	return p, nil, nil
}

// VerifyPKCE checks code_verifier against the stored challenge ("plain" or S256).
func VerifyPKCE(method, challenge, verifier string) bool {
	if method == "plain" {
		return verifier == challenge
	}
	return S256(verifier) == challenge
}

// Token is better-auth's POST /oauth2/token: the authorization_code and refresh_token grants.
func (s *Service) Token(ctx context.Context, req TokenRequest) (*endpointhooks.Response, error) {
	// Step 1: parameters and client_secret_basic
	p, res, err := ParseTokenRequest(req)
	if err != nil || res != nil {
		return res, err
	}
	// Step 2: lifetimes (seconds, like better-auth)
	iat := time.Now().Unix()
	exp := iat + int64(s.cfg.AccessTokenExpiresIn.Seconds())
	accessTokenExpiresAt := time.Unix(exp, 0)
	refreshTokenExpiresAt := time.Unix(iat+int64(s.cfg.RefreshTokenExpiresIn.Seconds()), 0)
	if p.GrantType == "refresh_token" {
		return s.refreshGrant(ctx, p, iat, accessTokenExpiresAt, refreshTokenExpiresAt)
	}

	// Step 3: authorization_code: the code is consumed before anything else is checked
	if p.Code == "" {
		return OAuthError(http.StatusBadRequest, "invalid_request", "code is required"), nil
	}
	if s.cfg.RequirePKCE && p.CodeVerifier == "" {
		return OAuthError(http.StatusBadRequest, "invalid_request", "code verifier is missing"), nil
	}
	ver, err := s.deps.Kit.Repos.ConsumeVerificationValue(ctx, p.Code)
	if err != nil || ver == nil {
		return OAuthError(http.StatusUnauthorized, "invalid_grant", "invalid code"), nil
	}
	if p.ClientID == "" {
		return OAuthError(http.StatusUnauthorized, "invalid_client", "client_id is required"), nil
	}
	if p.GrantType == "" {
		return OAuthError(http.StatusBadRequest, "invalid_request", "grant_type is required"), nil
	}
	if p.GrantType != "authorization_code" {
		return OAuthError(http.StatusBadRequest, "unsupported_grant_type", "grant_type must be 'authorization_code'"), nil
	}
	if p.RedirectURI == "" {
		return OAuthError(http.StatusBadRequest, "invalid_request", "redirect_uri is required"), nil
	}

	// Step 4: the client and the code must match
	client, err := s.GetClient(ctx, p.ClientID)
	if err != nil || client == nil {
		return OAuthError(http.StatusUnauthorized, "invalid_client", "invalid client_id"), nil
	}
	if client.Disabled {
		return OAuthError(http.StatusUnauthorized, "invalid_client", "client is disabled"), nil
	}
	var value CodeValue
	if err := json.Unmarshal([]byte(ver.Value), &value); err != nil {
		return nil, autherr.Internal(ctx, err)
	}
	if value.ClientID != p.ClientID {
		return OAuthError(http.StatusUnauthorized, "invalid_client", "invalid client_id"), nil
	}
	if value.RedirectURI != p.RedirectURI {
		return OAuthError(http.StatusUnauthorized, "invalid_client", "invalid redirect_uri"), nil
	}
	if value.CodeChallenge != "" && p.CodeVerifier == "" {
		return OAuthError(http.StatusBadRequest, "invalid_request", "code verifier is missing"), nil
	}

	// Step 5: client authentication: PKCE for public clients, the secret for confidential ones
	if client.Type == oidcconfig.ClientTypePublic {
		if p.CodeVerifier == "" {
			return OAuthError(http.StatusBadRequest, "invalid_request", "code verifier is required for public clients"), nil
		}
	} else {
		if client.ClientSecret == "" || p.ClientSecret == "" {
			return OAuthError(http.StatusUnauthorized, "invalid_client", "client_secret is required for confidential clients"), nil
		}
		if !s.VerifyStoredClientSecret(ctx, client.ClientSecret, p.ClientSecret) {
			return OAuthError(http.StatusUnauthorized, "invalid_client", "invalid client_secret"), nil
		}
	}
	if value.CodeChallenge != "" && !VerifyPKCE(value.CodeChallengeMethod, value.CodeChallenge, p.CodeVerifier) {
		return OAuthError(http.StatusUnauthorized, "invalid_request", "code verification failed"), nil
	}

	// Step 6: issue the tokens
	scopes := value.Scope
	if scopes == nil {
		scopes = []string{}
	}
	accessToken := RandomString(32, AlphaLower+AlphaUpper)
	refreshToken := RandomString(32, AlphaUpper+AlphaLower)
	if err := s.CreateAccessToken(ctx, AccessTokenRecord{
		AccessToken: accessToken, RefreshToken: refreshToken,
		AccessTokenExpiresAt: accessTokenExpiresAt, RefreshTokenExpiresAt: refreshTokenExpiresAt,
		ClientID: p.ClientID, UserID: value.UserID, Scopes: strings.Join(scopes, " "), CreatedAt: time.Unix(iat, 0),
	}); err != nil {
		return nil, autherr.Internal(ctx, err)
	}
	user := s.UserByID(ctx, value.UserID)
	if user == nil {
		return OAuthError(http.StatusUnauthorized, "invalid_grant", "user not found"), nil
	}

	// Step 7: the id_token (HS256 with the client secret, or the jwt plugin's key pair); better-auth signs
	// it for every request and only returns it with the openid scope
	claims, err := s.IDTokenClaims(ctx, user, client, scopes, value.Nonce, iat)
	if err != nil {
		return nil, err
	}
	idToken, err := s.signIDToken(ctx, claims, client, p.ClientID, user, iat, exp)
	if err != nil {
		return nil, err
	}
	out := TokenResponse{
		AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: int64(s.cfg.AccessTokenExpiresIn.Seconds()),
		Scope: strings.Join(scopes, " "),
	}
	if contains(scopes, "offline_access") {
		out.RefreshToken = refreshToken
	}
	if contains(scopes, "openid") {
		out.IDToken = idToken
	}
	return NoStore(JSON(http.StatusOK, out)), nil
}

// refreshGrant is the refresh_token grant: a new access/refresh token pair with the old scopes (the old
// pair stays valid, like better-auth).
func (s *Service) refreshGrant(ctx context.Context, p *TokenParams, iat int64, atExp, rtExp time.Time) (*endpointhooks.Response, error) {
	// Step 1: the refresh token must exist, belong to the client and be live
	if p.RefreshToken == "" {
		return OAuthError(http.StatusBadRequest, "invalid_request", "refresh_token is required"), nil
	}
	tok, err := s.FindAccessToken(ctx, "refreshToken", p.RefreshToken)
	if err != nil || tok == nil {
		return OAuthError(http.StatusUnauthorized, "invalid_grant", "invalid refresh token"), nil
	}
	if tok.ClientID != p.ClientID {
		return OAuthError(http.StatusUnauthorized, "invalid_client", "invalid client_id"), nil
	}
	if tok.RefreshTokenExpiresAt.Before(time.Now()) {
		return OAuthError(http.StatusUnauthorized, "invalid_grant", "refresh token expired"), nil
	}
	// Step 2: client authentication
	client, err := s.GetClient(ctx, p.ClientID)
	if err != nil || client == nil {
		return OAuthError(http.StatusUnauthorized, "invalid_client", "invalid client_id"), nil
	}
	if client.Disabled {
		return OAuthError(http.StatusUnauthorized, "invalid_client", "client is disabled"), nil
	}
	if client.Type != oidcconfig.ClientTypePublic {
		if client.ClientSecret == "" || p.ClientSecret == "" {
			return OAuthError(http.StatusUnauthorized, "invalid_client", "client_secret is required for confidential clients"), nil
		}
		if !s.VerifyStoredClientSecret(ctx, client.ClientSecret, p.ClientSecret) {
			return OAuthError(http.StatusUnauthorized, "invalid_client", "invalid client_secret"), nil
		}
	}
	// Step 3: the new pair
	accessToken := RandomString(32, AlphaLower+AlphaUpper)
	newRefresh := RandomString(32, AlphaLower+AlphaUpper)
	if err := s.CreateAccessToken(ctx, AccessTokenRecord{
		AccessToken: accessToken, RefreshToken: newRefresh, AccessTokenExpiresAt: atExp, RefreshTokenExpiresAt: rtExp,
		ClientID: p.ClientID, UserID: tok.UserID, Scopes: tok.Scopes, CreatedAt: time.Unix(iat, 0),
	}); err != nil {
		return nil, autherr.Internal(ctx, err)
	}
	return JSON(http.StatusOK, TokenResponse{
		AccessToken: accessToken, TokenType: "Bearer", ExpiresIn: int64(s.cfg.AccessTokenExpiresIn.Seconds()),
		RefreshToken: newRefresh, Scope: tok.Scopes,
	}), nil
}

// IDTokenClaims are the id_token claims better-auth puts in the payload: sub, aud, iat, nonce, acr, the
// profile/email claims of the granted scopes and GetAdditionalUserInfoClaim's claims.
func (s *Service) IDTokenClaims(ctx context.Context, user *models.User, client *oidcconfig.Client, scopes []string, nonce string, iat int64) (map[string]any, error) {
	// Step 1: the registered claims
	claims := map[string]any{"sub": user.ID, "aud": client.ClientID, "iat": iat, "acr": "urn:mace:incommon:iap:silver"}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	// Step 2: scope claims (profile.updated_at is an ISO string in the oidc-provider)
	if contains(scopes, "profile") {
		for k, v := range ProfileClaims(user) {
			claims[k] = v
		}
		claims["updated_at"] = user.UpdatedAt.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	if contains(scopes, "email") {
		claims["email"] = user.Email
		claims["email_verified"] = user.EmailVerified
	}
	// Step 3: additional claims
	if s.cfg.GetAdditionalUserInfoClaim != nil {
		extra, err := s.cfg.GetAdditionalUserInfoClaim(ctx, user, scopes, client)
		if err != nil {
			return nil, err
		}
		for k, v := range extra {
			claims[k] = v
		}
	}
	return claims, nil
}

// ProfileClaims are the profile scope claims (given_name/family_name split the name at spaces; profile is
// the image URL or null). updated_at is added by the caller.
func ProfileClaims(user *models.User) map[string]any {
	parts := strings.Split(user.Name, " ")
	out := map[string]any{"given_name": parts[0], "name": user.Name, "profile": nil}
	if len(parts) > 1 {
		out["family_name"] = parts[1]
	}
	if user.Image != nil {
		out["profile"] = *user.Image
	}
	return out
}

// signIDToken signs the id_token: HS256 with the stored client secret (no iss claim, like better-auth), or
// with the jwt plugin (iss = the jwt issuer or the base URL, kid of the active key).
func (s *Service) signIDToken(ctx context.Context, claims map[string]any, client *oidcconfig.Client, clientID string, user *models.User, iat, exp int64) (string, error) {
	// Step 1: the jwt plugin
	if s.cfg.UseJWTPlugin {
		j := s.jwt()
		if j == nil {
			logger.Error("OIDC: `useJWTPlugin` is enabled but the JWT plugin is not available. Make sure you have the JWT Plugin in your plugins array or set `useJWTPlugin` to false.")
			return "", autherr.Internal(ctx, errors.New("JWT plugin is not enabled"))
		}
		payload := map[string]any{"iat": iat}
		for k, v := range claims {
			payload[k] = v
		}
		payload["sub"] = user.ID
		payload["aud"] = clientID
		iss := j.Config().JWT.Issuer
		if iss == "" {
			iss = strings.TrimRight(s.deps.Kit.Conf.BaseURL, "/")
		}
		if iss != "" {
			payload["iss"] = iss
		}
		payload["exp"] = time.Now().Unix() + int64(s.cfg.AccessTokenExpiresIn.Seconds())
		return j.SignJWT(ctx, payload, nil)
	}
	// Step 2: HS256 with the client secret as stored
	if client.ClientSecret == "" {
		return "", autherr.Internal(ctx, errors.New("oidc-provider: cannot sign an HS256 id_token without a client secret"))
	}
	mc := jwt.MapClaims{}
	for k, v := range claims {
		mc[k] = v
	}
	mc["iat"] = iat
	mc["exp"] = exp
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, mc)
	delete(tok.Header, "typ")
	return tok.SignedString([]byte(client.ClientSecret))
}

// ─── access token records ────────────────────────────────────────────────────

// AccessTokenRecord is a row of oauthAccessToken.
type AccessTokenRecord struct {
	ID                    string
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  time.Time
	RefreshTokenExpiresAt time.Time
	ClientID              string
	UserID                string
	Scopes                string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}

// CreateAccessToken inserts an oauthAccessToken row (createdAt = updatedAt).
func (s *Service) CreateAccessToken(ctx context.Context, r AccessTokenRecord) error {
	data := adapter.Record{
		"accessToken": r.AccessToken, "refreshToken": r.RefreshToken,
		"accessTokenExpiresAt": r.AccessTokenExpiresAt, "refreshTokenExpiresAt": r.RefreshTokenExpiresAt,
		"clientId": r.ClientID, "scopes": r.Scopes, "createdAt": r.CreatedAt, "updatedAt": r.CreatedAt,
	}
	if r.UserID != "" {
		data["userId"] = r.UserID
	}
	_, err := s.deps.Store.Create(ctx, oidcconfig.ModelOAuthAccessToken, data)
	return err
}

// FindAccessToken returns the oauthAccessToken row whose field (accessToken or refreshToken) is value.
func (s *Service) FindAccessToken(ctx context.Context, field, value string) (*AccessTokenRecord, error) {
	rec, err := s.FindAccessTokenRecord(ctx, field, value)
	if err != nil || rec == nil {
		return nil, err
	}
	return AccessTokenFromRecord(rec), nil
}

// FindAccessTokenRecord returns the raw oauthAccessToken record (nil when missing).
func (s *Service) FindAccessTokenRecord(ctx context.Context, field, value string) (adapter.Record, error) {
	return s.findOne(ctx, oidcconfig.ModelOAuthAccessToken, []adapter.Where{{Field: field, Value: value}})
}

// AccessTokenFromRecord converts an oauthAccessToken record.
func AccessTokenFromRecord(rec adapter.Record) *AccessTokenRecord {
	return &AccessTokenRecord{
		ID: str(rec["id"]), AccessToken: str(rec["accessToken"]), RefreshToken: str(rec["refreshToken"]),
		AccessTokenExpiresAt: timeOf(rec["accessTokenExpiresAt"]), RefreshTokenExpiresAt: timeOf(rec["refreshTokenExpiresAt"]),
		ClientID: str(rec["clientId"]), UserID: str(rec["userId"]), Scopes: str(rec["scopes"]),
		CreatedAt: timeOf(rec["createdAt"]), UpdatedAt: timeOf(rec["updatedAt"]),
	}
}
