package services

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	oidcconfig "github.com/better-go-auth/goauth/src/plugins/oidc-provider/config"
	"github.com/better-go-auth/goauth/src/providers/cookies"
)

// Cookie names of the authorization flow. They are set as is (no cookie prefix), signed with the auth
// secret, like better-auth's ctx.setSignedCookie("oidc_login_prompt", ...).
const (
	LoginPromptCookie   = "oidc_login_prompt"
	ConsentPromptCookie = "oidc_consent_prompt"
)

// promptCookieMaxAge is the lifetime of the flow cookies (600 seconds).
const promptCookieMaxAge = 600

// AuthorizeRequest is one /oauth2/authorize call (or its resumption by the after hook).
type AuthorizeRequest struct {
	// Query holds the authorization parameters (better-auth's ctx.query); a missing key is undefined.
	Query map[string]string
	// RawQuery is the request URL's query string, nil when the URL has no '?'.
	RawQuery *string
	// Headers are the request headers (Sec-Fetch-Mode decides between a redirect and a JSON answer).
	Headers http.Header
	// Session is the signed-in user (nil when there is none).
	Session *dtos.SessionWithUser
}

// CodeValue is the JSON stored in the verification row of an authorization (or consent) code
// (better-auth's CodeVerificationValue).
type CodeValue struct {
	ClientID            string   `json:"clientId"`
	RedirectURI         string   `json:"redirectURI"`
	Scope               []string `json:"scope"`
	UserID              string   `json:"userId"`
	AuthTime            int64    `json:"authTime"`
	RequireConsent      bool     `json:"requireConsent"`
	State               *string  `json:"state"`
	CodeChallenge       string   `json:"codeChallenge,omitempty"`
	CodeChallengeMethod string   `json:"codeChallengeMethod,omitempty"`
	Nonce               string   `json:"nonce,omitempty"`
}

// SignedFlowCookie builds a flow cookie the way better-call's setSignedCookie does with
// {maxAge: 600, path: "/", sameSite: "lax"}: exact name, signed value, no HttpOnly or Secure.
func (s *Service) SignedFlowCookie(name, value string) http.Cookie {
	signed := EncodeURIComponent(cookies.SignCookieValue(value, s.deps.Kit.Cookies.Secret()))
	return http.Cookie{Name: name, Value: signed, MaxAge: promptCookieMaxAge, Path: "/", SameSite: http.SameSiteLaxMode}
}

// ExpiredFlowCookie is better-auth's expireCookie(ctx, {name, attributes: {path: "/"}}).
func ExpiredFlowCookie(name string) http.Cookie {
	return http.Cookie{Name: name, Value: "", MaxAge: -1, Path: "/"}
}

// ReadFlowCookie returns the verified value of a flow cookie from a Cookie header.
func (s *Service) ReadFlowCookie(cookieHeader, name string) (string, bool) {
	r := &http.Request{Header: http.Header{"Cookie": {cookieHeader}}}
	c, err := r.Cookie(name)
	if err != nil || c.Value == "" {
		return "", false
	}
	return s.deps.Kit.Cookies.Verify(cookies.DecodeCookieValue(c.Value))
}

// QueryJSON encodes the authorization query for the oidc_login_prompt cookie (JSON.stringify(ctx.query)).
func QueryJSON(q map[string]string) string {
	b, _ := json.Marshal(q)
	return string(b)
}

// QueryFromJSON decodes the oidc_login_prompt cookie back into a query (ok false for invalid JSON).
func QueryFromJSON(raw string) (map[string]string, bool) {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil || m == nil {
		return nil, false
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if s, ok := JSString(v); ok {
			out[k] = s
		}
	}
	return out, true
}

// ErrorURL is the oidc-provider's getErrorURL: onAPIError.errorURL, else <baseURL>/error, with the
// error appended unencoded.
func (s *Service) ErrorURL(ctx context.Context, code, description string) string {
	base := s.deps.Kit.Conf.OnAPIError.ErrorURL
	if base == "" {
		base = s.deps.Kit.BaseURL(ctx) + "/error"
	}
	return FormatErrorURL(base, code, description)
}

// loginPageURL is `${loginPage}?${queryFromURL}` (better-auth writes "undefined" when the URL has no query).
func loginPageURL(loginPage string, rawQuery *string) string {
	q := "undefined"
	if rawQuery != nil {
		q = *rawQuery
	}
	return loginPage + "?" + q
}

// Authorize is better-auth's oidc-provider authorize(): it validates the request, asks for login or
// consent when needed, and answers with the redirect carrying the authorization code.
func (s *Service) Authorize(ctx context.Context, req AuthorizeRequest) *endpointhooks.Response {
	q := req.Query
	if q == nil {
		q = map[string]string{}
	}
	// Step 1: no session: prompt=none fails at the client's redirect_uri, anything else goes to the login
	// page (the query is kept in the signed oidc_login_prompt cookie for the after hook)
	if req.Session == nil {
		prompt, perr := ParsePrompt(q["prompt"])
		if perr != nil {
			return perr
		}
		if prompt["none"] {
			if q["redirect_uri"] == "" {
				return InvalidRequest("redirect_uri is required when prompt=none and must be usable to return errors without displaying UI")
			}
			if q["client_id"] == "" {
				return InvalidClient("client_id is required")
			}
			client, err := s.GetClient(ctx, q["client_id"])
			if err != nil || client == nil {
				return InvalidClient("client_id is required")
			}
			if !contains(client.RedirectURLs, q["redirect_uri"]) {
				return InvalidRequest("redirect_uri is invalid or not registered for this client")
			}
			return HandleRedirect(req.Headers, FormatErrorURL(q["redirect_uri"], "login_required", "Authentication required but prompt is none"))
		}
		res := HandleRedirect(req.Headers, loginPageURL(s.cfg.LoginPage, req.RawQuery))
		return AddCookie(res, s.SignedFlowCookie(LoginPromptCookie, QueryJSON(q)))
	}

	// Step 2: the client and the redirect_uri (errors before the redirect_uri is trusted go to the error page)
	if q["client_id"] == "" {
		return Redirect(s.ErrorURL(ctx, "invalid_client", "client_id is required"))
	}
	if q["response_type"] == "" {
		return Redirect(s.ErrorURL(ctx, "invalid_request", "response_type is required"))
	}
	client, err := s.GetClient(ctx, q["client_id"])
	if err != nil || client == nil {
		return Redirect(s.ErrorURL(ctx, "invalid_client", "client_id is required"))
	}
	redirectURI, hasRedirect := q["redirect_uri"]
	if !hasRedirect || redirectURI == "" || !contains(client.RedirectURLs, redirectURI) {
		// better-auth shows this as an error instead of redirecting to an unregistered URI
		return MessageError(http.StatusBadRequest, "Invalid redirect URI")
	}
	if client.Disabled {
		return Redirect(s.ErrorURL(ctx, "client_disabled", "client is disabled"))
	}
	if q["response_type"] != "code" {
		return Redirect(s.ErrorURL(ctx, "unsupported_response_type", "unsupported response type"))
	}

	// Step 3: scopes and PKCE (errors go back to the client)
	requestScope := s.requestedScopes(q)
	var invalid []string
	allowed := s.cfg.AllScopes()
	for _, sc := range requestScope {
		if !contains(allowed, sc) {
			invalid = append(invalid, sc)
		}
	}
	if len(invalid) > 0 {
		return HandleRedirect(req.Headers, FormatErrorURL(redirectURI, "invalid_scope", "The following scopes are invalid: "+strings.Join(invalid, ", ")))
	}
	if (q["code_challenge"] == "" || q["code_challenge_method"] == "") && s.cfg.RequirePKCE {
		return HandleRedirect(req.Headers, FormatErrorURL(redirectURI, "invalid_request", "pkce is required"))
	}
	if q["code_challenge_method"] != "" && q["code_challenge"] == "" {
		return HandleRedirect(req.Headers, FormatErrorURL(redirectURI, "invalid_request", "code_challenge_method requires code_challenge"))
	}
	if q["code_challenge"] != "" {
		method, ok := s.challengeMethod(q["code_challenge_method"])
		if !ok {
			return HandleRedirect(req.Headers, FormatErrorURL(redirectURI, "invalid_request", "invalid code_challenge method"))
		}
		q["code_challenge_method"] = method
	}

	// Step 4: consent already given for every requested scope (or a trusted client skipping consent)
	code := RandomString(32, AlphaLower+AlphaUpper+Digits)
	skipConsent := client.SkipConsent
	consented := s.hasConsented(ctx, client.ClientID, req.Session.User.ID, requestScope)
	prompt, perr := ParsePrompt(q["prompt"])
	if perr != nil {
		return perr
	}
	if prompt["none"] && !skipConsent && !consented {
		return HandleRedirect(req.Headers, FormatErrorURL(redirectURI, "consent_required", "Consent required but prompt is none"))
	}
	// Step 5: prompt=login or an old session (max_age) asks for a new login
	requireLogin := prompt["login"]
	if raw, ok := q["max_age"]; ok {
		if maxAge, ok := jsInteger(raw); ok && maxAge >= 0 {
			if time.Since(time.Time(req.Session.Session.CreatedAt)).Seconds() > maxAge {
				requireLogin = true
			}
		}
	}
	requireConsent := !skipConsent && (!consented || prompt["consent"])

	// Step 6: store the code (it doubles as the consent code while consent is pending)
	value := CodeValue{
		ClientID:            client.ClientID,
		RedirectURI:         redirectURI,
		Scope:               requestScope,
		UserID:              req.Session.User.ID,
		AuthTime:            time.Time(req.Session.Session.CreatedAt).UnixMilli(),
		RequireConsent:      requireConsent,
		CodeChallenge:       q["code_challenge"],
		CodeChallengeMethod: q["code_challenge_method"],
		Nonce:               q["nonce"],
	}
	if state, ok := q["state"]; ok && requireConsent {
		value.State = &state
	}
	if err := s.storeCode(ctx, code, value); err != nil {
		return HandleRedirect(req.Headers, FormatErrorURL(redirectURI, "server_error", "An error occurred while processing the request"))
	}

	// Step 7: login required: back to the login page, the query and the code in signed cookies
	if requireLogin {
		state, ok := q["state"]
		if !ok {
			state = "undefined"
		}
		res := HandleRedirect(req.Headers, s.cfg.LoginPage+"?"+Params("client_id", client.ClientID, "code", code, "state", state).Encode())
		AddCookie(res, s.SignedFlowCookie(LoginPromptCookie, QueryJSON(q)))
		return AddCookie(res, s.SignedFlowCookie(ConsentPromptCookie, code))
	}
	// Step 8: no consent needed: the code goes to the client
	if !requireConsent {
		state, ok := q["state"]
		if !ok {
			state = "undefined"
		}
		target, ok := WithSearchParams(redirectURI, "code", code, "state", state)
		if !ok {
			return MessageError(http.StatusBadRequest, "Invalid redirect URI")
		}
		return HandleRedirect(req.Headers, target)
	}
	// Step 9: consent page (consent_code in the URL and in a signed cookie)
	if s.cfg.ConsentPage != "" {
		res := HandleRedirect(req.Headers, s.cfg.ConsentPage+"?"+Params("consent_code", code, "client_id", client.ClientID, "scope", strings.Join(requestScope, " ")).Encode())
		return AddCookie(res, s.SignedFlowCookie(ConsentPromptCookie, code))
	}
	// Step 10: the built-in consent screen
	if s.cfg.GetConsentHTML == nil {
		return MessageError(http.StatusInternalServerError, "No consent page provided")
	}
	return HTML(s.cfg.GetConsentHTML(oidcconfig.ConsentHTMLProps{
		Scopes:         requestScope,
		ClientMetadata: client.Metadata,
		ClientIcon:     client.Icon,
		ClientID:       client.ClientID,
		ClientName:     client.Name,
		Code:           code,
	}))
}

// jsInteger is `Number(raw)` followed by Number.isInteger (an empty string is 0).
func jsInteger(raw string) (float64, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, true
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || f != math.Trunc(f) || math.IsInf(f, 0) {
		return 0, false
	}
	return f, true
}

// requestedScopes is `query.scope?.split(" ").filter(Boolean) || defaultScope.split(" ")`: a present (even
// empty) scope parameter wins over the default scope.
func (s *Service) requestedScopes(q map[string]string) []string {
	if raw, ok := q["scope"]; ok {
		return SplitScopes(raw)
	}
	return strings.Split(s.cfg.DefaultScope, " ")
}

// challengeMethod normalizes code_challenge_method ("s256" or "plain"); ok is false when not allowed.
func (s *Service) challengeMethod(raw string) (string, bool) {
	allowed := []string{"s256"}
	if s.cfg.AllowPlainCodeChallengeMethod {
		allowed = append(allowed, "plain")
	}
	method := strings.ToLower(raw)
	if method == "" && s.cfg.AllowPlainCodeChallengeMethod {
		method = "plain"
	}
	if method == "" || !contains(allowed, method) {
		return "", false
	}
	return method, true
}

// hasConsented reports whether the user consented to every requested scope for the client.
func (s *Service) hasConsented(ctx context.Context, clientID, userID string, scopes []string) bool {
	rec, err := s.findOne(ctx, oidcconfig.ModelOAuthConsent, []adapter.Where{
		{Field: "clientId", Value: clientID},
		{Field: "userId", Value: userID},
	})
	if err != nil || rec == nil {
		return false
	}
	if given, _ := rec["consentGiven"].(bool); !given {
		return false
	}
	consented := []string{}
	if sc := str(rec["scopes"]); sc != "" {
		consented = strings.Split(sc, " ")
	}
	for _, sc := range scopes {
		if !contains(consented, sc) {
			return false
		}
	}
	return true
}

// storeCode writes the code's verification row (better-auth's createVerificationValue).
func (s *Service) storeCode(ctx context.Context, code string, value CodeValue) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = s.deps.Kit.Repos.UpsertVerificationValue(ctx, &models.Verification{
		Base:       models.Base{ID: s.deps.Kit.NewID()},
		Identifier: code,
		Value:      string(raw),
		ExpiresAt:  time.Now().Add(s.cfg.CodeExpiresIn),
	})
	return err
}

// StoreCode is storeCode for the mcp plugin.
func (s *Service) StoreCode(ctx context.Context, code string, value CodeValue) error {
	return s.storeCode(ctx, code, value)
}
