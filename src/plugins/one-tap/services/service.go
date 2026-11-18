// Package services implements better-auth's one-tap plugin: POST /one-tap/callback verifies a Google ID
// token and signs the user in (or links / signs up) through the social plugin's handleOAuthUserInfo.
package services

import (
	"context"
	"net/http"
	"strings"

	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins/one-tap/config"
	onetapdtos "github.com/better-go-auth/goauth/src/plugins/one-tap/dtos"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	socialservices "github.com/better-go-auth/goauth/src/plugins/social/services"
)

// ProviderID is the provider id of the accounts one-tap creates (better-auth links them as "google").
const ProviderID = "google"

// Scope is the scope stored on the accounts one-tap creates.
const Scope = "openid,profile,email"

// ErrNoEmailMessage is the `error` of the 200 answer for an ID token without email.
const ErrNoEmailMessage = "Email not available in token"

// ErrInvalidIDToken is better-auth's APIError("BAD_REQUEST", {message: "invalid id token"}). better-auth
// sends no code for it; goauth uses the status name as code, like every message-only error.
var ErrInvalidIDToken = pluginkit.NewError(http.StatusBadRequest, "BAD_REQUEST", "invalid id token")

// SocialSource gives the one-tap plugin the social plugin's settings (the Google client ID and the
// account linking / token storage options). *social.Plugin implements it.
type SocialSource interface {
	Config() socialconfig.SocialConfig
}

// Service verifies One Tap ID tokens and signs users in.
type Service struct {
	kit    *pluginkit.Kit
	cfg    config.OneTapConfig
	social SocialSource
	oauth  *socialservices.Service
}

// New builds the service. social may be nil (account linking defaults, no fallback client ID).
func New(kit *pluginkit.Kit, cfg config.OneTapConfig, social SocialSource) (*Service, error) {
	// Step 1: the social plugin's account options (linking policy, encrypted tokens), or the defaults
	var sc socialconfig.SocialConfig
	if social != nil {
		sc = social.Config()
	}
	// Step 2: one-tap only needs handleOAuthUserInfo, not the providers
	sc.Providers = nil
	oauth, err := socialservices.New(kit, sc)
	if err != nil {
		return nil, err
	}
	return &Service{kit: kit, cfg: cfg.WithDefaults(), social: social, oauth: oauth}, nil
}

// Kit returns the plugin kit.
func (s *Service) Kit() *pluginkit.Kit { return s.kit }

// Config returns the effective configuration.
func (s *Service) Config() config.OneTapConfig { return s.cfg }

// ClientID returns the audience ID tokens must carry: the configured ClientID, else the social plugin's
// "google" provider client ID (resolved on every call, so the social plugin may be configured later).
func (s *Service) ClientID() string {
	if s.cfg.ClientID != "" {
		return s.cfg.ClientID
	}
	if s.social == nil {
		return ""
	}
	for _, p := range s.social.Config().Providers {
		if p != nil && p.ID() == ProviderID {
			return p.Options().ClientID
		}
	}
	return ""
}

// VerifyIDToken verifies idToken's signature against the Google JWKS and its issuer and audience
// (jose's jwtVerify as better-auth calls it) and returns the claims.
func (s *Service) VerifyIDToken(ctx context.Context, idToken string) (map[string]any, error) {
	check := providers.IDTokenCheck{JWKSEndpoint: s.cfg.JWKSURL, Issuers: config.GoogleIssuers}
	if aud := s.ClientID(); aud != "" {
		check.Audiences = []string{aud}
	}
	claims, err := providers.VerifyJWT(ctx, s.cfg.HTTPClient, idToken, check)
	if err != nil {
		return nil, ErrInvalidIDToken
	}
	return claims, nil
}

// CallbackResult is the outcome of Callback: Body is the JSON answer, Session the new session (nil when the
// token has no email).
type CallbackResult struct {
	Body    onetapdtos.CallbackResponse
	Session *dtos.SessionWithUser
}

// Callback is better-auth's oneTapCallback endpoint without the cookie: verify the token, then sign in,
// link or sign up the Google account.
func (s *Service) Callback(ctx context.Context, idToken string) (*CallbackResult, error) {
	// Step 1: the token must be a valid Google ID token for our client
	claims, err := s.VerifyIDToken(ctx, idToken)
	if err != nil {
		return nil, err
	}
	// Step 2: without an email better-auth answers 200 {error}
	rawEmail, _ := claims["email"].(string)
	if rawEmail == "" {
		return &CallbackResult{Body: onetapdtos.CallbackResponse{Error: ErrNoEmailMessage}}, nil
	}
	sub := stringClaim(claims["sub"])
	name, _ := claims["name"].(string)
	picture, _ := claims["picture"].(string)
	// Step 3: sign in, link by email or sign up (social plugin's handleOAuthUserInfo)
	scope := Scope
	res, err := s.oauth.HandleOAuthUserInfo(ctx, socialservices.OAuthUserInput{
		UserInfo: providers.UserInfo{
			ID:            sub,
			Email:         strings.ToLower(rawEmail),
			EmailVerified: toBoolean(claims["email_verified"]),
			Name:          name,
			Image:         picture,
		},
		Account: socialservices.AccountData{
			ProviderID: ProviderID,
			AccountID:  sub,
			IDToken:    idToken,
			Scope:      &scope,
		},
		DisableSignUp: s.cfg.DisableSignup,
	})
	if err != nil {
		return nil, err
	}
	// Step 4: a refused link or sign-up is better-auth's APIError("UNAUTHORIZED", {message: result.error})
	if res.Error != "" {
		return nil, pluginkit.NewError(http.StatusUnauthorized, "UNAUTHORIZED", res.Error)
	}
	// Step 5: {token, user}
	user := dtos.UserFromModel(res.User)
	return &CallbackResult{
		Body:    onetapdtos.CallbackResponse{Token: res.Session.Session.Token, User: &user},
		Session: res.Session,
	}, nil
}

// toBoolean is better-auth's toBoolean: true for the boolean true and the string "true".
func toBoolean(v any) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return b == "true"
	}
	return false
}

// stringClaim returns a string claim ("" when missing or not a string).
func stringClaim(v any) string {
	s, _ := v.(string)
	return s
}
