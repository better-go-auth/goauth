package services

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/logger"
	socialservices "github.com/better-go-auth/goauth/src/plugins/social/services"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
)

// ErrSocialPluginMissing is returned by the proxy callback when the social plugin is not available.
var ErrSocialPluginMissing = errors.New("oauth-proxy: the social plugin is required")

// Redirect is the 302 GET /oauth-proxy-callback answers with (every outcome is a redirect).
type Redirect struct {
	Location string
	Cookies  []http.Cookie
}

// defaultErrorURL is onAPIError.errorURL, else "<BaseURL or base URL origin>/api/auth/error" (better-auth
// hard-codes /api/auth here).
func (s *Service) defaultErrorURL(ctx context.Context) string {
	if u := s.kit.Conf.OnAPIError.ErrorURL; u != "" {
		return u
	}
	base := s.kit.Conf.BaseURL
	if base == "" {
		base = originOf(s.kit.RequestBaseURL(ctx))
	}
	return stripTrailingSlash(base) + "/api/auth/error"
}

// socialOAuthUserInput is handleOAuthUserInfo's input for a profile payload.
func socialOAuthUserInput(p ProfilePayload) socialservices.OAuthUserInput {
	return socialservices.OAuthUserInput{
		UserInfo:      userInfoFromProfile(p.UserInfo),
		Account:       accountFromProfile(p.Account),
		CallbackURL:   p.CallbackURL,
		DisableSignUp: p.DisableSignUp,
	}
}

// errorRedirect is redirectOnError as a Redirect.
func errorRedirect(errorURL, code, description string, cookies []http.Cookie) *Redirect {
	res := redirectOnError(errorURL, code, description, nil)
	return &Redirect{Location: res.Header.Get("Location"), Cookies: cookies}
}

// Callback is GET /oauth-proxy-callback on the preview deployment: it decrypts and checks the profile sent by
// production, cleans up the OAuth state, signs the user in (or up) and redirects to the callback URL (new
// users to newUserURL). Failures redirect to the error URL with better-auth's error codes; only unexpected
// errors are returned.
func (s *Service) Callback(ctx context.Context, encryptedProfile string) (*Redirect, error) {
	defaultErrorURL := s.defaultErrorURL(ctx)
	// Step 1: the profile is mandatory
	if encryptedProfile == "" {
		logger.Error("OAuth proxy callback missing profile data")
		return errorRedirect(defaultErrorURL, "missing_profile", "", nil), nil
	}
	// Step 2: decrypt and decode it
	decrypted, err := authcrypto.SymmetricDecrypt(s.key(), encryptedProfile)
	if err != nil {
		logger.Error("Failed to decrypt OAuth proxy profile", "error", err)
		return errorRedirect(defaultErrorURL, "invalid_profile", "", nil), nil
	}
	var payload ProfilePayload
	if err := json.Unmarshal([]byte(decrypted), &payload); err != nil {
		logger.Error("Failed to parse OAuth proxy payload", "error", err)
		return errorRedirect(defaultErrorURL, "invalid_payload", "", nil), nil
	}
	if payload.Timestamp == nil || payload.UserInfo == nil || payload.Account == nil || payload.CallbackURL == "" {
		logger.Error("Failed to parse OAuth proxy payload")
		return errorRedirect(defaultErrorURL, "invalid_payload", "", nil), nil
	}
	errorURL := payload.ErrorURL
	if errorURL == "" {
		errorURL = defaultErrorURL
	}
	// Step 3: the profile is only valid for maxAge (and at most 10 s in the future, for clock skew)
	age := (float64(time.Now().UnixMilli()) - *payload.Timestamp) / 1000
	if age > s.cfg.MaxAge.Seconds() || age < -10 {
		logger.Error("OAuth proxy payload expired or invalid", "age", age, "maxAge", s.cfg.MaxAge.Seconds())
		return errorRedirect(errorURL, "payload_expired", "", nil), nil
	}
	social := s.socialService()
	if social == nil {
		return nil, ErrSocialPluginMissing
	}
	// Step 4: clean up this deployment's OAuth state (the state cookie is not required; failures are logged)
	_, cookies, err := social.ParseStateSkipCookieCheck(ctx, payload.State)
	if err != nil {
		logger.Warn("Failed to clean up OAuth state", "error", err)
	}
	// Step 5: sign in, link or sign up like an OAuth callback
	result, err := social.HandleOAuthUserInfo(ctx, socialOAuthUserInput(payload))
	if err != nil {
		if ae := autherr.AsAuthError(err); ae != nil && ae.Code != "" {
			return errorRedirect(errorURL, string(ae.Code), ae.Message, cookies), nil
		}
		return nil, err
	}
	if result.Error != "" {
		logger.Error("OAuth proxy callback error", "error", result.Error)
		return errorRedirect(errorURL, strings.Join(strings.Split(result.Error, " "), "_"), "", cookies), nil
	}
	if result.Session == nil {
		logger.Error("OAuth proxy callback missing session data")
		return errorRedirect(errorURL, "user_creation_failed", "", cookies), nil
	}
	// Step 6: session cookie, then the callback (new users go to newUserURL when set)
	finalURL := payload.CallbackURL
	if result.IsRegister && payload.NewUserURL != "" {
		finalURL = payload.NewUserURL
	}
	return &Redirect{Location: finalURL, Cookies: append(cookies, s.kit.SessionCookies(result.Session, false)...)}, nil
}
