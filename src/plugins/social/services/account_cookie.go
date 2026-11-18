package services

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
	"github.com/better-go-auth/goauth/src/providers/cookies"
)

// accountCookieMaxAge is better-auth's account_data default maxAge (session.cookieCache.maxAge || 300 s).
const accountCookieMaxAge = 300 * time.Second

// accountCookie is the account_data payload: the account row as better-auth's setAccountCookie stores it
// (tokens as stored, i.e. encrypted when EncryptOAuthTokens is on), encrypted as a JWE with the
// "better-auth-account" salt.
type accountCookie struct {
	ID                    string     `json:"id"`
	AccountID             string     `json:"accountId"`
	ProviderID            string     `json:"providerId"`
	UserID                string     `json:"userId"`
	AccessToken           *string    `json:"accessToken"`
	RefreshToken          *string    `json:"refreshToken"`
	IDToken               *string    `json:"idToken"`
	AccessTokenExpiresAt  *time.Time `json:"accessTokenExpiresAt"`
	RefreshTokenExpiresAt *time.Time `json:"refreshTokenExpiresAt"`
	Scope                 *string    `json:"scope"`
	CreatedAt             time.Time  `json:"createdAt"`
	UpdatedAt             time.Time  `json:"updatedAt"`
}

// storeAccountCookie reports AuthConfig.Account.StoreAccountCookie (better-auth's account.storeAccountCookie).
func (s *Service) storeAccountCookie() bool { return s.kit.Conf.Account.StoreAccountCookie }

// accountCookieMaxAge is session.cookieCache.maxAge, else 300 s (better-auth's account_data attributes).
func (s *Service) accountCookieMaxAge() time.Duration {
	if cc := s.kit.Conf.Session.CookieCache; cc != nil && cc.MaxAge > 0 {
		return cc.MaxAge
	}
	return accountCookieMaxAge
}

// AccountCookies is better-auth's setAccountCookie: the encrypted account_data cookie for acc (chunked when it
// is larger than one cookie), or nil when account.storeAccountCookie is off.
func (s *Service) AccountCookies(ctx context.Context, acc *models.Account) []http.Cookie {
	// Step 1: only with storeAccountCookie
	if !s.storeAccountCookie() || acc == nil {
		return nil
	}
	// Step 2: the account row, encrypted with the current secret
	payload := accountCookie{
		ID: acc.ID, AccountID: acc.AccountID, ProviderID: string(acc.ProviderID), UserID: acc.UserID,
		AccessToken: acc.AccessToken, RefreshToken: acc.RefreshToken, IDToken: acc.IDToken,
		AccessTokenExpiresAt: acc.AccessTokenExpiresAt, RefreshTokenExpiresAt: acc.RefreshTokenExpiresAt,
		Scope: acc.Scope, CreatedAt: acc.CreatedAt, UpdatedAt: acc.UpdatedAt,
	}
	maxAge := s.accountCookieMaxAge()
	value, err := s.kit.Cookies.Keys().EncodeJWE(payload, authcrypto.JWESaltAccount, maxAge)
	if err != nil {
		return nil
	}
	// Step 3: one cookie, or chunks (stale chunks of the request are expired)
	return s.kit.Cookies.ChunkedCookies(s.cookieHeader(ctx), cookies.CookieAccountData, value, int(maxAge/time.Second))
}

// readAccountCookie is better-auth's getAccountCookie: the account stored in the request's account_data
// cookie (nil when absent, undecryptable or expired).
func (s *Service) readAccountCookie(ctx context.Context) *models.Account {
	// Step 1: the (possibly chunked) cookie
	raw, ok := s.kit.Cookies.ReadChunked(s.cookieHeader(ctx), cookies.CookieAccountData)
	if !ok || raw == "" {
		return nil
	}
	// Step 2: decrypt with any configured secret version
	claims, err := s.kit.Cookies.Keys().DecodeJWE(raw, authcrypto.JWESaltAccount)
	if err != nil {
		return nil
	}
	var c accountCookie
	if err := json.Unmarshal(claims, &c); err != nil || c.UserID == "" {
		return nil
	}
	acc := &models.Account{
		AccountID: c.AccountID, ProviderID: models.Providers(c.ProviderID), UserID: c.UserID,
		AccessToken: c.AccessToken, RefreshToken: c.RefreshToken, IDToken: c.IDToken,
		AccessTokenExpiresAt: c.AccessTokenExpiresAt, RefreshTokenExpiresAt: c.RefreshTokenExpiresAt, Scope: c.Scope,
	}
	acc.ID, acc.CreatedAt, acc.UpdatedAt = c.ID, c.CreatedAt, c.UpdatedAt
	return acc
}

// accountFromCookie returns the account cookie when it belongs to userID / providerID (and accountID when
// given), like better-auth's getValidAccessToken / refreshToken lookups.
func (s *Service) accountFromCookie(ctx context.Context, userID, providerID, accountID string) *models.Account {
	acc := s.readAccountCookie(ctx)
	if acc == nil || acc.UserID != userID || string(acc.ProviderID) != providerID || (accountID != "" && acc.AccountID != accountID) {
		return nil
	}
	return acc
}

// SignInCookies are the cookies of a successful OAuth sign-in: the session cookies plus, with
// account.storeAccountCookie, the account_data cookie of the signed-in provider account.
func (s *Service) SignInCookies(ctx context.Context, res *OAuthUserResult) []http.Cookie {
	if res == nil || res.Session == nil {
		return nil
	}
	out := s.kit.SessionCookies(res.Session, false)
	return append(out, s.AccountCookies(ctx, res.Account)...)
}

func (s *Service) cookieHeader(ctx context.Context) string {
	if req := s.kit.Request(ctx); req != nil {
		return req.Header.Get("Cookie")
	}
	return ""
}
