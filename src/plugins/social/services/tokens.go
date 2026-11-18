package services

import (
	"context"
	"net/http"
	"strings"
	"time"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	socialdtos "github.com/better-go-auth/goauth/src/plugins/social/dtos"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
)

// ResolveUserID is better-auth's resolveUserId: over HTTP the caller's session always wins and is required.
func (s *Service) ResolveUserID(ctx context.Context, userID string) (string, error) {
	// Step 1: the session (attached by the middleware or resolved from cookies / bearer token)
	sw := s.kit.CurrentOrResolve(ctx)
	if sw == nil && s.kit.Request(ctx) != nil {
		return "", autherr.ErrUnauthorized
	}
	// Step 2: a trusted server-side caller may name the user
	if sw != nil && sw.User.ID != "" {
		return sw.User.ID, nil
	}
	if userID == "" {
		return "", ErrUserIDOrSessionRequired
	}
	return userID, nil
}

// findAccount returns the user's account for providerID (and accountID when given).
func (s *Service) findAccount(ctx context.Context, userID, providerID, accountID string) (*models.Account, error) {
	accounts, err := s.kit.Repos.FindAccounts(ctx, userID)
	if err != nil {
		return nil, err
	}
	for i := range accounts {
		a := &accounts[i]
		if string(a.ProviderID) == providerID && (accountID == "" || a.AccountID == accountID) {
			return a, nil
		}
	}
	return nil, nil
}

func splitScope(scope *string) []string {
	if scope == nil {
		return []string{}
	}
	return strings.Split(*scope, ",")
}

func timePtr(t *time.Time) *dtos.Time {
	if t == nil {
		return nil
	}
	v := dtos.Time(*t)
	return &v
}

// validAccessToken is better-auth's getValidAccessToken: refresh (and persist) the access token when it expires
// within five seconds and a refresh token is stored. With account.storeAccountCookie the account_data cookie is
// read first and rewritten after a refresh (the returned cookies).
func (s *Service) validAccessToken(ctx context.Context, userID, providerID, accountID string, account *models.Account) (*socialdtos.AccessTokenResponse, []http.Cookie, error) {
	var setCookies []http.Cookie
	// Step 1: the provider and the account
	p, ok := s.Provider(providerID)
	if !ok {
		return nil, nil, errProviderNotSupported(providerID)
	}
	if account == nil {
		// the account_data cookie when it matches, else the database
		if account = s.accountFromCookie(ctx, userID, providerID, accountID); account == nil {
			var err error
			if account, err = s.findAccount(ctx, userID, providerID, accountID); err != nil {
				return nil, nil, err
			}
		}
	}
	if account == nil {
		return nil, nil, autherr.ErrAccountNotFound
	}

	// Step 2: refresh when (almost) expired
	var fresh *providers.OAuth2Tokens
	expired := account.AccessTokenExpiresAt != nil && time.Until(*account.AccessTokenExpiresAt) < 5*time.Second
	if account.RefreshToken != nil && *account.RefreshToken != "" && expired && providers.CanRefresh(p) {
		rt, err := s.decryptToken(*account.RefreshToken)
		if err != nil {
			return nil, nil, ErrFailedToGetAccessToken
		}
		fresh, err = p.RefreshAccessToken(ctx, rt)
		if err != nil || fresh == nil {
			return nil, nil, ErrFailedToGetAccessToken
		}
		// Step 3: persist the new tokens, keeping the old refresh token / id token when none is returned
		update := map[string]interface{}{}
		if at, err := s.setToken(fresh.AccessToken); err == nil && at != nil {
			update["AccessToken"] = *at
		}
		if fresh.AccessTokenExpiresAt != nil {
			update["AccessTokenExpiresAt"] = fresh.AccessTokenExpiresAt.UTC()
		}
		if fresh.RefreshToken != "" {
			if enc, err := s.setToken(fresh.RefreshToken); err == nil && enc != nil {
				update["RefreshToken"] = *enc
			}
		}
		if fresh.RefreshTokenExpiresAt != nil {
			update["RefreshTokenExpiresAt"] = fresh.RefreshTokenExpiresAt.UTC()
		}
		if fresh.IDToken != "" {
			update["IDToken"] = fresh.IDToken
		}
		if len(update) > 0 {
			if updated, err := s.kit.Repos.UpdateAccount(ctx, account.ID, update); err == nil {
				account = updated
			}
		}
		// with storeAccountCookie the refreshed account goes back into account_data
		setCookies = s.AccountCookies(ctx, account)
	}

	// Step 4: the answer (fresh values first, then the stored ones)
	out := &socialdtos.AccessTokenResponse{Scopes: splitScope(account.Scope)}
	if fresh != nil && fresh.AccessToken != "" {
		out.AccessToken = fresh.AccessToken
	} else {
		stored := ""
		if account.AccessToken != nil {
			stored = *account.AccessToken
		}
		at, err := s.decryptToken(stored)
		if err != nil {
			return nil, nil, ErrFailedToGetAccessToken
		}
		out.AccessToken = at
	}
	if fresh != nil && fresh.AccessTokenExpiresAt != nil {
		out.AccessTokenExpiresAt = timePtr(fresh.AccessTokenExpiresAt)
	} else {
		out.AccessTokenExpiresAt = timePtr(account.AccessTokenExpiresAt)
	}
	if fresh != nil && fresh.IDToken != "" {
		out.IDToken = &fresh.IDToken
	} else if account.IDToken != nil {
		out.IDToken = account.IDToken
	}
	return out, setCookies, nil
}

// GetAccessToken is better-auth's POST /get-access-token. The cookies rewrite account_data after a refresh.
func (s *Service) GetAccessToken(ctx context.Context, in socialdtos.AccountTokenInput) (*socialdtos.AccessTokenResponse, []http.Cookie, error) {
	userID, err := s.ResolveUserID(ctx, in.UserID)
	if err != nil {
		return nil, nil, err
	}
	return s.validAccessToken(ctx, userID, in.ProviderID, in.AccountID, nil)
}

// RefreshToken is better-auth's POST /refresh-token: always refresh, persist and return the new tokens. When the
// account came from the account_data cookie (account.storeAccountCookie) the cookie is rewritten too.
func (s *Service) RefreshToken(ctx context.Context, in socialdtos.AccountTokenInput) (*socialdtos.RefreshTokenResponse, []http.Cookie, error) {
	// Step 1: caller, provider and account (the account_data cookie when it matches, else the database)
	userID, err := s.ResolveUserID(ctx, in.UserID)
	if err != nil {
		return nil, nil, err
	}
	p, ok := s.Provider(in.ProviderID)
	if !ok {
		return nil, nil, errProviderNotSupported(in.ProviderID)
	}
	if !providers.CanRefresh(p) {
		return nil, nil, errTokenRefreshNotSupported(in.ProviderID)
	}
	account := s.accountFromCookie(ctx, userID, in.ProviderID, in.AccountID)
	usedAccountCookie := account != nil
	if account == nil {
		if account, err = s.findAccount(ctx, userID, in.ProviderID, in.AccountID); err != nil {
			return nil, nil, err
		}
	}
	if account == nil {
		return nil, nil, autherr.ErrAccountNotFound
	}
	if account.RefreshToken == nil || *account.RefreshToken == "" {
		return nil, nil, ErrRefreshTokenNotFound
	}

	// Step 2: refresh with the (decrypted) refresh token
	decrypted, err := s.decryptToken(*account.RefreshToken)
	if err != nil {
		return nil, nil, ErrFailedToRefreshAccessToken
	}
	tokens, err := p.RefreshAccessToken(ctx, decrypted)
	if err != nil || tokens == nil {
		return nil, nil, ErrFailedToRefreshAccessToken
	}

	// Step 3: persist (keep the stored refresh token / scope / id token when none is returned)
	storedRefresh := *account.RefreshToken
	if tokens.RefreshToken != "" {
		enc, err := s.setToken(tokens.RefreshToken)
		if err != nil {
			return nil, nil, ErrFailedToRefreshAccessToken
		}
		storedRefresh = *enc
	}
	refreshExpires := tokens.RefreshTokenExpiresAt
	if refreshExpires == nil {
		refreshExpires = account.RefreshTokenExpiresAt
	}
	scope := account.Scope
	if len(tokens.Scopes) > 0 && strings.Join(tokens.Scopes, ",") != "" {
		sc := strings.Join(tokens.Scopes, ",")
		scope = &sc
	}
	idToken := account.IDToken
	if tokens.IDToken != "" {
		idToken = &tokens.IDToken
	}
	update := map[string]interface{}{"RefreshToken": storedRefresh}
	if at, err := s.setToken(tokens.AccessToken); err == nil && at != nil {
		update["AccessToken"] = *at
	}
	if tokens.AccessTokenExpiresAt != nil {
		update["AccessTokenExpiresAt"] = tokens.AccessTokenExpiresAt.UTC()
	}
	if refreshExpires != nil {
		update["RefreshTokenExpiresAt"] = refreshExpires.UTC()
	}
	if scope != nil {
		update["Scope"] = *scope
	}
	if idToken != nil {
		update["IDToken"] = *idToken
	}
	updated, err := s.kit.Repos.UpdateAccount(ctx, account.ID, update)
	if err != nil {
		return nil, nil, ErrFailedToRefreshAccessToken
	}
	var setCookies []http.Cookie
	if usedAccountCookie {
		setCookies = s.AccountCookies(ctx, updated)
	}

	// Step 4: the answer
	out := &socialdtos.RefreshTokenResponse{
		AccessToken:           tokens.AccessToken,
		RefreshToken:          tokens.RefreshToken,
		AccessTokenExpiresAt:  timePtr(tokens.AccessTokenExpiresAt),
		RefreshTokenExpiresAt: timePtr(refreshExpires),
		Scope:                 scope,
		IDToken:               idToken,
		ProviderID:            string(account.ProviderID),
		AccountID:             account.AccountID,
	}
	if out.RefreshToken == "" {
		out.RefreshToken = decrypted
	}
	return out, setCookies, nil
}

// AccountInfoQuery is the query of GET /account-info.
type AccountInfoQuery struct {
	AccountID  string
	ProviderID string
	UserID     string
}

// AccountInfo is better-auth's GET /account-info: the provider's current view of the user. Without accountId the
// account comes from the account_data cookie (account.storeAccountCookie).
func (s *Service) AccountInfo(ctx context.Context, q AccountInfoQuery) (*socialdtos.AccountInfoResponse, []http.Cookie, error) {
	// Step 1: caller
	userID, err := s.ResolveUserID(ctx, q.UserID)
	if err != nil {
		return nil, nil, err
	}
	// Step 2: the account: the account_data cookie without accountId, else the matching database row
	var account *models.Account
	if q.AccountID == "" {
		if s.storeAccountCookie() {
			account = s.readAccountCookie(ctx)
		}
	} else {
		accounts, err := s.kit.Repos.FindAccounts(ctx, userID)
		if err != nil {
			return nil, nil, err
		}
		var matching []*models.Account
		for i := range accounts {
			a := &accounts[i]
			if a.AccountID == q.AccountID && (q.ProviderID == "" || string(a.ProviderID) == q.ProviderID) {
				matching = append(matching, a)
			}
		}
		if len(matching) > 1 {
			return nil, nil, ErrAmbiguousAccount
		}
		if len(matching) == 1 {
			account = matching[0]
		}
	}
	if account == nil || account.UserID != userID {
		return nil, nil, autherr.ErrAccountNotFound
	}
	// Step 3: the provider and a valid access token
	p, ok := s.Provider(string(account.ProviderID))
	if !ok {
		return nil, nil, ErrProviderNotConfigured
	}
	tokens, setCookies, err := s.validAccessToken(ctx, userID, string(account.ProviderID), account.AccountID, account)
	if err != nil {
		return nil, nil, err
	}
	if tokens.AccessToken == "" {
		return nil, nil, ErrAccessTokenNotFound
	}
	// Step 4: ask the provider
	in := providers.UserInfoInput{OAuth2Tokens: providers.OAuth2Tokens{AccessToken: tokens.AccessToken, Scopes: tokens.Scopes}}
	if tokens.IDToken != nil {
		in.IDToken = *tokens.IDToken
	}
	info, err := p.GetUserInfo(ctx, in)
	if err != nil || info == nil {
		return nil, setCookies, nil
	}
	return &socialdtos.AccountInfoResponse{
		User: socialdtos.AccountInfoUser{
			ID: info.User.ID, Name: info.User.Name, Email: info.User.Email, Image: info.User.Image, EmailVerified: info.User.EmailVerified,
		},
		Data: info.Data,
	}, setCookies, nil
}
