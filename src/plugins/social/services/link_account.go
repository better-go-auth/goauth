package services

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"time"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
)

// accountData is the provider account better-auth passes to handleOAuthUserInfo (tokens in clear text).
type accountData struct {
	ProviderID            string
	AccountID             string
	AccessToken           string
	RefreshToken          string
	IDToken               string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	// Scope is nil when unknown (id_token sign-in); "" is a known empty scope list.
	Scope *string
}

// accountFromTokens builds accountData from a token response (better-auth's {...tokens, scope: scopes.join(",")}).
func accountFromTokens(providerID, accountID string, t *providers.OAuth2Tokens) accountData {
	scope := strings.Join(t.Scopes, ",")
	return accountData{
		ProviderID:            providerID,
		AccountID:             accountID,
		AccessToken:           t.AccessToken,
		RefreshToken:          t.RefreshToken,
		IDToken:               t.IDToken,
		AccessTokenExpiresAt:  t.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: t.RefreshTokenExpiresAt,
		Scope:                 &scope,
	}
}

// oauthUserInput is handleOAuthUserInfo's options.
type oauthUserInput struct {
	UserInfo         providers.UserInfo
	Account          accountData
	CallbackURL      string
	DisableSignUp    bool
	OverrideUserInfo bool
}

// oauthUserResult is handleOAuthUserInfo's result: Error is better-auth's `error` string ("account not linked",
// "signup disabled", ...), otherwise Session/User are set.
type oauthUserResult struct {
	Error      string
	Session    *dtos.SessionWithUser
	User       *models.User
	IsRegister bool
	// Account is the provider account signed in with (refreshed or created), for the account_data cookie.
	// It is nil after implicit linking, where better-auth does not set the cookie either.
	Account *models.Account
}

// ─── Token storage ───────────────────────────────────────────────────────────

// setToken is better-auth's setTokenUtil: encrypt when EncryptOAuthTokens is on. "" means no token.
func (s *Service) setToken(token string) (*string, error) {
	if token == "" {
		return nil, nil
	}
	if s.cfg.EncryptOAuthTokens {
		enc, err := s.kit.Cookies.Keys().Encrypt(token)
		if err != nil {
			return nil, err
		}
		return &enc, nil
	}
	return &token, nil
}

// isLikelyEncrypted is better-auth's heuristic for tokens written before encryption was enabled.
func isLikelyEncrypted(token string) bool {
	if strings.HasPrefix(token, "$ba$") {
		return true
	}
	if len(token)%2 != 0 || token == "" {
		return false
	}
	for _, c := range token {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// decryptToken is better-auth's decryptOAuthToken.
func (s *Service) decryptToken(token string) (string, error) {
	if token == "" || !s.cfg.EncryptOAuthTokens || !isLikelyEncrypted(token) {
		return token, nil
	}
	// versioned envelopes "$ba$<version>$<hex>" pick their secret, bare hex uses the legacy / single secret
	return s.kit.Cookies.Keys().Decrypt(token)
}

// tokenUpdate is the account update for fresh tokens, skipping unknown values (better-auth filters undefined).
func (s *Service) tokenUpdate(a accountData) (map[string]interface{}, error) {
	update := map[string]interface{}{}
	if a.IDToken != "" {
		update["IDToken"] = a.IDToken
	}
	at, err := s.setToken(a.AccessToken)
	if err != nil {
		return nil, err
	}
	if at != nil {
		update["AccessToken"] = *at
	}
	rt, err := s.setToken(a.RefreshToken)
	if err != nil {
		return nil, err
	}
	if rt != nil {
		update["RefreshToken"] = *rt
	}
	if a.AccessTokenExpiresAt != nil {
		update["AccessTokenExpiresAt"] = a.AccessTokenExpiresAt.UTC()
	}
	if a.RefreshTokenExpiresAt != nil {
		update["RefreshTokenExpiresAt"] = a.RefreshTokenExpiresAt.UTC()
	}
	if a.Scope != nil {
		update["Scope"] = *a.Scope
	}
	return update, nil
}

// newAccount builds the account row for userID with (possibly encrypted) tokens.
func (s *Service) newAccount(userID string, a accountData) (*models.Account, error) {
	at, err := s.setToken(a.AccessToken)
	if err != nil {
		return nil, err
	}
	rt, err := s.setToken(a.RefreshToken)
	if err != nil {
		return nil, err
	}
	acc := &models.Account{
		AccountID:             a.AccountID,
		ProviderID:            models.Providers(a.ProviderID),
		UserID:                userID,
		AccessToken:           at,
		RefreshToken:          rt,
		AccessTokenExpiresAt:  utcPtr(a.AccessTokenExpiresAt),
		RefreshTokenExpiresAt: utcPtr(a.RefreshTokenExpiresAt),
		Scope:                 a.Scope,
	}
	if a.IDToken != "" {
		idt := a.IDToken
		acc.IDToken = &idt
	}
	return acc, nil
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}

// ─── User info ───────────────────────────────────────────────────────────────

// extraUserFields maps mapProfileToUser keys onto goauth user columns. Security sensitive fields (role,
// banned, emailVerified, ...) are deliberately absent.
var extraUserFields = map[string]string{
	"firstName":   "FirstName",
	"lastName":    "LastName",
	"username":    "Username",
	"displayName": "DisplayName",
	"bio":         "Bio",
	"locale":      "Locale",
	"timezone":    "Timezone",
	"gender":      "Gender",
}

// applyExtraToUser copies UserInfo.Extra onto a new user.
func applyExtraToUser(u *models.User, extra map[string]any) {
	for k, v := range extra {
		s, ok := v.(string)
		if !ok {
			continue
		}
		switch extraUserFields[k] {
		case "FirstName":
			u.FirstName = s
		case "LastName":
			u.LastName = s
		case "Username":
			u.Username = &s
		case "DisplayName":
			u.DisplayName = &s
		case "Bio":
			u.Bio = &s
		case "Locale":
			u.Locale = s
		case "Timezone":
			u.Timezone = &s
		case "Gender":
			u.Gender = &s
		}
	}
}

// profileUpdate is the user update for a provider profile (name, image and the extra fields).
func profileUpdate(info providers.UserInfo) map[string]interface{} {
	update := map[string]interface{}{}
	if info.Name != "" {
		update["Name"] = info.Name
	}
	if info.Image != "" {
		update["Image"] = info.Image
	}
	for k, v := range info.Extra {
		if field, ok := extraUserFields[k]; ok {
			if s, ok := v.(string); ok {
				update[field] = s
			}
		}
	}
	return update
}

// applyUpdateUserInfoOnLink copies the linked provider's profile onto the user when
// AccountLinking.UpdateUserInfoOnLink is on. Email and emailVerified never change. Failures are ignored.
func (s *Service) applyUpdateUserInfoOnLink(ctx context.Context, userID string, info providers.UserInfo) *models.User {
	if !s.cfg.AccountLinking.UpdateUserInfoOnLink {
		return nil
	}
	update := profileUpdate(info)
	if len(update) == 0 {
		return nil
	}
	u, err := s.kit.Repos.UpdateUser(ctx, userID, update)
	if err != nil {
		return nil
	}
	s.kit.RefreshUser(ctx, u)
	return u
}

// isTrustedProvider reports whether providerID is in AccountLinking.TrustedProviders.
func (s *Service) isTrustedProvider(providerID string) bool {
	return slices.Contains(s.cfg.AccountLinking.TrustedProviders, providerID)
}

// findOAuthUser is better-auth's internalAdapter.findOAuthUser: the account's user, else the user by email.
func (s *Service) findOAuthUser(ctx context.Context, email, accountID, providerID string) (*models.User, *models.Account, error) {
	// Step 1: the provider account and its user
	acc, err := pluginkit.AcceptNotFound(s.kit.Repos.FindAccountByProviderID(ctx, models.Providers(providerID), accountID))
	if err != nil {
		return nil, nil, err
	}
	if acc != nil {
		user, err := pluginkit.AcceptNotFound(s.kit.Repos.FindUserByID(ctx, acc.UserID))
		if err != nil {
			return nil, nil, err
		}
		if user != nil {
			return user, acc, nil
		}
	}
	// Step 2: the user owning the email
	user, err := pluginkit.AcceptNotFound(s.kit.Repos.FindUserByEmail(ctx, strings.ToLower(email)))
	if err != nil || user == nil {
		return nil, nil, err
	}
	return user, acc, nil
}

// handleOAuthUserInfo is better-auth's handleOAuthUserInfo: sign in the account's user (refreshing its tokens),
// link the account to an existing user with the same email when the linking policy allows it, or create a
// new user, then create a session. Policy refusals are returned in result.Error; errors thrown by hooks
// (e.g. BANNED_USER) are returned as error.
func (s *Service) handleOAuthUserInfo(ctx context.Context, in oauthUserInput) (*oauthUserResult, error) {
	info, account := in.UserInfo, in.Account
	email := strings.ToLower(info.Email)

	// Step 1: find the user by account, then by email
	user, linked, err := s.findOAuthUser(ctx, email, account.AccountID, account.ProviderID)
	if err != nil {
		return &oauthUserResult{Error: "internal server error"}, nil
	}
	isRegister := user == nil
	var signedIn *models.Account

	if user != nil {
		if linked == nil {
			// Step 2a: existing user, account not linked yet: apply the implicit linking policy
			trusted := s.isTrustedProvider(account.ProviderID)
			if (!trusted && !info.EmailVerified) ||
				(s.cfg.RequireLocalEmailVerified() && !user.EmailVerified) ||
				!s.cfg.LinkingEnabled() ||
				s.cfg.AccountLinking.DisableImplicitLinking {
				return &oauthUserResult{Error: "account not linked"}, nil
			}
			acc, err := s.newAccount(user.ID, account)
			if err == nil {
				acc.AccountID = info.ID
				_, err = s.kit.Repos.CreateAccount(ctx, acc)
			}
			if err != nil {
				return &oauthUserResult{Error: "unable to link account"}, nil
			}
			// the provider vouches for the email: mark the local email verified
			if info.EmailVerified && !user.EmailVerified && email == user.Email {
				if u, err := s.kit.Repos.UpdateUser(ctx, user.ID, map[string]interface{}{"EmailVerified": true}); err == nil {
					user = u
				}
			}
			if u := s.applyUpdateUserInfoOnLink(ctx, user.ID, info); u != nil {
				user = u
			}
		} else {
			// Step 2b: returning user: refresh the stored tokens (updateAccountOnSignIn)
			signedIn = linked
			if s.cfg.UpdateAccountOnSignInEnabled() {
				update, err := s.tokenUpdate(account)
				if err == nil && len(update) > 0 {
					if updated, err := s.kit.Repos.UpdateAccount(ctx, linked.ID, update); err == nil && updated != nil {
						signedIn = updated
					}
				}
			}
			if info.EmailVerified && !user.EmailVerified && email == user.Email {
				if u, err := s.kit.Repos.UpdateUser(ctx, user.ID, map[string]interface{}{"EmailVerified": true}); err == nil {
					user = u
				}
			}
		}
		// Step 3: overrideUserInfoOnSignIn rewrites the local profile from the provider
		if in.OverrideUserInfo {
			update := profileUpdate(info)
			update["Email"] = email
			if email == user.Email {
				update["EmailVerified"] = user.EmailVerified || info.EmailVerified
			} else {
				update["EmailVerified"] = info.EmailVerified
			}
			if u, err := s.kit.Repos.UpdateUser(ctx, user.ID, update); err == nil {
				user = u
			}
		}
		s.kit.RefreshUser(ctx, user)
	} else {
		// Step 4: new user: sign-up policy, then user + account in one transaction
		if in.DisableSignUp {
			return &oauthUserResult{Error: "signup disabled"}, nil
		}
		created, createdAccount, errMsg := s.createOAuthUser(ctx, info, account)
		if errMsg != "" {
			return &oauthUserResult{Error: errMsg}, nil
		}
		user = created
		signedIn = createdAccount
		// Step 5: verification email for unverified provider emails (emailVerification.sendOnSignUp)
		if !info.EmailVerified {
			s.sendVerificationOnSignUp(ctx, user, in.CallbackURL)
		}
	}

	// Step 6: the session
	sw, err := s.kit.CreateSession(ctx, user, false)
	if err != nil {
		if ae := autherr.AsAuthError(err); ae != nil && ae.Code != autherr.ErrFailedToCreateSession.Code {
			return nil, ae
		}
		return &oauthUserResult{Error: "unable to create session"}, nil
	}
	return &oauthUserResult{Session: sw, User: user, IsRegister: isRegister, Account: signedIn}, nil
}

// createOAuthUser is better-auth's internalAdapter.createOAuthUser (user + account in a transaction). It
// returns better-auth's error string on failure.
func (s *Service) createOAuthUser(ctx context.Context, info providers.UserInfo, account accountData) (*models.User, *models.Account, string) {
	var (
		created        *models.User
		createdAccount *models.Account
	)
	err := s.kit.InTx(ctx, func(ctx context.Context) error {
		// Step 1: the user (BeforeUserCreate / AfterUserCreate hooks run inside)
		u := &models.User{UserDto: models.UserDto{
			Name:          info.Name,
			Email:         strings.ToLower(info.Email),
			EmailVerified: info.EmailVerified,
		}}
		if info.Image != "" {
			img := info.Image
			u.Image = &img
		}
		applyExtraToUser(u, info.Extra)
		user, err := s.kit.CreateUser(ctx, u)
		if err != nil {
			return err
		}
		// Step 2: the provider account
		acc, err := s.newAccount(user.ID, account)
		if err != nil {
			return err
		}
		acc.AccountID = info.ID
		stored, err := s.kit.Repos.CreateAccount(ctx, acc)
		if err != nil {
			return err
		}
		created, createdAccount = user, stored
		return nil
	})
	if err != nil {
		// hook errors (APIError upstream) surface their message; storage failures are generic
		if ae := autherr.AsAuthError(err); ae != nil && ae.Code != autherr.ErrFailedToCreateUser.Code {
			return nil, nil, ae.Message
		}
		return nil, nil, "unable to create user"
	}
	return created, createdAccount, ""
}

// sendVerificationOnSignUp emails a verification link to a new OAuth user whose provider email is not verified,
// when emailVerification.sendOnSignUp is true and a sender is configured (as better-auth does).
func (s *Service) sendVerificationOnSignUp(ctx context.Context, user *models.User, callbackURL string) {
	ev := s.kit.Conf.EmailVerification
	if ev.SendOnSignUp == nil || !*ev.SendOnSignUp || ev.SendVerificationEmail == nil {
		return
	}
	// Step 1: better-auth's createEmailVerificationToken (HS256 JWT {email})
	expires := ev.ExpiresIn
	if expires <= 0 {
		expires = time.Hour
	}
	tok, err := authcrypto.SignJWT(map[string]any{"email": strings.ToLower(user.Email)}, s.kit.Conf.Secret, expires)
	if err != nil {
		return
	}
	// Step 2: the link and the app's sender
	if callbackURL == "" {
		callbackURL = "/"
	}
	link := s.kit.BaseURL(ctx) + "/verify-email?token=" + tok + "&callbackURL=" + encodeURIComponent(callbackURL)
	data := config.EmailVerificationData{User: *user, URL: link, Token: tok}
	_ = s.kit.Conf.RunInBackgroundOrAwait(ctx, func(ctx context.Context) error {
		return ev.SendVerificationEmail(data, s.kit.Request(ctx))
	})
}

// encodeURIComponent mirrors JavaScript's encodeURIComponent.
func encodeURIComponent(s string) string {
	e := url.QueryEscape(s)
	e = strings.ReplaceAll(e, "+", "%20")
	for _, r := range []string{"!", "'", "(", ")", "*"} {
		e = strings.ReplaceAll(e, url.QueryEscape(r), r)
	}
	return e
}
