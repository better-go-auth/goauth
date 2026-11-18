// Package services implements the magic-link flows (better-auth's magic-link plugin endpoints).
package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	authconfig "github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	modeldtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/plugins/magic-link/config"
	"github.com/better-go-auth/goauth/src/plugins/magic-link/dtos"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// Redirect error codes better-auth appends as ?error=... to the error callback URL.
const (
	ErrCodeInvalidToken          = "INVALID_TOKEN"
	ErrCodeFailedToCreateUser    = "failed_to_create_user"
	ErrCodeNewUserSignupDisabled = "new_user_signup_disabled"
	ErrCodeFailedToCreateSession = "failed_to_create_session"
	defaultTokenLength           = 32
	tokenAlphabet                = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

// emailRegex is zod v4's z.email() pattern, which better-auth uses to validate the sign-in body.
var emailRegex = regexp.MustCompile(`^[A-Za-z0-9_'+\-.]*[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$`)

// ValidEmail reports whether email passes better-auth's (zod) email validation.
func ValidEmail(email string) bool {
	if strings.HasPrefix(email, ".") || strings.Contains(email, "..") {
		return false
	}
	return emailRegex.MatchString(email)
}

// RedirectError is a verify failure that better-auth reports by redirecting to the error callback URL.
type RedirectError struct{ Code string }

func (e *RedirectError) Error() string { return "magic-link: " + e.Code }

// AsRedirectError returns err as a *RedirectError, or nil.
func AsRedirectError(err error) *RedirectError {
	var re *RedirectError
	if errors.As(err, &re) {
		return re
	}
	return nil
}

// VerifyResult is a successful magic link verification.
type VerifyResult struct {
	Session   *modeldtos.SessionWithUser
	User      *models.User
	IsNewUser bool
}

// MagicLinkService holds the magic-link business logic.
type MagicLinkService struct {
	cfg config.MagicLinkConfig
	kit *pluginkit.Kit
}

// NewMagicLinkService builds the service.
func NewMagicLinkService(cfg config.MagicLinkConfig, kit *pluginkit.Kit) *MagicLinkService {
	return &MagicLinkService{cfg: cfg, kit: kit}
}

// Config returns the plugin configuration.
func (s *MagicLinkService) Config() config.MagicLinkConfig { return s.cfg }

// GenerateRandomToken returns better-auth's generateRandomString(32, "a-z", "A-Z").
func GenerateRandomToken() (string, error) {
	var sb strings.Builder
	max := big.NewInt(int64(len(tokenAlphabet)))
	for i := 0; i < defaultTokenLength; i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		sb.WriteByte(tokenAlphabet[n.Int64()])
	}
	return sb.String(), nil
}

// DefaultKeyHasher is better-auth's defaultKeyHasher: base64url(SHA-256(token)) without padding.
func DefaultKeyHasher(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// StoredToken returns the verification identifier for token according to StoreToken.
func (s *MagicLinkService) StoredToken(token string) (string, error) {
	st := s.cfg.StoreToken
	switch {
	case st.Mode == config.StoreTokenHashed:
		return DefaultKeyHasher(token), nil
	case st.Hash != nil && (st.Mode == config.StoreTokenCustom || st.Mode == ""):
		return st.Hash(token)
	default:
		return token, nil
	}
}

// VerifyURL builds the link sent to the user, reproducing better-auth's pathname/basePath logic:
// the path of ctx.context.baseURL is used when it is not "/", otherwise options.basePath.
func (s *MagicLinkService) VerifyURL(ctx context.Context, token string, in *dtos.SignInMagicLinkInput) string {
	// Step 1: split ctx.context.baseURL into origin and pathname
	origin, pathname := s.kit.BaseURL(ctx), ""
	if u, err := url.Parse(s.kit.BaseURL(ctx)); err == nil {
		origin = u.Scheme + "://" + u.Host
		pathname = u.EscapedPath()
		if pathname == "" || pathname == "/" {
			pathname = ""
		}
	}
	// Step 2: only fall back to the configured basePath when the base URL has no path of its own
	basePath := ""
	if pathname == "" {
		basePath = s.kit.BasePath
	}
	// Step 3: append the query in better-auth's order (token, callbackURL, newUserCallbackURL, errorCallbackURL)
	callbackURL := in.CallbackURL
	if callbackURL == "" {
		callbackURL = "/"
	}
	params := []string{"token=" + url.QueryEscape(token), "callbackURL=" + url.QueryEscape(callbackURL)}
	if in.NewUserCallbackURL != "" {
		params = append(params, "newUserCallbackURL="+url.QueryEscape(in.NewUserCallbackURL))
	}
	if in.ErrorCallbackURL != "" {
		params = append(params, "errorCallbackURL="+url.QueryEscape(in.ErrorCallbackURL))
	}
	return origin + pathname + basePath + "/magic-link/verify?" + strings.Join(params, "&")
}

// SendMagicLink creates a verification token for in.Email and hands the link to SendMagicLink.
func (s *MagicLinkService) SendMagicLink(ctx context.Context, in *dtos.SignInMagicLinkInput, req *http.Request) error {
	// Step 1: validate the email like better-auth's body schema
	if !ValidEmail(in.Email) {
		return autherr.ErrInvalidEmail
	}

	// Step 2: generate the token (custom generator or 32 random letters)
	var token string
	if s.cfg.GenerateToken != nil {
		token = s.cfg.GenerateToken(in.Email)
	} else {
		t, err := GenerateRandomToken()
		if err != nil {
			return autherr.ErrInternal
		}
		token = t
	}

	// Step 3: compute the identifier stored in the verification table (plain, hashed or custom hash)
	identifier, err := s.StoredToken(token)
	if err != nil {
		return autherr.ErrInternal
	}

	// Step 4: store {email, name} as JSON with the configured expiry
	value, err := json.Marshal(dtos.TokenValue{Email: in.Email, Name: in.Name})
	if err != nil {
		return autherr.ErrInternal
	}
	if _, err := s.kit.Repos.UpsertVerificationValue(ctx, &models.Verification{
		Identifier: identifier,
		Value:      string(value),
		ExpiresAt:  time.Now().Add(s.cfg.ExpiresIn),
	}); err != nil {
		return autherr.ErrInternal
	}

	// Step 5: build the verification URL and deliver it
	link := s.VerifyURL(ctx, token, in)
	if s.cfg.SendMagicLink == nil {
		return autherr.ErrInternal
	}
	// config: Advanced.BackgroundTasks.Handler runs the sender without blocking the response
	data := config.SendMagicLinkData{Email: in.Email, URL: link, Token: token, Metadata: in.Metadata}
	if err := s.kit.Conf.RunInBackgroundOrAwait(ctx, func(ctx context.Context) error {
		return s.cfg.SendMagicLink(data, authconfig.HTTPRequestOr(ctx, req))
	}); err != nil {
		if ae := autherr.AsAuthError(err); ae != nil {
			return ae
		}
		return autherr.ErrInternal
	}
	return nil
}

// Verify consumes token, signs the user up when needed and creates a session.
// Failures better-auth redirects for are returned as *RedirectError; hook errors (e.g. BANNED_USER)
// are returned unchanged.
func (s *MagicLinkService) Verify(ctx context.Context, token string) (*VerifyResult, error) {
	// Step 1: consume the verification row atomically (single use)
	identifier, err := s.StoredToken(token)
	if err != nil {
		return nil, &RedirectError{Code: ErrCodeInvalidToken}
	}
	row, err := s.kit.Repos.ConsumeVerificationValue(ctx, identifier)
	if err != nil || row == nil {
		return nil, &RedirectError{Code: ErrCodeInvalidToken}
	}

	// Step 2: decode the stored {email, name}
	var value dtos.TokenValue
	if err := json.Unmarshal([]byte(row.Value), &value); err != nil || value.Email == "" {
		return nil, &RedirectError{Code: ErrCodeInvalidToken}
	}

	// Step 3: find the user, or sign them up unless sign-up is disabled
	isNewUser := false
	user, err := pluginkit.AcceptNotFound(s.kit.Repos.FindUserByEmail(ctx, strings.ToLower(value.Email)))
	if err != nil {
		return nil, autherr.ErrInternal
	}
	if user == nil {
		if s.cfg.DisableSignUp {
			return nil, &RedirectError{Code: ErrCodeNewUserSignupDisabled}
		}
		name := ""
		if value.Name != nil {
			name = *value.Name
		}
		created, err := s.kit.CreateUser(ctx, &models.User{UserDto: models.UserDto{
			Email:         strings.ToLower(value.Email),
			Name:          name,
			EmailVerified: true,
			Role:          enums.User,
		}})
		if err != nil {
			if pluginkit.Code(err) == string(autherr.ErrFailedToCreateUser.Code) {
				return nil, &RedirectError{Code: ErrCodeFailedToCreateUser}
			}
			return nil, err
		}
		user, isNewUser = created, true
	}

	// Step 4: clicking the link proves ownership of the address
	if !user.EmailVerified {
		updated, err := s.kit.Repos.UpdateUser(ctx, user.ID, map[string]interface{}{"EmailVerified": true})
		if err == nil && updated != nil {
			user = updated
		} else {
			user.EmailVerified = true
		}
		s.kit.RefreshUser(ctx, user)
	}

	// Step 5: create the session (BeforeSessionCreate hooks such as the admin ban check may veto it)
	sw, err := s.kit.CreateSession(ctx, user, false)
	if err != nil {
		if pluginkit.Code(err) == string(autherr.ErrFailedToCreateSession.Code) {
			return nil, &RedirectError{Code: ErrCodeFailedToCreateSession}
		}
		return nil, err
	}
	return &VerifyResult{Session: sw, User: user, IsNewUser: isNewUser}, nil
}
