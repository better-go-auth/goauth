// Package services implements better-auth's one-time-token plugin: short-lived single-use tokens that can be
// exchanged for the session they were created from (e.g. to hand a session to another app or domain).
package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"net/http"
	"strings"
	"time"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins/one-time-token/config"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// IdentifierPrefix prefixes the verification identifier of every stored token ("one-time-token:<token>").
const IdentifierPrefix = "one-time-token:"

const (
	defaultTokenLength = 32
	// tokenAlphabet is better-auth's generateRandomString alphabet ("a-z", "0-9", "A-Z", "-_").
	tokenAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_"
)

// Errors better-auth throws with ctx.error("BAD_REQUEST", { message }). better-auth sends no code for
// them; goauth derives one from the message.
var (
	ErrClientRequestsDisabled = pluginkit.NewError(http.StatusBadRequest, "CLIENT_REQUESTS_ARE_DISABLED", "Client requests are disabled")
	ErrInvalidToken           = pluginkit.NewError(http.StatusBadRequest, "INVALID_TOKEN", "Invalid token")
	ErrTokenExpired           = pluginkit.NewError(http.StatusBadRequest, "TOKEN_EXPIRED", "Token expired")
	ErrSessionNotFound        = pluginkit.NewError(http.StatusBadRequest, "SESSION_NOT_FOUND", "Session not found")
	ErrSessionExpired         = pluginkit.NewError(http.StatusBadRequest, "SESSION_EXPIRED", "Session expired")
)

// OneTimeTokenService holds the one-time-token logic.
type OneTimeTokenService struct {
	cfg config.OneTimeTokenConfig
	kit *pluginkit.Kit
}

// NewOneTimeTokenService builds the service.
func NewOneTimeTokenService(cfg config.OneTimeTokenConfig, kit *pluginkit.Kit) *OneTimeTokenService {
	return &OneTimeTokenService{cfg: cfg.WithDefaults(), kit: kit}
}

// Config returns the effective configuration.
func (s *OneTimeTokenService) Config() config.OneTimeTokenConfig { return s.cfg }

// Kit returns the shared plugin runtime.
func (s *OneTimeTokenService) Kit() *pluginkit.Kit { return s.kit }

// GenerateRandomToken returns better-auth's generateRandomString(32) (a-z, 0-9, A-Z, "-", "_").
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

// StoredToken returns how token is stored in the verification identifier according to StoreToken.
func (s *OneTimeTokenService) StoredToken(token string) (string, error) {
	st := s.cfg.StoreToken
	switch {
	case st.Mode == config.StoreTokenHashed:
		return DefaultKeyHasher(token), nil
	case st.Mode == config.StoreTokenCustom && st.Hash != nil:
		return st.Hash(token)
	default:
		return token, nil
	}
}

// GenerateToken creates a one-time token for session and stores it (better-auth's generateToken). Use it on
// the server when DisableClientRequest is set.
func (s *OneTimeTokenService) GenerateToken(ctx context.Context, session *dtos.SessionWithUser) (string, error) {
	if session == nil {
		return "", autherr.ErrInternal
	}
	// Step 1: the custom generator or a 32-character random token
	var token string
	var err error
	if s.cfg.GenerateToken != nil {
		token, err = s.cfg.GenerateToken(ctx, session)
	} else {
		token, err = GenerateRandomToken()
	}
	if err != nil || token == "" {
		return "", autherr.ErrInternal
	}
	// Step 2: store "one-time-token:<stored token>" → session token, valid for ExpiresIn
	stored, err := s.StoredToken(token)
	if err != nil {
		return "", autherr.ErrInternal
	}
	if _, err := s.kit.Repos.UpsertVerificationValue(ctx, &models.Verification{
		Identifier: IdentifierPrefix + stored,
		Value:      session.Session.Token,
		ExpiresAt:  time.Now().Add(s.cfg.ExpiresIn),
	}); err != nil {
		return "", autherr.ErrInternal
	}
	return token, nil
}

// GenerateForClient is GET /one-time-token/generate: a token for the current session, unless client
// requests are disabled.
func (s *OneTimeTokenService) GenerateForClient(ctx context.Context, session *dtos.SessionWithUser) (string, error) {
	if s.cfg.DisableClientRequest {
		return "", ErrClientRequestsDisabled
	}
	return s.GenerateToken(ctx, session)
}

// Verify consumes token and returns the session it was created for (POST /one-time-token/verify).
// A token works once: concurrent requests with the same token cannot both succeed.
func (s *OneTimeTokenService) Verify(ctx context.Context, token string) (*dtos.SessionWithUser, error) {
	// Step 1: find the stored token
	stored, err := s.StoredToken(token)
	if err != nil {
		return nil, ErrInvalidToken
	}
	identifier := IdentifierPrefix + stored
	v, err := pluginkit.AcceptNotFound(s.kit.Repos.FindVerificationValue(ctx, identifier))
	if err != nil {
		return nil, autherr.ErrInternal
	}
	if v == nil {
		return nil, ErrInvalidToken
	}
	// Step 2: consume it atomically; losing a concurrent race is the same as an unknown token
	ok, err := s.kit.Repos.DeleteVerificationIfValue(ctx, v.ID, v.Value)
	if err != nil {
		return nil, autherr.ErrInternal
	}
	// Step 3: expired tokens are deleted but rejected (the read may already have purged the expired row)
	if v.ExpiresAt.Before(time.Now()) {
		return nil, ErrTokenExpired
	}
	if !ok {
		return nil, ErrInvalidToken
	}
	// Step 4: load the session the token was created for
	sw, err := s.kit.Sessions.Get(ctx, v.Value)
	if err != nil || sw == nil {
		return nil, ErrSessionNotFound
	}
	if time.Time(sw.Session.ExpiresAt).Before(time.Now()) {
		return nil, ErrSessionExpired
	}
	return sw, nil
}

// AfterHook is better-auth's setOttHeaderOnNewSession after hook: responses that set a new session cookie
// get a one-time token for that session in the `set-ott` header.
func (s *OneTimeTokenService) AfterHook(hc *pluginkit.AfterHookContext) {
	// Step 1: only when enabled and the response creates a session
	if !s.cfg.SetOttHeaderOnNewSession {
		return
	}
	sw := hc.NewSession()
	if sw == nil {
		return
	}
	// Step 2: create the token
	token, err := s.GenerateToken(hc.Context(), sw)
	if err != nil {
		return
	}
	// Step 3: send it and expose the header to browsers
	exposed := []string{}
	seen := map[string]bool{}
	for _, h := range strings.Split(hc.ResponseHeader("Access-Control-Expose-Headers"), ",") {
		if h = strings.TrimSpace(h); h != "" && !seen[h] {
			seen[h] = true
			exposed = append(exposed, h)
		}
	}
	if !seen["set-ott"] {
		exposed = append(exposed, "set-ott")
	}
	hc.SetHeader("set-ott", token)
	hc.SetHeader("Access-Control-Expose-Headers", strings.Join(exposed, ", "))
}
