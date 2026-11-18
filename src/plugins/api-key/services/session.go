package services

import (
	"context"
	"net/http"
	"time"

	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins/api-key/config"
)

// KeyFromRequest is better-auth's getApiKeyFromConfig: the configuration's CustomAPIKeyGetter, or the first
// non-empty APIKeyHeaders header.
func KeyFromRequest(r *http.Request, c config.Configuration) string {
	if r == nil {
		return ""
	}
	if c.CustomAPIKeyGetter != nil {
		return c.CustomAPIKeyGetter(r)
	}
	for _, h := range c.APIKeyHeaders {
		if v := r.Header.Get(h); v != "" {
			return v
		}
	}
	return ""
}

// StorageIdentifier names the storage backend of a configuration (configurations sharing one hold the
// same keys).
func StorageIdentifier(c config.Configuration) string { return storageIdentifier(c) }

// FindSessionKey is better-auth's findApiKeyAndConfig: the first configuration with
// EnableSessionForAPIKeys whose header (or getter) carries a key.
func (s *Service) FindSessionKey(r *http.Request) (string, config.Configuration, bool) {
	for _, c := range s.configs {
		if !c.EnableSessionForAPIKeys {
			continue
		}
		if key := KeyFromRequest(r, c); key != "" {
			return key, c, true
		}
	}
	return "", config.Configuration{}, false
}

// KeyAuth is the result of authenticating a request by API key.
type KeyAuth struct {
	// Key is the validated key (after its use was recorded).
	Key *APIKey
	// Config is the key's configuration.
	Config config.Configuration
	// Session is the session mocked for the key's owner (nil for organization-owned keys in the host
	// middleware).
	Session *dtos.SessionWithUser
}

// AuthenticateOptions tune AuthenticateKey.
type AuthenticateOptions struct {
	// Permissions the key must grant.
	Permissions map[string][]string
	// RequireUser rejects keys whose configuration does not reference users
	// (INVALID_REFERENCE_ID_FROM_API_KEY), like better-auth's session hook.
	RequireUser bool
	// AnyConfig accepts keys of every configuration stored where c keeps keys (the key's own configuration
	// then applies); otherwise a named configuration only accepts its own keys.
	AnyConfig bool
}

// AuthenticateKey is the body of better-auth's API-key session hook: the key must be at least
// DefaultKeyLength long and pass the custom validator (403 INVALID_API_KEY otherwise), then it is validated
// against its configuration (usage and rate limit recorded) and the owner's session is mocked.
func (s *Service) AuthenticateKey(ctx context.Context, r *http.Request, key string, c config.Configuration, o AuthenticateOptions) (*KeyAuth, error) {
	// Step 1: cheap checks before any lookup
	if jsLength(key) < c.DefaultKeyLength {
		return nil, ErrInvalidAPIKey.WithStatus(http.StatusForbidden)
	}
	if c.CustomAPIKeyValidator != nil {
		ok, err := c.CustomAPIKeyValidator(ctx, key)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrInvalidAPIKey.WithStatus(http.StatusForbidden)
		}
	}
	// Step 2: validate (the default configuration has no expected configId)
	var expected *string
	if c.ConfigID != "" && !o.AnyConfig {
		id := c.ConfigID
		expected = &id
	}
	k, keyConfig, err := s.validate(ctx, validateRequest{key: key, lookup: c, permissions: o.Permissions, expectedConfigID: expected})
	if err != nil {
		return nil, err
	}
	s.cleanupExpired(ctx)
	if o.AnyConfig {
		c = keyConfig
	}
	auth := &KeyAuth{Key: k, Config: c}
	// Step 3: only user keys become sessions
	if c.References != config.ReferencesUser {
		if o.RequireUser {
			return nil, ErrInvalidReferenceIDFromAPIKey
		}
		return auth, nil
	}
	if s.users == nil {
		return nil, ErrInvalidReferenceIDFromAPIKey
	}
	user, err := s.users.FindUserByID(ctx, k.ReferenceID)
	if err != nil || user == nil {
		return nil, ErrInvalidReferenceIDFromAPIKey
	}
	auth.Session = s.mockSession(r, key, k, dtos.UserFromModel(user))
	return auth, nil
}

// mockSession is the session better-auth builds for an API key: id = the key's id, token = the key,
// expiresAt = the key's expiry or the session lifetime from now. Note: better-auth adds
// session.expiresIn (seconds) as milliseconds here; goauth does the same, so the value matches.
func (s *Service) mockSession(r *http.Request, key string, k *APIKey, user dtos.UserResponse) *dtos.SessionWithUser {
	now := s.now()
	// Step 1: request metadata
	var ua, ip *string
	if r != nil {
		if v := r.Header.Get("User-Agent"); v != "" {
			ua = &v
		}
		if v := humaadapter.ClientIP(s.conf, r); v != "" {
			ip = &v
		}
	}
	// Step 2: expiry
	expiresAt := k.ExpiresAt
	if expiresAt == nil {
		secs := int64(s.conf.Session.ExpiresIn / time.Second)
		if secs <= 0 {
			secs = 3600 * 24 * 7
		}
		t := now.Add(time.Duration(secs) * time.Millisecond)
		expiresAt = &t
	}
	return &dtos.SessionWithUser{
		User: user,
		Session: dtos.SessionData{
			ID:        k.ID,
			Token:     key,
			UserID:    k.ReferenceID,
			UserAgent: ua,
			IPAddress: ip,
			CreatedAt: dtos.Time(now),
			UpdatedAt: dtos.Time(now),
			ExpiresAt: dtos.Time(*expiresAt),
		},
	}
}
