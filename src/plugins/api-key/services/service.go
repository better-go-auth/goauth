// Package services implements @better-auth/api-key 1.6.16: creating, verifying, reading, updating,
// deleting and listing API keys in the database or the secondary storage, per-key usage limits (remaining
// with refills) and rate limits, permissions, expiry, organization-owned keys and sessions mocked from an
// API key.
package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"sync"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/common/logger"
	authconfig "github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/api-key/config"
	"github.com/better-go-auth/goauth/src/providers/access"
	"github.com/better-go-auth/goauth/src/providers/idgen"
	sec_storage "github.com/better-go-auth/goauth/src/providers/sec-storage"
)

// expiredCleanupInterval is how often deleteAllExpiredApiKeys really runs (better-auth: 10 seconds).
const expiredCleanupInterval = 10 * time.Second

// OrganizationAuthorizer answers the organization questions of organization-owned keys (better-auth's
// checkOrgApiKeyPermission through the organization plugin). See apikey.OrganizationFrom.
type OrganizationAuthorizer interface {
	// MemberRole returns the user's role in the organization; found is false when the user is not a member.
	MemberRole(ctx context.Context, organizationID, userID string) (role string, found bool, err error)
	// HasPermission reports whether role grants request in the organization (the organization plugin's
	// hasPermission without the creator shortcut, which the api-key plugin applies itself).
	HasPermission(ctx context.Context, organizationID, role string, request access.Request) (bool, error)
	// CreatorRole is the organization's creator role (default "owner"); it is granted every API key action.
	CreatorRole() string
}

// UserFinder loads users (the session of an API key is its owner's).
type UserFinder interface {
	FindUserByID(ctx context.Context, id string) (*models.User, error)
}

// Deps are the service's dependencies.
type Deps struct {
	// Configurations are the plugin's configurations (defaults applied), in declaration order.
	Configurations []config.Configuration
	// Adapter reads and writes the apikey model (nil only without database storage).
	Adapter adapter.Adapter
	// Store is goauth's secondary storage (for StorageSecondary).
	Store sec_storage.SecondaryStorage
	// Users loads key owners.
	Users UserFinder
	// Conf is the auth configuration (background tasks, session lifetime, IP headers).
	Conf authconfig.AuthConfig
	// Organization authorizes organization-owned keys (nil = organization plugin not installed).
	Organization OrganizationAuthorizer
	// Now is the clock (default time.Now); tests pass a fake one.
	Now func() time.Time
	// GenerateID creates record ids for keys kept only in the secondary storage (default idgen).
	GenerateID func() string
}

// Service is the api-key plugin's logic, shared by the HTTP endpoints, the Go API and the middlewares.
type Service struct {
	configs []config.Configuration
	adapter adapter.Adapter
	store   sec_storage.SecondaryStorage
	users   UserFinder
	conf    authconfig.AuthConfig
	org     OrganizationAuthorizer
	clock   func() time.Time
	genID   func() string

	// lastChecked throttles deleteAllExpiredApiKeys (better-auth keeps it in a module variable)
	mu          sync.Mutex
	lastChecked time.Time
}

// New builds the service.
func New(d Deps) *Service {
	s := &Service{
		configs: d.Configurations,
		adapter: d.Adapter,
		store:   d.Store,
		users:   d.Users,
		conf:    d.Conf,
		org:     d.Organization,
		clock:   d.Now,
		genID:   d.GenerateID,
	}
	if s.clock == nil {
		s.clock = time.Now
	}
	return s
}

// Configurations returns the configurations (defaults applied).
func (s *Service) Configurations() []config.Configuration { return s.configs }

// SetOrganization sets the organization authorizer (organization-owned keys).
func (s *Service) SetOrganization(org OrganizationAuthorizer) { s.org = org }

// now returns the current time in UTC with millisecond precision (what the database keeps).
func (s *Service) now() time.Time { return s.clock().UTC().Truncate(time.Millisecond) }

// newID returns an id for a key kept only in the secondary storage (better-auth: generateId({model}) ||
// generateId()).
func (s *Service) newID() string {
	if s.genID != nil {
		if id := s.genID(); id != "" {
			return id
		}
	}
	return idgen.RandomID()
}

// ResolveConfiguration is better-auth's resolveConfiguration: the configuration named configID, or the
// default one ("" / "default", returned with ConfigID "default"); NO_DEFAULT_API_KEY_CONFIGURATION_FOUND
// when a default is needed and there is none.
func (s *Service) ResolveConfiguration(configID string) (config.Configuration, error) {
	// Step 1: a named configuration
	if configID != "" {
		for _, c := range s.configs {
			if c.ConfigID == configID {
				return c, nil
			}
		}
	}
	// Step 2: the default configuration
	for _, c := range s.configs {
		if c.IsDefault() {
			c.ConfigID = config.DefaultConfigID
			return c, nil
		}
	}
	logger.Error("No default api-key configuration found. Either provide an api-key configuration with configId 'default' or provide a configuration with no `configId` set.")
	return config.Configuration{}, ErrNoDefaultConfigurationFound
}

// configForKey returns the configuration a stored key belongs to (exact configId, or the default one for
// keys of the default configuration), ok=false when none is declared.
func (s *Service) configForKey(keyConfigID string) (config.Configuration, bool) {
	for _, c := range s.configs {
		if config.IsDefaultConfigID(keyConfigID) {
			if c.IsDefault() {
				return c, true
			}
			continue
		}
		if c.ConfigID == keyConfigID {
			return c, true
		}
	}
	return config.Configuration{}, false
}

// HashKey is better-auth's defaultKeyHasher: SHA-256 of the key, base64url without padding.
func HashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// hashFor returns the stored form of key for a configuration.
func hashFor(key string, opts config.Configuration) string {
	if opts.DisableKeyHashing {
		return key
	}
	return HashKey(key)
}

// letters is the alphabet of generated keys (better-auth: generateRandomString(length, "a-z", "A-Z")).
const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// randomLetters returns n random letters without modulo bias.
func randomLetters(n int) string {
	// Step 1: bytes below 208 (4 * 52) map evenly onto the alphabet
	out := make([]byte, 0, n)
	buf := make([]byte, n*2+8)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			panic("api-key: crypto/rand failed: " + err.Error())
		}
		// Step 2: keep the unbiased bytes
		for _, b := range buf {
			if b < 208 {
				out = append(out, letters[b%52])
				if len(out) == n {
					break
				}
			}
		}
	}
	return string(out)
}

// generateKey is better-auth's key generator: the configuration's CustomKeyGenerator, or prefix plus
// length random letters.
func generateKey(ctx context.Context, opts config.Configuration, prefix string) (string, error) {
	if opts.CustomKeyGenerator != nil {
		return opts.CustomKeyGenerator(ctx, opts.DefaultKeyLength, prefix)
	}
	return prefix + randomLetters(opts.DefaultKeyLength), nil
}

// runInBackground is better-auth's ctx.context.runInBackground: the background-task handler when one is
// configured, otherwise a goroutine (the request does not wait). Errors are logged.
func (s *Service) runInBackground(ctx context.Context, what string, task func(ctx context.Context) error) {
	// Step 1: the task must outlive the request
	bg := context.WithoutCancel(ctx)
	run := func() {
		if err := task(bg); err != nil {
			logger.Error(what, "err", err)
		}
	}
	// Step 2: the configured handler, or a goroutine
	if h := s.conf.Advanced.BackgroundTasks.Handler; h != nil {
		h(run)
		return
	}
	go run()
}

// DeleteAllExpired is better-auth's deleteAllExpiredApiKeys: it removes every database key whose
// expiresAt has passed, at most once every 10 seconds unless bypass is set. Failures are logged and
// returned.
func (s *Service) DeleteAllExpired(ctx context.Context, bypass bool) error {
	// Step 1: throttle
	s.mu.Lock()
	now := s.now()
	if !bypass && !s.lastChecked.IsZero() && now.Sub(s.lastChecked) < expiredCleanupInterval {
		s.mu.Unlock()
		return nil
	}
	s.lastChecked = now
	s.mu.Unlock()
	if s.adapter == nil {
		return nil
	}
	// Step 2: expiresAt < now AND expiresAt IS NOT NULL
	_, err := s.adapter.DeleteMany(ctx, ModelName, []adapter.Where{
		{Field: FieldExpiresAt, Op: adapter.Lt, Value: now},
		{Field: FieldExpiresAt, Op: adapter.Ne, Value: nil},
	})
	if err != nil {
		logger.Error("Failed to delete expired API keys:", "err", err)
	}
	return err
}

// cleanupExpired runs the throttled cleanup the endpoints trigger without waiting for it in better-auth
// (failures are only logged).
func (s *Service) cleanupExpired(ctx context.Context) { _ = s.DeleteAllExpired(ctx, false) }

// checkOrgPermission is better-auth's checkOrgApiKeyPermission: the user must be a member of the
// organization whose role grants apiKey:<action> (the creator role is granted everything).
func (s *Service) checkOrgPermission(ctx context.Context, userID, organizationID, action string) error {
	// Step 1: the organization plugin must be installed
	if s.org == nil {
		return ErrOrganizationPluginRequired
	}
	// Step 2: membership
	role, found, err := s.org.MemberRole(ctx, organizationID, userID)
	if err != nil {
		return err
	}
	if !found {
		return ErrUserNotMemberOfOrganization
	}
	// Step 3: the creator role, or the role's apiKey permission (errors count as "no")
	creator := s.org.CreatorRole()
	if creator == "" {
		creator = "owner"
	}
	for _, r := range access.SplitRoles(role) {
		if r == creator {
			return nil
		}
	}
	ok, err := s.org.HasPermission(ctx, organizationID, role, access.Req(map[string][]string{"apiKey": {action}}))
	if err != nil || !ok {
		return ErrInsufficientAPIKeyPermissions
	}
	return nil
}
