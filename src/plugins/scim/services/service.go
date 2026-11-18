// Package services implements better-auth's scim plugin (@better-auth/scim 1.6.16): SCIM 2.0 user
// provisioning (RFC 7643 / RFC 7644) with per-provider bearer tokens, optionally scoped to an organization.
package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/plugins/scim/config"
	scimdtos "github.com/better-go-auth/goauth/src/plugins/scim/dtos"
)

// Model is the logical model name of the provider table.
const Model = "scimProvider"

// Service runs the scim endpoints.
type Service struct {
	kit     *pluginkit.Kit
	cfg     config.SCIMConfig
	store   adapter.Adapter
	plugins []plugins.Plugin
}

// New builds the service.
func New(kit *pluginkit.Kit, cfg config.SCIMConfig, store adapter.Adapter, ps []plugins.Plugin) (*Service, error) {
	if kit == nil {
		return nil, errors.New("scim: plugin kit is required")
	}
	if store == nil {
		return nil, errors.New("scim: the storage adapter is required (configure GoAuthOptions.Conn or adapter-based repositories)")
	}
	return &Service{kit: kit, cfg: cfg.WithDefaults(), store: store, plugins: ps}, nil
}

// Kit exposes the plugin kit.
func (s *Service) Kit() *pluginkit.Kit { return s.kit }

// Config returns the effective configuration.
func (s *Service) Config() config.SCIMConfig { return s.cfg }

// orgs returns the organization plugin's store, or nil.
func (s *Service) orgs() plugins.OrganizationStore { return plugins.FindOrganizationStore(s.plugins) }

// ─── tokens ──────────────────────────────────────────────────────────────────

const randomAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// randomString is better-auth's generateRandomString (a-z A-Z 0-9).
func randomString(n int) string {
	out := make([]byte, 0, n)
	buf := make([]byte, n)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			panic("scim: crypto/rand failed: " + err.Error())
		}
		for _, b := range buf {
			if b < 248 && len(out) < n {
				out = append(out, randomAlphabet[int(b)%len(randomAlphabet)])
			}
		}
	}
	return string(out)
}

// hashToken is better-auth's defaultKeyHasher: base64url(sha256(token)) without padding.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// storeToken is better-auth's storeSCIMToken.
func (s *Service) storeToken(token string) (string, error) {
	st := s.cfg.StoreSCIMToken
	switch {
	case st.Hash != nil:
		return st.Hash(token)
	case st.Encrypt != nil:
		return st.Encrypt(token)
	case st.Mode == config.StoreEncrypted:
		return s.kit.Cookies.Keys().Encrypt(token)
	case st.Mode == config.StoreHashed:
		return hashToken(token), nil
	}
	return token, nil
}

// verifyToken is better-auth's verifySCIMToken (constant-time comparison).
func (s *Service) verifyToken(stored, token string) bool {
	st := s.cfg.StoreSCIMToken
	var candidate, against string
	switch {
	case st.Hash != nil:
		h, err := st.Hash(token)
		if err != nil {
			return false
		}
		candidate, against = h, stored
	case st.Decrypt != nil:
		plain, err := st.Decrypt(stored)
		if err != nil {
			return false
		}
		candidate, against = token, plain
	case st.Mode == config.StoreEncrypted:
		plain, err := s.kit.Cookies.Keys().Decrypt(stored)
		if err != nil {
			return false
		}
		candidate, against = token, plain
	case st.Mode == config.StoreHashed:
		candidate, against = hashToken(token), stored
	default:
		candidate, against = token, stored
	}
	return subtle.ConstantTimeCompare([]byte(candidate), []byte(against)) == 1
}

// encodeToken is base64url (padded) of "<token>:<providerId>[:<organizationId>]".
func encodeToken(base, providerID, organizationID string) string {
	raw := base + ":" + providerID
	if organizationID != "" {
		raw += ":" + organizationID
	}
	return base64.URLEncoding.EncodeToString([]byte(raw))
}

// decodeToken splits a SCIM bearer token into its parts.
func decodeToken(token string) (base, providerID, organizationID string, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(token, "="))
	if err != nil {
		return "", "", "", false
	}
	parts := strings.Split(string(raw), ":")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return "", "", "", false
	}
	return parts[0], parts[1], strings.Join(parts[2:], ":"), true
}

// providerFromRecord converts a stored row.
func providerFromRecord(r adapter.Record) *config.Provider {
	return &config.Provider{
		ID: str(r["id"]), ProviderID: str(r["providerId"]), OrganizationID: str(r["organizationId"]),
		SCIMToken: str(r["scimToken"]), UserID: str(r["userId"]),
	}
}

// Authenticate is better-auth's SCIM auth middleware: the bearer token must belong to a provider connection
// (defaultSCIM first, then the database).
func (s *Service) Authenticate(ctx context.Context, authorization string) (*config.Provider, error) {
	// Step 1: the token
	token := authorization
	if len(token) >= 7 && strings.EqualFold(token[:6], "bearer") && (token[6] == ' ' || token[6] == '\t') {
		token = strings.TrimLeft(token[6:], " \t")
	}
	if token == "" {
		return nil, ErrTokenRequired
	}
	base, providerID, organizationID, ok := decodeToken(token)
	if !ok {
		return nil, ErrInvalidToken
	}
	// Step 2: configured providers
	for _, p := range s.cfg.DefaultSCIM {
		if p.ProviderID == providerID && (organizationID == "" || p.OrganizationID == organizationID) {
			if subtle.ConstantTimeCompare([]byte(p.SCIMToken), []byte(base)) == 1 {
				out := p
				return &out, nil
			}
			return nil, ErrInvalidToken
		}
	}
	// Step 3: the stored connection
	where := []adapter.Where{{Field: "providerId", Value: providerID}}
	if organizationID != "" {
		where = append(where, adapter.Where{Field: "organizationId", Value: organizationID})
	}
	r, err := s.store.FindOne(ctx, Model, where)
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("scim: find provider: %w", err)
	}
	p := providerFromRecord(r)
	if !s.verifyToken(p.SCIMToken, base) {
		return nil, ErrInvalidToken
	}
	return p, nil
}

// ─── provider connections ────────────────────────────────────────────────────

// requiredRoles is resolveRequiredRoles: the option, else ["admin", creatorRole or "owner"].
func (s *Service) requiredRoles() []string {
	if s.cfg.RequiredRole != nil {
		return s.cfg.RequiredRole
	}
	creator := "owner"
	if orgs := s.orgs(); orgs != nil {
		creator = orgs.CreatorRole()
	}
	if creator == "admin" {
		return []string{"admin"}
	}
	return []string{"admin", creator}
}

// parseRoles splits a comma-separated member role.
func parseRoles(role string) []string {
	var out []string
	for _, r := range strings.Split(role, ",") {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// hasRequiredRole reports a member role among required (an empty requirement allows everyone).
func hasRequiredRole(role string, required []string) bool {
	if len(required) == 0 {
		return true
	}
	for _, r := range parseRoles(role) {
		if slices.Contains(required, r) {
			return true
		}
	}
	return false
}

// assertProviderAccess is better-auth's assertSCIMProviderAccess.
func (s *Service) assertProviderAccess(ctx context.Context, userID string, p *config.Provider, required []string) error {
	if p.OrganizationID != "" {
		orgs := s.orgs()
		if orgs == nil {
			return ErrOrgPluginForProvider
		}
		m, err := orgs.FindMember(ctx, p.OrganizationID, userID)
		if err != nil {
			return fmt.Errorf("scim: find member: %w", err)
		}
		if m == nil {
			return ErrMustBeOrgMember
		}
		if !hasRequiredRole(m.Role, required) {
			return ErrInsufficientRole
		}
		return nil
	}
	if p.UserID != "" && p.UserID != userID {
		return ErrMustBeOwner
	}
	return nil
}

// checkProviderAccess loads the provider by id and checks access.
func (s *Service) checkProviderAccess(ctx context.Context, userID, providerID string) (*config.Provider, error) {
	r, err := s.store.FindOne(ctx, Model, []adapter.Where{{Field: "providerId", Value: providerID}})
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, ErrSCIMProviderNotFound
		}
		return nil, fmt.Errorf("scim: find provider: %w", err)
	}
	p := providerFromRecord(r)
	if err := s.assertProviderAccess(ctx, userID, p, s.requiredRoles()); err != nil {
		return nil, err
	}
	return p, nil
}

// builtInProviderIDs are the account providers a SCIM provider id may not reuse.
var builtInProviderIDs = []string{"credential", "email-otp", "magic-link", "phone-number", "anonymous", "siwe"}

// GenerateToken is better-auth's generateSCIMToken: a new token for providerId (replacing an existing one).
func (s *Service) GenerateToken(ctx context.Context, user *models.User, providerID, organizationID string) (string, error) {
	required := s.requiredRoles()
	// Step 1: provider id rules
	if strings.Contains(providerID, ":") {
		return "", ErrForbiddenCharacters
	}
	reserved := slices.Contains(builtInProviderIDs, providerID)
	for _, p := range s.kit.Conf.SocialProviders {
		if p != nil && p.ID() == providerID {
			reserved = true
		}
	}
	if reserved {
		return "", ErrBuiltInProviderID
	}
	// Step 2: organization tokens need a member with the required role
	if organizationID != "" && s.orgs() == nil {
		return "", ErrOrgPluginRequired
	}
	var member *plugins.OrganizationMember
	if organizationID != "" {
		m, err := s.orgs().FindMember(ctx, organizationID, user.ID)
		if err != nil {
			return "", fmt.Errorf("scim: find member: %w", err)
		}
		if m == nil {
			return "", ErrNotOrgMember
		}
		if !hasRequiredRole(m.Role, required) {
			return "", ErrInsufficientRole
		}
		member = m
	}
	if s.cfg.CanGenerateToken != nil {
		ok, err := s.cfg.CanGenerateToken(ctx, config.CanGenerateTokenData{User: user, ProviderID: providerID, OrganizationID: organizationID, Member: member})
		if err != nil {
			return "", err
		}
		if !ok {
			return "", ErrNotAllowedToGenerate
		}
	}
	// Step 3: an existing connection is replaced (by someone allowed to manage it)
	where := []adapter.Where{{Field: "providerId", Value: providerID}}
	if organizationID != "" {
		where = append(where, adapter.Where{Field: "organizationId", Value: organizationID})
	}
	if r, err := s.store.FindOne(ctx, Model, where); err == nil {
		existing := providerFromRecord(r)
		if err := s.assertProviderAccess(ctx, user.ID, existing, required); err != nil {
			return "", err
		}
		if err := s.store.Delete(ctx, Model, []adapter.Where{{Field: "id", Value: existing.ID}}); err != nil {
			return "", fmt.Errorf("scim: delete provider: %w", err)
		}
	} else if !errors.Is(err, adapter.ErrNotFound) {
		return "", fmt.Errorf("scim: find provider: %w", err)
	}
	// Step 4: the token and the hooks around storing it
	base := randomString(24)
	token := encodeToken(base, providerID, organizationID)
	if s.cfg.BeforeSCIMTokenGenerated != nil {
		if err := s.cfg.BeforeSCIMTokenGenerated(ctx, config.TokenPayload{User: user, Member: member, SCIMToken: token}); err != nil {
			return "", err
		}
	}
	stored, err := s.storeToken(base)
	if err != nil {
		return "", fmt.Errorf("scim: store token: %w", err)
	}
	data := adapter.Record{"providerId": providerID, "scimToken": stored}
	if organizationID != "" {
		data["organizationId"] = organizationID
	}
	if s.cfg.ProviderOwnership {
		data["userId"] = user.ID
	}
	created, err := s.store.Create(ctx, Model, data)
	if err != nil {
		return "", fmt.Errorf("scim: create provider: %w", err)
	}
	if s.cfg.AfterSCIMTokenGenerated != nil {
		if err := s.cfg.AfterSCIMTokenGenerated(ctx, config.TokenPayload{User: user, Member: member, SCIMToken: token, Provider: providerFromRecord(created)}); err != nil {
			return "", err
		}
	}
	return token, nil
}

// normalize is better-auth's normalizeSCIMProvider.
func normalize(p *config.Provider) scimdtos.SCIMProviderConnection {
	out := scimdtos.SCIMProviderConnection{ID: p.ID, ProviderID: p.ProviderID}
	if p.OrganizationID != "" {
		org := p.OrganizationID
		out.OrganizationID = &org
	}
	return out
}

// ListConnections is better-auth's listSCIMProviderConnections: organization connections where the user has
// the required role, plus personal connections owned by the user (or without an owner).
func (s *Service) ListConnections(ctx context.Context, userID string) (*scimdtos.SCIMProviderConnections, error) {
	// Step 1: the user's organization roles
	required := s.requiredRoles()
	roles := map[string][]string{}
	if orgs := s.orgs(); orgs != nil {
		members, err := orgs.ListMembersByUser(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("scim: list memberships: %w", err)
		}
		for _, m := range members {
			roles[m.OrganizationID] = parseRoles(m.Role)
		}
	}
	// Step 2: filter the connections
	rows, err := s.store.FindMany(ctx, Model, adapter.Query{})
	if err != nil {
		return nil, fmt.Errorf("scim: list providers: %w", err)
	}
	out := &scimdtos.SCIMProviderConnections{Providers: []scimdtos.SCIMProviderConnection{}}
	for _, r := range rows {
		p := providerFromRecord(r)
		if p.OrganizationID != "" {
			rs, ok := roles[p.OrganizationID]
			if !ok {
				continue
			}
			allowed := len(required) == 0
			for _, role := range rs {
				if slices.Contains(required, role) {
					allowed = true
				}
			}
			if !allowed {
				continue
			}
		} else if p.UserID != "" && p.UserID != userID {
			continue
		}
		out.Providers = append(out.Providers, normalize(p))
	}
	return out, nil
}

// GetConnection is better-auth's getSCIMProviderConnection.
func (s *Service) GetConnection(ctx context.Context, userID, providerID string) (*scimdtos.SCIMProviderConnection, error) {
	p, err := s.checkProviderAccess(ctx, userID, providerID)
	if err != nil {
		return nil, err
	}
	out := normalize(p)
	return &out, nil
}

// DeleteConnection is better-auth's deleteSCIMProviderConnection (the token stops working).
func (s *Service) DeleteConnection(ctx context.Context, userID, providerID string) error {
	if _, err := s.checkProviderAccess(ctx, userID, providerID); err != nil {
		return err
	}
	if err := s.store.Delete(ctx, Model, []adapter.Where{{Field: "providerId", Value: providerID}}); err != nil {
		return fmt.Errorf("scim: delete provider: %w", err)
	}
	return nil
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
