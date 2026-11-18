package services

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/sso/config"
	ssodtos "github.com/better-go-auth/goauth/src/plugins/sso/dtos"
)

// adminRoles are the organization roles that manage SSO providers.
var adminRoles = map[string]bool{"owner": true, "admin": true}

// hasOrgAdminRole reports a member with owner or admin among its comma-separated roles.
func hasOrgAdminRole(role string) bool {
	for _, r := range strings.Split(role, ",") {
		if adminRoles[strings.TrimSpace(r)] {
			return true
		}
	}
	return false
}

// ─── POST /sso/register ──────────────────────────────────────────────────────

// Register is better-auth's registerSSOProvider.
func (s *Service) Register(ctx context.Context, user dtos.UserResponse, in ssodtos.SSORegisterInput) (*ssodtos.SSOProviderResponse, error) {
	isTrusted := s.isTrustedOrigin(ctx)

	// Step 1: the per-user providers limit (0 disables registration)
	limit := s.cfg.ProvidersLimit
	if s.cfg.ProvidersLimitFunc != nil {
		u, err := s.kit.Repos.FindUserByID(ctx, user.ID)
		if err != nil {
			return nil, errorf("find user: %w", err)
		}
		l, err := s.cfg.ProvidersLimitFunc(ctx, u)
		if err != nil {
			return nil, err
		}
		limit = l
	}
	if limit == 0 {
		return nil, ErrRegistrationDisabled
	}
	owned, err := s.listProviderRecords(ctx, []adapter.Where{{Field: "userId", Value: user.ID}})
	if err != nil {
		return nil, errorf("list providers: %w", err)
	}
	if len(owned) >= limit {
		return nil, ErrProvidersLimitReached
	}

	// Step 2: the issuer must be a URL; IdP metadata has a size limit
	if !isZodURL(in.Issuer) {
		return nil, ErrInvalidIssuer
	}
	if in.SAMLConfig != nil && in.SAMLConfig.IDPMetadata != nil && in.SAMLConfig.IDPMetadata.Metadata != "" {
		if len(in.SAMLConfig.IDPMetadata.Metadata) > s.cfg.SAML.MaxMetadataSize {
			return nil, errMetadataTooLarge(s.cfg.SAML.MaxMetadataSize)
		}
	}

	// Step 3: organization providers need a membership (owner or admin with the organization plugin)
	if in.OrganizationID != "" {
		orgs := s.orgs()
		var member *plugins.OrganizationMember
		if orgs != nil {
			if member, err = orgs.FindMember(ctx, in.OrganizationID, user.ID); err != nil {
				return nil, errorf("find member: %w", err)
			}
		}
		if member == nil {
			return nil, ErrNotOrganizationMember
		}
		if !hasOrgAdminRole(member.Role) {
			return nil, ErrNotOrganizationAdmin
		}
	}

	// Step 4: reserved and taken provider ids
	if s.isReservedProviderID(in.ProviderID) {
		logger.Warn("SSO provider registration rejected for reserved providerId: " + in.ProviderID)
		return nil, ErrReservedProviderID
	}
	if existing, err := s.findProviderRecord(ctx, in.ProviderID); err != nil {
		return nil, errorf("find provider: %w", err)
	} else if existing != nil {
		logger.Info("SSO provider creation attempt with existing providerId: " + in.ProviderID)
		return nil, ErrProviderIDExists
	}

	// Step 5: OIDC endpoints must be safe to fetch; discovery hydrates the missing ones
	var oidcJSON, samlJSON *string
	if oc := in.OIDCConfig; oc != nil {
		if err := validateSkipDiscoveryEndpoints(&OIDCEndpoints{
			AuthorizationEndpoint: oc.AuthorizationEndpoint, TokenEndpoint: oc.TokenEndpoint,
			UserInfoEndpoint: oc.UserInfoEndpoint, JWKSEndpoint: oc.JWKSEndpoint, DiscoveryEndpoint: oc.DiscoveryEndpoint,
		}, isTrusted); err != nil {
			return nil, mapDiscoveryError(err)
		}
		built, err := s.buildOIDCConfig(ctx, in, isTrusted)
		if err != nil {
			return nil, err
		}
		oidcJSON = &built
	}

	// Step 6: SAML: algorithms and an IdP entry point (metadata, SSO service or entryPoint URL)
	if sc := in.SAMLConfig; sc != nil {
		if err := validateConfigAlgorithms(sc.SignatureAlgorithm, sc.DigestAlgorithm, s.cfg.SAML.Algorithms); err != nil {
			return nil, err
		}
		hasMetadata := sc.IDPMetadata != nil && sc.IDPMetadata.Metadata != ""
		hasSSO := sc.IDPMetadata != nil && len(sc.IDPMetadata.SingleSignOnService) > 0
		if !hasMetadata && !isAbsoluteURL(sc.EntryPoint) && !hasSSO {
			return nil, ErrSAMLEntryPointRequired
		}
		raw, err := json.Marshal(samlConfigFromRegister(in.Issuer, sc))
		if err != nil {
			return nil, errorf("encode saml config: %w", err)
		}
		v := string(raw)
		samlJSON = &v
	}

	// Step 7: store the provider
	data := adapter.Record{
		"issuer":     in.Issuer,
		"domain":     in.Domain,
		"oidcConfig": nullable(oidcJSON),
		"samlConfig": nullable(samlJSON),
		"userId":     user.ID,
		"providerId": in.ProviderID,
	}
	if in.OrganizationID != "" {
		data["organizationId"] = in.OrganizationID
	}
	if s.cfg.DomainVerification.Enabled {
		data["domainVerified"] = false
	}
	created, err := s.store.Create(ctx, Model, data)
	if err != nil {
		return nil, errorf("create provider: %w", err)
	}

	// Step 8: domain verification token
	out := providerResponse(created)
	out.RedirectURI = s.redirectURI(ctx, out.ProviderID)
	if s.cfg.DomainVerification.Enabled {
		token := randomString(24)
		if err := s.storeVerification(ctx, s.verificationIdentifier(out.ProviderID), token, 7*24*time.Hour); err != nil {
			return nil, errorf("store domain verification: %w", err)
		}
		out.DomainVerified = config.Bool(false)
		out.DomainVerificationToken = token
	}
	return out, nil
}

// buildOIDCConfig is better-auth's buildOIDCConfig: the stored oidcConfig JSON (discovered unless skipDiscovery).
func (s *Service) buildOIDCConfig(ctx context.Context, in ssodtos.SSORegisterInput, isTrusted func(string) bool) (string, error) {
	oc := in.OIDCConfig
	override := in.OverrideUserInfo || s.cfg.DefaultOverrideUserInfo
	pkce := true
	if oc.PKCE != nil {
		pkce = *oc.PKCE
	}
	var mapping *config.OIDCMapping
	if oc.Mapping != nil {
		mapping = &config.OIDCMapping{ID: oc.Mapping.ID, Email: oc.Mapping.Email, EmailVerified: oc.Mapping.EmailVerified, Name: oc.Mapping.Name, Image: oc.Mapping.Image, ExtraFields: oc.Mapping.ExtraFields}
	}
	stored := config.OIDCConfig{
		Issuer:       in.Issuer,
		ClientID:     oc.ClientID,
		ClientSecret: oc.ClientSecret,
		PKCE:         &pkce,
		Mapping:      mapping,
		Scopes:       oc.Scopes,
		// overrideUserInfo is always written (false by default)
		OverrideUserInfo: &override,
	}
	if oc.SkipDiscovery {
		// Step 1a: the endpoints exactly as registered
		stored.AuthorizationEndpoint = oc.AuthorizationEndpoint
		stored.TokenEndpoint = oc.TokenEndpoint
		stored.TokenEndpointAuthentication = pick(oc.TokenEndpointAuthentication, "client_secret_basic")
		stored.JWKSEndpoint = oc.JWKSEndpoint
		stored.DiscoveryEndpoint = pick(oc.DiscoveryEndpoint, in.Issuer+"/.well-known/openid-configuration")
		stored.UserInfoEndpoint = oc.UserInfoEndpoint
	} else {
		// Step 1b: discovery (registered endpoints win over discovered ones)
		hydrated, err := s.discoverOIDCConfig(ctx, discoverParams{
			Issuer: in.Issuer,
			Existing: &config.OIDCConfig{
				DiscoveryEndpoint: oc.DiscoveryEndpoint, AuthorizationEndpoint: oc.AuthorizationEndpoint,
				TokenEndpoint: oc.TokenEndpoint, JWKSEndpoint: oc.JWKSEndpoint, UserInfoEndpoint: oc.UserInfoEndpoint,
				TokenEndpointAuthentication: oc.TokenEndpointAuthentication,
			},
			IsTrustedOrigin: isTrusted,
		})
		if err != nil {
			return "", mapDiscoveryError(err)
		}
		stored.Issuer = hydrated.Issuer
		stored.AuthorizationEndpoint = hydrated.AuthorizationEndpoint
		stored.TokenEndpoint = hydrated.TokenEndpoint
		stored.TokenEndpointAuthentication = hydrated.TokenEndpointAuthentication
		stored.JWKSEndpoint = hydrated.JWKSEndpoint
		stored.DiscoveryEndpoint = hydrated.DiscoveryEndpoint
		stored.UserInfoEndpoint = hydrated.UserInfoEndpoint
	}
	raw, err := json.Marshal(stored)
	if err != nil {
		return "", errorf("encode oidc config: %w", err)
	}
	return string(raw), nil
}

// samlConfigFromRegister is the samlConfig better-auth stores for a registration.
func samlConfigFromRegister(issuer string, sc *ssodtos.SSORegisterSAMLConfig) config.SAMLConfig {
	out := config.SAMLConfig{
		Issuer:               issuer,
		EntryPoint:           sc.EntryPoint,
		Cert:                 sc.Cert,
		CallbackURL:          sc.CallbackURL,
		Audience:             sc.Audience,
		SPMetadata:           spMetadataFromInput(&sc.SPMetadata),
		WantAssertionsSigned: sc.WantAssertionsSigned,
		AuthnRequestsSigned:  sc.AuthnRequestsSigned,
		SignatureAlgorithm:   sc.SignatureAlgorithm,
		DigestAlgorithm:      sc.DigestAlgorithm,
		IdentifierFormat:     sc.IdentifierFormat,
		PrivateKey:           sc.PrivateKey,
		DecryptionPvk:        sc.DecryptionPvk,
		AdditionalParams:     sc.AdditionalParams,
		IDPMetadata:          idpMetadataFromInput(sc.IDPMetadata),
	}
	if m := sc.Mapping; m != nil {
		out.Mapping = &config.SAMLMapping{ID: m.ID, Email: m.Email, EmailVerified: m.EmailVerified, Name: m.Name, FirstName: m.FirstName, LastName: m.LastName, ExtraFields: m.ExtraFields}
	}
	return out
}

func idpMetadataFromInput(in *ssodtos.SSOIDPMetadataInput) *config.IDPMetadata {
	if in == nil {
		return nil
	}
	return &config.IDPMetadata{
		Metadata: in.Metadata, EntityID: in.EntityID, Cert: in.Cert, PrivateKey: in.PrivateKey, PrivateKeyPass: in.PrivateKeyPass,
		IsAssertionEncrypted: in.IsAssertionEncrypted, EncPrivateKey: in.EncPrivateKey, EncPrivateKeyPass: in.EncPrivateKeyPass,
		SingleSignOnService: in.SingleSignOnService,
	}
}

func spMetadataFromInput(in *ssodtos.SSOSPMetadataInput) *config.SPMetadata {
	if in == nil {
		return nil
	}
	return &config.SPMetadata{
		Metadata: in.Metadata, EntityID: in.EntityID, Binding: in.Binding, PrivateKey: in.PrivateKey, PrivateKeyPass: in.PrivateKeyPass,
		IsAssertionEncrypted: in.IsAssertionEncrypted, EncPrivateKey: in.EncPrivateKey, EncPrivateKeyPass: in.EncPrivateKeyPass,
	}
}

// isReservedProviderID reports "credential", a configured social provider id or a trusted provider id.
func (s *Service) isReservedProviderID(id string) bool {
	// Step 1: credential and accountLinking.trustedProviders
	if id == string(models.ProvCredential) {
		return true
	}
	for _, tp := range s.kit.Conf.Account.AccountLinking.TrustedProviders {
		if tp == id {
			return true
		}
	}
	// Step 2: social providers (core socialProviders and plugins exposing providers)
	for _, p := range s.kit.Conf.SocialProviders {
		if p != nil && p.ID() == id {
			return true
		}
	}
	for _, p := range s.plugins {
		if hp, ok := p.(interface{ HasProvider(string) bool }); ok && hp.HasProvider(id) {
			return true
		}
	}
	return false
}

// providerResponse turns a stored row into the register response (configs parsed, missing values null).
func providerResponse(r adapter.Record) *ssodtos.SSOProviderResponse {
	out := &ssodtos.SSOProviderResponse{
		ID:         str(r["id"]),
		Issuer:     str(r["issuer"]),
		OIDCConfig: rawJSON(r["oidcConfig"]),
		SAMLConfig: rawJSON(r["samlConfig"]),
		UserID:     str(r["userId"]),
		ProviderID: str(r["providerId"]),
		Domain:     str(r["domain"]),
	}
	if org := str(r["organizationId"]); org != "" {
		out.OrganizationID = &org
	}
	if v, ok := r["domainVerified"]; ok {
		b, _ := v.(bool)
		out.DomainVerified = &b
	}
	return out
}

// rawJSON is safeJsonParse for the response: the stored JSON object, or null.
func rawJSON(v any) json.RawMessage {
	s := str(v)
	if s == "" || !json.Valid([]byte(s)) {
		return json.RawMessage("null")
	}
	return json.RawMessage(s)
}

func nullable(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// isZodURL is z.string().url(): an absolute URL with a scheme.
func isZodURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme != "" && (u.Host != "" || u.Opaque != "" || u.Path != "")
}

// ─── sanitized output ────────────────────────────────────────────────────────

// sanitize is better-auth's sanitizeProvider.
func (s *Service) sanitize(ctx context.Context, p *config.Provider) ssodtos.SSOSanitizedProvider {
	out := ssodtos.SSOSanitizedProvider{
		ProviderID:     p.ProviderID,
		Type:           "oidc",
		Issuer:         p.Issuer,
		Domain:         p.Domain,
		DomainVerified: p.IsDomainVerified(),
		SPMetadataURL:  s.kit.RequestBaseURL(ctx) + "/sso/saml2/sp/metadata?providerId=" + encodeURIComponent(p.ProviderID),
	}
	if p.OrganizationID != "" {
		org := p.OrganizationID
		out.OrganizationID = &org
	}
	if c := p.SAMLConfig; c != nil {
		out.Type = "saml"
		out.SAMLConfig = &ssodtos.SSOSanitizedSAMLConfig{
			EntryPoint: c.EntryPoint, CallbackURL: c.CallbackURL, Audience: c.Audience,
			WantAssertionsSigned: c.WantAssertionsSigned, AuthnRequestsSigned: c.AuthnRequestsSigned,
			IdentifierFormat: c.IdentifierFormat, SignatureAlgorithm: c.SignatureAlgorithm, DigestAlgorithm: c.DigestAlgorithm,
			Certificate: certificateInfo(c.Cert),
		}
	}
	if c := p.OIDCConfig; c != nil {
		out.OIDCConfig = &ssodtos.SSOSanitizedOIDCConfig{
			DiscoveryEndpoint: c.DiscoveryEndpoint, ClientIDLastFour: maskClientID(c.ClientID), PKCE: c.PKCE,
			AuthorizationEndpoint: c.AuthorizationEndpoint, TokenEndpoint: c.TokenEndpoint, UserInfoEndpoint: c.UserInfoEndpoint,
			JWKSEndpoint: c.JWKSEndpoint, Scopes: c.Scopes, TokenEndpointAuthentication: c.TokenEndpointAuthentication,
		}
	}
	return out
}

// certificateInfo is better-auth's parseCertificate (Node's X509Certificate fields), or {error}.
func certificateInfo(certPEM string) ssodtos.SSOCertificateInfo {
	cert, err := parseCertificate(certPEM)
	if err != nil {
		return ssodtos.SSOCertificateInfo{Error: "Failed to parse certificate"}
	}
	sum := sha256.Sum256(cert.Raw)
	hexParts := make([]string, len(sum))
	for i, b := range sum {
		hexParts[i] = fmt.Sprintf("%02X", b)
	}
	alg := "UNKNOWN"
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		alg = "RSA"
	case x509.ECDSA:
		alg = "EC"
	case x509.Ed25519:
		alg = "ED25519"
	}
	// Node formats validity dates like OpenSSL: "Jan  1 00:00:00 2024 GMT"
	const nodeDate = "Jan _2 15:04:05 2006 GMT"
	return ssodtos.SSOCertificateInfo{
		FingerprintSha256:  strings.Join(hexParts, ":"),
		NotBefore:          cert.NotBefore.UTC().Format(nodeDate),
		NotAfter:           cert.NotAfter.UTC().Format(nodeDate),
		PublicKeyAlgorithm: alg,
	}
}

// parseCertificate accepts a PEM certificate or its bare base64 body.
func parseCertificate(raw string) (*x509.Certificate, error) {
	// Step 1: wrap a bare body in PEM armor
	text := strings.TrimSpace(raw)
	if !strings.Contains(text, "-----BEGIN") {
		text = "-----BEGIN CERTIFICATE-----\n" + text + "\n-----END CERTIFICATE-----"
	}
	// Step 2: decode
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, fmt.Errorf("sso: invalid certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// encodeURIComponent mirrors JavaScript's encodeURIComponent.
func encodeURIComponent(v string) string {
	e := url.QueryEscape(v)
	e = strings.ReplaceAll(e, "+", "%20")
	for _, r := range []string{"!", "'", "(", ")", "*"} {
		e = strings.ReplaceAll(e, url.QueryEscape(r), r)
	}
	return e
}

// ─── GET /sso/providers ──────────────────────────────────────────────────────

// ListProviders is better-auth's listSSOProviders: the user's own providers, plus organization providers of
// organizations the user administers (or owns, without the organization plugin).
func (s *Service) ListProviders(ctx context.Context, userID string) (*ssodtos.SSOListProvidersResponse, error) {
	// Step 1: every provider
	all, err := s.listProviderRecords(ctx, nil)
	if err != nil {
		return nil, errorf("list providers: %w", err)
	}
	var owned, orgProviders []*config.Provider
	for _, r := range all {
		p := providerFromRecord(r)
		if p.OrganizationID == "" {
			if p.UserID == userID {
				owned = append(owned, p)
			}
			continue
		}
		orgProviders = append(orgProviders, p)
	}
	accessible := owned
	// Step 2: organization providers
	if orgs := s.orgs(); orgs != nil {
		if len(orgProviders) > 0 {
			admin, err := s.adminOrganizations(ctx, orgs, userID)
			if err != nil {
				return nil, err
			}
			for _, p := range orgProviders {
				if admin[p.OrganizationID] {
					accessible = append(accessible, p)
				}
			}
		}
	} else {
		for _, p := range orgProviders {
			if p.UserID == userID {
				accessible = append(accessible, p)
			}
		}
	}
	// Step 3: sanitize
	out := &ssodtos.SSOListProvidersResponse{Providers: make([]ssodtos.SSOSanitizedProvider, 0, len(accessible))}
	for _, p := range accessible {
		out.Providers = append(out.Providers, s.sanitize(ctx, p))
	}
	return out, nil
}

// adminOrganizations is batchCheckOrgAdmin: the organizations where userID is owner or admin.
func (s *Service) adminOrganizations(ctx context.Context, orgs plugins.OrganizationStore, userID string) (map[string]bool, error) {
	members, err := orgs.ListMembersByUser(ctx, userID)
	if err != nil {
		return nil, errorf("list memberships: %w", err)
	}
	out := map[string]bool{}
	for _, m := range members {
		if hasOrgAdminRole(m.Role) {
			out[m.OrganizationID] = true
		}
	}
	return out, nil
}

// checkProviderAccess is better-auth's checkProviderAccess: organization admins (organization plugin) or the
// owner may manage a provider.
func (s *Service) checkProviderAccess(ctx context.Context, userID, providerID string) (*config.Provider, adapter.Record, error) {
	// Step 1: the provider
	p, r, err := s.findStoredProvider(ctx, providerID)
	if err != nil {
		return nil, nil, errorf("find provider: %w", err)
	}
	if p == nil {
		return nil, nil, ErrProviderNotFound
	}
	// Step 2: access
	hasAccess := p.UserID == userID
	if p.OrganizationID != "" {
		if orgs := s.orgs(); orgs != nil {
			m, err := orgs.FindMember(ctx, p.OrganizationID, userID)
			if err != nil {
				return nil, nil, errorf("find member: %w", err)
			}
			hasAccess = m != nil && hasOrgAdminRole(m.Role)
		}
	}
	if !hasAccess {
		return nil, nil, ErrNoProviderAccess
	}
	return p, r, nil
}

// GetProvider is better-auth's getSSOProvider.
func (s *Service) GetProvider(ctx context.Context, userID, providerID string) (*ssodtos.SSOSanitizedProvider, error) {
	p, _, err := s.checkProviderAccess(ctx, userID, providerID)
	if err != nil {
		return nil, err
	}
	out := s.sanitize(ctx, p)
	return &out, nil
}

// DeleteProvider is better-auth's deleteSSOProvider.
func (s *Service) DeleteProvider(ctx context.Context, userID, providerID string) error {
	if _, _, err := s.checkProviderAccess(ctx, userID, providerID); err != nil {
		return err
	}
	if err := s.store.Delete(ctx, Model, []adapter.Where{{Field: "providerId", Value: providerID}}); err != nil {
		return errorf("delete provider: %w", err)
	}
	return nil
}

// ─── POST /sso/update-provider ───────────────────────────────────────────────

// UpdateProvider is better-auth's updateSSOProvider: a partial update; a new domain resets domainVerified.
func (s *Service) UpdateProvider(ctx context.Context, userID string, in ssodtos.SSOUpdateProviderInput) (*ssodtos.SSOSanitizedProvider, error) {
	// Step 1: something must change, and the user must manage the provider
	if in.Issuer == "" && (in.Domain == nil || *in.Domain == "") && in.SAMLConfig == nil && in.OIDCConfig == nil {
		return nil, ErrNoFieldsToUpdate
	}
	existing, rec, err := s.checkProviderAccess(ctx, userID, in.ProviderID)
	if err != nil {
		return nil, err
	}
	update := adapter.Record{}
	if in.Issuer != "" {
		update["issuer"] = in.Issuer
	}
	if in.Domain != nil {
		update["domain"] = *in.Domain
		if *in.Domain != existing.Domain && s.cfg.DomainVerification.Enabled {
			update["domainVerified"] = false
		}
	}
	issuerFor := func(current map[string]any) string {
		if in.Issuer != "" {
			return in.Issuer
		}
		if v := str(current["issuer"]); v != "" {
			return v
		}
		return existing.Issuer
	}
	// Step 2: SAML config: size and algorithm checks, then merge onto the stored config
	if sc := in.SAMLConfig; sc != nil {
		if sc.IDPMetadata != nil && sc.IDPMetadata.Metadata != "" && len(sc.IDPMetadata.Metadata) > s.cfg.SAML.MaxMetadataSize {
			return nil, errMetadataTooLarge(s.cfg.SAML.MaxMetadataSize)
		}
		if sc.SignatureAlgorithm != "" || sc.DigestAlgorithm != "" {
			if err := validateConfigAlgorithms(sc.SignatureAlgorithm, sc.DigestAlgorithm, s.cfg.SAML.Algorithms); err != nil {
				return nil, err
			}
		}
		current, err := parseStoredConfig(rec["samlConfig"], "SAML")
		if err != nil {
			return nil, err
		}
		merged, err := mergeConfig(current, sc, issuerFor(current), false)
		if err != nil {
			return nil, err
		}
		update["samlConfig"] = merged
	}
	// Step 3: OIDC config: endpoint checks, then merge (pkce defaults to true)
	if oc := in.OIDCConfig; oc != nil {
		if err := validateSkipDiscoveryEndpoints(&OIDCEndpoints{
			AuthorizationEndpoint: oc.AuthorizationEndpoint, TokenEndpoint: oc.TokenEndpoint,
			UserInfoEndpoint: oc.UserInfoEndpoint, JWKSEndpoint: oc.JWKSEndpoint, DiscoveryEndpoint: oc.DiscoveryEndpoint,
		}, s.isTrustedOrigin(ctx)); err != nil {
			return nil, mapDiscoveryError(err)
		}
		current, err := parseStoredConfig(rec["oidcConfig"], "OIDC")
		if err != nil {
			return nil, err
		}
		merged, err := mergeConfig(current, oc, issuerFor(current), true)
		if err != nil {
			return nil, err
		}
		update["oidcConfig"] = merged
	}
	// Step 4: write and return the sanitized provider
	if _, err := s.store.Update(ctx, Model, []adapter.Where{{Field: "providerId", Value: in.ProviderID}}, update); err != nil {
		return nil, errorf("update provider: %w", err)
	}
	full, _, err := s.findStoredProvider(ctx, in.ProviderID)
	if err != nil {
		return nil, errorf("find provider: %w", err)
	}
	if full == nil {
		return nil, ErrProviderNotFoundAfterWrite
	}
	out := s.sanitize(ctx, full)
	return &out, nil
}

// parseStoredConfig is parseAndValidateConfig: the stored JSON object, or 400 when the kind is not configured.
func parseStoredConfig(v any, kind string) (map[string]any, error) {
	var m map[string]any
	if raw := str(v); raw != "" {
		_ = json.Unmarshal([]byte(raw), &m)
	}
	if m == nil {
		return nil, errCannotUpdateConfig(kind)
	}
	return m, nil
}

// mergeConfig is mergeSAMLConfig / mergeOIDCConfig: the provided update fields overlay the stored config,
// issuer is set, and (OIDC) pkce defaults to true.
func mergeConfig(current map[string]any, updates any, issuer string, oidc bool) (string, error) {
	// Step 1: the provided update fields (absent ones are omitted by the JSON encoding)
	raw, err := json.Marshal(updates)
	if err != nil {
		return "", err
	}
	var upd map[string]any
	if err := json.Unmarshal(raw, &upd); err != nil {
		return "", err
	}
	// Step 2: overlay
	for k, v := range upd {
		if v != nil {
			current[k] = v
		}
	}
	current["issuer"] = issuer
	if oidc {
		if _, ok := current["pkce"]; !ok {
			current["pkce"] = true
		}
	}
	out, err := json.Marshal(current)
	return string(out), err
}
