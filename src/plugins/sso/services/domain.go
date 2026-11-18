package services

import (
	"context"
	"crypto/rand"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	ssodtos "github.com/better-go-auth/goauth/src/plugins/sso/dtos"
)

// dnsLabelMaxLength is the DNS label limit of the verification record name.
const dnsLabelMaxLength = 63

// domainTokenTTL is how long a domain verification token stays valid (7 days).
const domainTokenTTL = 7 * 24 * time.Hour

// verificationIdentifier is "_<tokenPrefix>-<providerId>", the DNS TXT record name (and verification identifier).
func (s *Service) verificationIdentifier(providerID string) string {
	return "_" + s.cfg.DomainVerification.TokenPrefix + "-" + providerID
}

// ─── verification values ─────────────────────────────────────────────────────

// storeVerification is internalAdapter.createVerificationValue.
func (s *Service) storeVerification(ctx context.Context, identifier, value string, ttl time.Duration) error {
	return s.storeVerificationUntil(ctx, identifier, value, time.Now().Add(ttl))
}

// storeVerificationUntil stores a verification value expiring at expiresAt.
func (s *Service) storeVerificationUntil(ctx context.Context, identifier, value string, expiresAt time.Time) error {
	_, err := s.kit.Repos.UpsertVerificationValue(ctx, &models.Verification{Identifier: identifier, Value: value, ExpiresAt: expiresAt.UTC()})
	return err
}

// findVerification is internalAdapter.findVerificationValue (nil when missing).
func (s *Service) findVerification(ctx context.Context, identifier string) (*models.Verification, error) {
	return pluginkit.AcceptNotFound(s.kit.Repos.FindVerificationValue(ctx, identifier))
}

// consumeVerification is internalAdapter.consumeVerificationValue (find + delete, nil when missing).
func (s *Service) consumeVerification(ctx context.Context, identifier string) (*models.Verification, error) {
	return pluginkit.AcceptNotFound(s.kit.Repos.ConsumeVerificationValue(ctx, identifier))
}

// deleteVerification is internalAdapter.deleteVerificationByIdentifier (errors are logged).
func (s *Service) deleteVerification(ctx context.Context, identifier string) {
	if err := s.kit.Repos.DeleteVerificationByIdentifier(ctx, identifier); err != nil && !pluginkit.IsNotFound(err) {
		logger.Warn("sso: failed to delete verification value", "error", err)
	}
}

const randomAlphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// randomString is better-auth's generateRandomString (a-z A-Z 0-9 by default).
func randomString(n int) string {
	buf := make([]byte, n)
	out := make([]byte, n)
	for i := 0; i < n; {
		if _, err := rand.Read(buf); err != nil {
			panic("sso: crypto/rand failed: " + err.Error())
		}
		for _, b := range buf {
			// rejection sampling: 62 symbols, keep bytes below 248 (4 * 62)
			if b >= 248 || i >= n {
				continue
			}
			out[i] = randomAlphabet[int(b)%len(randomAlphabet)]
			i++
		}
	}
	return string(out)
}

// ─── domain verification endpoints ───────────────────────────────────────────

// domainProvider loads the provider and checks that userID owns it and belongs to its organization.
func (s *Service) domainProvider(ctx context.Context, userID, providerID string) (adapter.Record, error) {
	// Step 1: the provider
	r, err := s.findProviderRecord(ctx, providerID)
	if err != nil {
		return nil, errorf("find provider: %w", err)
	}
	if r == nil {
		return nil, ErrDomainProviderNotFound
	}
	p := providerFromRecord(r)
	// Step 2: owner and (for organization providers) member
	isOrgMember := true
	if p.OrganizationID != "" {
		isOrgMember = false
		if orgs := s.orgs(); orgs != nil {
			m, err := orgs.FindMember(ctx, p.OrganizationID, userID)
			if err != nil {
				return nil, errorf("find member: %w", err)
			}
			isOrgMember = m != nil
		}
	}
	if p.UserID != userID || !isOrgMember {
		return nil, ErrDomainInsufficientAccess
	}
	// Step 3: not verified yet
	if p.IsDomainVerified() {
		return nil, ErrDomainVerified
	}
	return r, nil
}

// RequestDomainVerification is better-auth's requestDomainVerification: the pending token, or a new one.
func (s *Service) RequestDomainVerification(ctx context.Context, userID, providerID string) (*ssodtos.SSODomainVerificationTokenResponse, error) {
	// Step 1: access checks
	r, err := s.domainProvider(ctx, userID, providerID)
	if err != nil {
		return nil, err
	}
	identifier := s.verificationIdentifier(str(r["providerId"]))
	// Step 2: an active token is returned again
	active, err := s.findVerification(ctx, identifier)
	if err != nil {
		return nil, errorf("find verification: %w", err)
	}
	if active != nil && active.ExpiresAt.After(time.Now()) {
		return &ssodtos.SSODomainVerificationTokenResponse{DomainVerificationToken: active.Value}, nil
	}
	// Step 3: a new token valid for a week
	token := randomString(24)
	if err := s.storeVerification(ctx, identifier, token, domainTokenTTL); err != nil {
		return nil, errorf("store verification: %w", err)
	}
	return &ssodtos.SSODomainVerificationTokenResponse{DomainVerificationToken: token}, nil
}

// VerifyDomain is better-auth's verifyDomain: the TXT record "_<prefix>-<providerId>.<domain>" must contain
// "<identifier>=<token>".
func (s *Service) VerifyDomain(ctx context.Context, userID, providerID string) error {
	// Step 1: access checks
	r, err := s.domainProvider(ctx, userID, providerID)
	if err != nil {
		return err
	}
	identifier := s.verificationIdentifier(str(r["providerId"]))
	if len(identifier) > dnsLabelMaxLength {
		return ErrIdentifierTooLong
	}
	// Step 2: the pending token
	active, err := s.findVerification(ctx, identifier)
	if err != nil {
		return errorf("find verification: %w", err)
	}
	if active == nil || !active.ExpiresAt.After(time.Now()) {
		return ErrNoPendingVerification
	}
	// Step 3: the DNS TXT records of the provider domain
	hostname := hostnameFromDomain(str(r["domain"]))
	if hostname == "" {
		return ErrInvalidDomain
	}
	records, err := s.cfg.DomainVerification.LookupTXT(ctx, identifier+"."+hostname)
	if err != nil {
		logger.Warn("DNS resolution failure while validating domain ownership", "error", err)
	}
	want := identifier + "=" + active.Value
	found := false
	for _, rec := range records {
		if strings.Contains(rec, want) {
			found = true
			break
		}
	}
	if !found {
		return ErrDomainVerificationFailed
	}
	// Step 4: mark the domain verified
	if _, err := s.store.Update(ctx, Model, []adapter.Where{{Field: "providerId", Value: str(r["providerId"])}}, adapter.Record{"domainVerified": true}); err != nil {
		return errorf("update provider: %w", err)
	}
	return nil
}

var hostnamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// hostnameFromDomain is tldts' getHostname: the host of a URL or bare domain, "" when invalid.
func hostnameFromDomain(domain string) string {
	d := strings.TrimSpace(strings.ToLower(domain))
	if strings.Contains(d, "://") {
		u, err := url.Parse(d)
		if err != nil {
			return ""
		}
		d = u.Hostname()
	} else {
		if i := strings.IndexAny(d, "/?#"); i != -1 {
			d = d[:i]
		}
		if i := strings.LastIndex(d, "@"); i != -1 {
			d = d[i+1:]
		}
		if i := strings.Index(d, ":"); i != -1 {
			d = d[:i]
		}
	}
	d = strings.TrimSuffix(d, ".")
	if d == "" || !hostnamePattern.MatchString(d) {
		return ""
	}
	return d
}
