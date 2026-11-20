package services

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/better-go-auth/goauth/src/common/logger"
	socialsvc "github.com/better-go-auth/goauth/src/plugins/social/services"
	"github.com/better-go-auth/goauth/src/plugins/sso/config"
	ssodtos "github.com/better-go-auth/goauth/src/plugins/sso/dtos"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
)

// Verification identifier prefixes (better-auth's src/constants.ts).
const (
	AuthnRequestKeyPrefix  = "saml-authn-request:"
	UsedAssertionKeyPrefix = "saml-used-assertion:"
	SAMLSessionKeyPrefix   = "saml-session:"
	SAMLSessionByIDPrefix  = "saml-session-by-id:"
	LogoutRequestKeyPrefix = "saml-logout-request:"
)

// RelayStateCookie is the cookie of the SAML relay state (generateGenericState's cookieName).
const RelayStateCookie = "relay_state"

// nameIDEmail is samlify's default NameID format.
const nameIDEmail = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

// ─── service provider / identity provider ────────────────────────────────────

// spOptions tune buildSP.
type spOptions struct {
	// currentURL is where the message was received (Destination check).
	currentURL string
}

// buildSP is better-auth's createSP + createIdP on goauth's SAML library (github.com/crewjam/saml): the
// service provider for providerID with the identity provider's metadata. Signatures, issuer, audience,
// destination / recipient, status and timestamps are validated by the library; InResponseTo and replay
// protection are done by the plugin (better-auth's verification-table semantics).
func (s *Service) buildSP(ctx context.Context, providerID string, c *config.SAMLConfig) (*saml.ServiceProvider, error) {
	base := s.kit.RequestBaseURL(ctx)
	// Step 1: the SP identity (spMetadata XML wins over the computed values)
	entityID := c.Issuer
	if c.SPMetadata != nil && c.SPMetadata.EntityID != "" {
		entityID = c.SPMetadata.EntityID
	}
	acs := pick(c.CallbackURL, base+"/sso/saml2/sp/acs/"+providerID)
	if c.SPMetadata != nil && c.SPMetadata.Metadata != "" {
		if md, err := samlsp.ParseMetadata([]byte(c.SPMetadata.Metadata)); err == nil {
			entityID = pick(md.EntityID, entityID)
			for _, d := range md.SPSSODescriptors {
				for _, a := range d.AssertionConsumerServices {
					if a.Binding == saml.HTTPPostBinding {
						acs = a.Location
						break
					}
				}
			}
		}
	}
	acsURL, err := url.Parse(acs)
	if err != nil {
		return nil, fmt.Errorf("sso: invalid ACS URL: %w", err)
	}
	sloURL, _ := url.Parse(base + "/sso/saml2/sp/slo/" + providerID)
	// Step 2: the IdP metadata
	idp, err := buildIDPMetadata(c)
	if err != nil {
		return nil, err
	}
	sp := &saml.ServiceProvider{
		EntityID:          entityID,
		AcsURL:            *acsURL,
		SloURL:            *sloURL,
		IDPMetadata:       idp,
		AllowIDPInitiated: true,
		// InResponseTo is checked against the stored AuthnRequest IDs after parsing (better-auth semantics)
		ValidateRequestID: func(saml.Response, []string) error { return nil },
		AuthnNameIDFormat: saml.NameIDFormat(pick(c.IdentifierFormat, nameIDEmail)),
		HTTPClient:        s.cfg.HTTPClient,
	}
	// Step 3: audience: this SP's entity ID, or the configured audience
	audience := c.Audience
	sp.ValidateAudienceRestriction = func(a *saml.Assertion) error {
		if a.Conditions == nil || len(a.Conditions.AudienceRestrictions) == 0 {
			return fmt.Errorf("assertion has no AudienceRestriction")
		}
		for _, r := range a.Conditions.AudienceRestrictions {
			ok := false
			for _, aud := range r.AllAudiences() {
				if aud.Value == entityID || (audience != "" && aud.Value == audience) {
					ok = true
				}
			}
			if !ok {
				return fmt.Errorf("audience restriction does not contain %q", entityID)
			}
		}
		return nil
	}
	// Step 4: SP keys: signing (authnRequestsSigned) and decryption (encrypted assertions)
	signingPEM := ""
	if c.SPMetadata != nil {
		signingPEM = c.SPMetadata.PrivateKey
	}
	signingPEM = pick(signingPEM, c.PrivateKey)
	if signingPEM != "" {
		key, err := parsePrivateKey(signingPEM)
		if err != nil {
			return nil, err
		}
		sp.Key = key
		if sp.Certificate, err = selfSignedCertificate(key, entityID); err != nil {
			return nil, err
		}
		if c.AuthnRequestsSigned != nil && *c.AuthnRequestsSigned {
			sp.SignatureMethod = signatureMethodFor(key, c.SignatureAlgorithm)
		}
	}
	decPEM := c.DecryptionPvk
	if c.SPMetadata != nil && c.SPMetadata.EncPrivateKey != "" {
		decPEM = c.SPMetadata.EncPrivateKey
	}
	if decPEM != "" {
		if key, err := parsePrivateKey(decPEM); err == nil {
			if rk, ok := key.(*rsa.PrivateKey); ok {
				sp.DecryptionKeys = append(sp.DecryptionKeys, rk)
			}
		}
	}
	return sp, nil
}

// buildIDPMetadata is better-auth's createIdP: the IdP metadata XML, or an entity built from entityID, the
// SSO / SLO services (default: entryPoint with the HTTP-Redirect binding) and the signing certificate.
func buildIDPMetadata(c *config.SAMLConfig) (*saml.EntityDescriptor, error) {
	idp := c.IDPMetadata
	if idp != nil && idp.Metadata != "" {
		md, err := samlsp.ParseMetadata([]byte(idp.Metadata))
		if err != nil {
			return nil, fmt.Errorf("sso: invalid IdP metadata: %w", err)
		}
		return md, nil
	}
	// Step 1: endpoints
	entityID := c.Issuer
	cert := c.Cert
	var sso, slo []saml.Endpoint
	if idp != nil {
		entityID = pick(idp.EntityID, entityID)
		cert = pick(idp.Cert, cert)
		for _, e := range idp.SingleSignOnService {
			sso = append(sso, saml.Endpoint{Binding: e.Binding, Location: e.Location})
		}
		for _, e := range idp.SingleLogoutService {
			slo = append(slo, saml.Endpoint{Binding: e.Binding, Location: e.Location})
		}
	}
	if len(sso) == 0 {
		sso = []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: c.EntryPoint}}
	}
	// Step 2: the signing certificate (base64 DER inside KeyInfo)
	var keys []saml.KeyDescriptor
	if body := certBody(cert); body != "" {
		keys = append(keys, saml.KeyDescriptor{Use: "signing", KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{X509Certificates: []saml.X509Certificate{{Data: body}}}}})
	}
	want := c.AuthnRequestsSigned != nil && *c.AuthnRequestsSigned
	return &saml.EntityDescriptor{
		EntityID: entityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{
				RoleDescriptor:       saml.RoleDescriptor{ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol", KeyDescriptors: keys},
				SingleLogoutServices: slo,
			},
			WantAuthnRequestsSigned: &want,
			SingleSignOnServices:    sso,
		}},
	}, nil
}

// certBody returns the base64 body of a PEM certificate (or the input without whitespace).
func certBody(cert string) string {
	text := strings.TrimSpace(cert)
	if text == "" {
		return ""
	}
	if block, _ := pem.Decode([]byte(text)); block != nil {
		return base64.StdEncoding.EncodeToString(block.Bytes)
	}
	return strings.Join(strings.Fields(text), "")
}

// normalizePEM is better-auth's normalizePem: trim every line.
func normalizePEM(key string) string {
	lines := strings.Split(key, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(l)
	}
	return strings.TrimSpace(strings.Join(lines, "\n")) + "\n"
}

// parsePrivateKey reads a PEM RSA / EC private key (PKCS#1, PKCS#8 or SEC 1).
func parsePrivateKey(raw string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(normalizePEM(raw)))
	if block == nil {
		return nil, errors.New("sso: invalid private key PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sso: unsupported private key: %w", err)
	}
	signer, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("sso: unsupported private key type")
	}
	return signer, nil
}

// certCache keeps one self-signed certificate per SP key (the library needs a certificate to sign).
var certCache sync.Map

// selfSignedCertificate returns a certificate for key (cached). better-auth's SAML options carry only the SP
// private key; the certificate is only used inside signatures, IdPs verify with the registered SP key.
func selfSignedCertificate(key crypto.Signer, cn string) (*x509.Certificate, error) {
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(der)
	cacheKey := fmt.Sprintf("%x", sum)
	if c, ok := certCache.Load(cacheKey); ok {
		return c.(*x509.Certificate), nil
	}
	tmpl := &x509.Certificate{
		SerialNumber: new(big.Int).SetBytes(sum[:8]),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, err
	}
	certCache.Store(cacheKey, cert)
	return cert, nil
}

// signatureMethodFor picks the AuthnRequest signature method: the configured algorithm, else SHA-256 for the
// key type.
func signatureMethodFor(key crypto.Signer, configured string) string {
	if configured != "" {
		return normalizeSignatureAlgorithm(configured)
	}
	if _, ok := key.Public().(*ecdsa.PublicKey); ok {
		return SigECDSASHA256
	}
	return SigRSASHA256
}

// ─── POST /sign-in/sso (SAML) ────────────────────────────────────────────────

// signInSAML is the SAML branch of signInSSO: a relay state, an AuthnRequest (HTTP-Redirect binding) and
// its ID stored for InResponseTo validation.
func (s *Service) signInSAML(ctx context.Context, provider *config.Provider, in ssodtos.SSOSignInInput) (*StartResult, error) {
	c := provider.SAMLConfig
	// Step 1: signing needs a private key
	hasKey := c.PrivateKey != "" || (c.SPMetadata != nil && c.SPMetadata.PrivateKey != "")
	if c.AuthnRequestsSigned != nil && *c.AuthnRequestsSigned && !hasKey {
		return nil, ErrAuthnRequestsSignedNoKey
	}
	// Step 2: the relay state (stored like an OAuth state, cookie "relay_state")
	if in.CallbackURL == "" {
		return nil, ErrCallbackURLRequired
	}
	st, err := s.oauth.GenerateStateWithCookie(ctx, RelayStateCookie, nil, socialsvc.StateRequest{
		CallbackURL:      in.CallbackURL,
		ErrorCallbackURL: in.ErrorCallbackURL,
		NewUserURL:       in.NewUserCallbackURL,
		RequestSignUp:    in.RequestSignUp,
	})
	if err != nil {
		logger.Error("Failed to create verification for relay state", "error", err)
		return nil, ErrRelayStateCreate
	}
	// Step 3: the AuthnRequest redirect URL
	sp, err := s.buildSP(ctx, provider.ProviderID, c)
	if err != nil {
		logger.Error("sso: invalid SAML configuration", "error", err)
		return nil, ErrInvalidSAMLRequest
	}
	idpURL := sp.GetSSOBindingLocation(saml.HTTPRedirectBinding)
	if idpURL == "" {
		return nil, ErrInvalidSAMLRequest
	}
	req, err := sp.MakeAuthenticationRequest(idpURL, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	if err != nil {
		logger.Error("sso: create AuthnRequest", "error", err)
		return nil, ErrInvalidSAMLRequest
	}
	u, err := req.Redirect(st.State, sp)
	if err != nil {
		logger.Error("sso: encode AuthnRequest", "error", err)
		return nil, ErrInvalidSAMLRequest
	}
	// Step 4: remember the request ID for InResponseTo validation
	if req.ID != "" && s.cfg.SAML.InResponseToValidation() {
		now := time.Now()
		record, _ := json.Marshal(map[string]any{
			"id": req.ID, "providerId": provider.ProviderID,
			"createdAt": now.UnixMilli(), "expiresAt": now.Add(s.cfg.SAML.RequestTTL).UnixMilli(),
		})
		if err := s.storeVerification(ctx, AuthnRequestKeyPrefix+req.ID, string(record), s.cfg.SAML.RequestTTL); err != nil {
			return nil, errorf("store authn request: %w", err)
		}
	}
	return &StartResult{Body: ssodtos.SSORedirectResponse{URL: u.String(), Redirect: true}, Cookies: st.Cookies}, nil
}

// ─── SAML response processing ────────────────────────────────────────────────

// SAMLParams are the posted SAML response and where it was received.
type SAMLParams struct {
	ProviderID   string
	SAMLResponse string
	RelayState   string
	// CurrentCallbackPath is the full URL of the receiving endpoint (redirect-loop guard, Destination check).
	CurrentCallbackPath string
}

// appOrigin is new URL(baseURL).origin.
func (s *Service) appOrigin(ctx context.Context) string {
	u, err := url.Parse(s.kit.RequestBaseURL(ctx))
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// safeRedirectURL is better-auth's getSafeRedirectUrl: relative paths on the app origin and trusted absolute
// URLs, never the callback endpoint itself; anything else falls back to the app origin.
func (s *Service) safeRedirectURL(ctx context.Context, target, callbackPath string) string {
	origin := s.appOrigin(ctx)
	if target == "" {
		return origin
	}
	callbackPathname := ""
	if cu, err := url.Parse(callbackPath); err == nil {
		callbackPathname = cu.Path
	}
	// Step 1: relative paths
	if strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "//") {
		abs, err := url.Parse(origin + target)
		if err != nil || abs.Scheme+"://"+abs.Host != origin || abs.Path == callbackPathname {
			return origin
		}
		return target
	}
	// Step 2: absolute URLs must be trusted and not the callback
	if !s.kit.Origins.IsTrustedFor(s.kit.Request(ctx), target, false) {
		return origin
	}
	if tu, err := url.Parse(target); err == nil && tu.Scheme != "" {
		if tu.Path == callbackPathname {
			return origin
		}
	} else if target == callbackPath || strings.HasPrefix(target, callbackPath+"?") {
		return origin
	}
	return target
}

// validateSingleAssertion is better-auth's validateSingleAssertion: valid base64 XML with exactly one
// (encrypted) assertion.
func validateSingleAssertion(samlResponse string) ([]byte, error) {
	// Step 1: decode
	decoded, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil || !strings.Contains(string(decoded), "<") {
		return nil, codedError(http.StatusBadRequest, "SAML_INVALID_ENCODING", "Invalid base64-encoded SAML response")
	}
	// Step 2: count the assertions
	n, err := countAssertions(decoded)
	if err != nil {
		return nil, codedError(http.StatusBadRequest, "SAML_INVALID_XML", "Failed to parse SAML response XML")
	}
	if n == 0 {
		return nil, codedError(http.StatusBadRequest, "SAML_NO_ASSERTION", "SAML response contains no assertions")
	}
	if n > 1 {
		return nil, codedError(http.StatusBadRequest, "SAML_MULTIPLE_ASSERTIONS", fmt.Sprintf("SAML response contains %d assertions, expected exactly 1", n))
	}
	return decoded, nil
}

// samlResponseInfo is what the plugin reads from the Response element itself.
type samlResponseInfo struct {
	InResponseTo string `xml:"InResponseTo,attr"`
}

// mapSAMLParseError is the parse failure of better-auth's pipeline ("Invalid SAML response"); expired and
// not-yet-valid assertions get validateSAMLTimestamp's messages.
func mapSAMLParseError(err error) error {
	var ire *saml.InvalidResponseError
	cause := err
	if errors.As(err, &ire) && ire.PrivateErr != nil {
		cause = ire.PrivateErr
	}
	switch {
	case errors.Is(cause, saml.ErrExpired):
		return apiError(http.StatusBadRequest, "SAML assertion has expired")
	case errors.Is(cause, saml.ErrNotYetValid):
		return apiError(http.StatusBadRequest, "SAML assertion is not yet valid")
	}
	return apiError(http.StatusBadRequest, "Invalid SAML response")
}

// validateSAMLTimestamp is better-auth's validateSAMLTimestamp (NotBefore / NotOnOrAfter with clock skew).
func (s *Service) validateSAMLTimestamp(c *saml.Conditions) error {
	skew := s.cfg.SAML.ClockSkew
	if c == nil || (c.NotBefore.IsZero() && c.NotOnOrAfter.IsZero()) {
		if s.cfg.SAML.RequireTimestamps {
			return apiError(http.StatusBadRequest, "SAML assertion missing required timestamp conditions")
		}
		logger.Warn("SAML assertion accepted without timestamp conditions")
		return nil
	}
	now := time.Now()
	if !c.NotBefore.IsZero() && now.Before(c.NotBefore.Add(-skew)) {
		return apiError(http.StatusBadRequest, "SAML assertion is not yet valid")
	}
	if !c.NotOnOrAfter.IsZero() && now.After(c.NotOnOrAfter.Add(skew)) {
		return apiError(http.StatusBadRequest, "SAML assertion has expired")
	}
	return nil
}

// samlAttributes collects the assertion attributes by name (single values as strings, several as []string).
func samlAttributes(a *saml.Assertion) map[string]any {
	out := map[string]any{}
	for _, st := range a.AttributeStatements {
		for _, attr := range st.Attributes {
			vals := make([]string, 0, len(attr.Values))
			for _, v := range attr.Values {
				vals = append(vals, v.Value)
			}
			var v any = vals
			if len(vals) == 1 {
				v = vals[0]
			}
			out[attr.Name] = v
			if attr.FriendlyName != "" {
				if _, taken := out[attr.FriendlyName]; !taken {
					out[attr.FriendlyName] = v
				}
			}
		}
	}
	return out
}

// firstAttr is better-auth's attr(): the first value of an attribute.
func firstAttr(attrs map[string]any, key string) string {
	switch v := attrs[key].(type) {
	case string:
		return v
	case []string:
		if len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// ProcessSAMLResponse is better-auth's processSAMLResponse, shared by /sso/saml2/callback/{providerId} and
// /sso/saml2/sp/acs/{providerId}: validate the response, enforce InResponseTo and replay protection, sign the
// user in and return the redirect.
func (s *Service) ProcessSAMLResponse(ctx context.Context, p SAMLParams) (*Redirect, error) {
	// Step 1: size limit, then whitespace stripped
	if len(p.SAMLResponse) > s.cfg.SAML.MaxResponseSize {
		return nil, errResponseTooLarge(s.cfg.SAML.MaxResponseSize)
	}
	samlResponse := strings.Join(strings.Fields(p.SAMLResponse), "")

	// Step 2: the relay state (invalid ones are ignored)
	var relay *socialsvc.StateData
	var cookies []http.Cookie
	if p.RelayState != "" {
		if st, ck, err := s.oauth.ParseStateWithCookie(ctx, RelayStateCookie, p.RelayState, true); err == nil {
			relay, cookies = st, ck
			if relay.ErrorURL == "" {
				relay.ErrorURL = s.oauth.DefaultErrorURL(ctx)
			}
		}
	}
	relayCallback := ""
	if relay != nil {
		relayCallback = relay.CallbackURL
	}

	// Step 3: the provider
	provider, err := s.findSAMLProvider(ctx, p.ProviderID)
	if err != nil {
		return nil, errorf("find provider: %w", err)
	}
	if provider == nil || provider.SAMLConfig == nil {
		return nil, ErrNoSAMLProviderFound
	}
	if s.cfg.DomainVerification.Enabled && !provider.IsDomainVerified() {
		return nil, ErrDomainNotVerified
	}
	c := provider.SAMLConfig
	sp, err := s.buildSP(ctx, p.ProviderID, c)
	if err != nil {
		logger.Error("sso: invalid SAML configuration", "error", err)
		return nil, ErrInvalidSAMLConfiguration
	}
	samlRedirectURL := s.safeRedirectURL(ctx, pick(relayCallback, c.CallbackURL), p.CurrentCallbackPath)
	redirectErr := func(code, description string) (*Redirect, error) {
		return &Redirect{Location: samlRedirectURL + "?error=" + code + "&error_description=" + description, Cookies: cookies}, nil
	}

	// Step 4: exactly one assertion, then the library's validation (signature, issuer, audience,
	// destination, status, subject confirmation, conditions)
	decoded, err := validateSingleAssertion(samlResponse)
	if err != nil {
		return nil, err
	}
	currentURL, _ := url.Parse(p.CurrentCallbackPath)
	assertion, err := sp.ParseXMLResponse(decoded, nil, *currentURL)
	if err != nil {
		var ire *saml.InvalidResponseError
		detail := err.Error()
		if errors.As(err, &ire) && ire.PrivateErr != nil {
			detail = ire.PrivateErr.Error()
		}
		logger.Error("SAML response validation failed", "error", detail)
		return nil, mapSAMLParseError(err)
	}

	// Step 5: algorithms and timestamps
	if err := validateSAMLAlgorithms(scanResponseAlgorithms(decoded), s.cfg.SAML.Algorithms); err != nil {
		return nil, err
	}
	if err := s.validateSAMLTimestamp(assertion.Conditions); err != nil {
		return nil, err
	}

	// Step 6: InResponseTo: the response must answer a stored AuthnRequest of this provider
	var info samlResponseInfo
	_ = xml.Unmarshal(decoded, &info)
	if s.cfg.SAML.InResponseToValidation() {
		if info.InResponseTo != "" {
			consumed, err := s.consumeVerification(ctx, AuthnRequestKeyPrefix+info.InResponseTo)
			if err != nil {
				return nil, errorf("consume authn request: %w", err)
			}
			var stored struct {
				ProviderID string `json:"providerId"`
			}
			if consumed == nil || json.Unmarshal([]byte(consumed.Value), &stored) != nil {
				logger.Error("SAML InResponseTo validation failed: unknown or expired request ID", "inResponseTo", info.InResponseTo, "providerId", p.ProviderID)
				return redirectErr("invalid_saml_response", "Unknown+or+expired+request+ID")
			}
			if stored.ProviderID != p.ProviderID {
				logger.Error("SAML InResponseTo validation failed: provider mismatch", "inResponseTo", info.InResponseTo)
				return redirectErr("invalid_saml_response", "Provider+mismatch")
			}
		} else if !s.cfg.SAML.IdpInitiatedAllowed() {
			logger.Error("SAML IdP-initiated SSO rejected: InResponseTo missing and allowIdpInitiated is false", "providerId", p.ProviderID)
			return redirectErr("unsolicited_response", "IdP-initiated+SSO+not+allowed")
		}
	}

	// Step 7: replay protection: an assertion ID is accepted once until it expires
	if assertion.ID != "" {
		key := UsedAssertionKeyPrefix + assertion.ID
		expiresAt := time.Now().Add(config.DefaultAssertionTTL)
		if assertion.Conditions != nil && !assertion.Conditions.NotOnOrAfter.IsZero() {
			expiresAt = assertion.Conditions.NotOnOrAfter.Add(s.cfg.SAML.ClockSkew)
		}
		existing, err := s.findVerification(ctx, key)
		if err != nil {
			return nil, errorf("find used assertion: %w", err)
		}
		if existing != nil {
			var rec struct {
				ExpiresAt int64 `json:"expiresAt"`
			}
			if json.Unmarshal([]byte(existing.Value), &rec) == nil && rec.ExpiresAt >= time.Now().UnixMilli() {
				logger.Error("SAML assertion replay detected: assertion ID already used", "assertionId", assertion.ID, "providerId", p.ProviderID)
				return redirectErr("replay_detected", "SAML+assertion+has+already+been+used")
			}
		}
		record, _ := json.Marshal(map[string]any{
			"assertionId": assertion.ID, "issuer": sp.IDPMetadata.EntityID, "providerId": p.ProviderID,
			"usedAt": time.Now().UnixMilli(), "expiresAt": expiresAt.UnixMilli(),
		})
		if err := s.storeVerificationUntil(ctx, key, string(record), expiresAt); err != nil {
			return nil, errorf("store used assertion: %w", err)
		}
	} else {
		logger.Warn("Could not extract assertion ID for replay protection", "providerId", p.ProviderID)
	}

	// Step 8: the user from the attributes (mapping with better-auth's defaults)
	attrs := samlAttributes(assertion)
	nameID := ""
	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		nameID = assertion.Subject.NameID.Value
	}
	m := config.SAMLMapping{}
	if c.Mapping != nil {
		m = *c.Mapping
	}
	userInfo := map[string]any{}
	for key, field := range m.ExtraFields {
		if f, ok := field.(string); ok {
			userInfo[key] = attrs[f]
		}
	}
	id := pick(firstAttr(attrs, pick(m.ID, "nameID")), nameID)
	email := strings.ToLower(pick(firstAttr(attrs, pick(m.Email, "email")), nameID))
	name := strings.TrimSpace(strings.Join(nonEmpty(firstAttr(attrs, pick(m.FirstName, "givenName")), firstAttr(attrs, pick(m.LastName, "surname"))), " "))
	if name == "" {
		name = pick(firstAttr(attrs, pick(m.Name, "displayName")), nameID)
	}
	emailVerified := false
	if s.cfg.TrustEmailVerified && m.EmailVerified != "" {
		emailVerified = truthy(firstAttr(attrs, m.EmailVerified)) && firstAttr(attrs, m.EmailVerified) != "false"
	}
	userInfo["id"], userInfo["email"], userInfo["name"], userInfo["emailVerified"] = id, email, name, emailVerified
	if id == "" || email == "" {
		logger.Error("Missing essential user info from SAML response", "extractedId", id, "extractedEmail", email)
		return nil, ErrMissingUserInfoSAML
	}

	// Step 9: sign in, link or sign up
	callbackURL := pick(pick(relayCallback, c.CallbackURL), s.kit.RequestBaseURL(ctx))
	errorURL := samlRedirectURL
	if relay != nil && relay.ErrorURL != "" {
		errorURL = relay.ErrorURL
	}
	result, err := s.oauth.HandleOAuthUserInfo(ctx, socialsvc.OAuthUserInput{
		UserInfo:               socialProfile(id, email, pick(name, email), emailVerified),
		Account:                socialsvc.AccountData{ProviderID: p.ProviderID, AccountID: id},
		CallbackURL:            callbackURL,
		DisableSignUp:          s.cfg.DisableImplicitSignUp,
		IsTrustedProvider:      provider.IsDomainVerified() && validateEmailDomain(email, provider.Domain),
		IgnoreTrustedProviders: true,
	})
	if err != nil {
		if ae := codedAPIError(err); ae != nil {
			return &Redirect{Location: withParams(errorURL, url.Values{"error": {string(ae.Code)}, "error_description": {ae.Message}}), Cookies: cookies}, nil
		}
		return nil, err
	}
	if result.Error != "" {
		return &Redirect{Location: callbackURL + "?error=" + strings.Join(strings.Split(result.Error, " "), "_"), Cookies: cookies}, nil
	}

	// Step 10: provisioning, organization membership, session cookie
	if s.cfg.ProvisionUser != nil && (result.IsRegister || s.cfg.ProvisionUserOnEveryLogin) {
		if err := s.cfg.ProvisionUser(ctx, config.ProvisionUserData{User: result.User, UserInfo: userInfo, Provider: provider}); err != nil {
			return nil, err
		}
	}
	if err := s.assignOrganizationFromProvider(ctx, result.User, provider, attrs, nil); err != nil {
		return nil, err
	}
	cookies = append(cookies, s.oauth.SignInCookies(ctx, result)...)

	// Step 11: Single Logout bookkeeping (NameID + SessionIndex per session)
	if s.cfg.SAML.EnableSingleLogout && nameID != "" {
		s.recordSAMLSession(ctx, p.ProviderID, nameID, assertion, result.Session.Session.ID, result.Session.Session.Token, time.Time(result.Session.Session.ExpiresAt))
	}
	return &Redirect{Location: s.safeRedirectURL(ctx, pick(relayCallback, c.CallbackURL), p.CurrentCallbackPath), Cookies: cookies}, nil
}

// nonEmpty keeps the non-empty values (filter(Boolean)).
func nonEmpty(vals ...string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
