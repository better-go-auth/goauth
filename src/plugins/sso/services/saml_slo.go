package services

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	"github.com/crewjam/saml"
)

// socialProfile builds the provider profile passed to handleOAuthUserInfo.
func socialProfile(id, email, name string, emailVerified bool) providers.UserInfo {
	return providers.UserInfo{ID: id, Email: email, Name: name, EmailVerified: emailVerified}
}

// codedAPIError returns err as an API error with a code (better-auth's isAPIError(e) && e.body?.code), or nil.
func codedAPIError(err error) *autherr.AuthError {
	if ae := autherr.AsAuthError(err); ae != nil && ae.Code != "" {
		return ae
	}
	return nil
}

// ─── GET /sso/saml2/sp/metadata ──────────────────────────────────────────────

// SPMetadata is better-auth's spMetadata endpoint: the configured SP metadata XML, or samlify's SPMetadata
// document for the provider.
func (s *Service) SPMetadata(ctx context.Context, providerID string) ([]byte, error) {
	// Step 1: the provider
	provider, err := s.findSAMLProvider(ctx, providerID)
	if err != nil {
		return nil, errorf("find provider: %w", err)
	}
	if provider == nil {
		return nil, ErrNoProviderForProviderID
	}
	c := provider.SAMLConfig
	if c == nil {
		return nil, ErrInvalidSAMLConfiguration
	}
	// Step 2: configured metadata is served as is
	if c.SPMetadata != nil && c.SPMetadata.Metadata != "" {
		return []byte(c.SPMetadata.Metadata), nil
	}
	// Step 3: samlify's SPMetadata template
	base := s.kit.RequestBaseURL(ctx)
	entityID := c.Issuer
	if c.SPMetadata != nil && c.SPMetadata.EntityID != "" {
		entityID = c.SPMetadata.EntityID
	}
	acs := pick(c.CallbackURL, base+"/sso/saml2/sp/acs/"+providerID)
	attr := func(v string) string { return html.EscapeString(v) }
	var b strings.Builder
	b.WriteString(`<EntityDescriptor entityID="` + attr(entityID) + `" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:assertion="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`)
	b.WriteString(`<SPSSODescriptor AuthnRequestsSigned="` + boolText(c.AuthnRequestsSigned) + `" WantAssertionsSigned="` + boolText(c.WantAssertionsSigned) + `" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">`)
	b.WriteString(`<NameIDFormat>` + html.EscapeString(pick(c.IdentifierFormat, nameIDEmail)) + `</NameIDFormat>`)
	if s.cfg.SAML.EnableSingleLogout {
		slo := attr(base + "/sso/saml2/sp/slo/" + providerID)
		b.WriteString(`<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + slo + `"></SingleLogoutService>`)
		b.WriteString(`<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + slo + `"></SingleLogoutService>`)
	}
	b.WriteString(`<AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + attr(acs) + `"></AssertionConsumerService>`)
	b.WriteString(`</SPSSODescriptor></EntityDescriptor>`)
	return []byte(b.String()), nil
}

func boolText(b *bool) string {
	if b != nil && *b {
		return "true"
	}
	return "false"
}

// ─── Single Logout ───────────────────────────────────────────────────────────

// samlSession is the SLO record stored per NameID (better-auth's samlSessionData).
type samlSession struct {
	SessionID    string `json:"sessionId"`
	SessionToken string `json:"sessionToken"`
	ProviderID   string `json:"providerId"`
	NameID       string `json:"nameID"`
	SessionIndex string `json:"sessionIndex,omitempty"`
}

// recordSAMLSession stores the NameID / SessionIndex of a SAML session and the reverse lookup by session id.
func (s *Service) recordSAMLSession(ctx context.Context, providerID, nameID string, a *saml.Assertion, sessionID, token string, expiresAt time.Time) {
	key := SAMLSessionKeyPrefix + providerID + ":" + nameID
	data := samlSession{SessionID: sessionID, SessionToken: token, ProviderID: providerID, NameID: nameID}
	if len(a.AuthnStatements) > 0 {
		data.SessionIndex = a.AuthnStatements[0].SessionIndex
	}
	raw, _ := json.Marshal(data)
	if err := s.storeVerificationUntil(ctx, key, string(raw), expiresAt); err != nil {
		logger.Warn("Failed to create SAML session record", "error", err)
	}
	if err := s.storeVerificationUntil(ctx, SAMLSessionByIDPrefix+sessionID, key, expiresAt); err != nil {
		logger.Warn("Failed to create SAML session lookup record", "error", err)
	}
}

// ClearSAMLSession drops the SLO records of a session (before hook of /sign-out).
func (s *Service) ClearSAMLSession(ctx context.Context, sessionID string) {
	if !s.cfg.SAML.EnableSingleLogout || sessionID == "" {
		return
	}
	lookupKey := SAMLSessionByIDPrefix + sessionID
	lookup, err := s.findVerification(ctx, lookupKey)
	if err != nil || lookup == nil || lookup.Value == "" {
		return
	}
	s.deleteVerification(ctx, lookup.Value)
	s.deleteVerification(ctx, lookupKey)
}

// SLOParams are the fields of /sso/saml2/sp/slo/{providerId} (body and query).
type SLOParams struct {
	Method       string
	SAMLRequest  string
	SAMLResponse string
	RelayState   string
	// RawQuery is the request's raw query (the HTTP-Redirect binding signs it).
	RawQuery string
	// FromBody reports SAMLRequest / SAMLResponse posted in the body (HTTP-POST binding).
	FromBody bool
}

// SLOResult is a redirect, or an auto-submitting HTML form (HTTP-POST binding).
type SLOResult struct {
	Redirect *Redirect
	HTML     []byte
	Cookies  []http.Cookie
}

// HandleSLO is better-auth's sloEndpoint: a LogoutResponse finishes an SP-initiated logout, a LogoutRequest
// from the IdP ends the user's session and is answered with a LogoutResponse.
func (s *Service) HandleSLO(ctx context.Context, providerID string, p SLOParams, current *dtos.SessionWithUser) (*SLOResult, error) {
	// Step 1: enabled, with something to process
	if !s.cfg.SAML.EnableSingleLogout {
		return nil, samlError(http.StatusBadRequest, "SINGLE_LOGOUT_NOT_ENABLED")
	}
	origin := s.appOrigin(ctx)
	safe := s.safeRedirectURL(ctx, p.RelayState, origin+"/sso/saml2/sp/slo/"+providerID)
	if p.SAMLRequest == "" && p.SAMLResponse == "" {
		return &SLOResult{Redirect: &Redirect{Location: safe + "?error=invalid_request&error_description=missing_logout_data"}}, nil
	}
	// Step 2: the provider and its SP
	provider, err := s.findSAMLProvider(ctx, providerID)
	if err != nil {
		return nil, errorf("find provider: %w", err)
	}
	if provider == nil || provider.SAMLConfig == nil {
		return nil, samlError(http.StatusNotFound, "SAML_PROVIDER_NOT_FOUND")
	}
	sp, err := s.buildSP(ctx, providerID, provider.SAMLConfig)
	if err != nil {
		return nil, samlError(http.StatusBadRequest, "INVALID_LOGOUT_REQUEST")
	}
	if p.SAMLResponse != "" {
		return s.handleLogoutResponse(ctx, sp, p, safe)
	}
	return s.handleLogoutRequest(ctx, sp, providerID, p, current)
}

// sessionCookiesExpired are the cookies deleteSessionCookie sets.
func (s *Service) sessionCookiesExpired() []http.Cookie { return s.kit.ExpireSessionCookies(false) }

// handleLogoutResponse validates the IdP's LogoutResponse and clears the session cookie.
func (s *Service) handleLogoutResponse(ctx context.Context, sp *saml.ServiceProvider, p SLOParams, safe string) (*SLOResult, error) {
	// Step 1: parse and validate (signature, destination, issuer, status)
	var resp *saml.LogoutResponse
	var err error
	if p.FromBody {
		err = sp.ValidateLogoutResponseForm(p.SAMLResponse)
		if err == nil {
			resp = decodeLogoutResponse(p.SAMLResponse, false)
		}
	} else {
		resp = decodeLogoutResponse(p.SAMLResponse, true)
		ids := []string{}
		if resp != nil {
			ids = append(ids, resp.InResponseTo)
		}
		req := &http.Request{Method: http.MethodGet, URL: &url.URL{RawQuery: p.RawQuery}}
		_, err = sp.ParseLogoutResponse(req, ids)
	}
	if err != nil {
		var bad saml.ErrBadStatus
		if errors.As(err, &bad) {
			logger.Warn("LogoutResponse indicates failure", "statusCode", bad.Status)
			return nil, samlError(http.StatusBadRequest, "LOGOUT_FAILED_AT_IDP")
		}
		logger.Error("LogoutResponse validation failed", "error", err)
		return nil, samlError(http.StatusBadRequest, "INVALID_LOGOUT_RESPONSE")
	}
	// Step 2: forget the matching LogoutRequest
	if resp != nil && resp.InResponseTo != "" {
		key := LogoutRequestKeyPrefix + resp.InResponseTo
		if v, _ := s.findVerification(ctx, key); v == nil {
			logger.Warn("LogoutResponse references unknown or expired request", "inResponseTo", resp.InResponseTo)
		}
		s.deleteVerification(ctx, key)
	}
	// Step 3: sign out locally and go back to the app
	return &SLOResult{Redirect: &Redirect{Location: safe, Cookies: s.sessionCookiesExpired()}}, nil
}

// decodeLogoutResponse reads a LogoutResponse (deflated for the HTTP-Redirect binding) without validating it.
func decodeLogoutResponse(encoded string, deflated bool) *saml.LogoutResponse {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil
	}
	if deflated {
		if raw, err = io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(raw)), 1<<20)); err != nil {
			return nil
		}
	}
	var resp saml.LogoutResponse
	if xml.Unmarshal(raw, &resp) != nil {
		return nil
	}
	return &resp
}

// handleLogoutRequest validates the IdP's LogoutRequest, deletes the user's session and answers with a
// LogoutResponse (HTTP-POST form or HTTP-Redirect).
func (s *Service) handleLogoutRequest(ctx context.Context, sp *saml.ServiceProvider, providerID string, p SLOParams, current *dtos.SessionWithUser) (*SLOResult, error) {
	// Step 1: parse and validate (signature, destination, issuer, timestamps)
	var req *saml.LogoutRequest
	var err error
	if p.FromBody {
		req, err = sp.ValidateLogoutRequestForm(p.SAMLRequest)
	} else {
		req, err = sp.ValidateLogoutRequest(&http.Request{Method: http.MethodGet, URL: &url.URL{RawQuery: p.RawQuery}})
	}
	if err != nil || req == nil {
		logger.Error("LogoutRequest validation failed", "error", err)
		return nil, samlError(http.StatusBadRequest, "INVALID_LOGOUT_REQUEST")
	}
	nameID := ""
	if req.NameID != nil {
		nameID = req.NameID.Value
	}
	sessionIndex := ""
	if req.SessionIndex != nil {
		sessionIndex = req.SessionIndex.Value
	}
	// Step 2: end the session recorded for the NameID (matching SessionIndex)
	key := SAMLSessionKeyPrefix + providerID + ":" + nameID
	if stored, _ := s.findVerification(ctx, key); stored != nil {
		var data samlSession
		if json.Unmarshal([]byte(stored.Value), &data) == nil {
			if sessionIndex == "" || data.SessionIndex == "" || sessionIndex == data.SessionIndex {
				if err := s.kit.Sessions.Delete(ctx, data.SessionToken); err != nil {
					logger.Warn("Failed to delete session during SLO", "error", err)
				}
				s.deleteVerification(ctx, SAMLSessionByIDPrefix+data.SessionID)
			} else {
				logger.Warn("SessionIndex mismatch in LogoutRequest - skipping session deletion", "providerId", providerID)
			}
		}
		s.deleteVerification(ctx, key)
	}
	// Step 3: the browser's own session ends too
	if current != nil {
		_ = s.kit.Sessions.Delete(ctx, current.Session.Token)
	}
	cookies := s.sessionCookiesExpired()
	// Step 4: answer the IdP
	if p.FromBody {
		form, err := sp.MakePostLogoutResponse(req.ID, p.RelayState)
		if err != nil {
			return nil, samlError(http.StatusBadRequest, "INVALID_LOGOUT_REQUEST")
		}
		return &SLOResult{HTML: form, Cookies: cookies}, nil
	}
	u, err := sp.MakeRedirectLogoutResponse(req.ID, p.RelayState)
	if err != nil {
		return nil, samlError(http.StatusBadRequest, "INVALID_LOGOUT_REQUEST")
	}
	return &SLOResult{Redirect: &Redirect{Location: u.String(), Cookies: cookies}}, nil
}

// InitiateSLO is better-auth's initiateSLO (POST /sso/saml2/logout/{providerId}): send a LogoutRequest to the
// IdP for the current SAML session and sign out locally.
func (s *Service) InitiateSLO(ctx context.Context, providerID, callbackURL string, current *dtos.SessionWithUser) (*Redirect, error) {
	// Step 1: enabled, provider with an IdP SLO service
	if !s.cfg.SAML.EnableSingleLogout {
		return nil, samlError(http.StatusBadRequest, "SINGLE_LOGOUT_NOT_ENABLED")
	}
	callbackURL = pick(callbackURL, s.kit.RequestBaseURL(ctx))
	provider, err := s.findSAMLProvider(ctx, providerID)
	if err != nil {
		return nil, errorf("find provider: %w", err)
	}
	if provider == nil || provider.SAMLConfig == nil {
		return nil, samlError(http.StatusNotFound, "SAML_PROVIDER_NOT_FOUND")
	}
	idp := provider.SAMLConfig.IDPMetadata
	if idp == nil || (len(idp.SingleLogoutService) == 0 && !strings.Contains(idp.Metadata, "SingleLogoutService")) {
		return nil, samlError(http.StatusBadRequest, "IDP_SLO_NOT_SUPPORTED")
	}
	sp, err := s.buildSP(ctx, providerID, provider.SAMLConfig)
	if err != nil {
		return nil, samlError(http.StatusBadRequest, "IDP_SLO_NOT_SUPPORTED")
	}
	// Step 2: the NameID / SessionIndex recorded at sign-in (the email otherwise)
	lookupKey := SAMLSessionByIDPrefix + current.Session.ID
	nameID, sessionIndex, samlKey := current.User.Email, "", ""
	if lookup, _ := s.findVerification(ctx, lookupKey); lookup != nil {
		samlKey = lookup.Value
		if stored, _ := s.findVerification(ctx, samlKey); stored != nil {
			var data samlSession
			if json.Unmarshal([]byte(stored.Value), &data) == nil {
				nameID = pick(data.NameID, nameID)
				sessionIndex = data.SessionIndex
			}
		}
	}
	// Step 3: the LogoutRequest (HTTP-Redirect), remembered for the LogoutResponse
	var opts []saml.LogoutRequestOption
	if sessionIndex != "" {
		opts = append(opts, saml.WithSessionIndex(sessionIndex))
	}
	req, err := sp.MakeLogoutRequest(sp.GetSLOBindingLocation(saml.HTTPRedirectBinding), nameID, opts...)
	if err != nil {
		return nil, samlError(http.StatusBadRequest, "IDP_SLO_NOT_SUPPORTED")
	}
	u, err := sp.RedirectLogoutRequestURL(req, callbackURL)
	if err != nil {
		return nil, samlError(http.StatusBadRequest, "IDP_SLO_NOT_SUPPORTED")
	}
	if err := s.storeVerification(ctx, LogoutRequestKeyPrefix+req.ID, providerID, s.cfg.SAML.LogoutRequestTTL); err != nil {
		return nil, errorf("store logout request: %w", err)
	}
	// Step 4: drop the SAML session records and the local session
	if samlKey != "" {
		s.deleteVerification(ctx, samlKey)
	}
	s.deleteVerification(ctx, lookupKey)
	_ = s.kit.Sessions.Delete(ctx, current.Session.Token)
	return &Redirect{Location: u.String(), Cookies: s.sessionCookiesExpired()}, nil
}
