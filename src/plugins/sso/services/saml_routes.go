package services

import (
	"context"
	"net/http"
	"strings"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/models/dtos"
)

// samlErrorURL is onAPIError.errorURL, else "<app origin>/error".
func (s *Service) samlErrorURL(ctx context.Context) string {
	if u := s.kit.Conf.OnAPIError.ErrorURL; u != "" {
		return u
	}
	return s.appOrigin(ctx) + "/error"
}

// SAMLCallbackGet is the GET branch of better-auth's callbackSSOSAML: a signed-in browser is sent to the
// (safe) RelayState; without a session it goes to the error page.
func (s *Service) SAMLCallbackGet(ctx context.Context, providerID, relayState string, current *dtos.SessionWithUser) (*Redirect, error) {
	if current == nil {
		return &Redirect{Location: s.samlErrorURL(ctx) + "?error=invalid_request"}, nil
	}
	callbackPath := s.kit.RequestBaseURL(ctx) + "/sso/saml2/callback/" + providerID
	return &Redirect{Location: s.safeRedirectURL(ctx, relayState, callbackPath)}, nil
}

// SAMLCallbackPost is the POST branch of better-auth's callbackSSOSAML.
func (s *Service) SAMLCallbackPost(ctx context.Context, providerID, samlResponse, relayState string) (*Redirect, error) {
	if samlResponse == "" {
		return nil, apiError(http.StatusBadRequest, "SAMLResponse is required for POST requests")
	}
	return s.ProcessSAMLResponse(ctx, SAMLParams{
		ProviderID: providerID, SAMLResponse: samlResponse, RelayState: relayState,
		CurrentCallbackPath: s.kit.RequestBaseURL(ctx) + "/sso/saml2/callback/" + providerID,
	})
}

// ACS is better-auth's acsEndpoint: like the SAML callback, but 400 errors become redirects to the app with
// error / error_description.
func (s *Service) ACS(ctx context.Context, providerID, samlResponse, relayState string) (*Redirect, error) {
	callbackPath := s.kit.RequestBaseURL(ctx) + "/sso/saml2/sp/acs/" + providerID
	r, err := s.ProcessSAMLResponse(ctx, SAMLParams{
		ProviderID: providerID, SAMLResponse: samlResponse, RelayState: relayState, CurrentCallbackPath: callbackPath,
	})
	if err == nil {
		return r, nil
	}
	// Step 1: only 400 API errors are turned into redirects
	ae := autherr.AsAuthError(err)
	if ae == nil || ae.StatusCode != http.StatusBadRequest {
		return nil, err
	}
	// Step 2: the error code for the app
	code := strings.ToLower(string(ae.Code))
	switch string(ae.Code) {
	case "SAML_MULTIPLE_ASSERTIONS":
		code = "multiple_assertions"
	case "SAML_NO_ASSERTION":
		code = "no_assertion"
	}
	if code == "" {
		code = "saml_error"
	}
	target := s.safeRedirectURL(ctx, relayState, callbackPath)
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	return &Redirect{Location: target + sep + "error=" + encodeURIComponent(code) + "&error_description=" + encodeURIComponent(ae.Message)}, nil
}
