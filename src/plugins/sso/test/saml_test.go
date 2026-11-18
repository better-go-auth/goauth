package test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/plugins/social/socialtest"
	ssoconfig "github.com/better-go-auth/goauth/src/plugins/sso/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

const (
	samlProvider = "saml-idp"
	spEntityID   = "https://sp.corp.example"
	// samlCallback is both the registered callbackUrl (= the SP ACS URL) and the SAML callback endpoint.
	samlCallback = authBase + "/sso/saml2/callback/" + samlProvider
	samlACS      = authBase + "/sso/saml2/sp/acs/" + samlProvider
)

// samlBody is a SAML registration body for idp.
func samlBody(idp *testIdP, extra map[string]any) map[string]any {
	sc := map[string]any{
		"entryPoint":  idp.ssoURL,
		"cert":        idp.certPEM,
		"callbackUrl": samlCallback,
		"spMetadata":  map[string]any{"entityID": spEntityID},
		"idpMetadata": map[string]any{"entityID": idp.entityID},
	}
	for k, v := range extra {
		sc[k] = v
	}
	return map[string]any{"providerId": samlProvider, "issuer": idp.entityID, "domain": "saml.example", "samlConfig": sc}
}

// samlEnv is an env with a registered SAML provider (registered by admin@saml.example).
func samlEnv(t *testing.T, o envOpts, extra func(idp *testIdP) map[string]any) (*env, *testIdP) {
	t.Helper()
	e := newEnv(t, o)
	idp := newTestIdP(t, "https://idp.saml.example/metadata")
	e.signUp(t, "admin@saml.example")
	var more map[string]any
	if extra != nil {
		more = extra(idp)
	}
	e.mustRegister(t, samlBody(idp, more))
	e.freshBrowser()
	return e, idp
}

// postSAML posts SAMLResponse (+ RelayState) form-encoded, like an IdP's auto-submitting form (no Origin).
func (e *env) postSAML(t *testing.T, path, samlResponse, relayState string) *compattest.Response {
	t.Helper()
	form := url.Values{"SAMLResponse": {samlResponse}}
	if relayState != "" {
		form.Set("RelayState", relayState)
	}
	req, err := http.NewRequest(http.MethodPost, e.s.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://idp.saml.example")
	resp, err := e.s.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw := new(strings.Builder)
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		raw.WriteString(string(buf[:n]))
		if rerr != nil {
			break
		}
	}
	return &compattest.Response{Status: resp.StatusCode, Header: resp.Header, Body: []byte(raw.String())}
}

// janeOpts is a valid IdP-initiated response for jane@saml.example posted to the callback endpoint.
func janeOpts() assertionOpts {
	return assertionOpts{
		Destination: samlCallback, Recipient: samlCallback, Audience: spEntityID, NameID: "jane@saml.example",
		Attributes: map[string][]string{"email": {"Jane@Saml.Example"}, "givenName": {"Jane"}, "surname": {"Doe"}, "department": {"eng"}},
	}
}

func TestSAMLSPInitiatedFlow(t *testing.T) {
	e, idp := samlEnv(t, envOpts{}, nil)

	// Step 1: sign-in → AuthnRequest (HTTP-Redirect) to the IdP with a relay state
	authURL := e.startSignIn(t, map[string]any{"providerId": samlProvider, "callbackURL": "/dashboard"})
	if !strings.HasPrefix(authURL, idp.ssoURL+"?SAMLRequest=") {
		t.Fatalf("AuthnRequest URL %s", authURL)
	}
	req := decodeAuthnRequest(t, authURL)
	if req.ID == "" || req.RelayState == "" || req.AssertionConsumerServiceURL != samlCallback || req.Issuer != spEntityID || req.Destination != idp.ssoURL {
		t.Fatalf("AuthnRequest %+v", req)
	}

	// Step 2: the IdP posts the signed response to the callback: session + redirect to the relay callbackURL
	o := janeOpts()
	o.InResponseTo = req.ID
	r := e.postSAML(t, "/api/auth/sso/saml2/callback/"+samlProvider, idp.response(t, o), req.RelayState)
	if loc := location(t, r); loc != "/dashboard" {
		t.Fatalf("redirect %s", loc)
	}
	if sessionCookie(r) == nil {
		t.Fatal("no session cookie")
	}
	u := e.userByEmail(t, "jane@saml.example")
	if u == nil || u.Name != "Jane Doe" || u.EmailVerified {
		t.Fatalf("user %+v", u)
	}
	accs := e.accountsOf(t, u.ID)
	if len(accs) != 1 || string(accs[0].ProviderID) != samlProvider || accs[0].AccountID != "jane@saml.example" {
		t.Fatalf("accounts %+v", accs)
	}
	s := e.s.Get(t, "/api/auth/get-session")
	if !strings.Contains(string(s.Body), "jane@saml.example") {
		t.Fatalf("get-session %s", s.Body)
	}

	// Step 3: the same response again: its request ID was consumed
	r = e.postSAML(t, "/api/auth/sso/saml2/callback/"+samlProvider, idp.response(t, o), "")
	q := errorParams(t, r, baseURL)
	if q.Get("error") != "invalid_saml_response" || q.Get("error_description") != "Unknown or expired request ID" {
		t.Fatalf("reused request ID: %v", q)
	}
}

func TestSAMLIdPInitiatedAndReplay(t *testing.T) {
	e, idp := samlEnv(t, envOpts{}, nil)
	resp := idp.response(t, janeOpts())

	// Step 1: IdP-initiated (no InResponseTo) is accepted; without relay state the callbackUrl is the
	// callback endpoint itself, so the redirect falls back to the app origin
	r := e.postSAML(t, "/api/auth/sso/saml2/callback/"+samlProvider, resp, "")
	if loc := location(t, r); loc != baseURL {
		t.Fatalf("redirect %s", loc)
	}
	if sessionCookie(r) == nil {
		t.Fatal("no session")
	}
	// Step 2: the same assertion again is a replay
	r = e.postSAML(t, "/api/auth/sso/saml2/callback/"+samlProvider, resp, "")
	q := errorParams(t, r, baseURL)
	if q.Get("error") != "replay_detected" || q.Get("error_description") != "SAML assertion has already been used" {
		t.Fatalf("replay: %v", q)
	}
}

func TestSAMLCallbackGet(t *testing.T) {
	e, idp := samlEnv(t, envOpts{}, nil)
	// Step 1: without a session the GET callback goes to the error page
	r := e.s.Get(t, "/api/auth/sso/saml2/callback/"+samlProvider+"?RelayState=/after")
	if loc := location(t, r); loc != baseURL+"/error?error=invalid_request" {
		t.Fatalf("anonymous GET: %s", loc)
	}
	// Step 2: a signed-in browser is sent to the (safe) RelayState
	location(t, e.postSAML(t, "/api/auth/sso/saml2/callback/"+samlProvider, idp.response(t, janeOpts()), ""))
	if loc := location(t, e.s.Get(t, "/api/auth/sso/saml2/callback/"+samlProvider+"?RelayState=/after")); loc != "/after" {
		t.Fatalf("signed-in GET: %s", loc)
	}
	if loc := location(t, e.s.Get(t, "/api/auth/sso/saml2/callback/"+samlProvider+"?RelayState=https://evil.example/x")); loc != baseURL {
		t.Fatalf("untrusted RelayState: %s", loc)
	}
	// Step 3: a POST without SAMLResponse
	expectError(t, e.postSAML(t, "/api/auth/sso/saml2/callback/"+samlProvider, "", ""), http.StatusBadRequest, "", "SAMLResponse is required for POST requests")
}

func TestSAMLUnsolicitedRejected(t *testing.T) {
	no := false
	e, idp := samlEnv(t, envOpts{sso: func(_ *socialtest.Provider, c *ssoconfig.SSOConfig) { c.SAML.AllowIdpInitiated = &no }}, nil)
	r := e.postSAML(t, "/api/auth/sso/saml2/callback/"+samlProvider, idp.response(t, janeOpts()), "")
	q := errorParams(t, r, baseURL)
	if q.Get("error") != "unsolicited_response" || q.Get("error_description") != "IdP-initiated SSO not allowed" {
		t.Fatalf("unsolicited: %v", q)
	}
	// an unknown request ID is refused too
	o := janeOpts()
	o.InResponseTo = "_unknown"
	r = e.postSAML(t, "/api/auth/sso/saml2/callback/"+samlProvider, idp.response(t, o), "")
	if q := errorParams(t, r, baseURL); q.Get("error") != "invalid_saml_response" {
		t.Fatalf("unknown request id: %v", q)
	}
}

func TestSAMLValidationFailures(t *testing.T) {
	e, idp := samlEnv(t, envOpts{}, nil)
	otherKey, _, _ := newKeyPair(t, "attacker")
	cases := []struct {
		name    string
		mutate  func(o *assertionOpts)
		message string
	}{
		{"wrong audience", func(o *assertionOpts) { o.Audience = "https://other-sp.example" }, "Invalid SAML response"},
		{"bad signature", func(o *assertionOpts) { o.SignWith = otherKey }, "Invalid SAML response"},
		{"unsigned", func(o *assertionOpts) { o.Unsigned = true }, "Invalid SAML response"},
		{"wrong issuer", func(o *assertionOpts) { o.Issuer = "https://evil.example" }, "Invalid SAML response"},
		{"wrong recipient", func(o *assertionOpts) { o.Recipient = "https://evil.example/acs" }, "Invalid SAML response"},
		{"expired", func(o *assertionOpts) {
			o.IssueInstant = time.Now().Add(-2 * time.Hour)
			o.NotBefore = time.Now().Add(-2 * time.Hour)
			o.NotOnOrAfter = time.Now().Add(-time.Hour)
		}, "SAML assertion has expired"},
		{"not yet valid", func(o *assertionOpts) { o.NotBefore = time.Now().Add(time.Hour) }, "SAML assertion is not yet valid"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := janeOpts()
			o.NameID = "x-" + strings.ReplaceAll(c.name, " ", "") + "@saml.example"
			c.mutate(&o)
			r := e.postSAML(t, "/api/auth/sso/saml2/callback/"+samlProvider, idp.response(t, o), "")
			if r.Status != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d %s", r.Status, r.Body)
			}
			if _, m := errBody(t, r); m != c.message {
				t.Fatalf("message %q, want %q", m, c.message)
			}
			if sessionCookie(r) != nil {
				t.Fatal("no session may be created")
			}
		})
	}
	// Step 2: assertion counting and encoding
	o := janeOpts()
	o.Assertions = 2
	expectError(t, e.postSAML(t, "/api/auth/sso/saml2/callback/"+samlProvider, idp.response(t, o), ""), http.StatusBadRequest, "SAML_MULTIPLE_ASSERTIONS", "SAML response contains 2 assertions, expected exactly 1")
	expectError(t, e.postSAML(t, "/api/auth/sso/saml2/callback/"+samlProvider, "%%%not-base64", ""), http.StatusBadRequest, "SAML_INVALID_ENCODING", "Invalid base64-encoded SAML response")
	expectError(t, e.postSAML(t, "/api/auth/sso/saml2/callback/unknown", idp.response(t, janeOpts()), ""), http.StatusNotFound, "", "No SAML provider found")
}

func TestSAMLACSRedirectsErrors(t *testing.T) {
	e, idp := samlEnv(t, envOpts{}, nil)
	// Step 1: a 400 becomes a redirect with error / error_description
	o := janeOpts()
	o.Audience = "https://other-sp.example"
	r := e.postSAML(t, "/api/auth/sso/saml2/sp/acs/"+samlProvider, idp.response(t, o), "")
	loc := location(t, r)
	if loc != baseURL+"?error=saml_error&error_description=Invalid%20SAML%20response" {
		t.Fatalf("acs error redirect %s", loc)
	}
	o = janeOpts()
	o.Assertions = 2
	r = e.postSAML(t, "/api/auth/sso/saml2/sp/acs/"+samlProvider, idp.response(t, o), "")
	if q := errorParams(t, r, baseURL); q.Get("error") != "multiple_assertions" {
		t.Fatalf("multiple assertions: %v", q)
	}
	// Step 2: a valid response posted to the ACS signs in
	// (callbackUrl is trusted and is not the ACS itself, so it is the target)
	r = e.postSAML(t, "/api/auth/sso/saml2/sp/acs/"+samlProvider, idp.response(t, janeOpts()), "")
	if location(t, r) != samlCallback || sessionCookie(r) == nil {
		t.Fatalf("acs sign-in: %v", r.Header)
	}
	// Step 3: a missing SAMLResponse is a validation error
	r = e.s.Post(t, "/api/auth/sso/saml2/sp/acs/"+samlProvider, map[string]any{})
	expectError(t, r, http.StatusBadRequest, "VALIDATION_ERROR", "")
}

func TestSAMLSignUpDisabledAndMissingEmail(t *testing.T) {
	e, idp := samlEnv(t, envOpts{sso: func(_ *socialtest.Provider, c *ssoconfig.SSOConfig) { c.DisableImplicitSignUp = true }}, nil)
	// Step 1: disableImplicitSignUp: no new user, redirect with error=signup_disabled
	r := e.postSAML(t, "/api/auth/sso/saml2/callback/"+samlProvider, idp.response(t, janeOpts()), "")
	if loc := location(t, r); loc != samlCallback+"?error=signup_disabled" {
		t.Fatalf("redirect %s", loc)
	}
	if e.userByEmail(t, "jane@saml.example") != nil {
		t.Fatal("user must not be created")
	}
	// Step 2: no email and no NameID
	o := janeOpts()
	o.NameID = ""
	o.Attributes = map[string][]string{"displayName": {"Nobody"}}
	expectError(t, e.postSAML(t, "/api/auth/sso/saml2/callback/"+samlProvider, idp.response(t, o), ""), http.StatusBadRequest, "", "Unable to extract user ID or email from SAML response")
}

func TestSAMLMappingAndProvisionUser(t *testing.T) {
	var provisioned []string
	e, idp := samlEnv(t, envOpts{sso: func(_ *socialtest.Provider, c *ssoconfig.SSOConfig) {
		c.ProvisionUser = func(_ context.Context, d ssoconfig.ProvisionUserData) error {
			provisioned = append(provisioned, d.User.Email+"|"+d.UserInfo["department"].(string))
			return nil
		}
	}}, func(*testIdP) map[string]any {
		return map[string]any{"mapping": map[string]any{"id": "uid", "email": "mail", "name": "cn", "extraFields": map[string]any{"department": "dept"}}}
	})
	o := janeOpts()
	o.Attributes = map[string][]string{"uid": {"u-77"}, "mail": {"mapped@saml.example"}, "cn": {"Mapped Name"}, "dept": {"sales"}}
	r := e.postSAML(t, "/api/auth/sso/saml2/callback/"+samlProvider, idp.response(t, o), "")
	location(t, r)
	u := e.userByEmail(t, "mapped@saml.example")
	if u == nil || u.Name != "Mapped Name" {
		t.Fatalf("mapped user %+v", u)
	}
	if accs := e.accountsOf(t, u.ID); len(accs) != 1 || accs[0].AccountID != "u-77" {
		t.Fatalf("accounts %+v", accs)
	}
	if len(provisioned) != 1 || provisioned[0] != "mapped@saml.example|sales" {
		t.Fatalf("provisionUser calls %v", provisioned)
	}
	// a second sign-in is not a registration: provisionUser is not called again
	e.freshBrowser()
	o.AssertionID = ""
	location(t, e.postSAML(t, "/api/auth/sso/saml2/callback/"+samlProvider, idp.response(t, o), ""))
	if len(provisioned) != 1 {
		t.Fatalf("provisionUser called on login: %v", provisioned)
	}
}

func TestSAMLMetadataAndSignedAuthnRequest(t *testing.T) {
	spKey, _, _ := newKeyPair(t, "sp")
	e, _ := samlEnv(t, envOpts{}, func(*testIdP) map[string]any {
		return map[string]any{"authnRequestsSigned": true, "privateKey": keyPEM(spKey), "identifierFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"}
	})
	// Step 1: SP metadata (samlify's template)
	r := e.s.Get(t, "/api/auth/sso/saml2/sp/metadata?providerId="+samlProvider)
	if r.Status != http.StatusOK || r.Header.Get("Content-Type") != "application/xml" {
		t.Fatalf("metadata %d %s", r.Status, r.Header)
	}
	want := `<EntityDescriptor entityID="` + spEntityID + `" xmlns="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:assertion="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat><AssertionConsumerService index="0" Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="` + samlCallback + `"></AssertionConsumerService></SPSSODescriptor></EntityDescriptor>`
	if string(r.Body) != want {
		t.Fatalf("metadata\n%s\nwant\n%s", r.Body, want)
	}
	expectError(t, e.s.Get(t, "/api/auth/sso/saml2/sp/metadata?providerId=nope"), http.StatusNotFound, "", "No provider found for the given providerId")
	// Step 2: the AuthnRequest URL carries a query-string signature
	req := decodeAuthnRequest(t, e.startSignIn(t, map[string]any{"providerId": samlProvider, "callbackURL": "/x"}))
	if !req.Signed {
		t.Fatal("AuthnRequest must be signed")
	}
}

func TestSAMLSingleLogout(t *testing.T) {
	// the IdP metadata document declares the SingleLogoutService
	e, idp := samlEnv(t, envOpts{sso: func(_ *socialtest.Provider, c *ssoconfig.SSOConfig) { c.SAML.EnableSingleLogout = true }}, func(idp *testIdP) map[string]any {
		return map[string]any{"idpMetadata": map[string]any{"metadata": idp.metadataXML()}}
	})
	// Step 1: sign in through SAML
	o := janeOpts()
	o.SessionIndex = "_idp-session-1"
	location(t, e.postSAML(t, "/api/auth/sso/saml2/callback/"+samlProvider, idp.response(t, o), ""))
	if s := e.s.Get(t, "/api/auth/get-session"); !strings.Contains(string(s.Body), "jane@saml.example") {
		t.Fatalf("not signed in: %s", s.Body)
	}
	// Step 2: SP-initiated logout redirects to the IdP's SLO service and ends the local session
	r := e.s.Post(t, "/api/auth/sso/saml2/logout/"+samlProvider, map[string]any{"callbackURL": "/bye"})
	loc := location(t, r)
	if !strings.HasPrefix(loc, idp.sloURL+"?SAMLRequest=") {
		t.Fatalf("logout redirect %s", loc)
	}
	raw, q := decodeRedirectMessage(t, loc, "SAMLRequest")
	if !strings.Contains(string(raw), "jane@saml.example") || !strings.Contains(string(raw), "_idp-session-1") || q.Get("RelayState") != "/bye" {
		t.Fatalf("LogoutRequest %s %v", raw, q)
	}
	if s := e.s.Get(t, "/api/auth/get-session"); strings.Contains(string(s.Body), "jane@saml.example") {
		t.Fatalf("session must be gone: %s", s.Body)
	}

	// Step 3: IdP-initiated logout (signed LogoutRequest, HTTP-POST) deletes the recorded session
	e.freshBrowser()
	o.AssertionID, o.SessionIndex = "", "_idp-session-2"
	location(t, e.postSAML(t, "/api/auth/sso/saml2/callback/"+samlProvider, idp.response(t, o), ""))
	other := e.s.Client.Jar
	e.freshBrowser()
	form := url.Values{"SAMLRequest": {idp.logoutRequest(t, authBase+"/sso/saml2/sp/slo/"+samlProvider, "jane@saml.example", "_idp-session-2")}}
	req, _ := http.NewRequest(http.MethodPost, e.s.URL+"/api/auth/sso/saml2/sp/slo/"+samlProvider, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := e.s.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("slo response %d %v", resp.StatusCode, resp.Header)
	}
	e.s.Client.Jar = other
	if s := e.s.Get(t, "/api/auth/get-session"); strings.Contains(string(s.Body), "jane@saml.example") {
		t.Fatalf("IdP logout must end the SAML session: %s", s.Body)
	}
	// Step 4: the HTTP-Redirect binding (query-string signature) is answered with a redirect LogoutResponse
	r = e.s.Get(t, "/api/auth/sso/saml2/sp/slo/"+samlProvider+"?"+idp.redirectLogoutRequest(t, authBase+"/sso/saml2/sp/slo/"+samlProvider, "jane@saml.example", "/bye"))
	if loc := location(t, r); !strings.HasPrefix(loc, idp.sloURL+"?SAMLResponse=") || !strings.Contains(loc, "RelayState=%2Fbye") {
		t.Fatalf("redirect logout response %s", loc)
	}
	if loc := location(t, e.s.Get(t, "/api/auth/sso/saml2/sp/slo/"+samlProvider)); loc != baseURL+"?error=invalid_request&error_description=missing_logout_data" {
		t.Fatalf("empty slo request %s", loc)
	}

	// Step 5: an unsigned or forged LogoutRequest is refused
	bad := url.Values{"SAMLRequest": {"PHNhbWxwOkxvZ291dFJlcXVlc3QvPg=="}}
	req, _ = http.NewRequest(http.MethodPost, e.s.URL+"/api/auth/sso/saml2/sp/slo/"+samlProvider, strings.NewReader(bad.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err = e.s.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("forged logout request: %d", resp.StatusCode)
	}
}
