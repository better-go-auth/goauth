package test

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"io"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// testIdP is a SAML identity provider for tests: it signs assertions (and logout messages) with its own key.
type testIdP struct {
	entityID string
	key      *rsa.PrivateKey
	cert     *x509.Certificate
	certPEM  string
	// ssoURL is the IdP's SSO endpoint (the AuthnRequest redirect target).
	ssoURL string
	sloURL string
}

// newTestIdP creates an IdP with a fresh RSA key and self-signed certificate.
func newTestIdP(t *testing.T, entityID string) *testIdP {
	t.Helper()
	key, cert, certPEM := newKeyPair(t, entityID)
	return &testIdP{entityID: entityID, key: key, cert: cert, certPEM: certPEM, ssoURL: "https://idp.test/sso", sloURL: "https://idp.test/slo"}
}

// newKeyPair returns an RSA key with a self-signed certificate (and its PEM).
func newKeyPair(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return key, cert, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// keyPEM encodes an RSA key as PKCS#1 PEM.
func keyPEM(k *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
}

// assertionOpts describes one SAML response.
type assertionOpts struct {
	// Destination / Recipient: the endpoint URL and the SP ACS URL.
	Destination, Recipient string
	Audience               string
	InResponseTo           string
	NameID                 string
	Attributes             map[string][]string
	AssertionID            string
	// NotBefore / NotOnOrAfter of the Conditions (and SubjectConfirmationData for NotOnOrAfter).
	NotBefore, NotOnOrAfter time.Time
	IssueInstant            time.Time
	SessionIndex            string
	// SignWith signs the assertion with another key (bad signature); Unsigned leaves it unsigned.
	SignWith *rsa.PrivateKey
	Unsigned bool
	// Assertions is the number of (identical) assertions (default 1, 0 means one).
	Assertions int
	// Issuer overrides the IdP entity ID.
	Issuer string
}

const (
	nsProtocol  = "urn:oasis:names:tc:SAML:2.0:protocol"
	nsAssertion = "urn:oasis:names:tc:SAML:2.0:assertion"
)

func samlTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// response builds a base64 SAML Response with a signed assertion.
func (i *testIdP) response(t *testing.T, o assertionOpts) string {
	t.Helper()
	now := time.Now()
	if o.IssueInstant.IsZero() {
		o.IssueInstant = now
	}
	if o.NotBefore.IsZero() {
		o.NotBefore = now.Add(-time.Minute)
	}
	if o.NotOnOrAfter.IsZero() {
		o.NotOnOrAfter = now.Add(5 * time.Minute)
	}
	if o.AssertionID == "" {
		o.AssertionID = "_a" + randID()
	}
	if o.SessionIndex == "" {
		o.SessionIndex = "_s" + randID()
	}
	issuer := o.Issuer
	if issuer == "" {
		issuer = i.entityID
	}
	// Step 1: the Response envelope
	doc := etree.NewDocument()
	resp := doc.CreateElement("samlp:Response")
	resp.CreateAttr("xmlns:samlp", nsProtocol)
	resp.CreateAttr("xmlns:saml", nsAssertion)
	resp.CreateAttr("ID", "_r"+randID())
	resp.CreateAttr("Version", "2.0")
	resp.CreateAttr("IssueInstant", samlTime(o.IssueInstant))
	resp.CreateAttr("Destination", o.Destination)
	if o.InResponseTo != "" {
		resp.CreateAttr("InResponseTo", o.InResponseTo)
	}
	resp.CreateElement("saml:Issuer").SetText(issuer)
	resp.CreateElement("samlp:Status").CreateElement("samlp:StatusCode").CreateAttr("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
	// Step 2: the assertion(s)
	n := o.Assertions
	if n <= 0 {
		n = 1
	}
	for k := 0; k < n; k++ {
		a := i.assertion(t, o, issuer, o.AssertionID)
		if k > 0 {
			a = i.assertion(t, o, issuer, o.AssertionID+"-"+randID())
		}
		resp.AddChild(a)
	}
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// assertion builds one (signed) Assertion element.
func (i *testIdP) assertion(t *testing.T, o assertionOpts, issuer, id string) *etree.Element {
	t.Helper()
	a := etree.NewElement("saml:Assertion")
	a.CreateAttr("xmlns:saml", nsAssertion)
	a.CreateAttr("ID", id)
	a.CreateAttr("Version", "2.0")
	a.CreateAttr("IssueInstant", samlTime(o.IssueInstant))
	a.CreateElement("saml:Issuer").SetText(issuer)
	// Step 1: subject with a bearer confirmation
	subj := a.CreateElement("saml:Subject")
	nameID := subj.CreateElement("saml:NameID")
	nameID.CreateAttr("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
	nameID.SetText(o.NameID)
	sc := subj.CreateElement("saml:SubjectConfirmation")
	sc.CreateAttr("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
	scd := sc.CreateElement("saml:SubjectConfirmationData")
	scd.CreateAttr("NotOnOrAfter", samlTime(o.NotOnOrAfter))
	scd.CreateAttr("Recipient", o.Recipient)
	if o.InResponseTo != "" {
		scd.CreateAttr("InResponseTo", o.InResponseTo)
	}
	// Step 2: conditions and audience
	cond := a.CreateElement("saml:Conditions")
	cond.CreateAttr("NotBefore", samlTime(o.NotBefore))
	cond.CreateAttr("NotOnOrAfter", samlTime(o.NotOnOrAfter))
	cond.CreateElement("saml:AudienceRestriction").CreateElement("saml:Audience").SetText(o.Audience)
	// Step 3: authentication statement and attributes
	as := a.CreateElement("saml:AuthnStatement")
	as.CreateAttr("AuthnInstant", samlTime(o.IssueInstant))
	as.CreateAttr("SessionIndex", o.SessionIndex)
	as.CreateElement("saml:AuthnContext").CreateElement("saml:AuthnContextClassRef").SetText("urn:oasis:names:tc:SAML:2.0:ac:classes:Password")
	if len(o.Attributes) > 0 {
		st := a.CreateElement("saml:AttributeStatement")
		for name, vals := range o.Attributes {
			attr := st.CreateElement("saml:Attribute")
			attr.CreateAttr("Name", name)
			for _, v := range vals {
				attr.CreateElement("saml:AttributeValue").SetText(v)
			}
		}
	}
	if o.Unsigned {
		return a
	}
	key := i.key
	if o.SignWith != nil {
		key = o.SignWith
	}
	return i.sign(t, a, key)
}

// sign adds an enveloped signature right after the Issuer element.
func (i *testIdP) sign(t *testing.T, el *etree.Element, key *rsa.PrivateKey) *etree.Element {
	t.Helper()
	ctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{Certificate: [][]byte{i.cert.Raw}, PrivateKey: key, Leaf: i.cert}))
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatal(err)
	}
	signed, err := ctx.SignEnveloped(el)
	if err != nil {
		t.Fatal(err)
	}
	// the schema wants ds:Signature right after Issuer
	for idx, tok := range signed.Child {
		if c, ok := tok.(*etree.Element); ok && c.Tag == "Signature" {
			sig := signed.RemoveChildAt(idx).(*etree.Element)
			signed.InsertChildAt(1, sig)
			break
		}
	}
	return signed
}

// metadataXML is the IdP metadata document (signing certificate, SSO and SLO services).
func (i *testIdP) metadataXML() string {
	body := base64.StdEncoding.EncodeToString(i.cert.Raw)
	return `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="` + i.entityID + `">` +
		`<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>` + body + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor>` +
		`<SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + i.sloURL + `"/>` +
		`<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="` + i.ssoURL + `"/>` +
		`</IDPSSODescriptor></EntityDescriptor>`
}

// logoutRequest builds a signed, base64 LogoutRequest (HTTP-POST binding).
func (i *testIdP) logoutRequest(t *testing.T, destination, nameID, sessionIndex string) string {
	t.Helper()
	el := etree.NewElement("samlp:LogoutRequest")
	el.CreateAttr("xmlns:samlp", nsProtocol)
	el.CreateAttr("xmlns:saml", nsAssertion)
	el.CreateAttr("ID", "_lr"+randID())
	el.CreateAttr("Version", "2.0")
	el.CreateAttr("IssueInstant", samlTime(time.Now()))
	el.CreateAttr("Destination", destination)
	el.CreateElement("saml:Issuer").SetText(i.entityID)
	el.CreateElement("saml:NameID").SetText(nameID)
	if sessionIndex != "" {
		el.CreateElement("samlp:SessionIndex").SetText(sessionIndex)
	}
	doc := etree.NewDocument()
	doc.SetRoot(i.sign(t, el, i.key))
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// redirectLogoutRequest builds the HTTP-Redirect binding query of an unsigned-XML LogoutRequest with a
// query-string RSA-SHA256 signature (saml-bindings §3.4.4.1).
func (i *testIdP) redirectLogoutRequest(t *testing.T, destination, nameID, relayState string) string {
	t.Helper()
	// Step 1: the deflated, base64 message
	el := etree.NewElement("samlp:LogoutRequest")
	el.CreateAttr("xmlns:samlp", nsProtocol)
	el.CreateAttr("xmlns:saml", nsAssertion)
	el.CreateAttr("ID", "_lr"+randID())
	el.CreateAttr("Version", "2.0")
	el.CreateAttr("IssueInstant", samlTime(time.Now()))
	el.CreateAttr("Destination", destination)
	el.CreateElement("saml:Issuer").SetText(i.entityID)
	el.CreateElement("saml:NameID").SetText(nameID)
	doc := etree.NewDocument()
	doc.SetRoot(el)
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = fw.Write(raw)
	_ = fw.Close()
	// Step 2: the signed query string
	query := "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes())) +
		"&RelayState=" + url.QueryEscape(relayState) +
		"&SigAlg=" + url.QueryEscape(dsig.RSASHA256SignatureMethod)
	sum := sha256.Sum256([]byte(query))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return query + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
}

// authnRequest decodes the SAMLRequest and RelayState of an HTTP-Redirect AuthnRequest URL.
type authnRequest struct {
	ID                          string `xml:"ID,attr"`
	AssertionConsumerServiceURL string `xml:"AssertionConsumerServiceURL,attr"`
	Destination                 string `xml:"Destination,attr"`
	Issuer                      string `xml:"Issuer"`
	RelayState                  string `xml:"-"`
	Signed                      bool   `xml:"-"`
}

func decodeRedirectMessage(t *testing.T, raw, param string) ([]byte, url.Values) {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	compressed, err := base64.StdEncoding.DecodeString(q.Get(param))
	if err != nil {
		t.Fatalf("decode %s: %v", param, err)
	}
	xmlBytes, err := io.ReadAll(flate.NewReader(bytes.NewReader(compressed)))
	if err != nil {
		t.Fatalf("inflate %s: %v", param, err)
	}
	return xmlBytes, q
}

func decodeAuthnRequest(t *testing.T, raw string) authnRequest {
	t.Helper()
	xmlBytes, q := decodeRedirectMessage(t, raw, "SAMLRequest")
	var req authnRequest
	if err := xml.Unmarshal(xmlBytes, &req); err != nil {
		t.Fatal(err)
	}
	req.RelayState = q.Get("RelayState")
	req.Signed = q.Get("Signature") != "" && q.Get("SigAlg") != ""
	return req
}

func randID() string {
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
