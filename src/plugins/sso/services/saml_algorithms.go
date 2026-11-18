package services

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/plugins/sso/config"
)

// XML signature and encryption algorithm URIs (better-auth's SignatureAlgorithm / DigestAlgorithm /
// KeyEncryptionAlgorithm / DataEncryptionAlgorithm).
const (
	SigRSASHA1     = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	SigRSASHA256   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	SigRSASHA384   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	SigRSASHA512   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	SigECDSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	SigECDSASHA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	SigECDSASHA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"

	DigestSHA1   = "http://www.w3.org/2000/09/xmldsig#sha1"
	DigestSHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
	DigestSHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	DigestSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"

	KeyEncRSA15      = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
	DataEncTripleDES = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
)

var (
	secureSignatureAlgorithms = []string{SigRSASHA256, SigRSASHA384, SigRSASHA512, SigECDSASHA256, SigECDSASHA384, SigECDSASHA512}
	secureDigestAlgorithms    = []string{DigestSHA256, DigestSHA384, DigestSHA512}
	shortSignature            = map[string]string{
		"sha1": SigRSASHA1, "sha256": SigRSASHA256, "sha384": SigRSASHA384, "sha512": SigRSASHA512,
		"rsa-sha1": SigRSASHA1, "rsa-sha256": SigRSASHA256, "rsa-sha384": SigRSASHA384, "rsa-sha512": SigRSASHA512,
		"ecdsa-sha256": SigECDSASHA256, "ecdsa-sha384": SigECDSASHA384, "ecdsa-sha512": SigECDSASHA512,
	}
	shortDigest = map[string]string{"sha1": DigestSHA1, "sha256": DigestSHA256, "sha384": DigestSHA384, "sha512": DigestSHA512}
)

// normalizeSignatureAlgorithm maps short names ("sha256", "rsa-sha256", ...) to URIs.
func normalizeSignatureAlgorithm(alg string) string {
	if u, ok := shortSignature[strings.ToLower(alg)]; ok {
		return u
	}
	return alg
}

// normalizeDigestAlgorithm maps short names to URIs.
func normalizeDigestAlgorithm(alg string) string {
	if u, ok := shortDigest[strings.ToLower(alg)]; ok {
		return u
	}
	return alg
}

// handleDeprecated is better-auth's handleDeprecatedAlgorithm ("warn" by default).
func handleDeprecated(message, behavior, code string) error {
	switch behavior {
	case "reject":
		return codedError(http.StatusBadRequest, code, message)
	case "allow":
		return nil
	}
	logger.Warn("[SAML Security Warning] " + message)
	return nil
}

func onDeprecated(o *config.AlgorithmOptions) string {
	if o == nil || o.OnDeprecated == "" {
		return "warn"
	}
	return o.OnDeprecated
}

// validateConfigAlgorithms is better-auth's validateConfigAlgorithms (provider registration / update).
func validateConfigAlgorithms(signature, digest string, o *config.AlgorithmOptions) error {
	behavior := onDeprecated(o)
	// Step 1: the signature algorithm
	if signature != "" {
		n := normalizeSignatureAlgorithm(signature)
		switch {
		case o != nil && o.AllowedSignatureAlgorithms != nil:
			allowed := make([]string, 0, len(o.AllowedSignatureAlgorithms))
			for _, a := range o.AllowedSignatureAlgorithms {
				allowed = append(allowed, normalizeSignatureAlgorithm(a))
			}
			if !slices.Contains(allowed, n) {
				return codedError(http.StatusBadRequest, "SAML_ALGORITHM_NOT_ALLOWED", "SAML signature algorithm not in allow-list: "+signature)
			}
		case n == SigRSASHA1:
			if err := handleDeprecated("SAML config uses deprecated signature algorithm: "+signature+". Consider using SHA-256 or stronger.", behavior, "SAML_DEPRECATED_CONFIG_ALGORITHM"); err != nil {
				return err
			}
		case !slices.Contains(secureSignatureAlgorithms, n):
			return codedError(http.StatusBadRequest, "SAML_UNKNOWN_ALGORITHM", "SAML signature algorithm not recognized: "+signature)
		}
	}
	// Step 2: the digest algorithm
	if digest != "" {
		n := normalizeDigestAlgorithm(digest)
		switch {
		case o != nil && o.AllowedDigestAlgorithms != nil:
			allowed := make([]string, 0, len(o.AllowedDigestAlgorithms))
			for _, a := range o.AllowedDigestAlgorithms {
				allowed = append(allowed, normalizeDigestAlgorithm(a))
			}
			if !slices.Contains(allowed, n) {
				return codedError(http.StatusBadRequest, "SAML_ALGORITHM_NOT_ALLOWED", "SAML digest algorithm not in allow-list: "+digest)
			}
		case n == DigestSHA1:
			if err := handleDeprecated("SAML config uses deprecated digest algorithm: "+digest+". Consider using SHA-256 or stronger.", behavior, "SAML_DEPRECATED_CONFIG_ALGORITHM"); err != nil {
				return err
			}
		case !slices.Contains(secureDigestAlgorithms, n):
			return codedError(http.StatusBadRequest, "SAML_UNKNOWN_ALGORITHM", "SAML digest algorithm not recognized: "+digest)
		}
	}
	return nil
}

// responseAlgorithms are the algorithms found in a SAML response.
type responseAlgorithms struct {
	signature      string
	keyEncryption  string
	dataEncryption string
	encrypted      bool
}

// scanResponseAlgorithms reads the first SignatureMethod, the EncryptedKey / EncryptedData methods and whether
// an EncryptedAssertion is present.
func scanResponseAlgorithms(doc []byte) responseAlgorithms {
	var out responseAlgorithms
	dec := xml.NewDecoder(bytes.NewReader(doc))
	var stack []string
	for {
		tok, err := dec.Token()
		if err != nil {
			return out
		}
		switch t := tok.(type) {
		case xml.StartElement:
			parent := ""
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			name := t.Name.Local
			stack = append(stack, name)
			alg := ""
			for _, a := range t.Attr {
				if a.Name.Local == "Algorithm" {
					alg = a.Value
				}
			}
			switch {
			case name == "EncryptedAssertion":
				out.encrypted = true
			case name == "SignatureMethod" && out.signature == "":
				out.signature = alg
			case name == "EncryptionMethod" && parent == "EncryptedKey" && out.keyEncryption == "":
				out.keyEncryption = alg
			case name == "EncryptionMethod" && parent == "EncryptedData" && out.dataEncryption == "":
				out.dataEncryption = alg
			}
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
}

// validateSAMLAlgorithms is better-auth's validateSAMLAlgorithms (signature, then encryption when encrypted).
func validateSAMLAlgorithms(found responseAlgorithms, o *config.AlgorithmOptions) error {
	behavior := onDeprecated(o)
	// Step 1: signature algorithm
	if alg := found.signature; alg != "" {
		switch {
		case o != nil && o.AllowedSignatureAlgorithms != nil:
			if !slices.Contains(o.AllowedSignatureAlgorithms, alg) {
				return codedError(http.StatusBadRequest, "SAML_ALGORITHM_NOT_ALLOWED", "SAML signature algorithm not in allow-list: "+alg)
			}
		case alg == SigRSASHA1:
			if err := handleDeprecated("SAML response uses deprecated signature algorithm: "+alg+". Please configure your IdP to use SHA-256 or stronger.", behavior, "SAML_DEPRECATED_ALGORITHM"); err != nil {
				return err
			}
		case !slices.Contains(secureSignatureAlgorithms, alg):
			return codedError(http.StatusBadRequest, "SAML_UNKNOWN_ALGORITHM", "SAML signature algorithm not recognized: "+alg)
		}
	}
	if !found.encrypted {
		return nil
	}
	// Step 2: key encryption
	if alg := found.keyEncryption; alg != "" {
		if o != nil && o.AllowedKeyEncryptionAlgorithms != nil {
			if !slices.Contains(o.AllowedKeyEncryptionAlgorithms, alg) {
				return codedError(http.StatusBadRequest, "SAML_ALGORITHM_NOT_ALLOWED", "SAML key encryption algorithm not in allow-list: "+alg)
			}
		} else if alg == KeyEncRSA15 {
			if err := handleDeprecated("SAML response uses deprecated key encryption algorithm: "+alg+". Please configure your IdP to use RSA-OAEP.", behavior, "SAML_DEPRECATED_ALGORITHM"); err != nil {
				return err
			}
		}
	}
	// Step 3: data encryption
	if alg := found.dataEncryption; alg != "" {
		if o != nil && o.AllowedDataEncryptionAlgorithms != nil {
			if !slices.Contains(o.AllowedDataEncryptionAlgorithms, alg) {
				return codedError(http.StatusBadRequest, "SAML_ALGORITHM_NOT_ALLOWED", "SAML data encryption algorithm not in allow-list: "+alg)
			}
		} else if alg == DataEncTripleDES {
			if err := handleDeprecated("SAML response uses deprecated data encryption algorithm: "+alg+". Please configure your IdP to use AES-GCM.", behavior, "SAML_DEPRECATED_ALGORITHM"); err != nil {
				return err
			}
		}
	}
	return nil
}

// countAssertions counts Assertion and EncryptedAssertion elements (any namespace prefix).
func countAssertions(doc []byte) (int, error) {
	dec := xml.NewDecoder(bytes.NewReader(doc))
	n := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return n, nil
			}
			return n, err
		}
		if t, ok := tok.(xml.StartElement); ok && (t.Name.Local == "Assertion" || t.Name.Local == "EncryptedAssertion") {
			n++
		}
	}
}
