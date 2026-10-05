package cookies

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/url"
	"strings"
)

// signatureLength is the length of a padded standard-base64 HMAC-SHA256 digest.
const signatureLength = 44

// SignCookieValue returns "value.signature" as written by better-call's setSignedCookie
// (HMAC-SHA256 with secret, standard base64 with padding). The result is not URL-encoded.
func SignCookieValue(value, secret string) string {
	return value + "." + cookieSignature(value, secret)
}

// VerifyCookieValue checks a "value.signature" string and returns value when the signature is valid.
func VerifyCookieValue(signed, secret string) (string, bool) {
	dot := strings.LastIndex(signed, ".")
	if dot < 1 {
		return "", false
	}
	value, sig := signed[:dot], signed[dot+1:]
	if len(sig) != signatureLength || !strings.HasSuffix(sig, "=") {
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(cookieSignature(value, secret)), []byte(sig)) != 1 {
		return "", false
	}
	return value, true
}

// EncodeCookieValue escapes like JavaScript's encodeURIComponent for the base64 alphabet.
func EncodeCookieValue(v string) string {
	return url.QueryEscape(v)
}

// DecodeCookieValue reverses EncodeCookieValue without turning '+' into a space.
func DecodeCookieValue(v string) string {
	if d, err := url.PathUnescape(v); err == nil {
		return d
	}
	return v
}

func cookieSignature(value, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(value))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
