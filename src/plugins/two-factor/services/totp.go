package services

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// HOTP computes an RFC 4226 code (HMAC-SHA1, dynamic truncation) like @better-auth/utils/otp generateHOTP.
// The key is the raw secret string bytes, exactly as better-auth uses it.
func HOTP(secret string, counter uint64, digits int) string {
	// Step 1: HMAC-SHA1 over the big-endian 8 byte counter
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	// Step 2: dynamic truncation to a 31 bit integer
	offset := sum[len(sum)-1] & 0x0f
	code := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	// Step 3: keep the last `digits` digits, left padded with zeros
	mod := uint32(math.Pow10(digits))
	return fmt.Sprintf("%0*d", digits, code%mod)
}

// TOTP computes the RFC 6238 code for time t.
func TOTP(secret string, t time.Time, period time.Duration, digits int) string {
	return HOTP(secret, totpCounter(t, period), digits)
}

func totpCounter(t time.Time, period time.Duration) uint64 {
	ms := period.Milliseconds()
	if ms <= 0 {
		ms = 30_000
	}
	return uint64(t.UnixMilli() / ms)
}

// VerifyTOTP checks code against the current, previous and next time step (better-auth's window 1).
func VerifyTOTP(secret, code string, t time.Time, period time.Duration, digits int) bool {
	counter := int64(totpCounter(t, period))
	ok := false
	for i := int64(-1); i <= 1; i++ {
		if counter+i < 0 {
			continue
		}
		want := HOTP(secret, uint64(counter+i), digits)
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			ok = true
		}
	}
	return ok
}

// TOTPURI builds the otpauth:// URI exactly like @better-auth/utils/otp createOTP(...).url(issuer, account):
// otpauth://totp/<issuer>:<account>?secret=<base32 nopad>&issuer=<issuer>&digits=<d>&period=<p>
func TOTPURI(secret, issuer, account string, digits int, period time.Duration) string {
	// Step 1: path components use encodeURIComponent
	base := "otpauth://totp/" + encodeURIComponent(issuer) + ":" + encodeURIComponent(account)
	// Step 2: query keeps URLSearchParams insertion order and form encoding
	params := [][2]string{
		{"secret", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(secret))},
		{"issuer", issuer},
		{"digits", strconv.Itoa(digits)},
		{"period", strconv.Itoa(int(period / time.Second))},
	}
	parts := make([]string, len(params))
	for i, p := range params {
		parts[i] = formEncode(p[0]) + "=" + formEncode(p[1])
	}
	return base + "?" + strings.Join(parts, "&")
}

// encodeURIComponent mirrors JavaScript's encodeURIComponent (unreserved: A-Z a-z 0-9 - _ . ! ~ * ' ( )).
func encodeURIComponent(s string) string {
	return percentEncode(s, "-_.!~*'()", false)
}

// formEncode mirrors URLSearchParams serialisation (unreserved: A-Z a-z 0-9 * - . _, space → +).
func formEncode(s string) string {
	return percentEncode(s, "*-._", true)
}

func percentEncode(s, unreserved string, spaceAsPlus bool) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', strings.IndexByte(unreserved, c) >= 0:
			b.WriteByte(c)
		case c == ' ' && spaceAsPlus:
			b.WriteByte('+')
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// ParseTOTPURI extracts the raw secret string from an otpauth URI (helper for apps and tests).
func ParseTOTPURI(uri string) (secret string, err error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(u.Query().Get("secret"))
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// TrustDeviceToken is better-auth's createHMAC("SHA-256", "base64urlnopad").sign(secret, `${userId}!${trustIdentifier}`).
func TrustDeviceToken(secret, userID, trustIdentifier string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(userID + "!" + trustIdentifier))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// HashOTP is better-auth's defaultKeyHasher: base64url (no padding) of SHA-256.
func HashOTP(otp string) string {
	sum := sha256.Sum256([]byte(otp))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
