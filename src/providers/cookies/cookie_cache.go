package cookies

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/hkdf"
)

// CachedSessionPayload is the serialized payload stored inside session_data.
type CachedSessionPayload struct {
	Session   dtos.SessionData  `json:"session"`
	User      dtos.UserResponse `json:"user"`
	Version   string            `json:"version"`
	ExpiresAt int64             `json:"expiresAt"`
}

// jwtCacheClaims represents standard JWT claims wrapping CachedSessionPayload.
type jwtCacheClaims struct {
	Session dtos.SessionData  `json:"session"`
	User    dtos.UserResponse `json:"user"`
	Version string            `json:"version"`
	jwt.RegisteredClaims
}

var (
	errInvalidCookieCache = errors.New("cookies: invalid cookie cache payload")
	errExpiredCookieCache = errors.New("cookies: cookie cache expired")
	errVersionMismatch    = errors.New("cookies: cookie cache version mismatch")
)

// CookieCacheEnabled reports whether cookie caching is active on the manager.
func (c *Manager) CookieCacheEnabled() bool {
	return c.cookieCache != nil && c.cookieCache.IsEnabled()
}

// CreateSessionDataCookie builds the Set-Cookie for session_data caching sw.
func (c *Manager) CreateSessionDataCookie(sw *dtos.SessionWithUser, dontRemember bool) (*http.Cookie, error) {
	if sw == nil {
		return nil, errors.New("cookies: nil session provided")
	}

	// 1. Calculate expiration duration
	maxAge := c.cookieCache.EffectiveMaxAge()
	expiresAt := time.Now().Add(maxAge).Unix()
	cookieMaxAge := int(maxAge.Seconds())
	if dontRemember {
		cookieMaxAge = 0
	}

	// 2. Build payload structure
	payload := CachedSessionPayload{
		Session:   sw.Session,
		User:      sw.User,
		Version:   c.cookieCache.EffectiveVersion(),
		ExpiresAt: expiresAt,
	}

	// 3. Encode according to configured strategy
	strategy := c.cookieCache.EffectiveStrategy()
	var encodedVal string
	var err error

	switch strategy {
	case config.CookieCacheStrategyJwt:
		encodedVal, err = c.encodeJWT(payload, expiresAt)
	case config.CookieCacheStrategyJwe:
		encodedVal, err = c.encodeJWE(payload)
	case config.CookieCacheStrategyCompact:
		fallthrough
	default:
		encodedVal, err = c.encodeCompact(payload)
	}

	if err != nil {
		return nil, fmt.Errorf("cookies: failed to encode session_data: %w", err)
	}

	// 4. Construct cookie object with secure attributes
	ck := c.cookie(CookieSessionData, encodedVal, cookieMaxAge)
	return &ck, nil
}

// ReadSessionData extracts, verifies, and returns the cached SessionWithUser from a Cookie header.
func (c *Manager) ReadSessionData(cookieHeader string) (*dtos.SessionWithUser, error) {
	if !c.CookieCacheEnabled() {
		return nil, errors.New("cookies: cookie cache not enabled")
	}

	// 1. Read raw session_data cookie value
	raw, ok := c.read(cookieHeader, CookieSessionData)
	if !ok || raw == "" {
		return nil, http.ErrNoCookie
	}

	// 2. Decode based on configured strategy
	strategy := c.cookieCache.EffectiveStrategy()
	var payload *CachedSessionPayload
	var err error

	switch strategy {
	case config.CookieCacheStrategyJwt:
		payload, err = c.decodeJWT(raw)
	case config.CookieCacheStrategyJwe:
		payload, err = c.decodeJWE(raw)
	case config.CookieCacheStrategyCompact:
		fallthrough
	default:
		payload, err = c.decodeCompact(raw)
	}

	if err != nil {
		return nil, err
	}

	// 3. Verify expiration
	if payload.ExpiresAt > 0 && time.Now().Unix() > payload.ExpiresAt {
		return nil, errExpiredCookieCache
	}

	// 4. Verify version match for cache invalidation
	if payload.Version != c.cookieCache.EffectiveVersion() {
		return nil, errVersionMismatch
	}

	// 5. Return reconstructed SessionWithUser
	return &dtos.SessionWithUser{
		Session: payload.Session,
		User:    payload.User,
	}, nil
}

// ShouldRefreshCookieCache reports whether the cached session in cookieHeader should be refreshed statelessly.
func (c *Manager) ShouldRefreshCookieCache(cookieHeader string) bool {
	if !c.CookieCacheEnabled() || !c.cookieCache.IsRefreshEnabled() {
		return false
	}

	// 1. Read raw cookie value
	raw, ok := c.read(cookieHeader, CookieSessionData)
	if !ok || raw == "" {
		return false
	}

	// 2. Decode payload
	var payload *CachedSessionPayload
	var err error
	switch c.cookieCache.EffectiveStrategy() {
	case config.CookieCacheStrategyJwt:
		payload, err = c.decodeJWT(raw)
	case config.CookieCacheStrategyJwe:
		payload, err = c.decodeJWE(raw)
	default:
		payload, err = c.decodeCompact(raw)
	}
	if err != nil || payload == nil {
		return false
	}

	// 3. Check remaining lifetime against RefreshUpdateAge
	remaining := time.Until(time.Unix(payload.ExpiresAt, 0))
	return remaining <= c.cookieCache.RefreshUpdateAge()
}

// SessionCookiesWithData returns session cookies including session_data when CookieCache is enabled.
func (c *Manager) SessionCookiesWithData(sw *dtos.SessionWithUser, dontRemember bool) []http.Cookie {
	if sw == nil {
		return nil
	}
	cookies := c.SessionCookies(sw.Session.Token, dontRemember)
	if c.CookieCacheEnabled() {
		if dataCookie, err := c.CreateSessionDataCookie(sw, dontRemember); err == nil && dataCookie != nil {
			cookies = append(cookies, *dataCookie)
		}
	}
	return cookies
}

// ─── Compact Strategy Implementation ──────────────────────────────────────────

// encodeCompact serializes payload to JSON, encodes to Base64URL, and signs via HMAC-SHA256.
func (c *Manager) encodeCompact(payload CachedSessionPayload) (string, error) {
	// 1. Marshal payload to JSON
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	// 2. Encode to unpadded URL-safe base64
	b64Val := base64.RawURLEncoding.EncodeToString(jsonBytes)

	// 3. Sign using HMAC-SHA256 and encode cookie
	signed := SignCookieValue(b64Val, c.secret)
	return EncodeCookieValue(signed), nil
}

// decodeCompact verifies HMAC-SHA256 and decodes the JSON payload.
func (c *Manager) decodeCompact(raw string) (*CachedSessionPayload, error) {
	// 1. Decode URL encoding and verify HMAC signature
	decodedCookie := DecodeCookieValue(raw)
	b64Val, valid := VerifyCookieValue(decodedCookie, c.secret)
	if !valid {
		return nil, errInvalidCookieCache
	}

	// 2. Decode unpadded URL-safe base64
	jsonBytes, err := base64.RawURLEncoding.DecodeString(b64Val)
	if err != nil {
		// Fallback to standard Base64 if needed
		jsonBytes, err = base64.StdEncoding.DecodeString(b64Val)
		if err != nil {
			return nil, errInvalidCookieCache
		}
	}

	// 3. Unmarshal JSON
	var payload CachedSessionPayload
	if err := json.Unmarshal(jsonBytes, &payload); err != nil {
		return nil, errInvalidCookieCache
	}

	return &payload, nil
}

// ─── JWT Strategy Implementation ──────────────────────────────────────────────

// encodeJWT signs the session cache as an HS256 JWT using Manager.secret.
func (c *Manager) encodeJWT(payload CachedSessionPayload, expiresAt int64) (string, error) {
	claims := jwtCacheClaims{
		Session: payload.Session,
		User:    payload.User,
		Version: payload.Version,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Unix(expiresAt, 0)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(c.secret))
	if err != nil {
		return "", err
	}
	return EncodeCookieValue(tokenString), nil
}

// decodeJWT parses and validates the HS256 JWT cookie cache.
func (c *Manager) decodeJWT(raw string) (*CachedSessionPayload, error) {
	tokenString := DecodeCookieValue(raw)
	var claims jwtCacheClaims

	token, err := jwt.ParseWithClaims(tokenString, &claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("cookies: unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(c.secret), nil
	})

	if err != nil || token == nil || !token.Valid {
		return nil, errInvalidCookieCache
	}

	var exp int64
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Unix()
	}

	return &CachedSessionPayload{
		Session:   claims.Session,
		User:      claims.User,
		Version:   claims.Version,
		ExpiresAt: exp,
	}, nil
}

// ─── JWE Strategy Implementation ──────────────────────────────────────────────
// Implements standard RFC 7516 Direct JWE with A256CBC-HS512 authenticated encryption.

const (
	jweHeaderCompact = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0" // {"alg":"dir","enc":"A256CBC-HS512"}
	jweKeyDeriveInfo = "better-auth-jwe-cookie-cache"
)

// deriveJWEKeys derives a 32-byte MAC key and 32-byte AES key from the secret via HKDF-SHA512.
func (c *Manager) deriveJWEKeys() (macKey, encKey []byte, err error) {
	kdf := hkdf.New(sha512.New, []byte(c.secret), nil, []byte(jweKeyDeriveInfo))
	keyMaterial := make([]byte, 64)
	if _, err := io.ReadFull(kdf, keyMaterial); err != nil {
		return nil, nil, err
	}
	return keyMaterial[:32], keyMaterial[32:64], nil
}

// encodeJWE encrypts payload into a compact 5-part JWE string (header..iv.ciphertext.tag).
func (c *Manager) encodeJWE(payload CachedSessionPayload) (string, error) {
	// 1. Serialize JSON payload
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	// 2. Derive MAC and Encryption keys
	macKey, encKey, err := c.deriveJWEKeys()
	if err != nil {
		return "", err
	}

	// 3. Generate random 16-byte IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// 4. PKCS#7 pad plaintext
	paddedPlaintext := pkcs7Pad(plaintext, aes.BlockSize)

	// 5. Encrypt with AES-256-CBC
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return "", err
	}
	ciphertext := make([]byte, len(paddedPlaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedPlaintext)

	// 6. Compute HMAC-SHA512 authentication tag over AAD || IV || Ciphertext || AL
	aad := []byte(jweHeaderCompact)
	tag := computeJWETag(macKey, aad, iv, ciphertext)

	// 7. Assemble 5-part compact JWE: header..iv.ciphertext.tag
	jweToken := fmt.Sprintf("%s..%s.%s.%s",
		jweHeaderCompact,
		base64.RawURLEncoding.EncodeToString(iv),
		base64.RawURLEncoding.EncodeToString(ciphertext),
		base64.RawURLEncoding.EncodeToString(tag),
	)

	return EncodeCookieValue(jweToken), nil
}

// decodeJWE decrypts and verifies a compact 5-part JWE string.
func (c *Manager) decodeJWE(raw string) (*CachedSessionPayload, error) {
	jweToken := DecodeCookieValue(raw)
	parts := strings.Split(jweToken, ".")
	if len(parts) != 5 {
		return nil, errInvalidCookieCache
	}

	headerB64, encKeyB64, ivB64, cipherB64, tagB64 := parts[0], parts[1], parts[2], parts[3], parts[4]

	// 1. Direct encryption requires empty encrypted key
	if encKeyB64 != "" || headerB64 != jweHeaderCompact {
		return nil, errInvalidCookieCache
	}

	// 2. Decode IV, Ciphertext, and Tag
	iv, err := base64.RawURLEncoding.DecodeString(ivB64)
	if err != nil || len(iv) != aes.BlockSize {
		return nil, errInvalidCookieCache
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(cipherB64)
	if err != nil || len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errInvalidCookieCache
	}
	tag, err := base64.RawURLEncoding.DecodeString(tagB64)
	if err != nil || len(tag) != 32 {
		return nil, errInvalidCookieCache
	}

	// 3. Derive keys and verify authentication tag
	macKey, encKey, err := c.deriveJWEKeys()
	if err != nil {
		return nil, err
	}

	expectedTag := computeJWETag(macKey, []byte(headerB64), iv, ciphertext)
	if subtle.ConstantTimeCompare(tag, expectedTag) != 1 {
		return nil, errInvalidCookieCache
	}

	// 4. Decrypt with AES-256-CBC
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	paddedPlaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(paddedPlaintext, ciphertext)

	// 5. Unpad PKCS#7
	plaintext, err := pkcs7Unpad(paddedPlaintext, aes.BlockSize)
	if err != nil {
		return nil, errInvalidCookieCache
	}

	// 6. Unmarshal JSON payload
	var payload CachedSessionPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, errInvalidCookieCache
	}

	return &payload, nil
}

// computeJWETag computes the 32-byte truncated HMAC-SHA512 tag per RFC 7518 section 5.2.2.1.
func computeJWETag(macKey, aad, iv, ciphertext []byte) []byte {
	// AL = 64-bit big-endian representation of number of bits in AAD
	al := make([]byte, 8)
	binary.BigEndian.PutUint64(al, uint64(len(aad)*8))

	mac := hmac.New(sha512.New, macKey)
	mac.Write(aad)
	mac.Write(iv)
	mac.Write(ciphertext)
	mac.Write(al)

	digest := mac.Sum(nil)
	return digest[:32] // Truncate to 32 bytes (256 bits) for A256CBC-HS512
}

// pkcs7Pad appends PKCS#7 padding to data.
func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// pkcs7Unpad removes PKCS#7 padding from data.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	length := len(data)
	if length == 0 || length%blockSize != 0 {
		return nil, errors.New("pkcs7: invalid padding size")
	}
	padLen := int(data[length-1])
	if padLen == 0 || padLen > blockSize {
		return nil, errors.New("pkcs7: invalid padding value")
	}
	for i := length - padLen; i < length; i++ {
		if data[i] != byte(padLen) {
			return nil, errors.New("pkcs7: invalid padding byte")
		}
	}
	return data[:length-padLen], nil
}
