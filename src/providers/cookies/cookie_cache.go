package cookies

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
	"github.com/golang-jwt/jwt/v5"
)

// CachedSessionPayload is a decoded session_data cookie: better-auth's cookie-cache sessionData
// ({session, user, updatedAt, version}) plus the moment the cache expires.
type CachedSessionPayload struct {
	Session dtos.SessionData  `json:"session"`
	User    dtos.UserResponse `json:"user"`
	// UpdatedAt is when the cache was written (unix milliseconds).
	UpdatedAt int64  `json:"updatedAt"`
	Version   string `json:"version"`
	// ExpiresAt is when the cache expires (unix seconds).
	ExpiresAt int64 `json:"-"`
}

// sessionData is better-auth's cookie-cache payload; the field order is JSON.stringify's, which the compact
// strategy's signature covers.
type sessionData struct {
	Session   dtos.SessionData  `json:"session"`
	User      dtos.UserResponse `json:"user"`
	UpdatedAt int64             `json:"updatedAt"`
	Version   string            `json:"version"`
}

// compactEnvelope is the compact strategy's cookie: base64url(JSON{session, expiresAt, signature}).
type compactEnvelope struct {
	Session   json.RawMessage `json:"session"`
	ExpiresAt int64           `json:"expiresAt"`
	Signature string          `json:"signature"`
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

// CreateSessionDataCookie builds the Set-Cookie for session_data caching sw, in better-auth's format for the
// configured strategy (setCookieCache), signed / encrypted with the current secret.
func (c *Manager) CreateSessionDataCookie(sw *dtos.SessionWithUser, dontRemember bool) (*http.Cookie, error) {
	if sw == nil {
		return nil, errors.New("cookies: nil session provided")
	}

	// Step 1: calculate expiration duration
	maxAge := c.cookieCache.EffectiveMaxAge()
	cookieMaxAge := int(maxAge.Seconds())
	if dontRemember {
		cookieMaxAge = 0
	}

	// Step 2: build better-auth's sessionData
	data := sessionData{
		Session:   sw.Session,
		User:      sw.User,
		UpdatedAt: time.Now().UnixMilli(),
		Version:   c.cookieCache.EffectiveVersion(),
	}

	// Step 3: encode according to configured strategy
	var encodedVal string
	var err error
	switch c.cookieCache.EffectiveStrategy() {
	case config.CookieCacheStrategyJwt:
		encodedVal, err = c.encodeJWT(data, maxAge)
	case config.CookieCacheStrategyJwe:
		encodedVal, err = c.keys.EncodeJWE(data, authcrypto.JWESaltSession, maxAge)
	default:
		encodedVal, err = c.encodeCompact(data, time.Now().Add(maxAge).UnixMilli())
	}
	if err != nil {
		return nil, fmt.Errorf("cookies: failed to encode session_data: %w", err)
	}

	// Step 4: construct cookie object with secure attributes
	ck := c.cookie(CookieSessionData, encodedVal, cookieMaxAge)
	return &ck, nil
}

// ReadSessionData extracts, verifies, and returns the cached SessionWithUser from a Cookie header.
func (c *Manager) ReadSessionData(cookieHeader string) (*dtos.SessionWithUser, error) {
	if !c.CookieCacheEnabled() {
		return nil, errors.New("cookies: cookie cache not enabled")
	}

	// Step 1: decode and verify the cookie
	payload, err := c.decodeSessionData(cookieHeader)
	if err != nil {
		return nil, err
	}

	// Step 2: version match for cache invalidation (missing version counts as "1", like better-auth)
	version := payload.Version
	if version == "" {
		version = "1"
	}
	if version != c.cookieCache.EffectiveVersion() {
		return nil, errVersionMismatch
	}

	// Step 3: the cache and the cached session must both still be valid
	if payload.ExpiresAt > 0 && time.Now().Unix() > payload.ExpiresAt {
		return nil, errExpiredCookieCache
	}
	if exp := time.Time(payload.Session.ExpiresAt); !exp.IsZero() && exp.Before(time.Now()) {
		return nil, errExpiredCookieCache
	}

	// Step 4: return reconstructed SessionWithUser
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
	// Step 1: decode payload
	payload, err := c.decodeSessionData(cookieHeader)
	if err != nil || payload == nil {
		return false
	}
	// Step 2: check remaining lifetime against RefreshUpdateAge
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

// decodeSessionData reads session_data (joining chunks) and decodes it with the configured strategy.
func (c *Manager) decodeSessionData(cookieHeader string) (*CachedSessionPayload, error) {
	raw, ok := c.ReadChunked(cookieHeader, CookieSessionData)
	if !ok || raw == "" {
		return nil, http.ErrNoCookie
	}
	switch c.cookieCache.EffectiveStrategy() {
	case config.CookieCacheStrategyJwt:
		return c.decodeJWT(raw)
	case config.CookieCacheStrategyJwe:
		return c.decodeJWE(raw)
	default:
		return c.decodeCompact(raw)
	}
}

// ─── Compact Strategy ────────────────────────────────────────────────────────

// encodeCompact is better-auth's compact strategy: base64url(JSON{session: sessionData, expiresAt, signature})
// where signature = HMAC-SHA256(secret, JSON.stringify({...sessionData, expiresAt})) in unpadded base64url.
func (c *Manager) encodeCompact(data sessionData, expiresAtMs int64) (string, error) {
	// Step 1: sessionData serialized like JSON.stringify
	inner, err := authcrypto.MarshalJSON(data)
	if err != nil {
		return "", err
	}
	// Step 2: sign the sessionData with expiresAt appended
	sig := compactSignature(c.keys.CurrentSecret(), inner, expiresAtMs)
	// Step 3: the envelope, base64url without padding
	outer, err := authcrypto.MarshalJSON(compactEnvelope{Session: inner, ExpiresAt: expiresAtMs, Signature: sig})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(outer), nil
}

// decodeCompact verifies the signature (current secret, then older ones) and decodes the payload.
func (c *Manager) decodeCompact(raw string) (*CachedSessionPayload, error) {
	// Step 1: base64url-decode the envelope
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return nil, errInvalidCookieCache
	}
	var env compactEnvelope
	if err := json.Unmarshal(b, &env); err != nil || len(env.Session) == 0 || env.Signature == "" {
		return nil, errInvalidCookieCache
	}
	// Step 2: verify; the raw JSON text is exactly what JSON.stringify produced when it was signed
	inner := bytes.TrimSpace(env.Session)
	valid := false
	for _, secret := range c.keys.VerifySecrets() {
		if subtle.ConstantTimeCompare([]byte(compactSignature(secret, inner, env.ExpiresAt)), []byte(env.Signature)) == 1 {
			valid = true
			break
		}
	}
	if !valid {
		return nil, errInvalidCookieCache
	}
	// Step 3: decode the sessionData
	var data sessionData
	if err := json.Unmarshal(inner, &data); err != nil {
		return nil, errInvalidCookieCache
	}
	return &CachedSessionPayload{Session: data.Session, User: data.User, UpdatedAt: data.UpdatedAt, Version: data.Version, ExpiresAt: env.ExpiresAt / 1000}, nil
}

// compactSignature signs JSON.stringify({...sessionData, expiresAt}) given sessionData's JSON text.
func compactSignature(secret string, inner []byte, expiresAtMs int64) string {
	signed := make([]byte, 0, len(inner)+32)
	signed = append(signed, inner[:len(inner)-1]...)
	if len(inner) > 2 {
		signed = append(signed, ',')
	}
	signed = append(signed, `"expiresAt":`+strconv.FormatInt(expiresAtMs, 10)+`}`...)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(signed)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// ─── JWT Strategy ────────────────────────────────────────────────────────────

// encodeJWT is better-auth's signJWT(sessionData, secret, maxAge): HS256 with iat and exp.
func (c *Manager) encodeJWT(data sessionData, maxAge time.Duration) (string, error) {
	// Step 1: sessionData as claims
	raw, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	claims := jwt.MapClaims{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return "", err
	}
	// Step 2: iat / exp and the signature with the current secret
	now := time.Now()
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(maxAge).Unix()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(c.keys.CurrentSecret()))
}

// decodeJWT verifies the HS256 cookie cache with the current secret, then the older ones.
func (c *Manager) decodeJWT(raw string) (*CachedSessionPayload, error) {
	for _, secret := range c.keys.VerifySecrets() {
		var claims struct {
			sessionData
			jwt.RegisteredClaims
		}
		token, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("cookies: unexpected signing method: %v", t.Header["alg"])
			}
			return []byte(secret), nil
		})
		if err != nil || token == nil || !token.Valid {
			continue
		}
		return payloadFromClaims(claims.sessionData, claims.ExpiresAt), nil
	}
	return nil, errInvalidCookieCache
}

// ─── JWE Strategy ────────────────────────────────────────────────────────────

// decodeJWE decrypts better-auth's symmetricEncodeJWT(sessionData, secretConfig, "better-auth-session").
func (c *Manager) decodeJWE(raw string) (*CachedSessionPayload, error) {
	b, err := c.keys.DecodeJWE(raw, authcrypto.JWESaltSession)
	if err != nil {
		return nil, errInvalidCookieCache
	}
	var claims struct {
		sessionData
		Exp *jwt.NumericDate `json:"exp"`
	}
	if err := json.Unmarshal(b, &claims); err != nil || claims.Session.Token == "" {
		return nil, errInvalidCookieCache
	}
	return payloadFromClaims(claims.sessionData, claims.Exp), nil
}

func payloadFromClaims(d sessionData, exp *jwt.NumericDate) *CachedSessionPayload {
	p := &CachedSessionPayload{Session: d.Session, User: d.User, UpdatedAt: d.UpdatedAt, Version: d.Version}
	if exp != nil {
		p.ExpiresAt = exp.Unix()
	}
	return p
}
