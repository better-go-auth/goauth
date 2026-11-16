package providers

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWK is one JSON Web Key (RSA or EC public key).
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// PublicKey converts the JWK to a crypto public key.
func (k JWK) PublicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("social: unsupported curve %q", k.Crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
	default:
		return nil, fmt.Errorf("social: unsupported key type %q", k.Kty)
	}
}

// jwksCache caches a remote key set and refetches on an unknown kid (at most once per minute).
type jwksCache struct {
	mu        sync.Mutex
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
}

var (
	jwksMu     sync.Mutex
	jwksCaches = map[string]*jwksCache{}
)

const (
	jwksTTL         = 10 * time.Minute
	jwksMinInterval = time.Minute
)

// FetchJWK returns the public key with kid from the JWKS at endpoint.
func FetchJWK(ctx context.Context, client *http.Client, endpoint, kid string) (crypto.PublicKey, error) {
	// Step 1: one cache per endpoint
	jwksMu.Lock()
	c, ok := jwksCaches[endpoint]
	if !ok {
		c = &jwksCache{}
		jwksCaches[endpoint] = c
	}
	jwksMu.Unlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	// Step 2: serve from cache while fresh
	if key, ok := c.keys[kid]; ok && time.Since(c.fetchedAt) < jwksTTL {
		return key, nil
	}
	// Step 3: refetch (rate limited when the kid is simply unknown)
	if c.keys != nil && time.Since(c.fetchedAt) < jwksMinInterval {
		if key, ok := c.keys[kid]; ok {
			return key, nil
		}
		return nil, fmt.Errorf("social: JWK with kid %s not found", kid)
	}
	var set struct {
		Keys []JWK `json:"keys"`
	}
	if err := GetJSON(ctx, client, endpoint, nil, &set); err != nil {
		return nil, err
	}
	if set.Keys == nil {
		return nil, errors.New("social: keys not found")
	}
	keys := map[string]crypto.PublicKey{}
	for _, k := range set.Keys {
		if pk, err := k.PublicKey(); err == nil {
			keys[k.Kid] = pk
		}
	}
	c.keys, c.fetchedAt = keys, time.Now()
	// Step 4: look the kid up in the fresh set
	key, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("social: JWK with kid %s not found", kid)
	}
	return key, nil
}

// ResetJWKSCache drops every cached key set (tests rotate keys between servers).
func ResetJWKSCache() {
	jwksMu.Lock()
	defer jwksMu.Unlock()
	jwksCaches = map[string]*jwksCache{}
}

// IDTokenCheck configures VerifyJWT (jose's jwtVerify options).
type IDTokenCheck struct {
	JWKSEndpoint string
	// Issuers accepted in "iss" (empty = any).
	Issuers []string
	// Audiences: "aud" must contain one of them (empty = any).
	Audiences []string
	// MaxAge rejects tokens whose "iat" is older (0 = no limit).
	MaxAge time.Duration
	// Algorithms allowed (default RS256/RS384/RS512/ES256/ES384/ES512/PS256).
	Algorithms []string
}

// VerifyJWT verifies token's signature against the JWKS and its registered claims, returning the claims.
func VerifyJWT(ctx context.Context, client *http.Client, token string, check IDTokenCheck) (jwt.MapClaims, error) {
	// Step 1: parser options mirroring jwtVerify
	algs := check.Algorithms
	if len(algs) == 0 {
		algs = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"}
	}
	opts := []jwt.ParserOption{jwt.WithValidMethods(algs), jwt.WithLeeway(5 * time.Second)}
	if check.MaxAge > 0 {
		opts = append(opts, jwt.WithIssuedAt())
	}
	// Step 2: resolve the signing key from the "kid" header
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("social: id token has no kid")
		}
		return FetchJWK(ctx, client, check.JWKSEndpoint, kid)
	}, opts...)
	if err != nil {
		return nil, err
	}
	// Step 3: issuer
	if len(check.Issuers) > 0 {
		iss, _ := claims.GetIssuer()
		if !slices.Contains(check.Issuers, iss) {
			return nil, fmt.Errorf("social: unexpected issuer %q", iss)
		}
	}
	// Step 4: audience
	if len(check.Audiences) > 0 {
		aud, _ := claims.GetAudience()
		ok := false
		for _, a := range aud {
			if slices.Contains(check.Audiences, a) {
				ok = true
				break
			}
		}
		if !ok {
			return nil, errors.New("social: unexpected audience")
		}
	}
	// Step 5: token age (jose's maxTokenAge requires iat)
	if check.MaxAge > 0 {
		iat, err := claims.GetIssuedAt()
		if err != nil || iat == nil {
			return nil, errors.New("social: id token has no iat")
		}
		if time.Since(iat.Time) > check.MaxAge {
			return nil, errors.New("social: id token too old")
		}
	}
	return claims, nil
}
