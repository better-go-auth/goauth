package authcrypto

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// SignJWT signs claims with HS256 like better-auth's signJWT (adds iat and exp).
func SignJWT(claims map[string]any, secret string, expiresIn time.Duration) (string, error) {
	now := time.Now()
	c := jwt.MapClaims{}
	for k, v := range claims {
		c[k] = v
	}
	c["iat"] = now.Unix()
	c["exp"] = now.Add(expiresIn).Unix()
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(secret))
}

// VerifyJWT verifies an HS256 token signed by SignJWT or better-auth and returns its claims.
func VerifyJWT(token, secret string) (map[string]any, error) {
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		return []byte(secret), nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithExpirationRequired())
	if err != nil {
		return nil, fmt.Errorf("authcrypto: verify jwt: %w", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("authcrypto: unexpected claims type %T", parsed.Claims)
	}
	return claims, nil
}
