package middleware

import (
	"fmt"

	"github.com/better-go-auth/goauth/src/providers/token"
	jwttoken "github.com/better-go-auth/goauth/src/providers/token/jwt-token"
)

// TokenVerifier handles cryptographic token verification
type TokenVerifier interface {
	VerifyToken(tokenStr string) (token.CustomClaims, error)
}

type JWTTokenVerifier struct {
	accessSecret string
}

func NewJWTTokenVerifier(accessSecret string) TokenVerifier {
	return &JWTTokenVerifier{accessSecret: accessSecret}
}

func (v *JWTTokenVerifier) VerifyToken(tokenStr string) (token.CustomClaims, error) {
	claims, err := jwttoken.ValidateAccessToken(tokenStr, v.accessSecret)
	if err != nil || claims == nil {
		return token.CustomClaims{}, fmt.Errorf("invalid token: %w", err)
	}
	return *claims, nil
}
