package middleware

import (
	"fmt"

	"github.com/better-go-auth/goauth/src/providers/token"
	jwttoken "github.com/better-go-auth/goauth/src/providers/token/jwt-token"
)

type JWTTokenVerifier struct {
	accessSecret string
}

func NewJWTTokenVerifier(accessSecret string) *JWTTokenVerifier {
	return &JWTTokenVerifier{accessSecret: accessSecret}
}

func (v *JWTTokenVerifier) VerifyToken(tokenStr string) (token.CustomClaims, error) {
	claims, err := jwttoken.ValidateAccessToken(tokenStr, v.accessSecret)
	if err != nil || claims == nil {
		return token.CustomClaims{}, fmt.Errorf("invalid token: %w", err)
	}
	return *claims, nil
}
