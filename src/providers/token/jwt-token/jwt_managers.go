package jwttoken

import (
	"context"
	"fmt"
	"time"

	"github.com/better-go-auth/goauth/src/providers/token"
	"github.com/golang-jwt/jwt/v5"
)

func JwtValid[T jwt.Claims](signedToken string, signingKey string, claims T) (T, bool, error) {
	token, err := jwt.ParseWithClaims(signedToken, claims,
		func(token *jwt.Token) (any, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(signingKey), nil
		})

	var zero T
	if err != nil {
		return zero, false, err
	}

	if parsedClaims, ok := token.Claims.(T); ok && token.Valid {
		return parsedClaims, true, nil
	}

	return zero, false, err
}

// Generate generates jwt token
func Generate(signingKey string, claims jwt.Claims) (string, error) {
	tn := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedString, err := tn.SignedString([]byte(signingKey))
	return signedString, err
}

//================================================   The Jwt Manager =======================
//
//==================================================================================
// JWTManager signs and verifies HS256 JWTs.
type JWTManager struct {
	Secret    []byte
	ExpiresIn time.Duration
}

// New creates a new JWTManager.
func New(secret string, expiresIn time.Duration) *JWTManager {
	return &JWTManager{
		Secret:    []byte(secret),
		ExpiresIn: expiresIn,
	}
}

type jwtClaims struct {
	jwt.RegisteredClaims
	UserID        string `json:"userId"`
	SessionID     string `json:"sessionId"`
	Role          string `json:"role"`
	ActiveOrgID   string `json:"activeOrgId,omitempty"`
	ActiveOrgRole string `json:"activeOrgRole,omitempty"`
}

// Implementation of token.ITokenManager

// GenerateToken creates a new JWT token with HS256 algorithm.
// It sets the standard claims (IssuedAt, ExpiresAt, Issuer) and custom claims.
func (m *JWTManager) GenerateToken(_ context.Context, claims token.Claims) (string, error) {
	now := time.Now()
	jwtClaims := jwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.ExpiresIn)),
			Issuer:    "better-go-auth",
		},
		UserID:        claims.UserID,
		SessionID:     claims.SessionID,
		Role:          claims.Role,
		ActiveOrgID:   claims.ActiveOrgId,
		ActiveOrgRole: claims.ActiveOrgRole,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
	signed, err := token.SignedString(m.Secret)
	if err != nil {
		return "", fmt.Errorf("jwttoken: failed to sign token: %w", err)
	}
	return signed, nil
}

// ValidateToken validates a JWT token.
// It checks the signature and expiration time.
func (m *JWTManager) ValidateToken(ctx context.Context, tokenStr string) (*token.Claims, error) {
	tkn, err := jwt.ParseWithClaims(tokenStr, &jwtClaims{}, func(tk *jwt.Token) (interface{}, error) {
		if _, ok := tk.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("jwttoken: unexpected signing method: %v", tk.Header["alg"])
		}
		return m.Secret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := tkn.Claims.(*jwtClaims); ok && tkn.Valid {
		return &token.Claims{
			UserID:    claims.UserID,
			SessionID: claims.SessionID,
			Role:      claims.Role,
			ExpiresAt: claims.ExpiresAt.Unix(),
			// multi tenancy support
			ActiveOrgId:   claims.ActiveOrgID,
			ActiveOrgRole: claims.ActiveOrgRole,
		}, nil
	}
	return nil, jwt.ErrInvalidKey
}

// IsJWT returns true because this is a JWT manager.
func (m *JWTManager) IsJWT() bool {
	return true
}
