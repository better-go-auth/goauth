package jwttoken

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/better-go-auth/goauth/src/providers/token"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
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

// ValidateToken validates a JWT token.
// It checks the signature and expiration time.
func ValidateToken(tokenStr string, signingKey string) (*token.CustomClaims, error) {
	tkn, err := jwt.ParseWithClaims(tokenStr, &jwtClaims{}, func(tk *jwt.Token) (interface{}, error) {
		if _, ok := tk.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("jwttoken: unexpected signing method: %v", tk.Header["alg"])
		}
		return []byte(signingKey), nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := tkn.Claims.(*jwtClaims); ok && tkn.Valid {
		return &token.CustomClaims{
			UserID:    claims.UserID,
			SessionID: claims.SessionID,
			Role:      claims.Role,
			Type:      claims.Type,
			ExpiresAt: claims.ExpiresAt.Unix(),
			// multi tenancy support
			ActiveOrgId:   claims.ActiveOrgID,
			ActiveOrgRole: claims.ActiveOrgRole,
		}, nil
	}
	return nil, jwt.ErrInvalidKey
}

// ErrWrongTokenType is returned when a valid JWT carries an unexpected `typ` claim.
var ErrWrongTokenType = errors.New("jwttoken: wrong token type")

// ValidateAccessToken validates tokenStr and requires typ "access".
func ValidateAccessToken(tokenStr, signingKey string) (*token.CustomClaims, error) {
	return validateTyped(tokenStr, signingKey, token.TypeAccess)
}

// ValidateRefreshToken validates tokenStr and requires typ "refresh".
func ValidateRefreshToken(tokenStr, signingKey string) (*token.CustomClaims, error) {
	return validateTyped(tokenStr, signingKey, token.TypeRefresh)
}

func validateTyped(tokenStr, signingKey, typ string) (*token.CustomClaims, error) {
	claims, err := ValidateToken(tokenStr, signingKey)
	if err != nil {
		return nil, err
	}
	if claims.Type != typ {
		return nil, ErrWrongTokenType
	}
	return claims, nil
}

// Generate generates jwt token
func SignWithExpiry(signingKey string, claims *token.CustomClaims, expiryMinutes time.Duration) (string, error) {
	now := time.Now()
	jwtClaims := jwtClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			// unique per token so rotation never re-issues an identical refresh token
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiryMinutes)),
			Issuer:    "better-go-auth",
		},
		UserID:        claims.UserID,
		SessionID:     claims.SessionID,
		Role:          claims.Role,
		Type:          claims.Type,
		ActiveOrgID:   claims.ActiveOrgId,
		ActiveOrgRole: claims.ActiveOrgRole,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtClaims)
	signed, err := token.SignedString([]byte(signingKey))
	if err != nil {
		return "", fmt.Errorf("jwttoken: failed to sign token: %w", err)
	}
	return signed, nil
}

// func SignWithExpiry(RefreshSecret string, expMin int, claims token.Claims) (string, error) {
// 	//claims.ExpiresAt= 20
// 	claims.IssuedAt = jwt.NewNumericDate(time.Now())
// 	claims.ExpiresAt = jwt.NewNumericDate(time.Now().Add(time.Minute * time.Duration(expMin)))
// 	token, err := Generate(RefreshSecret, claims)
// 	if err != nil {
// 		return "", err
// 	}
// 	return token, nil
// }

// ================================================   The Jwt Manager =======================
//
// ==================================================================================
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
	Type          string `json:"typ,omitempty"`
	ActiveOrgID   string `json:"activeOrgId,omitempty"`
	ActiveOrgRole string `json:"activeOrgRole,omitempty"`
}

// Implementation of token.ITokenManager

// GenerateToken creates a new JWT token with HS256 algorithm.
// It sets the standard claims (IssuedAt, ExpiresAt, Issuer) and custom claims.
func (m *JWTManager) GenerateToken(_ context.Context, claims token.CustomClaims) (string, error) {
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
func (m *JWTManager) ValidateToken(ctx context.Context, tokenStr string) (*token.CustomClaims, error) {
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
		return &token.CustomClaims{
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
