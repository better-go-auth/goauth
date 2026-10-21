package services

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/models/dtos"
	jwtconfig "github.com/better-go-auth/goauth/src/plugins/jwt/config"
	"github.com/better-go-auth/goauth/src/plugins/jwt/models"
	"github.com/better-go-auth/goauth/src/plugins/jwt/repository"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
	"github.com/better-go-auth/goauth/src/providers/idgen"
	"github.com/golang-jwt/jwt/v5"
)

// JWTService handles key generation, JWKS publication, and JWT signing/verification.
type JWTService struct {
	config  jwtconfig.JWTConfig
	secret  string
	baseURL string
	repo    repository.IJwksRepo
}

// NewJWTService creates a new instance of JWTService.
func NewJWTService(cfg jwtconfig.JWTConfig, secret, baseURL string, repo repository.IJwksRepo) *JWTService {
	return &JWTService{
		config:  cfg,
		secret:  secret,
		baseURL: baseURL,
		repo:    repo,
	}
}

// CreateKey generates a new key pair and stores it in the database.
func (s *JWTService) CreateKey(ctx context.Context) (*models.JWK, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("jwt: generate ed25519 key: %w", err)
	}

	x := base64.RawURLEncoding.EncodeToString(pub)
	d := base64.RawURLEncoding.EncodeToString(priv.Seed())

	pubJWK := map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   x,
		"use": "sig",
	}
	privJWK := map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   x,
		"d":   d,
	}

	pubBytes, err := json.Marshal(pubJWK)
	if err != nil {
		return nil, err
	}
	privBytes, err := json.Marshal(privJWK)
	if err != nil {
		return nil, err
	}

	var storedPrivKey string
	if !s.config.Jwks.DisablePrivateKeyEncryption && s.secret != "" {
		enc, err := authcrypto.SymmetricEncrypt(s.secret, string(privBytes))
		if err != nil {
			return nil, fmt.Errorf("jwt: encrypt private key: %w", err)
		}
		// Better Auth stores JSON.stringify(encrypted)
		encBytes, _ := json.Marshal(enc)
		storedPrivKey = string(encBytes)
	} else {
		storedPrivKey = string(privBytes)
	}

	now := time.Now()
	var expiresAt *time.Time
	if s.config.Jwks.RotationInterval > 0 {
		exp := now.Add(s.config.Jwks.RotationInterval)
		expiresAt = &exp
	}

	keyID := idgen.GenerateID()
	jwkRecord := &models.JWK{
		ID:         keyID,
		PublicKey:  string(pubBytes),
		PrivateKey: storedPrivKey,
		CreatedAt:  now,
		ExpiresAt:  expiresAt,
		Alg:        "EdDSA",
		Crv:        "Ed25519",
	}

	if err := s.repo.CreateJWK(ctx, jwkRecord); err != nil {
		return nil, fmt.Errorf("jwt: save key to db: %w", err)
	}

	return jwkRecord, nil
}

// GetOrCreateActiveKey returns the current valid signing key or creates one.
func (s *JWTService) GetOrCreateActiveKey(ctx context.Context) (*models.JWK, error) {
	key, err := s.repo.GetLatestKey(ctx)
	if err != nil {
		return nil, err
	}
	if key == nil || (key.ExpiresAt != nil && key.ExpiresAt.Before(time.Now())) {
		return s.CreateKey(ctx)
	}
	return key, nil
}

func (s *JWTService) decryptPrivateKey(key *models.JWK) (ed25519.PrivateKey, error) {
	privStr := key.PrivateKey
	if !s.config.Jwks.DisablePrivateKeyEncryption && s.secret != "" {
		var hexStr string
		if err := json.Unmarshal([]byte(privStr), &hexStr); err == nil {
			privStr = hexStr
		}
		dec, err := authcrypto.SymmetricDecrypt(s.secret, privStr)
		if err != nil {
			return nil, fmt.Errorf("jwt: decrypt private key: %w", err)
		}
		privStr = dec
	}

	var privMap map[string]any
	if err := json.Unmarshal([]byte(privStr), &privMap); err != nil {
		return nil, fmt.Errorf("jwt: parse private key jwk: %w", err)
	}

	dVal, ok := privMap["d"].(string)
	if !ok || dVal == "" {
		return nil, errors.New("jwt: private key jwk missing 'd'")
	}

	seed, err := base64.RawURLEncoding.DecodeString(dVal)
	if err != nil {
		return nil, fmt.Errorf("jwt: decode private key seed: %w", err)
	}

	return ed25519.NewKeyFromSeed(seed), nil
}

// GetJWKS returns all valid public keys matching Better Auth's JWKS response specification.
func (s *JWTService) GetJWKS(ctx context.Context) ([]models.JWKKey, error) {
	if s.config.Jwks.RemoteURL != "" {
		return nil, errors.New("jwt: remote jwks url configured, local endpoint disabled")
	}

	keys, err := s.repo.GetAllKeys(ctx)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		_, err := s.CreateKey(ctx)
		if err != nil {
			return nil, err
		}
		keys, err = s.repo.GetAllKeys(ctx)
		if err != nil {
			return nil, err
		}
	}

	now := time.Now()
	gracePeriod := s.config.Jwks.GracePeriod
	if gracePeriod <= 0 {
		gracePeriod = 30 * 24 * time.Hour
	}

	var publicKeys []models.JWKKey
	for _, k := range keys {
		if k.ExpiresAt != nil && k.ExpiresAt.Add(gracePeriod).Before(now) {
			continue
		}

		var jwk models.JWKKey
		if err := json.Unmarshal([]byte(k.PublicKey), &jwk); err != nil {
			continue
		}
		jwk.Kid = k.ID
		if jwk.Alg == "" {
			if k.Alg != "" {
				jwk.Alg = k.Alg
			} else {
				jwk.Alg = "EdDSA"
			}
		}
		if jwk.Crv == "" && k.Crv != "" {
			jwk.Crv = k.Crv
		}
		publicKeys = append(publicKeys, jwk)
	}

	return publicKeys, nil
}

// SignJWT signs an arbitrary payload using the active key pair.
func (s *JWTService) SignJWT(ctx context.Context, payload map[string]any, overrideOptions map[string]any) (string, error) {
	if s.config.JWT.Sign != nil {
		return s.config.JWT.Sign(payload)
	}

	key, err := s.GetOrCreateActiveKey(ctx)
	if err != nil {
		return nilToken(err)
	}

	privKey, err := s.decryptPrivateKey(key)
	if err != nil {
		return nilToken(err)
	}

	now := time.Now().Unix()
	claims := jwt.MapClaims{}
	for k, v := range payload {
		claims[k] = v
	}

	if _, ok := claims["iat"]; !ok {
		claims["iat"] = now
	}

	expDuration := s.config.JWT.ExpirationTime
	if expDuration <= 0 {
		expDuration = 15 * time.Minute
	}
	if _, ok := claims["exp"]; !ok {
		claims["exp"] = now + int64(expDuration.Seconds())
	}

	iss := s.config.JWT.Issuer
	if iss == "" {
		iss = s.baseURL
	}
	if overrideOptions != nil {
		if overrideIss, ok := overrideOptions["issuer"].(string); ok && overrideIss != "" {
			iss = overrideIss
		}
	}
	if _, ok := claims["iss"]; !ok && iss != "" {
		claims["iss"] = iss
	}

	aud := s.config.JWT.Audience
	if aud == "" {
		aud = s.baseURL
	}
	if overrideOptions != nil {
		if overrideAud, ok := overrideOptions["audience"].(string); ok && overrideAud != "" {
			aud = overrideAud
		}
	}
	if _, ok := claims["aud"]; !ok && aud != "" {
		claims["aud"] = aud
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	alg := key.Alg
	if alg == "" {
		alg = "EdDSA"
	}
	token.Header["alg"] = alg
	token.Header["kid"] = key.ID

	signed, err := token.SignedString(privKey)
	if err != nil {
		return nilToken(fmt.Errorf("jwt: sign token: %w", err))
	}
	return signed, nil
}

func nilToken(err error) (string, error) {
	return "", err
}

// GetJWTToken creates a signed JWT representing the user and session.
func (s *JWTService) GetJWTToken(ctx context.Context, session *dtos.SessionWithUser) (string, error) {
	if session == nil {
		return "", errors.New("jwt: session is required")
	}

	var payload map[string]any
	if s.config.JWT.DefinePayload != nil {
		customPayload, err := s.config.JWT.DefinePayload(session)
		if err != nil {
			return "", err
		}
		payload = customPayload
	} else {
		payload = map[string]any{
			"id":            session.User.ID,
			"name":          session.User.Name,
			"email":         session.User.Email,
			"emailVerified": session.User.EmailVerified,
			"image":         session.User.Image,
			"createdAt":     session.User.CreatedAt,
			"updatedAt":     session.User.UpdatedAt,
		}
		if session.User.Role != "" {
			payload["role"] = session.User.Role
		}
	}

	sub := session.User.ID
	if s.config.JWT.GetSubject != nil {
		if customSub, err := s.config.JWT.GetSubject(session); err == nil && customSub != "" {
			sub = customSub
		}
	}
	payload["sub"] = sub

	return s.SignJWT(ctx, payload, nil)
}

// VerifyJWT parses and verifies a JWT token string against stored public keys.
func (s *JWTService) VerifyJWT(ctx context.Context, tokenStr string, issuer string) (map[string]any, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt: invalid token format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwt: decode header: %w", err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("jwt: parse header: %w", err)
	}

	kid, _ := header["kid"].(string)
	if kid == "" {
		return nil, errors.New("jwt: missing kid in header")
	}

	keys, err := s.repo.GetAllKeys(ctx)
	if err != nil {
		return nil, err
	}

	var matchedKey *models.JWK
	for i := range keys {
		if keys[i].ID == kid {
			matchedKey = &keys[i]
			break
		}
	}
	if matchedKey == nil {
		return nil, fmt.Errorf("jwt: no jwk found for kid: %s", kid)
	}

	var pubJWK models.JWKKey
	if err := json.Unmarshal([]byte(matchedKey.PublicKey), &pubJWK); err != nil {
		return nil, fmt.Errorf("jwt: parse public jwk: %w", err)
	}

	pubBytes, err := base64.RawURLEncoding.DecodeString(pubJWK.X)
	if err != nil {
		return nil, fmt.Errorf("jwt: decode public key x: %w", err)
	}
	edPub := ed25519.PublicKey(pubBytes)

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != "EdDSA" {
			return nil, fmt.Errorf("jwt: unexpected alg %s", t.Method.Alg())
		}
		return edPub, nil
	})
	if err != nil {
		return nil, fmt.Errorf("jwt: verify failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("jwt: invalid token claims")
	}

	expectedIss := issuer
	if expectedIss == "" {
		expectedIss = s.config.JWT.Issuer
	}
	if expectedIss == "" {
		expectedIss = s.baseURL
	}
	if expectedIss != "" {
		issVal, ok := claims["iss"].(string)
		if !ok || issVal == "" {
			return nil, errors.New("jwt: missing iss claim")
		}
		if issVal != expectedIss {
			return nil, fmt.Errorf("jwt: issuer mismatch: expected %s, got %s", expectedIss, issVal)
		}
	}

	expectedAud := s.config.JWT.Audience
	if expectedAud == "" {
		expectedAud = s.baseURL
	}
	if expectedAud != "" {
		audClaim, ok := claims["aud"]
		if !ok || audClaim == nil {
			return nil, errors.New("jwt: missing aud claim")
		}
		matched := false
		switch v := audClaim.(type) {
		case string:
			matched = v == expectedAud
		case []string:
			for _, item := range v {
				if item == expectedAud {
					matched = true
					break
				}
			}
		case []interface{}:
			for _, item := range v {
				if sItem, ok := item.(string); ok && sItem == expectedAud {
					matched = true
					break
				}
			}
		}
		if !matched {
			return nil, fmt.Errorf("jwt: audience mismatch: expected %s, got %v", expectedAud, audClaim)
		}
	}

	if _, ok := claims["sub"]; !ok {
		return nil, errors.New("jwt: missing sub claim")
	}

	return claims, nil
}
