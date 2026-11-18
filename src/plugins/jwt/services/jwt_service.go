package services

import (
	"context"
	"crypto"
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

// SignJWTOptions overrides the plugin's JWT options for a single SignJWT call (better-auth's
// signJWT overrideOptions.jwt). Zero fields keep the plugin configuration.
type SignJWTOptions struct {
	// Issuer replaces the "iss" claim (default: JWT.Issuer, then the base URL).
	Issuer string
	// Audience replaces the "aud" claim (default: JWT.Audience, then the base URL).
	Audience string
	// ExpirationTime replaces the token lifetime (default: JWT.ExpirationTime, then 15 minutes).
	ExpirationTime time.Duration
}

// NewJWTService creates a new instance of JWTService.
// An invalid Jwks.KeyPairConfig is reported by CreateKey (the plugin rejects it earlier, in Init).
func NewJWTService(cfg jwtconfig.JWTConfig, secret, baseURL string, repo repository.IJwksRepo) *JWTService {
	if kp, err := cfg.Jwks.KeyPairConfig.Normalize(); err == nil {
		cfg.Jwks.KeyPairConfig = kp
	}
	return &JWTService{
		config:  cfg,
		secret:  secret,
		baseURL: baseURL,
		repo:    repo,
	}
}

// CreateKey generates a new key pair for the configured algorithm (Jwks.KeyPairConfig) and stores it in
// the database.
func (s *JWTService) CreateKey(ctx context.Context) (*models.JWK, error) {
	// Step 1: validate the configured algorithm and generate a key pair for it
	kp, err := s.config.Jwks.KeyPairConfig.Normalize()
	if err != nil {
		return nil, err
	}
	pubJWK, privJWK, err := generateKeyPair(kp)
	if err != nil {
		return nil, err
	}
	pubJWK["use"] = "sig"

	// Step 2: serialize both JWKs and encrypt the private one
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

	// Step 3: store the key with its algorithm and curve (expiring after RotationInterval, if set)
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
		Alg:        kp.Alg,
		Crv:        kp.Crv,
	}

	if err := s.repo.CreateJWK(ctx, jwkRecord); err != nil {
		return nil, fmt.Errorf("jwt: save key to db: %w", err)
	}

	return jwkRecord, nil
}

// GetOrCreateActiveKey returns the current valid signing key or creates one.
// The active key is the newest key whose algorithm matches Jwks.KeyPairConfig.Alg, so changing the
// algorithm starts signing with a new key while older keys stay in the JWKS for verification.
func (s *JWTService) GetOrCreateActiveKey(ctx context.Context) (*models.JWK, error) {
	// Step 1: load the keys, newest first
	keys, err := s.repo.GetAllKeys(ctx)
	if err != nil {
		return nil, err
	}

	// Step 2: the newest key with the configured algorithm is active unless it has expired
	want := s.config.Jwks.KeyPairConfig.Alg
	for i := range keys {
		key := &keys[i]
		if keyAlg(key, want) != want {
			continue
		}
		if key.ExpiresAt != nil && key.ExpiresAt.Before(time.Now()) {
			break
		}
		return key, nil
	}

	// Step 3: no usable key, create one
	return s.CreateKey(ctx)
}

func (s *JWTService) decryptPrivateKey(key *models.JWK) (crypto.Signer, error) {
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

	return parsePrivateJWK(privStr)
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
			jwk.Alg = keyAlg(&k, s.config.Jwks.KeyPairConfig.Alg)
		}
		if jwk.Crv == "" && k.Crv != "" {
			jwk.Crv = k.Crv
		}
		publicKeys = append(publicKeys, jwk)
	}

	return publicKeys, nil
}

// SignJWT signs an arbitrary payload using the active key pair. It is the Go equivalent of better-auth's
// server-only auth.api.signJWT: it is not exposed over HTTP, call it from your own server code.
// Missing iat, exp, iss and aud claims are filled in from the plugin configuration (or opts, which may
// be nil). A nil payload is treated as empty.
func (s *JWTService) SignJWT(ctx context.Context, payload map[string]any, opts *SignJWTOptions) (string, error) {
	// Step 1: a custom signer replaces the built-in keys
	if s.config.JWT.Sign != nil {
		return s.config.JWT.Sign(payload)
	}
	if opts == nil {
		opts = &SignJWTOptions{}
	}

	// Step 2: load the active key pair and decrypt its private key
	key, err := s.GetOrCreateActiveKey(ctx)
	if err != nil {
		return nilToken(err)
	}

	privKey, err := s.decryptPrivateKey(key)
	if err != nil {
		return nilToken(err)
	}

	// Step 3: build the claims (payload plus defaults for the registered claims)
	now := time.Now().Unix()
	claims := jwt.MapClaims{}
	for k, v := range payload {
		claims[k] = v
	}

	if _, ok := claims["iat"]; !ok {
		claims["iat"] = now
	}

	expDuration := s.config.JWT.ExpirationTime
	if opts.ExpirationTime > 0 {
		expDuration = opts.ExpirationTime
	}
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
	if opts.Issuer != "" {
		iss = opts.Issuer
	}
	if _, ok := claims["iss"]; !ok && iss != "" {
		claims["iss"] = iss
	}

	aud := s.config.JWT.Audience
	if aud == "" {
		aud = s.baseURL
	}
	if opts.Audience != "" {
		aud = opts.Audience
	}
	if _, ok := claims["aud"]; !ok && aud != "" {
		claims["aud"] = aud
	}

	// Step 4: sign with the key's algorithm; the kid header names the key in the JWKS
	method, err := signingMethod(keyAlg(key, s.config.Jwks.KeyPairConfig.Alg))
	if err != nil {
		return nilToken(err)
	}
	token := jwt.NewWithClaims(method, claims)
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

	// Step 1: the claims come from DefinePayload, or default to the user object
	var payload map[string]any
	if s.config.JWT.DefinePayload != nil {
		customPayload, err := s.config.JWT.DefinePayload(session)
		if err != nil {
			return "", err
		}
		// copy so "sub" is never written into the caller's map (and a nil map counts as empty)
		payload = make(map[string]any, len(customPayload)+1)
		for k, v := range customPayload {
			payload[k] = v
		}
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
		// role is part of the user object only with the admin plugin (plain "user" otherwise stays out)
		if role := session.User.Role; role != "" && (role != "user" || dtos.UserFieldInstalled(dtos.FieldRole)) {
			payload["role"] = role
		}
	}

	// Step 2: the subject is always added (user ID unless GetSubject overrides it)
	sub := session.User.ID
	if s.config.JWT.GetSubject != nil {
		if customSub, err := s.config.JWT.GetSubject(session); err == nil && customSub != "" {
			sub = customSub
		}
	}
	payload["sub"] = sub

	// Step 3: sign with the active key
	return s.SignJWT(ctx, payload, nil)
}

// VerifyJWT parses and verifies a JWT token string against stored public keys. It is the Go equivalent
// of better-auth's server-only auth.api.verifyJWT. issuer overrides the expected "iss" claim ("" uses
// the plugin's issuer). The signature, exp, iss, aud and the presence of sub are checked; the token's
// alg must be the algorithm of the key named by its kid.
func (s *JWTService) VerifyJWT(ctx context.Context, tokenStr string, issuer string) (map[string]any, error) {
	// Step 1: read the kid from the token header
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

	// Step 2: find the stored key named by kid
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

	// Step 3: verify the signature with the key's public key, accepting only the key's algorithm
	pubKey, err := parsePublicJWK(matchedKey.PublicKey)
	if err != nil {
		return nil, err
	}
	alg := keyAlg(matchedKey, s.config.Jwks.KeyPairConfig.Alg)

	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return pubKey, nil
	}, jwt.WithValidMethods([]string{alg}))
	if err != nil {
		return nil, fmt.Errorf("jwt: verify failed: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, errors.New("jwt: invalid token claims")
	}

	// Step 4: check the issuer, audience and subject claims
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
