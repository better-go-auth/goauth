package jwttest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins"
	bearer "github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	jwtplugin "github.com/better-go-auth/goauth/src/plugins/jwt"
	jwtconfig "github.com/better-go-auth/goauth/src/plugins/jwt/config"
	"github.com/better-go-auth/goauth/src/plugins/jwt/models"
	"github.com/better-go-auth/goauth/src/plugins/jwt/repository"
	"github.com/better-go-auth/goauth/src/plugins/jwt/services"
	"github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const testSecret = "jwt-plugin-test-secret-012345678901234567890"

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:jwttest_%s?mode=memory&cache=shared", uuid.NewString())),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite open: %v", err)
	}
	if err := db.AutoMigrate(&models.JWK{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestJWTService_Unit(t *testing.T) {
	db := setupTestDB(t)
	repo := repository.NewGormJwksRepo(db)
	cfg := jwtconfig.DefaultConfig()
	cfg.JWT.Issuer = "http://localhost:8080"
	cfg.JWT.Audience = "http://localhost:8080"
	cfg.JWT.ExpirationTime = 5 * time.Minute

	svc := services.NewJWTService(cfg, testSecret, "http://localhost:8080", repo)
	ctx := context.Background()

	// 1. Test auto-creation of key on GetJWKS
	jwks, err := svc.GetJWKS(ctx)
	if err != nil {
		t.Fatalf("GetJWKS failed: %v", err)
	}
	if len(jwks) != 1 {
		t.Fatalf("expected 1 jwk key, got %d", len(jwks))
	}
	k := jwks[0]
	if k.Kty != "OKP" || k.Crv != "Ed25519" || k.Alg != "EdDSA" || k.X == "" || k.Kid == "" {
		t.Fatalf("unexpected JWK fields: %+v", k)
	}

	// 2. Sign custom JWT
	customPayload := map[string]any{
		"sub":   "user-test-123",
		"email": "tester@example.com",
		"role":  "admin",
	}
	tokenStr, err := svc.SignJWT(ctx, customPayload, nil)
	if err != nil {
		t.Fatalf("SignJWT failed: %v", err)
	}
	if tokenStr == "" || len(strings.Split(tokenStr, ".")) != 3 {
		t.Fatalf("invalid token string format: %s", tokenStr)
	}

	// 3. Verify valid JWT
	claims, err := svc.VerifyJWT(ctx, tokenStr, "http://localhost:8080")
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	if claims["sub"] != "user-test-123" || claims["email"] != "tester@example.com" || claims["role"] != "admin" {
		t.Fatalf("unexpected claims: %+v", claims)
	}

	// 4. Verify with tampered signature
	tampered := tokenStr[:len(tokenStr)-4] + "ABCD"
	if _, err := svc.VerifyJWT(ctx, tampered, "http://localhost:8080"); err == nil {
		t.Fatalf("expected tampered token to fail verification")
	}

	// 5. Verify with mismatched issuer
	if _, err := svc.VerifyJWT(ctx, tokenStr, "http://wrong-issuer.com"); err == nil {
		t.Fatalf("expected issuer mismatch to fail")
	}

	// 6. Test Key Rotation: expired key generates a new active key
	past := time.Now().Add(-1 * time.Hour)
	db.Model(&models.JWK{}).Where("id = ?", k.Kid).Update("expires_at", past)

	newKey, err := svc.GetOrCreateActiveKey(ctx)
	if err != nil {
		t.Fatalf("GetOrCreateActiveKey failed: %v", err)
	}
	if newKey.ID == k.Kid {
		t.Fatalf("expected new key to be created after expiration")
	}

	// JWKS should return both keys during grace period
	jwksAfterRotation, err := svc.GetJWKS(ctx)
	if err != nil {
		t.Fatalf("GetJWKS after rotation failed: %v", err)
	}
	if len(jwksAfterRotation) != 2 {
		t.Fatalf("expected 2 keys in JWKS within grace period, got %d", len(jwksAfterRotation))
	}
}

func setupFullServer(t *testing.T, jwtCfg jwtconfig.JWTConfig) (*httptest.Server, *goauth.GoAuth) {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:jwthttp_%s?mode=memory&cache=shared", uuid.NewString())),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite open: %v", err)
	}

	secStore, err := memory.NewSecondaryStorage()
	if err != nil {
		t.Fatalf("sec storage: %v", err)
	}

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("JWT Plugin Full Test", "1.0.0"))

	jwtPlug := jwtplugin.New(jwtCfg, jwtplugin.WithDB(db))
	bearerPlug := bearer.New(bearerconfig.DefaultConfig())

	auth, err := goauth.SetupGoAuth(context.Background(), api, goauth.GoAuthOptions{
		Conn:             db,
		SecondaryStorage: secStore,
		Plugins:          []plugins.Plugin{bearerPlug, jwtPlug},
		AuthConfig: config.AuthConfig{
			Secret:         testSecret,
			BaseURL:        "http://localhost:8080",
			TrustedOrigins: []string{"http://127.0.0.1:*", "http://localhost:*"},
		},
	})
	if err != nil {
		t.Fatalf("SetupGoAuth: %v", err)
	}

	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	return ts, auth
}

func TestJWTPlugin_Endpoints(t *testing.T) {
	ts, _ := setupFullServer(t, jwtconfig.DefaultConfig())

	// 1. Test GET /jwks and GET /api/auth/jwks
	jwksResp, err := http.Get(ts.URL + "/jwks")
	if err != nil {
		t.Fatal(err)
	}
	defer jwksResp.Body.Close()
	if jwksResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /jwks failed with status %d", jwksResp.StatusCode)
	}
	var jwksData models.JWKSResponse
	if err := json.NewDecoder(jwksResp.Body).Decode(&jwksData); err != nil {
		t.Fatal(err)
	}
	if len(jwksData.Keys) == 0 {
		t.Fatalf("expected at least 1 key in /jwks response")
	}
	t.Logf("Retrieved JWKS with %d key(s)", len(jwksData.Keys))

	// 2. Test POST /api/auth/sign-jwt
	signBody := `{"payload":{"sub":"user-custom","project":"better-go-auth"}}`
	signReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/sign-jwt", strings.NewReader(signBody))
	signReq.Header.Set("Content-Type", "application/json")
	signReq.Header.Set("Origin", ts.URL)
	signResp, err := http.DefaultClient.Do(signReq)
	if err != nil {
		t.Fatal(err)
	}
	defer signResp.Body.Close()
	if signResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(signResp.Body)
		t.Fatalf("POST /sign-jwt failed (%d): %s", signResp.StatusCode, body)
	}
	var signResult struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(signResp.Body).Decode(&signResult); err != nil {
		t.Fatal(err)
	}
	if signResult.Token == "" {
		t.Fatalf("expected non-empty token from /sign-jwt")
	}

	// 3. Test POST /api/auth/verify-jwt
	verifyBody := fmt.Sprintf(`{"token":"%s"}`, signResult.Token)
	verifyReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/verify-jwt", strings.NewReader(verifyBody))
	verifyReq.Header.Set("Content-Type", "application/json")
	verifyReq.Header.Set("Origin", ts.URL)
	verifyResp, err := http.DefaultClient.Do(verifyReq)
	if err != nil {
		t.Fatal(err)
	}
	defer verifyResp.Body.Close()
	if verifyResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(verifyResp.Body)
		t.Fatalf("POST /verify-jwt failed (%d): %s", verifyResp.StatusCode, body)
	}
	var verifyResult struct {
		Payload map[string]any `json:"payload"`
	}
	if err := json.NewDecoder(verifyResp.Body).Decode(&verifyResult); err != nil {
		t.Fatal(err)
	}
	if verifyResult.Payload["sub"] != "user-custom" || verifyResult.Payload["project"] != "better-go-auth" {
		t.Fatalf("payload mismatch in verify result: %+v", verifyResult.Payload)
	}

	// 4. Test POST /api/auth/verify-jwt with invalid token returns { payload: null }
	badVerifyReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/verify-jwt", strings.NewReader(`{"token":"invalid.jwt.token"}`))
	badVerifyReq.Header.Set("Content-Type", "application/json")
	badVerifyReq.Header.Set("Origin", ts.URL)
	badVerifyResp, err := http.DefaultClient.Do(badVerifyReq)
	if err != nil {
		t.Fatal(err)
	}
	defer badVerifyResp.Body.Close()
	var badResult struct {
		Payload any `json:"payload"`
	}
	if err := json.NewDecoder(badVerifyResp.Body).Decode(&badResult); err != nil {
		t.Fatal(err)
	}
	if badResult.Payload != nil {
		t.Fatalf("expected null payload for invalid token, got: %+v", badResult.Payload)
	}

	// 5. Test User SignUp, /get-session (set-auth-jwt header), and GET /token
	signUpBody := `{"email":"jwt-user@example.com","password":"Password123!","name":"JWT User"}`
	signUpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/sign-up/email", strings.NewReader(signUpBody))
	signUpReq.Header.Set("Content-Type", "application/json")
	signUpReq.Header.Set("Origin", ts.URL)
	signUpResp, err := http.DefaultClient.Do(signUpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer signUpResp.Body.Close()
	if signUpResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(signUpResp.Body)
		t.Fatalf("sign-up failed: %s", body)
	}

	bearerTok := signUpResp.Header.Get("set-auth-token")
	if bearerTok == "" {
		t.Fatalf("expected set-auth-token from signup")
	}

	// Call GET /api/auth/get-session -> inspect set-auth-jwt header!
	getSessReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/auth/get-session", nil)
	getSessReq.Header.Set("Authorization", "Bearer "+bearerTok)
	getSessReq.Header.Set("Origin", ts.URL)
	getSessResp, err := http.DefaultClient.Do(getSessReq)
	if err != nil {
		t.Fatal(err)
	}
	defer getSessResp.Body.Close()
	if getSessResp.StatusCode != http.StatusOK {
		t.Fatalf("get-session failed with status %d", getSessResp.StatusCode)
	}

	setAuthJwt := getSessResp.Header.Get("set-auth-jwt")
	if setAuthJwt == "" {
		t.Fatalf("expected set-auth-jwt header on /get-session response, got none")
	}
	exposedHdr := getSessResp.Header.Get("Access-Control-Expose-Headers")
	if !strings.Contains(strings.ToLower(exposedHdr), "set-auth-jwt") {
		t.Fatalf("expected Access-Control-Expose-Headers to contain set-auth-jwt, got %s", exposedHdr)
	}
	t.Logf("Received set-auth-jwt: %s", setAuthJwt)

	// Call GET /api/auth/token using Bearer token
	tokenReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/auth/token", nil)
	tokenReq.Header.Set("Authorization", "Bearer "+bearerTok)
	tokenReq.Header.Set("Origin", ts.URL)
	tokenResp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		t.Fatal(err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("GET /token failed with status %d: %s", tokenResp.StatusCode, body)
	}
	var tokenRes struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenRes); err != nil {
		t.Fatal(err)
	}
	if tokenRes.Token == "" {
		t.Fatalf("expected non-empty token from /token")
	}

	// Verify the token obtained from /token via POST /api/auth/verify-jwt
	verifyBody2, _ := json.Marshal(map[string]string{"token": tokenRes.Token})
	vReq2, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/verify-jwt", bytes.NewReader(verifyBody2))
	vReq2.Header.Set("Content-Type", "application/json")
	vReq2.Header.Set("Origin", ts.URL)
	vResp2, err := http.DefaultClient.Do(vReq2)
	if err != nil {
		t.Fatal(err)
	}
	defer vResp2.Body.Close()
	var vResult2 struct {
		Payload map[string]any `json:"payload"`
	}
	if err := json.NewDecoder(vResp2.Body).Decode(&vResult2); err != nil {
		t.Fatal(err)
	}
	if vResult2.Payload["email"] != "jwt-user@example.com" {
		t.Fatalf("expected email jwt-user@example.com in token payload, got: %+v", vResult2.Payload)
	}
}
