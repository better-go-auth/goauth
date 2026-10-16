package bearertest

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins"
	bearer "github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	"github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const testSecret = "test-secret-bearer-plugin-01234567890"

func signToken(raw, secret string, encoding *base64.Encoding) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(raw))
	sig := encoding.EncodeToString(mac.Sum(nil))
	return raw + "." + sig
}

func TestVerifyAndExtractToken(t *testing.T) {
	raw := "session-token-abc-123"

	// 1. Signed with standard base64 padded
	signedStd := signToken(raw, testSecret, base64.StdEncoding)
	if tok, ok := bearer.VerifyAndExtractToken(signedStd, testSecret, false); !ok || tok != raw {
		t.Fatalf("expected %q, got %q (ok=%v)", raw, tok, ok)
	}
	if tok, ok := bearer.VerifyAndExtractToken(signedStd, testSecret, true); !ok || tok != raw {
		t.Fatalf("expected %q with requireSignature=true, got %q (ok=%v)", raw, tok, ok)
	}

	// 2. Signed with URL-safe base64 unpadded (Better Auth base64urlnopad)
	signedURL := signToken(raw, testSecret, base64.RawURLEncoding)
	if tok, ok := bearer.VerifyAndExtractToken(signedURL, testSecret, true); !ok || tok != raw {
		t.Fatalf("expected %q with raw URL encoding, got %q (ok=%v)", raw, tok, ok)
	}

	// 3. URL-encoded signed token
	urlEncoded := strings.ReplaceAll(signedStd, "=", "%3D")
	if tok, ok := bearer.VerifyAndExtractToken(urlEncoded, testSecret, true); !ok || tok != raw {
		t.Fatalf("expected %q with URL-encoded token, got %q (ok=%v)", raw, tok, ok)
	}

	// 4. Invalid signature
	invalidSig := raw + ".invalid-sig"
	if _, ok := bearer.VerifyAndExtractToken(invalidSig, testSecret, false); ok {
		t.Fatalf("expected invalid signature to fail")
	}

	// 5. Unsigned token with requireSignature = false
	if tok, ok := bearer.VerifyAndExtractToken(raw, testSecret, false); !ok || tok != raw {
		t.Fatalf("expected unsigned token to pass with requireSignature=false, got %q (ok=%v)", tok, ok)
	}

	// 6. Unsigned token with requireSignature = true
	if _, ok := bearer.VerifyAndExtractToken(raw, testSecret, true); ok {
		t.Fatalf("expected unsigned token to be rejected with requireSignature=true")
	}

	// 7. Empty token
	if _, ok := bearer.VerifyAndExtractToken("", testSecret, false); ok {
		t.Fatalf("expected empty token to fail")
	}
}

func setupTestServer(t *testing.T, bearerCfg bearerconfig.BearerConfig) (*httptest.Server, *goauth.GoAuth) {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:bearer_%s?mode=memory&cache=shared", uuid.NewString())),
		&gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("sqlite open: %v", err)
	}

	secStore, err := memory.NewSecondaryStorage()
	if err != nil {
		t.Fatalf("sec storage: %v", err)
	}

	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("Bearer Plugin Test", "1.0.0"))

	bPlugin := bearer.New(bearerCfg)

	auth, err := goauth.SetupGoAuth(context.Background(), api, goauth.GoAuthOptions{
		Conn:             db,
		SecondaryStorage: secStore,
		Plugins:          []plugins.Plugin{bPlugin},
		AuthConfig: config.AuthConfig{
			Secret:         testSecret,
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

func TestBearerPlugin_RoundTrip(t *testing.T) {
	ts, _ := setupTestServer(t, bearerconfig.BearerConfig{RequireSignature: false})

	// 1. Sign up a new user via /api/auth/sign-up/email
	signUpBody := `{"email":"bearer-test@example.com","password":"Password123!","name":"Bearer User"}`
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/sign-up/email", strings.NewReader(signUpBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", ts.URL)

	client := &http.Client{} // Notice: NO cookie jar!
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("sign-up failed with status %d: %s", resp.StatusCode, body)
	}

	for k, v := range resp.Header {
		t.Logf("Response Header %s: %v", k, v)
	}

	// Verify set-auth-token header was emitted
	authToken := resp.Header.Get("set-auth-token")
	if authToken == "" {
		t.Fatalf("expected set-auth-token header in sign-up response, got none")
	}

	// Verify Access-Control-Expose-Headers contains set-auth-token
	exposed := resp.Header.Get("Access-Control-Expose-Headers")
	if !strings.Contains(strings.ToLower(exposed), "set-auth-token") {
		t.Fatalf("expected Access-Control-Expose-Headers to contain set-auth-token, got %q", exposed)
	}

	t.Logf("Received set-auth-token: %s", authToken)

	// 2. Query /api/auth/get-session using ONLY Authorization: Bearer <token>
	getSessReq, err := http.NewRequest(http.MethodGet, ts.URL+"/api/auth/get-session", nil)
	if err != nil {
		t.Fatal(err)
	}
	getSessReq.Header.Set("Authorization", "Bearer "+authToken)
	getSessReq.Header.Set("Origin", ts.URL)

	sessResp, err := client.Do(getSessReq)
	if err != nil {
		t.Fatal(err)
	}
	defer sessResp.Body.Close()

	if sessResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(sessResp.Body)
		t.Fatalf("get-session failed with status %d: %s", sessResp.StatusCode, body)
	}

	sessBody, _ := io.ReadAll(sessResp.Body)
	if !strings.Contains(string(sessBody), "bearer-test@example.com") {
		t.Fatalf("expected session to contain user email, got: %s", sessBody)
	}

	// 3. Sign out with Bearer token
	signOutReq, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/sign-out", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	signOutReq.Header.Set("Content-Type", "application/json")
	signOutReq.Header.Set("Authorization", "Bearer "+authToken)
	signOutReq.Header.Set("Origin", ts.URL)

	signOutResp, err := client.Do(signOutReq)
	if err != nil {
		t.Fatal(err)
	}
	signOutResp.Body.Close()
	if signOutResp.StatusCode != http.StatusOK {
		t.Fatalf("sign-out failed with status %d", signOutResp.StatusCode)
	}

	// 4. Query /api/auth/get-session again - should return empty/null session
	getSessReq2, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/auth/get-session", nil)
	getSessReq2.Header.Set("Authorization", "Bearer "+authToken)
	getSessReq2.Header.Set("Origin", ts.URL)

	sessResp2, err := client.Do(getSessReq2)
	if err != nil {
		t.Fatal(err)
	}
	defer sessResp2.Body.Close()

	body2, _ := io.ReadAll(sessResp2.Body)
	// getSession returns null or 200 with null or 401 when unauthenticated
	if strings.Contains(string(body2), "bearer-test@example.com") {
		t.Fatalf("session should be revoked, but still returned user: %s", body2)
	}
}

func TestBearerPlugin_RequireSignature(t *testing.T) {
	ts, _ := setupTestServer(t, bearerconfig.BearerConfig{RequireSignature: true})

	// Sign up
	signUpBody := `{"email":"bearer-sig@example.com","password":"Password123!","name":"Sig User"}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/sign-up/email", strings.NewReader(signUpBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", ts.URL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	signedToken := resp.Header.Get("set-auth-token")
	if signedToken == "" {
		t.Fatalf("expected set-auth-token")
	}

	// 1. Signed token must succeed
	getSessReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/auth/get-session", nil)
	getSessReq.Header.Set("Authorization", "Bearer "+signedToken)
	getSessReq.Header.Set("Origin", ts.URL)
	sessResp, err := http.DefaultClient.Do(getSessReq)
	if err != nil {
		t.Fatal(err)
	}
	defer sessResp.Body.Close()
	sessBody, _ := io.ReadAll(sessResp.Body)
	if !strings.Contains(string(sessBody), "bearer-sig@example.com") {
		t.Fatalf("signed token failed to authenticate: %s", sessBody)
	}

	// 2. Unsigned token (raw token stripped of signature) must be rejected because RequireSignature = true
	rawToken := signedToken
	if dot := strings.Index(signedToken, "."); dot != -1 {
		rawToken = signedToken[:dot]
	}
	getSessReqUnsigned, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/auth/get-session", nil)
	getSessReqUnsigned.Header.Set("Authorization", "Bearer "+rawToken)
	getSessReqUnsigned.Header.Set("Origin", ts.URL)
	sessRespUnsigned, err := http.DefaultClient.Do(getSessReqUnsigned)
	if err != nil {
		t.Fatal(err)
	}
	defer sessRespUnsigned.Body.Close()
	unsignedBody, _ := io.ReadAll(sessRespUnsigned.Body)
	if strings.Contains(string(unsignedBody), "bearer-sig@example.com") {
		t.Fatalf("unsigned token should have been rejected when RequireSignature=true, but got: %s", unsignedBody)
	}
}

func TestBearerPlugin_UntrustedOriginBlocked(t *testing.T) {
	ts, _ := setupTestServer(t, bearerconfig.BearerConfig{RequireSignature: false})

	// Sign up to get a valid token
	signUpBody := `{"email":"bearer-csrf@example.com","password":"Password123!","name":"CSRF User"}`
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/sign-up/email", strings.NewReader(signUpBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", ts.URL)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	authToken := resp.Header.Get("set-auth-token")

	// Mutating request (e.g. sign-out) with Bearer token AND an untrusted origin must be BLOCKED (status 403)
	signOutReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/sign-out", strings.NewReader("{}"))
	signOutReq.Header.Set("Content-Type", "application/json")
	signOutReq.Header.Set("Authorization", "Bearer "+authToken)
	signOutReq.Header.Set("Origin", "http://evil-attacker.com")

	signOutResp, err := http.DefaultClient.Do(signOutReq)
	if err != nil {
		t.Fatal(err)
	}
	defer signOutResp.Body.Close()

	if signOutResp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(signOutResp.Body)
		t.Fatalf("expected 403 Forbidden for untrusted origin with bearer token, got %d: %s", signOutResp.StatusCode, body)
	}
}
