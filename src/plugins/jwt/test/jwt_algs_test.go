package jwttest

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins"
	jwtplugin "github.com/better-go-auth/goauth/src/plugins/jwt"
	jwtconfig "github.com/better-go-auth/goauth/src/plugins/jwt/config"
	"github.com/better-go-auth/goauth/src/plugins/jwt/models"
	"github.com/better-go-auth/goauth/src/plugins/jwt/repository"
	"github.com/better-go-auth/goauth/src/plugins/jwt/services"
	"github.com/golang-jwt/jwt/v5"
)

// publicKeyFromJWKS builds a verification key from a JWKS entry with the standard library only, the way
// an external verifier would (independently of the plugin's own parsing).
func publicKeyFromJWKS(t *testing.T, k models.JWKKey) any {
	t.Helper()
	dec := func(v string) []byte {
		b, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			t.Fatalf("decode jwk member: %v", err)
		}
		return b
	}
	switch k.Kty {
	case "OKP":
		return ed25519.PublicKey(dec(k.X))
	case "EC":
		curve := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-521": elliptic.P521()}[k.Crv]
		if curve == nil {
			t.Fatalf("unexpected curve %q", k.Crv)
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, append(append([]byte{4}, dec(k.X)...), dec(k.Y)...))
		if err != nil {
			t.Fatalf("ec public key: %v", err)
		}
		return pub
	case "RSA":
		return &rsa.PublicKey{N: new(big.Int).SetBytes(dec(k.N)), E: int(new(big.Int).SetBytes(dec(k.E)).Int64())}
	}
	t.Fatalf("unexpected kty %q", k.Kty)
	return nil
}

func TestJWTPlugin_Algorithms(t *testing.T) {
	cases := []struct {
		name    string
		kp      jwtconfig.KeyPairConfig
		kty     string
		crv     string
		alg     string
		rsaBits int
	}{
		{name: "default", kp: jwtconfig.KeyPairConfig{}, kty: "OKP", crv: "Ed25519", alg: "EdDSA"},
		{name: "EdDSA", kp: jwtconfig.KeyPairConfig{Alg: "EdDSA", Crv: "Ed25519"}, kty: "OKP", crv: "Ed25519", alg: "EdDSA"},
		{name: "ES256", kp: jwtconfig.KeyPairConfig{Alg: "ES256"}, kty: "EC", crv: "P-256", alg: "ES256"},
		{name: "ES512", kp: jwtconfig.KeyPairConfig{Alg: "ES512"}, kty: "EC", crv: "P-521", alg: "ES512"},
		{name: "PS256", kp: jwtconfig.KeyPairConfig{Alg: "PS256"}, kty: "RSA", alg: "PS256", rsaBits: 2048},
		{name: "RS256", kp: jwtconfig.KeyPairConfig{Alg: "RS256"}, kty: "RSA", alg: "RS256", rsaBits: 2048},
		{name: "RS256-3072", kp: jwtconfig.KeyPairConfig{Alg: "RS256", ModulusLength: 3072}, kty: "RSA", alg: "RS256", rsaBits: 3072},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Step 1: a server whose plugin generates keys of this algorithm
			cfg := jwtconfig.DefaultConfig()
			cfg.Jwks.KeyPairConfig = tc.kp
			ts, plug := setupFullServer(t, cfg)
			ctx := context.Background()

			// Step 2: sign from Go
			tok, err := plug.SignJWT(ctx, map[string]any{"sub": "user-1", "scope": "read"}, nil)
			if err != nil {
				t.Fatalf("SignJWT: %v", err)
			}

			// Step 3: the JWKS publishes the key with the expected members
			resp, err := http.Get(ts.URL + "/api/auth/jwks")
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			var set models.JWKSResponse
			if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
				t.Fatal(err)
			}
			if len(set.Keys) != 1 {
				t.Fatalf("expected 1 key, got %+v", set.Keys)
			}
			k := set.Keys[0]
			if k.Kty != tc.kty || k.Crv != tc.crv || k.Alg != tc.alg || k.Kid == "" {
				t.Fatalf("jwk = %+v, want kty %s crv %q alg %s", k, tc.kty, tc.crv, tc.alg)
			}
			switch tc.kty {
			case "OKP":
				if k.X == "" || k.Y != "" || k.N != "" {
					t.Fatalf("okp jwk members: %+v", k)
				}
			case "EC":
				if k.X == "" || k.Y == "" || k.N != "" {
					t.Fatalf("ec jwk members: %+v", k)
				}
			case "RSA":
				if k.N == "" || k.E != "AQAB" || k.X != "" {
					t.Fatalf("rsa jwk members: %+v", k)
				}
			}

			// Step 4: an external verifier checks the token with the JWKS key only
			pub := publicKeyFromJWKS(t, k)
			if tc.rsaBits != 0 && pub.(*rsa.PublicKey).N.BitLen() != tc.rsaBits {
				t.Fatalf("rsa modulus = %d bits, want %d", pub.(*rsa.PublicKey).N.BitLen(), tc.rsaBits)
			}
			parsed, err := jwt.Parse(tok, func(tk *jwt.Token) (any, error) {
				if tk.Header["kid"] != k.Kid {
					t.Errorf("kid header = %v, want %s", tk.Header["kid"], k.Kid)
				}
				return pub, nil
			}, jwt.WithValidMethods([]string{tc.alg}), jwt.WithIssuer("http://localhost:8080"), jwt.WithAudience("http://localhost:8080"), jwt.WithExpirationRequired())
			if err != nil {
				t.Fatalf("verify with jwks key: %v", err)
			}
			if claims := parsed.Claims.(jwt.MapClaims); claims["sub"] != "user-1" || claims["scope"] != "read" {
				t.Fatalf("claims = %v", claims)
			}

			// Step 5: the plugin verifies it too, and rejects a tampered signature
			if _, err := plug.VerifyJWT(ctx, tok, ""); err != nil {
				t.Fatalf("plugin VerifyJWT: %v", err)
			}
			parts := strings.Split(tok, ".")
			forged := parts[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin"}`)) + "." + parts[2]
			if _, err := plug.VerifyJWT(ctx, forged, ""); err == nil {
				t.Fatal("tampered token verified")
			}
		})
	}
}

func TestJWTService_PrivateKeysEncryptedForAllAlgs(t *testing.T) {
	for _, alg := range []string{"EdDSA", "ES256", "ES512", "PS256", "RS256"} {
		t.Run(alg, func(t *testing.T) {
			db := setupTestDB(t)
			cfg := jwtconfig.DefaultConfig()
			cfg.Jwks.KeyPairConfig = jwtconfig.KeyPairConfig{Alg: alg}
			svc := services.NewJWTService(cfg, testSecret, "http://localhost:8080", repository.NewGormJwksRepo(db))

			key, err := svc.CreateKey(context.Background())
			if err != nil {
				t.Fatalf("CreateKey: %v", err)
			}
			// the stored private key is the encrypted JWK (a JSON string), not the plain JWK
			if strings.Contains(key.PrivateKey, `"d"`) || !strings.HasPrefix(key.PrivateKey, `"`) {
				t.Fatalf("private key stored unencrypted: %s", key.PrivateKey)
			}
			if key.Alg != alg {
				t.Fatalf("stored alg = %q, want %q", key.Alg, alg)
			}
			if _, err := svc.SignJWT(context.Background(), map[string]any{"sub": "x"}, nil); err != nil {
				t.Fatalf("SignJWT: %v", err)
			}
		})
	}
}

func TestJWTPlugin_UnsupportedAlgRejectedAtInit(t *testing.T) {
	for _, kp := range []jwtconfig.KeyPairConfig{
		{Alg: "ECDH-ES"},
		{Alg: "HS256"},
		{Alg: "ES256", Crv: "Ed25519"},
		{Alg: "EdDSA", Crv: "Ed448"},
		{Alg: "RS256", ModulusLength: 1024},
	} {
		cfg := jwtconfig.DefaultConfig()
		cfg.Jwks.KeyPairConfig = kp
		err := jwtplugin.New(cfg).Init(&plugins.InitContext{})
		if err == nil || !strings.Contains(err.Error(), "keyPairConfig") {
			t.Fatalf("Init with %+v: err = %v, want a keyPairConfig error", kp, err)
		}
	}
}

func TestJWTService_LegacyEd25519KeyStillWorks(t *testing.T) {
	db := setupTestDB(t)
	repo := repository.NewGormJwksRepo(db)
	ctx := context.Background()
	svc := services.NewJWTService(jwtconfig.DefaultConfig(), testSecret, "http://localhost:8080", repo)

	// Step 1: a key stored before the alg / crv columns were filled in
	key, err := svc.CreateKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&models.JWK{}).Where("id = ?", key.ID).Updates(map[string]any{"alg": "", "crv": ""}).Error; err != nil {
		t.Fatal(err)
	}

	// Step 2: it is still the active key, signs EdDSA tokens and verifies them
	tok, err := svc.SignJWT(ctx, map[string]any{"sub": "legacy"}, nil)
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Header["kid"] != key.ID || parsed.Header["alg"] != "EdDSA" {
		t.Fatalf("header = %v, want kid %s alg EdDSA", parsed.Header, key.ID)
	}
	if _, err := svc.VerifyJWT(ctx, tok, ""); err != nil {
		t.Fatalf("VerifyJWT: %v", err)
	}

	// Step 3: the JWKS still describes it as EdDSA / Ed25519
	set, err := svc.GetJWKS(ctx)
	if err != nil || len(set) != 1 || set[0].Alg != "EdDSA" || set[0].Crv != "Ed25519" {
		t.Fatalf("jwks = %+v, err %v", set, err)
	}

	// Step 4: switching the algorithm creates a new key; old tokens keep verifying
	esCfg := jwtconfig.DefaultConfig()
	esCfg.Jwks.KeyPairConfig = jwtconfig.KeyPairConfig{Alg: "ES256"}
	esSvc := services.NewJWTService(esCfg, testSecret, "http://localhost:8080", repo)
	esTok, err := esSvc.SignJWT(ctx, map[string]any{"sub": "new"}, nil)
	if err != nil {
		t.Fatalf("ES256 SignJWT: %v", err)
	}
	esParsed, _, _ := jwt.NewParser().ParseUnverified(esTok, jwt.MapClaims{})
	if esParsed.Header["alg"] != "ES256" || esParsed.Header["kid"] == key.ID {
		t.Fatalf("ES256 header = %v", esParsed.Header)
	}
	for _, tk := range []string{tok, esTok} {
		if _, err := esSvc.VerifyJWT(ctx, tk, ""); err != nil {
			t.Fatalf("VerifyJWT after alg change: %v", err)
		}
	}
	if set, _ := esSvc.GetJWKS(ctx); len(set) != 2 {
		t.Fatalf("expected both keys in the JWKS, got %+v", set)
	}
}

func TestJWTService_AlgConfusionRejected(t *testing.T) {
	db := setupTestDB(t)
	cfg := jwtconfig.DefaultConfig()
	cfg.Jwks.KeyPairConfig = jwtconfig.KeyPairConfig{Alg: "RS256"}
	svc := services.NewJWTService(cfg, testSecret, "http://localhost:8080", repository.NewGormJwksRepo(db))
	ctx := context.Background()
	tok, err := svc.SignJWT(ctx, map[string]any{"sub": "x"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// re-label the RS256 token as PS256 / none: the key's algorithm is enforced
	parts := strings.Split(tok, ".")
	hdr, _ := base64.RawURLEncoding.DecodeString(parts[0])
	for _, alg := range []string{"PS256", "none"} {
		swapped := strings.Replace(string(hdr), `"RS256"`, `"`+alg+`"`, 1)
		forged := base64.RawURLEncoding.EncodeToString([]byte(swapped)) + "." + parts[1] + "." + parts[2]
		if _, err := svc.VerifyJWT(ctx, forged, ""); err == nil {
			t.Fatalf("token re-labelled %s verified", alg)
		}
	}
}

func TestJWTService_DefinePayloadNilMap(t *testing.T) {
	db := setupTestDB(t)
	cfg := jwtconfig.DefaultConfig()
	cfg.JWT.DefinePayload = func(any) (map[string]any, error) { return nil, nil }
	svc := services.NewJWTService(cfg, testSecret, "http://localhost:8080", repository.NewGormJwksRepo(db))
	ctx := context.Background()

	session := &dtos.SessionWithUser{}
	session.User.ID = "user-nil-payload"
	tok, err := svc.GetJWTToken(ctx, session)
	if err != nil {
		t.Fatalf("GetJWTToken: %v", err)
	}
	claims, err := svc.VerifyJWT(ctx, tok, "")
	if err != nil {
		t.Fatalf("VerifyJWT: %v", err)
	}
	if claims["sub"] != "user-nil-payload" {
		t.Fatalf("claims = %v", claims)
	}
}

func TestJWTService_SignJWTOptions(t *testing.T) {
	db := setupTestDB(t)
	svc := services.NewJWTService(jwtconfig.DefaultConfig(), testSecret, "http://localhost:8080", repository.NewGormJwksRepo(db))
	ctx := context.Background()

	// overrides apply to this token only; a nil payload is an empty one
	tok, err := svc.SignJWT(ctx, nil, &services.SignJWTOptions{Issuer: "https://issuer.example", Audience: "https://aud.example", ExpirationTime: time.Minute})
	if err != nil {
		t.Fatalf("SignJWT: %v", err)
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tok, claims); err != nil {
		t.Fatal(err)
	}
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if claims["iss"] != "https://issuer.example" || claims["aud"] != "https://aud.example" || exp-iat != 60 {
		t.Fatalf("claims = %v", claims)
	}
}
