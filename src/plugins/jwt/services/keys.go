package services

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	jwtconfig "github.com/better-go-auth/goauth/src/plugins/jwt/config"
	"github.com/better-go-auth/goauth/src/plugins/jwt/models"
	"github.com/golang-jwt/jwt/v5"
)

// b64 is the JWK encoding of binary values (base64url, no padding).
var b64 = base64.RawURLEncoding

// generateKeyPair creates a key pair for kp (already normalized) and returns its public and private JWKs,
// in the shape jose's exportJWK produces (what better-auth stores in the jwks table).
func generateKeyPair(kp jwtconfig.KeyPairConfig) (pubJWK, privJWK map[string]any, err error) {
	switch kp.Alg {
	case jwtconfig.AlgEdDSA:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("jwt: generate ed25519 key: %w", err)
		}
		x := b64.EncodeToString(pub)
		pubJWK = map[string]any{"kty": "OKP", "crv": jwtconfig.CrvEd25519, "x": x}
		privJWK = map[string]any{"kty": "OKP", "crv": jwtconfig.CrvEd25519, "x": x, "d": b64.EncodeToString(priv.Seed())}
		return pubJWK, privJWK, nil

	case jwtconfig.AlgES256, jwtconfig.AlgES512:
		curve, err := ecCurve(kp.Crv)
		if err != nil {
			return nil, nil, err
		}
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("jwt: generate ecdsa key: %w", err)
		}
		// PublicKey.Bytes is the uncompressed point 0x04 || X || Y, each coordinate fixed-length
		point, err := priv.PublicKey.Bytes()
		if err != nil {
			return nil, nil, fmt.Errorf("jwt: encode ecdsa public key: %w", err)
		}
		d, err := priv.Bytes()
		if err != nil {
			return nil, nil, fmt.Errorf("jwt: encode ecdsa private key: %w", err)
		}
		size := (len(point) - 1) / 2
		x, y := b64.EncodeToString(point[1:1+size]), b64.EncodeToString(point[1+size:])
		pubJWK = map[string]any{"kty": "EC", "crv": kp.Crv, "x": x, "y": y}
		privJWK = map[string]any{"kty": "EC", "crv": kp.Crv, "x": x, "y": y, "d": b64.EncodeToString(d)}
		return pubJWK, privJWK, nil

	case jwtconfig.AlgPS256, jwtconfig.AlgRS256:
		priv, err := rsa.GenerateKey(rand.Reader, kp.ModulusLength)
		if err != nil {
			return nil, nil, fmt.Errorf("jwt: generate rsa key: %w", err)
		}
		n, e := b64.EncodeToString(priv.N.Bytes()), b64.EncodeToString(big.NewInt(int64(priv.E)).Bytes())
		pubJWK = map[string]any{"kty": "RSA", "n": n, "e": e}
		privJWK = map[string]any{
			"kty": "RSA", "n": n, "e": e,
			"d":  b64.EncodeToString(priv.D.Bytes()),
			"p":  b64.EncodeToString(priv.Primes[0].Bytes()),
			"q":  b64.EncodeToString(priv.Primes[1].Bytes()),
			"dp": b64.EncodeToString(priv.Precomputed.Dp.Bytes()),
			"dq": b64.EncodeToString(priv.Precomputed.Dq.Bytes()),
			"qi": b64.EncodeToString(priv.Precomputed.Qinv.Bytes()),
		}
		return pubJWK, privJWK, nil
	}
	return nil, nil, fmt.Errorf("jwt: unsupported key algorithm %q", kp.Alg)
}

// ecCurve maps a JWK curve name to its elliptic curve.
func ecCurve(crv string) (elliptic.Curve, error) {
	switch crv {
	case jwtconfig.CrvP256:
		return elliptic.P256(), nil
	case jwtconfig.CrvP521:
		return elliptic.P521(), nil
	}
	return nil, fmt.Errorf("jwt: unsupported ec curve %q", crv)
}

// rawJWK holds the members of a stored JWK (public or private) that the supported key types use.
type rawJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
	N   string `json:"n"`
	E   string `json:"e"`
	P   string `json:"p"`
	Q   string `json:"q"`
}

// decodeB64 decodes one base64url JWK member, naming it in the error.
func decodeB64(name, v string) ([]byte, error) {
	if v == "" {
		return nil, fmt.Errorf("jwt: jwk missing %q", name)
	}
	b, err := b64.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("jwt: decode jwk %q: %w", name, err)
	}
	return b, nil
}

// keyAlg returns the signing algorithm of a stored key. Rows written before the alg column existed (or
// by better-auth without it) fall back to the key type: OKP → EdDSA, EC → ES256 / ES512 by curve, and
// RSA → the configured RSA algorithm (RS256 when the configuration is not RSA).
func keyAlg(k *models.JWK, configured string) string {
	if k.Alg != "" {
		return k.Alg
	}
	var j rawJWK
	_ = json.Unmarshal([]byte(k.PublicKey), &j)
	switch j.Kty {
	case "EC":
		if j.Crv == jwtconfig.CrvP521 {
			return jwtconfig.AlgES512
		}
		return jwtconfig.AlgES256
	case "RSA":
		if configured == jwtconfig.AlgPS256 {
			return jwtconfig.AlgPS256
		}
		return jwtconfig.AlgRS256
	}
	return jwtconfig.AlgEdDSA
}

// signingMethod returns the golang-jwt signing method for alg.
func signingMethod(alg string) (jwt.SigningMethod, error) {
	switch alg {
	case jwtconfig.AlgEdDSA:
		return jwt.SigningMethodEdDSA, nil
	case jwtconfig.AlgES256:
		return jwt.SigningMethodES256, nil
	case jwtconfig.AlgES512:
		return jwt.SigningMethodES512, nil
	case jwtconfig.AlgPS256:
		return jwt.SigningMethodPS256, nil
	case jwtconfig.AlgRS256:
		return jwt.SigningMethodRS256, nil
	}
	return nil, fmt.Errorf("jwt: unsupported signing algorithm %q", alg)
}

// parsePrivateJWK turns a decrypted private JWK into the key golang-jwt signs with
// (ed25519.PrivateKey, *ecdsa.PrivateKey or *rsa.PrivateKey).
func parsePrivateJWK(data string) (crypto.Signer, error) {
	var j rawJWK
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		return nil, fmt.Errorf("jwt: parse private key jwk: %w", err)
	}
	switch j.Kty {
	case "OKP", "":
		// Step 1 (OKP): the private key is the 32-byte Ed25519 seed in "d"
		if j.Crv != "" && j.Crv != jwtconfig.CrvEd25519 {
			return nil, fmt.Errorf("jwt: unsupported okp curve %q", j.Crv)
		}
		seed, err := decodeB64("d", j.D)
		if err != nil {
			return nil, err
		}
		if len(seed) != ed25519.SeedSize {
			return nil, errors.New("jwt: invalid ed25519 private key seed")
		}
		return ed25519.NewKeyFromSeed(seed), nil

	case "EC":
		// Step 1 (EC): "d" is the fixed-length big-endian scalar of the curve
		curve, err := ecCurve(j.Crv)
		if err != nil {
			return nil, err
		}
		d, err := decodeB64("d", j.D)
		if err != nil {
			return nil, err
		}
		priv, err := ecdsa.ParseRawPrivateKey(curve, d)
		if err != nil {
			return nil, fmt.Errorf("jwt: parse ecdsa private key: %w", err)
		}
		return priv, nil

	case "RSA":
		// Step 1 (RSA): rebuild the key from n, e, d and the two primes, then precompute the CRT values
		var ints [5]*big.Int
		for i, m := range []struct{ name, v string }{{"n", j.N}, {"e", j.E}, {"d", j.D}, {"p", j.P}, {"q", j.Q}} {
			b, err := decodeB64(m.name, m.v)
			if err != nil {
				return nil, err
			}
			ints[i] = new(big.Int).SetBytes(b)
		}
		if !ints[1].IsInt64() {
			return nil, errors.New("jwt: rsa public exponent too large")
		}
		priv := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: ints[0], E: int(ints[1].Int64())},
			D:         ints[2],
			Primes:    []*big.Int{ints[3], ints[4]},
		}
		if err := priv.Validate(); err != nil {
			return nil, fmt.Errorf("jwt: invalid rsa private key: %w", err)
		}
		priv.Precompute()
		return priv, nil
	}
	return nil, fmt.Errorf("jwt: unsupported private key type %q", j.Kty)
}

// parsePublicJWK turns a stored public JWK into the key golang-jwt verifies with
// (ed25519.PublicKey, *ecdsa.PublicKey or *rsa.PublicKey).
func parsePublicJWK(data string) (crypto.PublicKey, error) {
	var j rawJWK
	if err := json.Unmarshal([]byte(data), &j); err != nil {
		return nil, fmt.Errorf("jwt: parse public jwk: %w", err)
	}
	switch j.Kty {
	case "OKP", "":
		if j.Crv != "" && j.Crv != jwtconfig.CrvEd25519 {
			return nil, fmt.Errorf("jwt: unsupported okp curve %q", j.Crv)
		}
		x, err := decodeB64("x", j.X)
		if err != nil {
			return nil, err
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, errors.New("jwt: invalid ed25519 public key")
		}
		return ed25519.PublicKey(x), nil

	case "EC":
		curve, err := ecCurve(j.Crv)
		if err != nil {
			return nil, err
		}
		x, err := decodeB64("x", j.X)
		if err != nil {
			return nil, err
		}
		y, err := decodeB64("y", j.Y)
		if err != nil {
			return nil, err
		}
		// ParseUncompressedPublicKey also checks that the point is on the curve
		point := append(append([]byte{4}, x...), y...)
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, fmt.Errorf("jwt: parse ecdsa public key: %w", err)
		}
		return pub, nil

	case "RSA":
		n, err := decodeB64("n", j.N)
		if err != nil {
			return nil, err
		}
		e, err := decodeB64("e", j.E)
		if err != nil {
			return nil, err
		}
		eInt := new(big.Int).SetBytes(e)
		if !eInt.IsInt64() {
			return nil, errors.New("jwt: rsa public exponent too large")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(eInt.Int64())}, nil
	}
	return nil, fmt.Errorf("jwt: unsupported public key type %q", j.Kty)
}
