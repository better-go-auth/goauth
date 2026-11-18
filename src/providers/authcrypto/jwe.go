package authcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
)

// JWE salts better-auth uses with symmetricEncodeJWT.
const (
	// JWESaltSession encrypts the session_data cookie cache (strategy "jwe").
	JWESaltSession = "better-auth-session"
	// JWESaltAccount encrypts the account_data cookie (account.storeAccountCookie).
	JWESaltAccount = "better-auth-account"
)

// jweInfo is the HKDF info better-auth (and Auth.js) use to derive JWE keys.
const jweInfo = "BetterAuth.js Generated Encryption Key"

// jweClockTolerance is jose's clockTolerance in better-auth's jwtDecrypt options.
const jweClockTolerance = 15 * time.Second

var errInvalidJWE = errors.New("authcrypto: invalid jwe")

// jweHeader is the protected header of better-auth's encrypted JWTs.
type jweHeader struct {
	Alg string `json:"alg"`
	Enc string `json:"enc"`
	Kid string `json:"kid,omitempty"`
}

// deriveJWEKey is better-auth's deriveEncryptionSecret: HKDF-SHA256(secret, salt, info) → 64 bytes, the
// A256CBC-HS512 content key (MAC key = first 32 bytes, AES key = last 32 bytes).
func deriveJWEKey(secret, salt string) ([]byte, error) {
	key := make([]byte, 64)
	if _, err := io.ReadFull(hkdf.New(sha256.New, []byte(secret), []byte(salt), []byte(jweInfo)), key); err != nil {
		return nil, err
	}
	return key, nil
}

// jwkThumbprint is jose's calculateJwkThumbprint({kty: "oct", k}) with SHA-256 (RFC 7638), used as `kid`.
func jwkThumbprint(key []byte) string {
	canonical := `{"k":"` + base64.RawURLEncoding.EncodeToString(key) + `","kty":"oct"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// EncodeJWE is better-auth's symmetricEncodeJWT: payload (a JSON object) plus iat, exp and jti claims,
// encrypted with the current secret as a compact JWE ({"alg":"dir","enc":"A256CBC-HS512","kid":...}).
func (k SecretKeys) EncodeJWE(payload any, salt string, expiresIn time.Duration) (string, error) {
	// Step 1: the claims: the payload object followed by iat, exp and jti (jose's EncryptJWT)
	body, err := marshalNoEscape(payload)
	if err != nil {
		return "", err
	}
	body = bytes.TrimSpace(body)
	if len(body) < 2 || body[0] != '{' || body[len(body)-1] != '}' {
		return "", errors.New("authcrypto: jwe payload must be a JSON object")
	}
	now := time.Now().Unix()
	extra := `"iat":` + strconv.FormatInt(now, 10) + `,"exp":` + strconv.FormatInt(now+int64(expiresIn/time.Second), 10) +
		`,"jti":"` + uuid.NewString() + `"}`
	if len(body) > 2 {
		extra = "," + extra
	}
	claims := append(append([]byte{}, body[:len(body)-1]...), extra...)

	// Step 2: derive the content key from the current secret
	secret := k.CurrentSecret()
	if secret == "" {
		return "", errors.New("authcrypto: no secret configured")
	}
	key, err := deriveJWEKey(secret, salt)
	if err != nil {
		return "", err
	}

	// Step 3: protected header with the key thumbprint as kid
	hdr, err := json.Marshal(jweHeader{Alg: "dir", Enc: "A256CBC-HS512", Kid: jwkThumbprint(key)})
	if err != nil {
		return "", err
	}
	protected := base64.RawURLEncoding.EncodeToString(hdr)

	// Step 4: A256CBC-HS512 encryption with a random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key[32:])
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad(claims, aes.BlockSize)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	tag := cbcHS512Tag(key[:32], []byte(protected), iv, ct)

	// Step 5: compact serialization header..iv.ciphertext.tag (no encrypted key with "dir")
	return protected + ".." + base64.RawURLEncoding.EncodeToString(iv) + "." +
		base64.RawURLEncoding.EncodeToString(ct) + "." + base64.RawURLEncoding.EncodeToString(tag), nil
}

// DecodeJWE is better-auth's symmetricDecodeJWT: it decrypts a JWE written by EncodeJWE (or by a TypeScript
// better-auth server with the same secrets) and returns its claims as JSON. With a `kid` the secret whose
// derived key matches is used (any version, then the legacy secret); without one every secret is tried.
// Expired tokens (exp more than 15 s in the past) fail.
func (k SecretKeys) DecodeJWE(token, salt string) (json.RawMessage, error) {
	// Step 1: split the compact serialization and read the protected header
	parts := strings.Split(token, ".")
	if len(parts) != 5 || parts[1] != "" {
		return nil, errInvalidJWE
	}
	rawHdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errInvalidJWE
	}
	var hdr jweHeader
	if err := json.Unmarshal(rawHdr, &hdr); err != nil || hdr.Alg != "dir" || hdr.Enc != "A256CBC-HS512" {
		return nil, errInvalidJWE
	}
	iv, err1 := base64.RawURLEncoding.DecodeString(parts[2])
	ct, err2 := base64.RawURLEncoding.DecodeString(parts[3])
	tag, err3 := base64.RawURLEncoding.DecodeString(parts[4])
	if err1 != nil || err2 != nil || err3 != nil || len(iv) != aes.BlockSize || len(ct) == 0 || len(ct)%aes.BlockSize != 0 || len(tag) != 32 {
		return nil, errInvalidJWE
	}

	// Step 2: candidate keys: the kid match only, or every secret when the token has no kid
	var candidates [][]byte
	for _, secret := range k.VerifySecrets() {
		key, err := deriveJWEKey(secret, salt)
		if err != nil {
			return nil, err
		}
		if hdr.Kid != "" {
			if jwkThumbprint(key) == hdr.Kid {
				candidates = [][]byte{key}
				break
			}
			continue
		}
		candidates = append(candidates, key)
	}
	if len(candidates) == 0 {
		return nil, errors.New("authcrypto: no matching decryption secret")
	}

	// Step 3: authenticate and decrypt with the first key whose tag matches
	for _, key := range candidates {
		if subtle.ConstantTimeCompare(tag, cbcHS512Tag(key[:32], []byte(parts[0]), iv, ct)) != 1 {
			continue
		}
		block, err := aes.NewCipher(key[32:])
		if err != nil {
			return nil, err
		}
		padded := make([]byte, len(ct))
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(padded, ct)
		claims, err := pkcs7Unpad(padded, aes.BlockSize)
		if err != nil {
			return nil, errInvalidJWE
		}
		// Step 4: jose's claim checks: a JSON object whose exp (if any) has not passed
		var std struct {
			Exp *float64 `json:"exp"`
		}
		if err := json.Unmarshal(claims, &std); err != nil {
			return nil, errInvalidJWE
		}
		if std.Exp != nil && time.Unix(int64(*std.Exp), 0).Add(jweClockTolerance).Before(time.Now()) {
			return nil, errors.New("authcrypto: jwe expired")
		}
		return claims, nil
	}
	return nil, errInvalidJWE
}

// cbcHS512Tag is the A256CBC-HS512 authentication tag (RFC 7518 §5.2.2.1): HMAC-SHA-512 over
// AAD || IV || ciphertext || AL, truncated to 32 bytes.
func cbcHS512Tag(macKey, aad, iv, ct []byte) []byte {
	al := make([]byte, 8)
	binary.BigEndian.PutUint64(al, uint64(len(aad))*8)
	mac := hmac.New(sha512.New, macKey)
	mac.Write(aad)
	mac.Write(iv)
	mac.Write(ct)
	mac.Write(al)
	return mac.Sum(nil)[:32]
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	n := blockSize - len(data)%blockSize
	return append(append([]byte{}, data...), bytes.Repeat([]byte{byte(n)}, n)...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("pkcs7: invalid length")
	}
	n := int(data[len(data)-1])
	if n == 0 || n > blockSize {
		return nil, errors.New("pkcs7: invalid padding")
	}
	for _, b := range data[len(data)-n:] {
		if int(b) != n {
			return nil, errors.New("pkcs7: invalid padding")
		}
	}
	return data[:len(data)-n], nil
}

// marshalNoEscape is json.Marshal without HTML escaping, so the bytes equal JavaScript's JSON.stringify for
// strings containing <, > or & (needed when a signature covers the JSON text).
func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, fmt.Errorf("authcrypto: marshal: %w", err)
	}
	// nested MarshalJSON methods use json.Marshal, which escapes HTML anyway: undo it
	return unescapeJSHTML(bytes.TrimRight(buf.Bytes(), "\n")), nil
}

// jsUnescaped are the escapes Go's encoder writes that JSON.stringify does not.
var jsUnescaped = map[string]string{"u003c": "<", "u003e": ">", "u0026": "&", "u2028": string(rune(0x2028)), "u2029": string(rune(0x2029))}

// unescapeJSHTML turns the HTML and line-separator escapes Go writes (backslash-u003c, -u003e, -u0026, -u2028, -u2029)
// back into the characters, leaving every other escape (including an escaped backslash followed by "u003c") untouched.
func unescapeJSHTML(b []byte) []byte {
	if !bytes.Contains(b, []byte(`\u`)) {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' || i+1 >= len(b) {
			out = append(out, b[i])
			continue
		}
		if b[i+1] == 'u' && i+6 <= len(b) {
			if ch, ok := jsUnescaped[string(b[i+1:i+6])]; ok {
				out = append(out, ch...)
				i += 5
				continue
			}
		}
		// any other escape pair is copied as is
		out = append(out, b[i], b[i+1])
		i++
	}
	return out
}

// MarshalJSON marshals v like JavaScript's JSON.stringify would (no HTML escaping, no trailing newline).
func MarshalJSON(v any) ([]byte, error) { return marshalNoEscape(v) }
