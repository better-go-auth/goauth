package authcrypto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
)

// envelopePrefix marks better-auth's versioned (secret rotation) ciphertexts: "$ba$<version>$<hex>".
const envelopePrefix = "$ba$"

// SymmetricEncrypt encrypts data like better-auth's symmetricEncrypt with a string key:
// XChaCha20-Poly1305, key = SHA-256(secret), random nonce prepended, hex encoded.
func SymmetricEncrypt(secret, data string) (string, error) {
	aead, err := newAEAD(secret)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(data)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return hex.EncodeToString(aead.Seal(nonce, nonce, []byte(data), nil)), nil
}

// SymmetricDecrypt reverses SymmetricEncrypt.
func SymmetricDecrypt(secret, hexData string) (string, error) {
	aead, err := newAEAD(secret)
	if err != nil {
		return "", err
	}
	raw, err := hex.DecodeString(hexData)
	if err != nil {
		return "", fmt.Errorf("authcrypto: decode ciphertext: %w", err)
	}
	if len(raw) < aead.NonceSize()+aead.Overhead() {
		return "", errors.New("authcrypto: ciphertext too short")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], nil)
	if err != nil {
		return "", fmt.Errorf("authcrypto: decrypt: %w", err)
	}
	return string(plain), nil
}

func parseEnvelope(data string) (int, string, bool) {
	rest, ok := strings.CutPrefix(data, envelopePrefix)
	if !ok {
		return 0, "", false
	}
	v, ct, ok := strings.Cut(rest, "$")
	if !ok {
		return 0, "", false
	}
	version, err := strconv.Atoi(v)
	if err != nil || version < 0 {
		return 0, "", false
	}
	return version, ct, true
}

func newAEAD(secret string) (cipher.AEAD, error) {
	key := sha256.Sum256([]byte(secret))
	return chacha20poly1305.NewX(key[:])
}
