package eip4361

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// Keccak256 is Ethereum's Keccak-256 (the original Keccak padding, not FIPS-202 SHA3-256).
func Keccak256(data ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// HashPersonalMessage is the EIP-191 version 0x45 hash personal_sign signs:
// keccak256("\x19Ethereum Signed Message:\n" + len(message) + message).
func HashPersonalMessage(message []byte) []byte {
	prefix := "\x19Ethereum Signed Message:\n" + strconv.Itoa(len(message))
	return Keccak256([]byte(prefix), message)
}

// ChecksumAddress is EIP-55 (better-auth's toChecksumAddress): the address in lower case, with every hex
// letter upper-cased where the matching nibble of keccak256(lower-case address) is ≥ 8.
func ChecksumAddress(address string) string {
	lower := strings.ToLower(strings.TrimPrefix(strings.TrimPrefix(address, "0x"), "0X"))
	hash := hex.EncodeToString(Keccak256([]byte(lower)))
	out := []byte("0x" + lower)
	for i := 0; i < len(lower) && i < len(hash); i++ {
		if hash[i] >= '8' && lower[i] >= 'a' && lower[i] <= 'f' {
			out[i+2] = lower[i] - 'a' + 'A'
		}
	}
	return string(out)
}

// IsAddress reports whether s is 0x followed by 40 hex digits (any case).
func IsAddress(s string) bool { return addressRegex.MatchString(s) }

// PublicKeyToAddress returns the EIP-55 address of a public key: the last 20 bytes of the Keccak-256 hash
// of the uncompressed X||Y coordinates.
func PublicKeyToAddress(pub *secp256k1.PublicKey) string {
	raw := pub.SerializeUncompressed() // 0x04 || X || Y
	return ChecksumAddress(hex.EncodeToString(Keccak256(raw[1:])[12:]))
}

// ErrInvalidSignature is returned for signatures that cannot be decoded or recovered.
var ErrInvalidSignature = errors.New("eip4361: invalid signature")

// decodeSignature decodes a 0x-prefixed signature: 65 bytes r || s || v (v = 27/28 or 0/1) or a 64-byte
// EIP-2098 compact signature r || yParityAndS. It returns decred's compact form [27+recid] || r || s.
func decodeSignature(signature string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(signature, "0x"), "0X"))
	if err != nil {
		return nil, ErrInvalidSignature
	}
	out := make([]byte, 65)
	switch len(raw) {
	case 65:
		v := raw[64]
		if v >= 27 {
			v -= 27
		}
		if v > 1 {
			return nil, ErrInvalidSignature
		}
		out[0] = 27 + v
		copy(out[1:], raw[:64])
	case 64:
		// EIP-2098: the top bit of s is the y parity
		out[0] = 27 + raw[32]>>7
		copy(out[1:], raw[:64])
		out[33] &= 0x7f
	default:
		return nil, ErrInvalidSignature
	}
	return out, nil
}

// RecoverAddress returns the EIP-55 address that personal_sign-ed message with signature.
func RecoverAddress(message []byte, signature string) (string, error) {
	compact, err := decodeSignature(signature)
	if err != nil {
		return "", err
	}
	pub, _, err := ecdsa.RecoverCompact(compact, HashPersonalMessage(message))
	if err != nil {
		return "", ErrInvalidSignature
	}
	return PublicKeyToAddress(pub), nil
}

// SignPersonalMessage signs message like personal_sign / eth_sign: an EIP-191 hash signed with a low-s
// deterministic (RFC 6979) signature, returned as 0x-prefixed hex r || s || v with v = 27 or 28. It is
// meant for tests, examples and server-side wallets.
func SignPersonalMessage(key *secp256k1.PrivateKey, message []byte) string {
	compact := ecdsa.SignCompact(key, HashPersonalMessage(message), false) // [27+recid] || r || s
	out := make([]byte, 65)
	copy(out, compact[1:])
	out[64] = compact[0]
	return "0x" + hex.EncodeToString(out)
}
