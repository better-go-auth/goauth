package test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

var b64url = base64.RawURLEncoding

// Authenticator flag bits.
const (
	flagUP = 0x01
	flagUV = 0x04
	flagBE = 0x08
	flagBS = 0x10
	flagAT = 0x40
)

// softAuthenticator is a software WebAuthn authenticator: ES256 key, "none" attestation.
type softAuthenticator struct {
	key     *ecdsa.PrivateKey
	credID  []byte
	counter uint32
	aaguid  [16]byte
	// flags are the UP/UV/BE/BS bits put in every authenticatorData.
	flags byte
	// rpID and origin are what the authenticator/client claims (override to forge responses).
	rpID   string
	origin string
	// counterStep is added to counter before each assertion (0 keeps a zero counter).
	counterStep uint32
}

func newSoftAuthenticator(t testing.TB, rpID, origin string) *softAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	a := &softAuthenticator{key: key, credID: id, flags: flagUP | flagUV, rpID: rpID, origin: origin}
	copy(a.aaguid[:], []byte{0xad, 0xce, 0x00, 0x02, 0x35, 0xbc, 0xc6, 0x0a, 0x64, 0x8b, 0x0b, 0x25, 0xf1, 0xf0, 0x55, 0x03})
	return a
}

// credentialID returns the base64url credential ID.
func (a *softAuthenticator) credentialID() string { return b64url.EncodeToString(a.credID) }

// coseKey returns the COSE_Key encoding of the public key (EC2, ES256, P-256).
func (a *softAuthenticator) coseKey(t testing.TB) []byte {
	t.Helper()
	x := a.key.X.FillBytes(make([]byte, 32))
	y := a.key.Y.FillBytes(make([]byte, 32))
	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := enc.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: x, -3: y})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// authData builds authenticatorData; withCredential adds the attested credential data.
func (a *softAuthenticator) authData(t testing.TB, withCredential bool) []byte {
	t.Helper()
	rpHash := sha256.Sum256([]byte(a.rpID))
	out := append([]byte{}, rpHash[:]...)
	flags := a.flags
	if withCredential {
		flags |= flagAT
	}
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, a.counter)
	if withCredential {
		out = append(out, a.aaguid[:]...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.credID)))
		out = append(out, a.credID...)
		out = append(out, a.coseKey(t)...)
	}
	return out
}

func clientData(typ, challenge, origin string) []byte {
	raw, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": false})
	return raw
}

// register answers registration options with a RegistrationResponseJSON (what startRegistration returns).
func (a *softAuthenticator) register(t testing.TB, challenge string) map[string]any {
	t.Helper()
	att, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(t, true)})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"id":    a.credentialID(),
		"rawId": a.credentialID(),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64url.EncodeToString(clientData("webauthn.create", challenge, a.origin)),
			"attestationObject": b64url.EncodeToString(att),
			"transports":        []string{"internal", "hybrid"},
		},
		"authenticatorAttachment": "platform",
	}
}

// assert answers authentication options with an AuthenticationResponseJSON (what startAuthentication returns).
func (a *softAuthenticator) assert(t testing.TB, challenge string) map[string]any {
	t.Helper()
	a.counter += a.counterStep
	ad := a.authData(t, false)
	cdj := clientData("webauthn.get", challenge, a.origin)
	cdHash := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"id":    a.credentialID(),
		"rawId": a.credentialID(),
		"type":  "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64url.EncodeToString(cdj),
			"authenticatorData": b64url.EncodeToString(ad),
			"signature":         b64url.EncodeToString(sig),
			"userHandle":        b64url.EncodeToString([]byte("user-handle")),
		},
		"authenticatorAttachment": "platform",
	}
}
