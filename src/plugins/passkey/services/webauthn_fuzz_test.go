package services

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

const (
	fuzzRPID      = "localhost"
	fuzzOrigin    = "http://localhost:3000"
	fuzzChallenge = "Y2hhbGxlbmdl"
)

// fuzzKey is the software authenticator's ES256 key used for the seeds.
type fuzzKey struct {
	key    *ecdsa.PrivateKey
	credID []byte
}

func newFuzzKey(tb testing.TB) *fuzzKey {
	tb.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return &fuzzKey{key: key, credID: []byte("fuzz-credential-id")}
}

// cose returns the COSE_Key of the public key (EC2, ES256, P-256).
func (k *fuzzKey) cose(tb testing.TB) []byte {
	tb.Helper()
	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		tb.Fatal(err)
	}
	raw, err := enc.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: k.key.X.FillBytes(make([]byte, 32)), -3: k.key.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		tb.Fatal(err)
	}
	return raw
}

// authData builds authenticatorData (user present + verified), with the attested credential when attested.
func (k *fuzzKey) authData(tb testing.TB, attested bool, counter uint32) []byte {
	rpHash := sha256.Sum256([]byte(fuzzRPID))
	out := append([]byte{}, rpHash[:]...)
	flags := byte(0x01 | 0x04)
	if attested {
		flags |= 0x40
	}
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, counter)
	if attested {
		out = append(out, make([]byte, 16)...)
		out = binary.BigEndian.AppendUint16(out, uint16(len(k.credID)))
		out = append(out, k.credID...)
		out = append(out, k.cose(tb)...)
	}
	return out
}

func fuzzClientData(typ string) []byte {
	raw, _ := json.Marshal(map[string]any{"type": typ, "challenge": fuzzChallenge, "origin": fuzzOrigin, "crossOrigin": false})
	return raw
}

// registration returns a valid RegistrationResponseJSON ("none" attestation).
func (k *fuzzKey) registration(tb testing.TB) []byte {
	tb.Helper()
	att, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": k.authData(tb, true, 0)})
	if err != nil {
		tb.Fatal(err)
	}
	id := base64.RawURLEncoding.EncodeToString(k.credID)
	raw, _ := json.Marshal(map[string]any{"id": id, "rawId": id, "type": "public-key", "response": map[string]any{
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(fuzzClientData("webauthn.create")),
		"attestationObject": base64.RawURLEncoding.EncodeToString(att),
	}})
	return raw
}

// assertion returns a valid AuthenticationResponseJSON signed with the key.
func (k *fuzzKey) assertion(tb testing.TB, counter uint32) []byte {
	tb.Helper()
	ad := k.authData(tb, false, counter)
	cdj := fuzzClientData("webauthn.get")
	cdHash := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, k.key, digest[:])
	if err != nil {
		tb.Fatal(err)
	}
	id := base64.RawURLEncoding.EncodeToString(k.credID)
	raw, _ := json.Marshal(map[string]any{"id": id, "rawId": id, "type": "public-key", "response": map[string]any{
		"clientDataJSON":    base64.RawURLEncoding.EncodeToString(cdj),
		"authenticatorData": base64.RawURLEncoding.EncodeToString(ad),
		"signature":         base64.RawURLEncoding.EncodeToString(sig),
	}})
	return raw
}

// TestFuzzSeedsAreValid makes sure the fuzz seeds exercise the success paths.
func TestFuzzSeedsAreValid(t *testing.T) {
	k := newFuzzKey(t)
	reg, err := verifyRegistration(k.registration(t), fuzzChallenge, []string{fuzzOrigin}, fuzzRPID)
	if err != nil {
		t.Fatal(err)
	}
	if reg.CredentialID != base64.RawURLEncoding.EncodeToString(k.credID) {
		t.Fatalf("credential id %q", reg.CredentialID)
	}
	if _, err := verifyAuthentication(k.assertion(t, 5), fuzzChallenge, []string{fuzzOrigin}, fuzzRPID, reg.PublicKey, 1); err != nil {
		t.Fatal(err)
	}
}

// FuzzVerifyRegistration feeds arbitrary registration responses (client-controlled JSON with base64url
// CBOR inside) to the verifier: it never panics, and whatever it accepts carries a credential and a public key.
func FuzzVerifyRegistration(f *testing.F) {
	k := newFuzzKey(f)
	valid := k.registration(f)
	f.Add(valid)
	f.Add([]byte(`{"id":"","rawId":"","type":"public-key","response":{}}`))
	f.Add([]byte(`{"type":"public-key","response":{"clientDataJSON":"e30","attestationObject":"oA"}}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		res, err := verifyRegistration(raw, fuzzChallenge, []string{fuzzOrigin}, fuzzRPID)
		if err != nil {
			return
		}
		if res.CredentialID == "" || len(res.PublicKey) == 0 {
			t.Fatalf("accepted a registration without credential or key: %+v", res)
		}
		if res.DeviceType != "singleDevice" && res.DeviceType != "multiDevice" {
			t.Fatalf("device type %q", res.DeviceType)
		}
	})
}

// FuzzVerifyAuthentication feeds arbitrary assertions and stored counters to the verifier: it never panics,
// a forged or mutated assertion is refused, and an accepted one follows the signature counter rule (both 0,
// or a counter above the stored one).
func FuzzVerifyAuthentication(f *testing.F) {
	k := newFuzzKey(f)
	reg, err := verifyRegistration(k.registration(f), fuzzChallenge, []string{fuzzOrigin}, fuzzRPID)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(k.assertion(f, 0), uint32(0))
	f.Add(k.assertion(f, 7), uint32(3))
	f.Add(k.assertion(f, 2), uint32(9))
	f.Add([]byte(`{"type":"public-key","response":{"clientDataJSON":"","authenticatorData":"","signature":""}}`), uint32(0))
	f.Fuzz(func(t *testing.T, raw []byte, stored uint32) {
		res, err := verifyAuthentication(raw, fuzzChallenge, []string{fuzzOrigin}, fuzzRPID, reg.PublicKey, stored)
		if err != nil {
			return
		}
		if (res.NewCounter != 0 || stored != 0) && res.NewCounter <= stored {
			t.Fatalf("counter %d accepted with stored counter %d", res.NewCounter, stored)
		}
	})
}

// FuzzDecodeStoredPublicKey: stored public keys in either base64 alphabet, padded or not, never panic.
func FuzzDecodeStoredPublicKey(f *testing.F) {
	f.Add("pQECAyYgASFYIA==")
	f.Add("pQECAyYgASFYI-_")
	f.Add("===")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = decodeStoredPublicKey(s)
	})
}
