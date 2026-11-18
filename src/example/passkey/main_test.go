package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	"github.com/fxamacker/cbor/v2"
)

// ─── software authenticator ──────────────────────────────────────────────────
// In a browser, @simplewebauthn/browser's startRegistration / startAuthentication (or the better-auth
// passkeyClient) talk to the real authenticator. The tests use this small software authenticator
// instead: an ES256 key with "none" attestation that produces the same JSON the browser would post.

var b64url = base64.RawURLEncoding

// softAuthenticator holds one passkey (credential) bound to rpID, used from origin.
type softAuthenticator struct {
	key     *ecdsa.PrivateKey
	credID  []byte
	counter uint32
	rpID    string
	origin  string
}

func newSoftAuthenticator(t *testing.T, rpID, origin string) *softAuthenticator {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	return &softAuthenticator{key: key, credID: id, rpID: rpID, origin: origin}
}

func (a *softAuthenticator) credentialID() string { return b64url.EncodeToString(a.credID) }

// authData builds authenticatorData (rpIdHash, flags UP|UV, counter, and on registration the credential).
func (a *softAuthenticator) authData(t *testing.T, withCredential bool) []byte {
	t.Helper()
	// Step 1: rpIdHash, flags (user present + user verified, attested credential on registration), counter
	rpHash := sha256.Sum256([]byte(a.rpID))
	out := append([]byte{}, rpHash[:]...)
	flags := byte(0x01 | 0x04)
	if withCredential {
		flags |= 0x40
	}
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, a.counter)
	if !withCredential {
		return out
	}
	// Step 2: attested credential data: AAGUID (zeros), credential ID and the COSE public key
	out = append(out, make([]byte, 16)...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(a.credID)))
	out = append(out, a.credID...)
	enc, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		t.Fatal(err)
	}
	cose, err := enc.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: a.key.X.FillBytes(make([]byte, 32)), -3: a.key.Y.FillBytes(make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	return append(out, cose...)
}

func (a *softAuthenticator) clientData(typ, challenge string) []byte {
	raw, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
	return raw
}

// register answers registration options like startRegistration (RegistrationResponseJSON).
func (a *softAuthenticator) register(t *testing.T, challenge string) map[string]any {
	t.Helper()
	att, err := cbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": a.authData(t, true)})
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{
		"id": a.credentialID(), "rawId": a.credentialID(), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64url.EncodeToString(a.clientData("webauthn.create", challenge)),
			"attestationObject": b64url.EncodeToString(att),
			"transports":        []string{"internal"},
		},
		"authenticatorAttachment": "platform",
	}
}

// assert answers authentication options like startAuthentication (AuthenticationResponseJSON).
func (a *softAuthenticator) assert(t *testing.T, challenge string) map[string]any {
	t.Helper()
	// Step 1: bump the signature counter and sign authenticatorData || sha256(clientDataJSON)
	a.counter++
	ad := a.authData(t, false)
	cdj := a.clientData("webauthn.get", challenge)
	cdHash := sha256.Sum256(cdj)
	digest := sha256.Sum256(append(append([]byte{}, ad...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	// Step 2: the JSON the browser posts
	return map[string]any{
		"id": a.credentialID(), "rawId": a.credentialID(), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64url.EncodeToString(cdj),
			"authenticatorData": b64url.EncodeToString(ad),
			"signature":         b64url.EncodeToString(sig),
		},
		"authenticatorAttachment": "platform",
	}
}

// ─── the flow ────────────────────────────────────────────────────────────────

type passkeyBody struct {
	ID           string  `json:"id"`
	Name         *string `json:"name"`
	UserID       string  `json:"userId"`
	CredentialID string  `json:"credentialID"`
	Counter      int64   `json:"counter"`
}

// signInWithPasskey runs the authentication ceremony in client c.
func signInWithPasskey(t *testing.T, c *exkit.Client, a *softAuthenticator) *exkit.Response {
	t.Helper()
	// Step 1: options with a fresh challenge (stored in a signed cookie)
	var opts struct {
		Challenge string `json:"challenge"`
		RPID      string `json:"rpId"`
	}
	c.MustOK(c.Get("/api/auth/passkey/generate-authenticate-options"), &opts)
	// Step 2: the authenticator signs the challenge; the server verifies it and creates the session
	return c.Post("/api/auth/passkey/verify-authentication", map[string]any{"response": a.assert(t, opts.Challenge)})
}

func TestPasskeyFlow(t *testing.T) {
	app, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)
	authenticator := newSoftAuthenticator(t, "localhost", c.Origin)

	// Step 1: registering a passkey needs a session
	if r := c.Get("/api/auth/passkey/generate-register-options"); r.Status != http.StatusUnauthorized {
		t.Fatalf("register options without session: status %d, want 401", r.Status)
	}
	c.MustOK(c.SignUp("alice@example.com", "Password123!", "Alice"), nil)

	// Step 2: registration options (what navigator.credentials.create receives)
	var regOpts struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"rp"`
		User struct {
			Name        string `json:"name"`
			DisplayName string `json:"displayName"`
		} `json:"user"`
	}
	c.MustOK(c.Get("/api/auth/passkey/generate-register-options?authenticatorAttachment=platform"), &regOpts)
	if regOpts.RP.ID != "localhost" || regOpts.RP.Name != "GoAuth Example" || regOpts.User.Name != "alice@example.com" {
		t.Fatalf("register options = %+v", regOpts)
	}

	// Step 3: the authenticator creates the credential; verify-registration stores it
	var pk passkeyBody
	c.MustOK(c.Post("/api/auth/passkey/verify-registration", map[string]any{
		"response": authenticator.register(t, regOpts.Challenge),
		"name":     "Laptop",
	}), &pk)
	if pk.ID == "" || pk.Name == nil || *pk.Name != "Laptop" || pk.CredentialID != authenticator.credentialID() {
		t.Fatalf("passkey = %+v", pk)
	}

	// Step 4: list and rename the user's passkeys
	var list []passkeyBody
	c.MustOK(c.Get("/api/auth/passkey/list-user-passkeys"), &list)
	if len(list) != 1 || list[0].ID != pk.ID {
		t.Fatalf("list = %+v", list)
	}
	var updated struct {
		Passkey passkeyBody `json:"passkey"`
	}
	c.MustOK(c.Post("/api/auth/passkey/update-passkey", map[string]any{"id": pk.ID, "name": "Work laptop"}), &updated)
	if updated.Passkey.Name == nil || *updated.Passkey.Name != "Work laptop" {
		t.Fatalf("update = %+v", updated)
	}
	c.MustOK(c.Post("/api/auth/sign-out", map[string]any{}), nil)

	// Step 5: a new browser signs in with the passkey alone (no email, no password)
	b := c.Fork()
	var signedIn struct {
		Session struct {
			Token string `json:"token"`
		} `json:"session"`
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	b.MustOK(signInWithPasskey(t, b, authenticator), &signedIn)
	if signedIn.Session.Token == "" || signedIn.User.Email != "alice@example.com" {
		t.Fatalf("verify-authentication = %+v", signedIn)
	}

	// Step 6: the session cookie opens the protected route
	var me exkit.MeOutput
	b.MustOK(b.Get("/api/example/me"), &me.Body)
	if me.Body.Email != "alice@example.com" {
		t.Fatalf("me = %+v", me.Body)
	}

	// Step 7: a challenge is single-use: replaying the same signed response fails
	var opts struct {
		Challenge string `json:"challenge"`
	}
	b.MustOK(b.Get("/api/auth/passkey/generate-authenticate-options"), &opts)
	resp := authenticator.assert(t, opts.Challenge)
	b.MustOK(b.Post("/api/auth/passkey/verify-authentication", map[string]any{"response": resp}), nil)
	if r := b.Post("/api/auth/passkey/verify-authentication", map[string]any{"response": resp}); r.Status != http.StatusBadRequest || r.ErrorCode() != "CHALLENGE_NOT_FOUND" {
		t.Fatalf("replayed response: %d %s", r.Status, r.Body)
	}

	// Step 8: delete the passkey; it can no longer sign in
	b.MustOK(b.Post("/api/auth/passkey/delete-passkey", map[string]any{"id": pk.ID}), nil)
	if r := signInWithPasskey(t, c.Fork(), authenticator); r.Status != http.StatusUnauthorized || r.ErrorCode() != "PASSKEY_NOT_FOUND" {
		t.Fatalf("deleted passkey: %d %s", r.Status, r.Body)
	}
}
