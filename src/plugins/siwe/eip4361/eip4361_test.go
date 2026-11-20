package eip4361

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// web3.js documentation vector: web3.eth.accounts.sign("Some data", key).
const (
	vectorKey       = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	vectorAddress   = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
	vectorHash      = "1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655"
	vectorSignature = "0xb91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c"
)

func vectorPrivateKey(t *testing.T) *secp256k1.PrivateKey {
	t.Helper()
	raw, err := hex.DecodeString(vectorKey)
	if err != nil {
		t.Fatal(err)
	}
	return secp256k1.PrivKeyFromBytes(raw)
}

func TestChecksumAddressEIP55Vectors(t *testing.T) {
	for _, want := range []string{
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		"0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
		"0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
		"0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
	} {
		for _, in := range []string{want, strings.ToLower(want), "0X" + strings.ToUpper(want[2:])} {
			if got := ChecksumAddress(in); got != want {
				t.Fatalf("ChecksumAddress(%s) = %s, want %s", in, got, want)
			}
		}
	}
}

func TestPersonalSignVector(t *testing.T) {
	key := vectorPrivateKey(t)
	// Step 1: the key's address
	if got := PublicKeyToAddress(key.PubKey()); got != vectorAddress {
		t.Fatalf("address = %s", got)
	}
	// Step 2: the EIP-191 hash
	if got := hex.EncodeToString(HashPersonalMessage([]byte("Some data"))); got != vectorHash {
		t.Fatalf("hash = %s", got)
	}
	// Step 3: the published signature recovers to the address, and ours is the same (RFC 6979)
	if got, err := RecoverAddress([]byte("Some data"), vectorSignature); err != nil || got != vectorAddress {
		t.Fatalf("recover = %s %v", got, err)
	}
	if got := SignPersonalMessage(key, []byte("Some data")); got != vectorSignature {
		t.Fatalf("signature = %s", got)
	}
}

func TestSignatureFormats(t *testing.T) {
	key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	addr := PublicKeyToAddress(key.PubKey())
	msg := []byte("hello")
	sig := SignPersonalMessage(key, msg)
	raw, _ := hex.DecodeString(sig[2:])

	// Step 1: v = 0/1 is accepted like 27/28
	alt := append([]byte(nil), raw...)
	alt[64] -= 27
	if got, err := RecoverAddress(msg, "0x"+hex.EncodeToString(alt)); err != nil || got != addr {
		t.Fatalf("v=0/1: %s %v", got, err)
	}
	// Step 2: EIP-2098 compact signatures
	compact := append([]byte(nil), raw[:64]...)
	if raw[64] == 28 {
		compact[32] |= 0x80
	}
	if got, err := RecoverAddress(msg, "0x"+hex.EncodeToString(compact)); err != nil || got != addr {
		t.Fatalf("EIP-2098: %s %v", got, err)
	}
	// Step 3: malformed signatures
	for _, bad := range []string{"", "0x", "0xzz", "0x" + strings.Repeat("00", 65), sig[:len(sig)-2] + "05", sig + "00"} {
		if _, err := RecoverAddress(msg, bad); !errors.Is(err, ErrInvalidSignature) {
			t.Fatalf("RecoverAddress(%q) err = %v", bad, err)
		}
	}
	// Step 4: another message recovers to another address
	if got, _ := RecoverAddress([]byte("other"), sig); got == addr {
		t.Fatal("signature valid for another message")
	}
}

func sampleMessage() *Message {
	exp := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	return &Message{
		Scheme:         "https",
		Domain:         "example.com",
		Address:        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
		Statement:      "Sign in to Example",
		URI:            "https://example.com/login",
		Version:        "1",
		ChainID:        1,
		Nonce:          "abcdef12345",
		IssuedAt:       time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC),
		ExpirationTime: &exp,
		RequestID:      "req-1",
		Resources:      []string{"ipfs://bafy", "https://example.com/terms"},
	}
}

func TestMessageFormatAndParse(t *testing.T) {
	m := sampleMessage()
	want := "https://example.com wants you to sign in with your Ethereum account:\n" +
		"0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed\n\n" +
		"Sign in to Example\n\n" +
		"URI: https://example.com/login\nVersion: 1\nChain ID: 1\nNonce: abcdef12345\n" +
		"Issued At: 2026-11-18T10:00:00.000Z\nExpiration Time: 2030-01-01T00:00:00.000Z\nRequest ID: req-1\n" +
		"Resources:\n- ipfs://bafy\n- https://example.com/terms"
	if got := m.String(); got != want {
		t.Fatalf("String() =\n%s\nwant\n%s", got, want)
	}
	// Step 1: round trip
	p, err := ParseMessage(want)
	if err != nil {
		t.Fatal(err)
	}
	if p.String() != want || p.Scheme != "https" || p.Domain != "example.com" || len(p.Resources) != 2 {
		t.Fatalf("parsed = %+v", p)
	}
	// Step 2: no statement (three line feeds), no scheme
	m.Statement, m.Scheme, m.Resources, m.ExpirationTime, m.RequestID = "", "", nil, nil, ""
	s := m.String()
	if !strings.Contains(s, "BeAed\n\n\nURI: ") || !strings.HasPrefix(s, "example.com wants") {
		t.Fatalf("no statement: %q", s)
	}
	if p, err := ParseMessage(s); err != nil || p.Statement != "" || p.Scheme != "" {
		t.Fatalf("parse no statement: %+v %v", p, err)
	}
	// Step 3: CRLF line endings
	if _, err := ParseMessage(strings.ReplaceAll(s, "\n", "\r\n")); err != nil {
		t.Fatalf("CRLF: %v", err)
	}
}

func TestParseMessageRejects(t *testing.T) {
	good := sampleMessage().String()
	cases := map[string]string{
		"header":        strings.Replace(good, "wants you to sign in", "wants to sign in", 1),
		"address":       strings.Replace(good, "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed", "0x5aAeb", 1),
		"version":       strings.Replace(good, "Version: 1", "Version: 2", 1),
		"chain":         strings.Replace(good, "Chain ID: 1", "Chain ID: one", 1),
		"short nonce":   strings.Replace(good, "Nonce: abcdef12345", "Nonce: abc", 1),
		"nonce charset": strings.Replace(good, "Nonce: abcdef12345", "Nonce: abcdef-12345", 1),
		"issued at":     strings.Replace(good, "Issued At: 2026-11-18T10:00:00.000Z", "Issued At: yesterday", 1),
		"order":         strings.Replace(good, "URI: https://example.com/login\nVersion: 1", "Version: 1\nURI: https://example.com/login", 1),
		"trailing":      good + "\nExtra: x",
		"no uri":        strings.Replace(good, "URI: https://example.com/login\n", "", 1),
		"blank line":    strings.Replace(good, "BeAed\n\n", "BeAed\n", 1),
	}
	for name, msg := range cases {
		if _, err := ParseMessage(msg); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestLooseParse(t *testing.T) {
	f := LooseParse(sampleMessage().String())
	if f.Scheme != "https" || f.Domain != "example.com" || f.Address != "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed" ||
		!f.HasChainID || f.ChainID != 1 || f.Nonce != "abcdef12345" || f.ExpirationTime != "2030-01-01T00:00:00.000Z" || f.RequestID != "req-1" {
		t.Fatalf("fields = %+v", f)
	}
	// Step 1: garbage yields empty fields, not an error
	if f := LooseParse("not a siwe message"); f.Domain != "" || f.Address != "" || f.HasChainID {
		t.Fatalf("garbage = %+v", f)
	}
	// Step 2: non-integer chain ids are ignored
	if f := LooseParse("x\ny\nChain ID: 1.5"); f.HasChainID {
		t.Fatalf("chain = %+v", f)
	}
}

func TestNormalizeDomain(t *testing.T) {
	for in, want := range map[string]string{
		"Example.COM":                 "example.com",
		"https://example.com/path":    "example.com",
		" localhost:3000 ":            "localhost:3000",
		"http://LOCALHOST:3000/a/b?c": "localhost:3000",
	} {
		if got := NormalizeDomain(in); got != want {
			t.Fatalf("NormalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestVerify(t *testing.T) {
	key, _ := secp256k1.GeneratePrivateKey()
	addr := PublicKeyToAddress(key.PubKey())
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	exp := now.Add(time.Hour)
	m := &Message{Domain: "localhost:3000", Address: addr, URI: "http://localhost:3000", ChainID: 10, Nonce: "nonce12345", IssuedAt: now, ExpirationTime: &exp}
	msg := m.String()
	args := VerifyArgs{
		Message: msg, Signature: SignPersonalMessage(key, []byte(msg)), Address: addr, ChainID: 10,
		Cacao: &Cacao{P: CacaoPayload{Domain: "http://localhost:3000", Nonce: "nonce12345"}},
	}
	if err := Verify(args, now); err != nil {
		t.Fatalf("valid sign-in: %v", err)
	}

	// Step 1: every mismatch is reported
	other, _ := secp256k1.GeneratePrivateKey()
	mutate := map[error]func(a *VerifyArgs) time.Time{
		ErrAddressMismatch: func(a *VerifyArgs) time.Time { a.Address = PublicKeyToAddress(other.PubKey()); return now },
		ErrChainMismatch:   func(a *VerifyArgs) time.Time { a.ChainID = 1; return now },
		ErrDomainMismatch:  func(a *VerifyArgs) time.Time { a.Cacao = &Cacao{P: CacaoPayload{Domain: "evil.com"}}; return now },
		ErrNonceMismatch:   func(a *VerifyArgs) time.Time { a.Cacao = &Cacao{P: CacaoPayload{Nonce: "othernonce"}}; return now },
		ErrMessageExpired:  func(a *VerifyArgs) time.Time { return exp },
		ErrSignerMismatch: func(a *VerifyArgs) time.Time {
			a.Signature = SignPersonalMessage(other, []byte(msg))
			return now
		},
		ErrMessageMalformed: func(a *VerifyArgs) time.Time { a.Message = "garbage"; return now },
		ErrInvalidSignature: func(a *VerifyArgs) time.Time { a.Signature = "0x1234"; return now },
	}
	for want, fn := range mutate {
		a := args
		at := fn(&a)
		if err := Verify(a, at); !errors.Is(err, want) {
			t.Errorf("want %v, got %v", want, err)
		}
	}

	// Step 2: Not Before
	nbf := now.Add(time.Minute)
	m.NotBefore = &nbf
	msg = m.String()
	a := args
	a.Message, a.Signature = msg, SignPersonalMessage(key, []byte(msg))
	if err := Verify(a, now); !errors.Is(err, ErrMessageNotYet) {
		t.Fatalf("not before: %v", err)
	}
	if err := Verify(a, nbf); err != nil {
		t.Fatalf("at not before: %v", err)
	}
}
