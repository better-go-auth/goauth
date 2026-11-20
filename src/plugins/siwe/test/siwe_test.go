package test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	deviceauthorization "github.com/better-go-auth/goauth/src/plugins/device-authorization"
	daconfig "github.com/better-go-auth/goauth/src/plugins/device-authorization/config"
	onetimetoken "github.com/better-go-auth/goauth/src/plugins/one-time-token"
	ottconfig "github.com/better-go-auth/goauth/src/plugins/one-time-token/config"
	openapi "github.com/better-go-auth/goauth/src/plugins/open-api"
	openapiconfig "github.com/better-go-auth/goauth/src/plugins/open-api/config"
	phonenumber "github.com/better-go-auth/goauth/src/plugins/phone-number"
	phoneconfig "github.com/better-go-auth/goauth/src/plugins/phone-number/config"
	"github.com/better-go-auth/goauth/src/plugins/siwe"
	siweconfig "github.com/better-go-auth/goauth/src/plugins/siwe/config"
	"github.com/better-go-auth/goauth/src/plugins/siwe/dtos"
	"github.com/better-go-auth/goauth/src/plugins/siwe/eip4361"
	"github.com/better-go-auth/goauth/src/plugins/siwe/services"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ─── Harness ─────────────────────────────────────────────────────────────────

type harness struct {
	*compattest.Server
	plugin *siwe.Plugin
	clock  *fakeClock
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// newHarness starts goauth (BaseURL http://localhost:3000) with the siwe plugin and a fake clock.
func newHarness(t *testing.T, cfg siweconfig.SIWEConfig, configure ...func(*config.AuthConfig)) *harness {
	t.Helper()
	p := siwe.New(cfg)
	s := compattest.NewServer(t,
		compattest.WithPlugin(p),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
			for _, fn := range configure {
				fn(c)
			}
		}),
	)
	s.Client.Jar = nil
	clock := &fakeClock{now: time.Now()}
	p.Service().SetClock(clock.Now)
	return &harness{Server: s, plugin: p, clock: clock}
}

// wallet is a secp256k1 key with its EIP-55 address.
type wallet struct {
	key     *secp256k1.PrivateKey
	address string
}

func newWallet(t *testing.T) wallet {
	t.Helper()
	key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return wallet{key: key, address: eip4361.PublicKeyToAddress(key.PubKey())}
}

// message builds an EIP-4361 message for the harness domain.
func (w wallet) message(nonce string, chainID int64, edit ...func(*eip4361.Message)) string {
	m := &eip4361.Message{
		Scheme: "http", Domain: "localhost:3000", Address: w.address, Statement: "Sign in with Ethereum to the app.",
		URI: "http://localhost:3000", Version: "1", ChainID: chainID, Nonce: nonce, IssuedAt: time.Now(),
	}
	for _, fn := range edit {
		fn(m)
	}
	return m.String()
}

func (w wallet) sign(msg string) string { return eip4361.SignPersonalMessage(w.key, []byte(msg)) }

// nonce asks for a nonce.
func (h *harness) nonce(t *testing.T, address string, chainID int64) string {
	t.Helper()
	r := h.Post(t, "/api/auth/siwe/nonce", map[string]any{"walletAddress": address, "chainId": chainID})
	expectOK(t, r)
	var b dtos.SiweNonceResponse
	r.JSON(t, &b)
	if b.Nonce == "" {
		t.Fatalf("empty nonce: %s", r.Body)
	}
	return b.Nonce
}

// verify posts /siwe/verify.
func (h *harness) verify(t *testing.T, body map[string]any) *compattest.Response {
	t.Helper()
	return h.Post(t, "/api/auth/siwe/verify", body)
}

// signIn runs nonce → sign → verify for w on chainID and returns the response body.
func (h *harness) signIn(t *testing.T, w wallet, chainID int64, extra map[string]any) (dtos.SiweVerifyResponse, *compattest.Response) {
	t.Helper()
	nonce := h.nonce(t, w.address, chainID)
	msg := w.message(nonce, chainID)
	body := map[string]any{"message": msg, "signature": w.sign(msg), "walletAddress": w.address, "chainId": chainID}
	for k, v := range extra {
		body[k] = v
	}
	r := h.verify(t, body)
	expectOK(t, r)
	var b dtos.SiweVerifyResponse
	r.JSON(t, &b)
	return b, r
}

func expectOK(t *testing.T, r *compattest.Response) {
	t.Helper()
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", r.Status, r.Body)
	}
}

// expectBody checks the status and the exact JSON body.
func expectBody(t *testing.T, r *compattest.Response, status int, body string) {
	t.Helper()
	if r.Status != status || strings.TrimSpace(string(r.Body)) != body {
		t.Fatalf("got %d %s\nwant %d %s", r.Status, r.Body, status, body)
	}
}

// expectValidation checks a 400 VALIDATION_ERROR with message.
func expectValidation(t *testing.T, r *compattest.Response, message string) {
	t.Helper()
	expectBody(t, r, http.StatusBadRequest, `{"code":"VALIDATION_ERROR","message":"`+message+`"}`)
}

const (
	bodyInvalidNonce = `{"message":"Unauthorized: Invalid or expired nonce","status":401,"code":"UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE"}`
	bodyMismatch     = `{"message":"Unauthorized: SIWE message does not match the expected nonce, domain, address, or chain ID","status":401,"code":"UNAUTHORIZED_SIWE_MESSAGE_MISMATCH"}`
	bodyInvalidSig   = `{"message":"Unauthorized: Invalid SIWE signature","status":401}`
	bodyExpired      = `{"message":"Unauthorized: SIWE message has expired","status":401,"code":"UNAUTHORIZED_SIWE_MESSAGE_EXPIRED"}`
	bodyNotYet       = `{"message":"Unauthorized: SIWE message is not yet valid","status":401,"code":"UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID"}`
)

// cookieHeader turns the response's non-expired Set-Cookie entries into a Cookie request header.
func cookieHeader(r *compattest.Response) string {
	var parts []string
	for _, c := range (&http.Response{Header: r.Header}).Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			continue
		}
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

type sessionBody struct {
	User struct {
		ID    string  `json:"id"`
		Name  string  `json:"name"`
		Email string  `json:"email"`
		Image *string `json:"image"`
	} `json:"user"`
}

// accounts returns the user's accounts.
func (h *harness) accounts(t *testing.T, userID string) []models.Account {
	t.Helper()
	accs, err := h.Auth.Repositories().FindAccounts(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	return accs
}

// ─── The flow ────────────────────────────────────────────────────────────────

func TestSiweSignIn(t *testing.T) {
	h := newHarness(t, siweconfig.SIWEConfig{})
	w := newWallet(t)

	// Step 1: nonce → sign → verify (the address is sent in lower case)
	nonce := h.nonce(t, strings.ToLower(w.address), 1)
	if len(nonce) != 32 {
		t.Fatalf("nonce = %q", nonce)
	}
	msg := w.message(nonce, 1)
	r := h.verify(t, map[string]any{"message": msg, "signature": w.sign(msg), "walletAddress": strings.ToLower(w.address)})
	expectOK(t, r)
	var b dtos.SiweVerifyResponse
	r.JSON(t, &b)
	if !b.Success || b.Token == "" || b.User.ID == "" || b.User.WalletAddress != w.address || b.User.ChainID != 1 {
		t.Fatalf("verify = %+v", b)
	}

	// Step 2: the session cookie works; the user is named after the address with a placeholder email
	r = h.Get(t, "/api/auth/get-session", map[string]string{"Cookie": cookieHeader(r)})
	expectOK(t, r)
	var sess sessionBody
	r.JSON(t, &sess)
	if sess.User.ID != b.User.ID || sess.User.Name != w.address ||
		sess.User.Email != strings.ToLower(w.address)+"@http://localhost:3000" || sess.User.Image == nil || *sess.User.Image != "" {
		t.Fatalf("session user = %+v", sess.User)
	}

	// Step 3: the primary wallet row and the siwe account
	wallets, err := h.plugin.Service().WalletAddresses(context.Background(), b.User.ID)
	if err != nil || len(wallets) != 1 || wallets[0].Address != w.address || wallets[0].ChainID != 1 || !wallets[0].IsPrimary {
		t.Fatalf("wallets = %+v %v", wallets, err)
	}
	accs := h.accounts(t, b.User.ID)
	if len(accs) != 1 || accs[0].ProviderID != "siwe" || accs[0].AccountID != w.address+":1" {
		t.Fatalf("accounts = %+v", accs)
	}

	// Step 4: the nonce is single use
	expectBody(t, h.verify(t, map[string]any{"message": msg, "signature": w.sign(msg), "walletAddress": w.address, "chainId": 1}),
		401, bodyInvalidNonce)
}

func TestSiweReturningWalletAndChains(t *testing.T) {
	h := newHarness(t, siweconfig.SIWEConfig{})
	w := newWallet(t)

	// Step 1: first sign-in, then again on the same chain: same user, no new rows
	first, _ := h.signIn(t, w, 1, nil)
	again, _ := h.signIn(t, w, 1, nil)
	if again.User.ID != first.User.ID || again.Token == first.Token {
		t.Fatalf("again = %+v, first = %+v", again, first)
	}
	// Step 2: the same address on another chain is linked to the same user (not primary)
	poly, _ := h.signIn(t, w, 137, nil)
	if poly.User.ID != first.User.ID || poly.User.ChainID != 137 {
		t.Fatalf("polygon = %+v", poly)
	}
	wallets, _ := h.plugin.Service().WalletAddresses(context.Background(), first.User.ID)
	if len(wallets) != 2 || !wallets[0].IsPrimary || wallets[1].IsPrimary || wallets[1].ChainID != 137 {
		t.Fatalf("wallets = %+v", wallets)
	}
	if accs := h.accounts(t, first.User.ID); len(accs) != 2 {
		t.Fatalf("accounts = %+v", accs)
	}
	// Step 3: another wallet is another user
	other, _ := h.signIn(t, newWallet(t), 1, nil)
	if other.User.ID == first.User.ID {
		t.Fatal("different wallets share a user")
	}
}

// ─── Failures ────────────────────────────────────────────────────────────────

func TestSiweVerifyFailures(t *testing.T) {
	h := newHarness(t, siweconfig.SIWEConfig{})
	w := newWallet(t)
	attacker := newWallet(t)

	t.Run("wrong signature", func(t *testing.T) {
		nonce := h.nonce(t, w.address, 1)
		msg := w.message(nonce, 1)
		expectBody(t, h.verify(t, map[string]any{"message": msg, "signature": attacker.sign(msg), "walletAddress": w.address}), 401, bodyInvalidSig)
		expectBody(t, h.verify(t, map[string]any{"message": msg, "signature": "0xdeadbeef", "walletAddress": w.address}), 401, bodyInvalidSig)
		// a failed signature does not burn the nonce
		expectOK(t, h.verify(t, map[string]any{"message": msg, "signature": w.sign(msg), "walletAddress": w.address}))
	})
	t.Run("no nonce", func(t *testing.T) {
		v := newWallet(t)
		msg := v.message("abcdefgh1234", 1)
		expectBody(t, h.verify(t, map[string]any{"message": msg, "signature": v.sign(msg), "walletAddress": v.address}), 401, bodyInvalidNonce)
	})
	t.Run("wrong nonce", func(t *testing.T) {
		h.nonce(t, w.address, 1)
		msg := w.message("someothernonce1", 1)
		expectBody(t, h.verify(t, map[string]any{"message": msg, "signature": w.sign(msg), "walletAddress": w.address}), 401, bodyMismatch)
	})
	t.Run("expired nonce", func(t *testing.T) {
		nonce := h.nonce(t, w.address, 1)
		h.clock.Advance(15*time.Minute + time.Second)
		msg := w.message(nonce, 1)
		expectBody(t, h.verify(t, map[string]any{"message": msg, "signature": w.sign(msg), "walletAddress": w.address}), 401, bodyInvalidNonce)
	})
	t.Run("chain id", func(t *testing.T) {
		nonce := h.nonce(t, w.address, 1)
		// the message is for another chain than the request
		msg := w.message(nonce, 137)
		expectBody(t, h.verify(t, map[string]any{"message": msg, "signature": w.sign(msg), "walletAddress": w.address, "chainId": 1}), 401, bodyMismatch)
		// the nonce was issued for chain 1, not 137
		expectBody(t, h.verify(t, map[string]any{"message": msg, "signature": w.sign(msg), "walletAddress": w.address, "chainId": 137}), 401, bodyInvalidNonce)
	})
	t.Run("domain", func(t *testing.T) {
		nonce := h.nonce(t, w.address, 1)
		msg := w.message(nonce, 1, func(m *eip4361.Message) { m.Domain = "evil.example" })
		expectBody(t, h.verify(t, map[string]any{"message": msg, "signature": w.sign(msg), "walletAddress": w.address}), 401, bodyMismatch)
	})
	t.Run("address", func(t *testing.T) {
		nonce := h.nonce(t, w.address, 1)
		msg := attacker.message(nonce, 1)
		expectBody(t, h.verify(t, map[string]any{"message": msg, "signature": attacker.sign(msg), "walletAddress": w.address}), 401, bodyMismatch)
	})
	t.Run("expiration time", func(t *testing.T) {
		nonce := h.nonce(t, w.address, 1)
		past := h.clock.Now().Add(-time.Second)
		msg := w.message(nonce, 1, func(m *eip4361.Message) { m.ExpirationTime = &past })
		expectBody(t, h.verify(t, map[string]any{"message": msg, "signature": w.sign(msg), "walletAddress": w.address}), 401, bodyExpired)
	})
	t.Run("not before", func(t *testing.T) {
		nonce := h.nonce(t, w.address, 1)
		future := h.clock.Now().Add(time.Hour)
		msg := w.message(nonce, 1, func(m *eip4361.Message) { m.NotBefore = &future })
		expectBody(t, h.verify(t, map[string]any{"message": msg, "signature": w.sign(msg), "walletAddress": w.address}), 401, bodyNotYet)
	})
	t.Run("malformed message", func(t *testing.T) {
		nonce := h.nonce(t, w.address, 1)
		// the fields better-auth reads are right, but the default verifier parses the message strictly
		msg := w.message(nonce, 1) + "\nGarbage line"
		expectBody(t, h.verify(t, map[string]any{"message": msg, "signature": w.sign(msg), "walletAddress": w.address}), 401, bodyInvalidSig)
	})
}

func TestSiweConcurrentNonceUse(t *testing.T) {
	h := newHarness(t, siweconfig.SIWEConfig{})
	w := newWallet(t)
	nonce := h.nonce(t, w.address, 1)
	msg := w.message(nonce, 1)
	body := map[string]any{"message": msg, "signature": w.sign(msg), "walletAddress": w.address}

	// Step 1: the same signed message posted many times at once
	var wg sync.WaitGroup
	var ok atomic.Int32
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if h.verify(t, body).Status == http.StatusOK {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	// Step 2: exactly one sign-in
	if ok.Load() != 1 {
		t.Fatalf("successful sign-ins = %d", ok.Load())
	}
}

// ─── Options ─────────────────────────────────────────────────────────────────

func TestSiweEmailRequired(t *testing.T) {
	anonymous := false
	h := newHarness(t, siweconfig.SIWEConfig{Anonymous: &anonymous})
	w := newWallet(t)

	// Step 1: without email the request is invalid (better-auth's schema refine)
	nonce := h.nonce(t, w.address, 1)
	msg := w.message(nonce, 1)
	expectValidation(t, h.verify(t, map[string]any{"message": msg, "signature": w.sign(msg), "walletAddress": w.address}),
		"[body.email] Email is required when the anonymous plugin option is disabled.")
	expectValidation(t, h.verify(t, map[string]any{"message": msg, "signature": w.sign(msg), "walletAddress": w.address, "email": "nope"}),
		"[body.email] Invalid email address")

	// Step 2: with an email the user gets it (lower-cased)
	b, r := h.signIn(t, w, 1, map[string]any{"email": "Wallet.Owner@Example.com"})
	r = h.Get(t, "/api/auth/get-session", map[string]string{"Cookie": cookieHeader(r)})
	var sess sessionBody
	r.JSON(t, &sess)
	if sess.User.ID != b.User.ID || sess.User.Email != "wallet.owner@example.com" {
		t.Fatalf("user = %+v", sess.User)
	}

	// Step 3: a second wallet with an email that is taken fails like better-auth (catch-all 401)
	v := newWallet(t)
	nonce = h.nonce(t, v.address, 1)
	msg = v.message(nonce, 1)
	r = h.verify(t, map[string]any{"message": msg, "signature": v.sign(msg), "walletAddress": v.address, "email": "wallet.owner@example.com"})
	if r.Status != http.StatusUnauthorized || !strings.Contains(string(r.Body), `"message":"Something went wrong. Please try again later."`) ||
		!strings.Contains(string(r.Body), `"status":401`) || !strings.Contains(string(r.Body), `"error":"Failed to create user"`) {
		t.Fatalf("taken email: %d %s", r.Status, r.Body)
	}
}

func TestSiweCallbacks(t *testing.T) {
	var gotArgs siweconfig.VerifyMessageArgs
	fail := atomic.Bool{}
	h := newHarness(t, siweconfig.SIWEConfig{
		Domain:          "localhost:3000",
		EmailDomainName: "wallets.example.com",
		GetNonce:        func(context.Context) (string, error) { return "fixednonce123", nil },
		VerifyMessage: func(_ context.Context, args siweconfig.VerifyMessageArgs) (bool, error) {
			gotArgs = args
			if fail.Load() {
				return false, errors.New("rpc unavailable")
			}
			return args.Signature == "0xtrusted", nil
		},
		ENSLookup: func(_ context.Context, args siweconfig.ENSLookupArgs) (*siweconfig.ENSLookupResult, error) {
			return &siweconfig.ENSLookupResult{Name: "vitalik.eth", Avatar: "https://ens.example/" + args.WalletAddress}, nil
		},
	})
	w := newWallet(t)

	// Step 1: GetNonce's nonce; VerifyMessage decides and sees better-auth's arguments
	nonce := h.nonce(t, w.address, 5)
	if nonce != "fixednonce123" {
		t.Fatalf("nonce = %q", nonce)
	}
	msg := w.message(nonce, 5)
	r := h.verify(t, map[string]any{"message": msg, "signature": "0xtrusted", "walletAddress": w.address, "chainId": 5})
	expectOK(t, r)
	if gotArgs.Message != msg || gotArgs.Address != w.address || gotArgs.ChainID != 5 || gotArgs.Cacao == nil ||
		gotArgs.Cacao.H.T != "caip122" || gotArgs.Cacao.P.Domain != "localhost:3000" || gotArgs.Cacao.P.Nonce != nonce ||
		gotArgs.Cacao.S.T != "eip191" || gotArgs.Cacao.S.S != "0xtrusted" {
		t.Fatalf("args = %+v", gotArgs)
	}

	// Step 2: ENS name and avatar, and the configured email domain
	r = h.Get(t, "/api/auth/get-session", map[string]string{"Cookie": cookieHeader(r)})
	var sess sessionBody
	r.JSON(t, &sess)
	if sess.User.Name != "vitalik.eth" || sess.User.Image == nil || *sess.User.Image != "https://ens.example/"+w.address ||
		sess.User.Email != strings.ToLower(w.address)+"@wallets.example.com" {
		t.Fatalf("user = %+v", sess.User)
	}

	// Step 3: an error from VerifyMessage is better-auth's catch-all 401 with the error text
	fail.Store(true)
	h.nonce(t, w.address, 5)
	expectBody(t, h.verify(t, map[string]any{"message": msg, "signature": "0xtrusted", "walletAddress": w.address, "chainId": 5}),
		401, `{"message":"Something went wrong. Please try again later.","status":401,"error":"rpc unavailable"}`)
}

// ─── Validation ──────────────────────────────────────────────────────────────

func TestSiweValidation(t *testing.T) {
	h := newHarness(t, siweconfig.SIWEConfig{})
	w := newWallet(t)

	// Step 1: /siwe/nonce
	expectValidation(t, h.Post(t, "/api/auth/siwe/nonce", map[string]any{}), "[body.walletAddress] walletAddress or address is required")
	expectValidation(t, h.Post(t, "/api/auth/siwe/nonce", map[string]any{"walletAddress": "0x1234"}),
		"[body.walletAddress] Invalid string: must match pattern /^0[xX][a-fA-F0-9]{40}$/i; [body.walletAddress] Too small: expected string to have >=42 characters")
	expectValidation(t, h.Post(t, "/api/auth/siwe/nonce", map[string]any{"walletAddress": w.address, "chainId": 0}),
		"[body.chainId] Too small: expected number to be >0")
	expectValidation(t, h.Post(t, "/api/auth/siwe/nonce", map[string]any{"walletAddress": w.address, "chainId": 1.5}),
		"[body.chainId] Invalid input: expected int, received number")

	// Step 2: the address alias and the /siwe/get-nonce alias issue nonces too
	r := h.Post(t, "/api/auth/siwe/get-nonce", map[string]any{"address": w.address})
	expectOK(t, r)
	var b dtos.SiweNonceResponse
	r.JSON(t, &b)
	if b.Nonce == "" {
		t.Fatalf("nonce: %s", r.Body)
	}
	msg := w.message(b.Nonce, 1)
	expectOK(t, h.verify(t, map[string]any{"message": msg, "signature": w.sign(msg), "walletAddress": w.address}))

	// Step 3: /siwe/verify
	expectValidation(t, h.verify(t, map[string]any{}),
		"[body.message] Invalid input: expected string, received undefined; [body.signature] Invalid input: expected string, received undefined; "+
			"[body.walletAddress] Invalid input: expected string, received undefined")
	expectValidation(t, h.verify(t, map[string]any{"message": "", "signature": "x", "walletAddress": w.address}),
		"[body.message] Too small: expected string to have >=1 characters")
}

func TestSiweRenamedTableAndIdentifier(t *testing.T) {
	h := newHarness(t, siweconfig.SIWEConfig{ModelName: "wallets", FieldNames: map[string]string{"address": "eth_address"}})
	w := newWallet(t)
	h.signIn(t, w, 1, nil)
	var n int64
	if err := h.DB.Table("wallets").Where("eth_address = ?", w.address).Count(&n).Error; err != nil || n != 1 {
		t.Fatalf("renamed table: n=%d err=%v", n, err)
	}
	if got := services.Identifier(w.address, 1); got != "siwe:"+w.address+":1" {
		t.Fatalf("identifier = %q", got)
	}
}

// TestCoexistsWithOtherPlugins installs siwe and device-authorization next to plugins with similarly named
// handler types (phone-number and one-time-token also have /verify endpoints) and the open-api plugin: Huma
// must register every schema, and the generated document lists both plugins' routes.
func TestCoexistsWithOtherPlugins(t *testing.T) {
	s := compattest.NewServer(t,
		compattest.WithPlugin(openapi.New(openapiconfig.OpenAPIConfig{})),
		compattest.WithPlugin(siwe.New(siweconfig.SIWEConfig{})),
		compattest.WithPlugin(deviceauthorization.New(daconfig.DeviceAuthorizationConfig{})),
		compattest.WithPlugin(phonenumber.New(phoneconfig.PhoneNumberConfig{})),
		compattest.WithPlugin(onetimetoken.New(ottconfig.OneTimeTokenConfig{})),
	)
	r := s.Get(t, "/api/auth/open-api/generate-schema")
	expectOK(t, r)
	for _, path := range []string{"/siwe/nonce", "/siwe/get-nonce", "/siwe/verify", "/device/code", "/device/token", "/device", "/device/approve", "/device/deny"} {
		if !strings.Contains(string(r.Body), `"`+path+`"`) {
			t.Errorf("open-api document misses %s", path)
		}
	}
}
