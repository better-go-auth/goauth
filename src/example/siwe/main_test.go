package main

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	"github.com/better-go-auth/goauth/src/plugins/siwe/eip4361"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func TestSiweFlow(t *testing.T) {
	app, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)

	// Step 1: a wallet (in a browser this is MetaMask & co.)
	key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	address := eip4361.PublicKeyToAddress(key.PubKey())

	// Step 2: ask for a nonce for the wallet and chain
	var nonce struct {
		Nonce string `json:"nonce"`
	}
	c.MustOK(c.Post("/api/auth/siwe/nonce", map[string]any{"walletAddress": address, "chainId": 1}), &nonce)

	// Step 3: build the EIP-4361 message and sign it (personal_sign)
	msg := (&eip4361.Message{
		Scheme: "http", Domain: "localhost:8080", Address: address,
		Statement: "Sign in to the goauth example.", URI: "http://localhost:8080",
		ChainID: 1, Nonce: nonce.Nonce, IssuedAt: time.Now(),
	}).String()
	signature := eip4361.SignPersonalMessage(key, []byte(msg))

	// Step 4: verify: goauth signs the wallet in (and creates its user the first time)
	var res struct {
		Token   string `json:"token"`
		Success bool   `json:"success"`
		User    struct {
			ID            string `json:"id"`
			WalletAddress string `json:"walletAddress"`
		} `json:"user"`
	}
	c.MustOK(c.Post("/api/auth/siwe/verify", map[string]any{
		"message": msg, "signature": signature, "walletAddress": address, "chainId": 1,
	}), &res)
	if !res.Success || res.User.WalletAddress != address {
		t.Fatalf("verify = %+v", res)
	}

	// Step 5: the session cookie opens the protected route
	var me exkit.MeOutput
	c.MustOK(c.Get("/api/example/me"), &me.Body)
	if me.Body.UserID != res.User.ID || me.Body.Email != strings.ToLower(address)+"@wallet.example.com" {
		t.Fatalf("me = %+v", me.Body)
	}

	// Step 6: the nonce cannot be replayed
	r := c.Fork().Post("/api/auth/siwe/verify", map[string]any{"message": msg, "signature": signature, "walletAddress": address})
	if r.Status != http.StatusUnauthorized || r.ErrorCode() != "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE" {
		t.Fatalf("replay: %d %s", r.Status, r.Body)
	}
}
