// Package humasiwe mounts the siwe endpoints on a Huma API.
package humasiwe

import (
	"context"
	"math"
	"net/http"
	"regexp"
	"strings"

	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/plugins/siwe/dtos"
	"github.com/better-go-auth/goauth/src/plugins/siwe/services"
)

// Handler adapts the siwe Service to Huma operations.
type Handler struct {
	Service *services.Service
}

// NewHandler builds the Huma handler.
func NewHandler(svc *services.Service) *Handler { return &Handler{Service: svc} }

// ─── validation (better-call / zod messages) ─────────────────────────────────

// walletPattern is better-auth's wallet address regex, printed like JavaScript's RegExp.toString.
const walletPattern = `/^0[xX][a-fA-F0-9]{40}$/i`

var (
	walletRegex = regexp.MustCompile(`^0[xX][a-fA-F0-9]{40}$`)
	// emailRegex is zod's default email pattern without its two lookaheads (checked separately)
	emailRegex = regexp.MustCompile(`^([A-Za-z0-9_'+\-.]*)[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$`)
)

// issues collects zod style validation issues.
type issues []string

// add records an issue at loc.
func (is *issues) add(loc, msg string) { *is = append(*is, "["+loc+"] "+msg) }

// wallet checks a wallet address string (z.string().regex(...).length(42)).
func (is *issues) wallet(loc, v string) {
	if !walletRegex.MatchString(v) {
		is.add(loc, "Invalid string: must match pattern "+walletPattern)
	}
	switch n := len([]rune(v)); {
	case n < 42:
		is.add(loc, "Too small: expected string to have >=42 characters")
	case n > 42:
		is.add(loc, "Too big: expected string to have <=42 characters")
	}
}

// chainID checks an optional chain id (z.number().int().positive().optional().default(1)).
func (is *issues) chainID(v *float64) int64 {
	if v == nil {
		return 1
	}
	if *v != math.Trunc(*v) || math.IsInf(*v, 0) {
		is.add("body.chainId", "Invalid input: expected int, received number")
		return 0
	}
	if *v <= 0 {
		is.add("body.chainId", "Too small: expected number to be >0")
	}
	return int64(*v)
}

// nonEmpty checks a required non-empty string (z.string().min(1)).
func (is *issues) nonEmpty(loc string, v *string) {
	switch {
	case v == nil:
		is.add(loc, "Invalid input: expected string, received undefined")
	case *v == "":
		is.add(loc, "Too small: expected string to have >=1 characters")
	}
}

// isEmail is zod's z.email() check.
func isEmail(s string) bool {
	return !strings.HasPrefix(s, ".") && !strings.Contains(s, "..") && emailRegex.MatchString(s)
}

// err returns the 400 VALIDATION_ERROR for the collected issues, or nil.
func (is issues) err() error {
	if len(is) == 0 {
		return nil
	}
	return pluginkit.NewError(http.StatusBadRequest, "VALIDATION_ERROR", strings.Join(is, "; "))
}

// ─── POST /siwe/nonce, POST /siwe/get-nonce ──────────────────────────────────

type siweNonceInput struct {
	Body struct {
		dtos.SiweNonceRequest
		_ struct{} `json:"-" additionalProperties:"true"`
	}
}

type siweNonceOutput struct {
	Body dtos.SiweNonceResponse
}

// Nonce issues a nonce for a wallet address and chain.
func (h *Handler) Nonce(ctx context.Context, in *siweNonceInput) (*siweNonceOutput, error) {
	// Step 1: validate the body like better-auth's schema (refine runs only on a valid object)
	var is issues
	if in.Body.WalletAddress != nil {
		is.wallet("body.walletAddress", *in.Body.WalletAddress)
	}
	if in.Body.Address != nil {
		is.wallet("body.address", *in.Body.Address)
	}
	chainID := is.chainID(in.Body.ChainID)
	if err := is.err(); err != nil {
		return nil, err
	}
	address := ""
	switch {
	case in.Body.WalletAddress != nil && *in.Body.WalletAddress != "":
		address = *in.Body.WalletAddress
	case in.Body.Address != nil && *in.Body.Address != "":
		address = *in.Body.Address
	default:
		return nil, issues{"[body.walletAddress] walletAddress or address is required"}.err()
	}
	// Step 2: issue the nonce
	nonce, err := h.Service.Nonce(ctx, address, chainID)
	if err != nil {
		return nil, err
	}
	return &siweNonceOutput{Body: dtos.SiweNonceResponse{Nonce: nonce}}, nil
}

// ─── POST /siwe/verify ───────────────────────────────────────────────────────

type siweVerifyInput struct {
	Body struct {
		dtos.SiweVerifyRequest
		_ struct{} `json:"-" additionalProperties:"true"`
	}
}

type siweVerifyOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      dtos.SiweVerifyResponse
}

// Verify signs a wallet in with a signed SIWE message.
func (h *Handler) Verify(ctx context.Context, in *siweVerifyInput) (*siweVerifyOutput, error) {
	// Step 1: validate the body like better-auth's schema
	var is issues
	b := in.Body.SiweVerifyRequest
	is.nonEmpty("body.message", b.Message)
	is.nonEmpty("body.signature", b.Signature)
	if b.WalletAddress == nil {
		is.add("body.walletAddress", "Invalid input: expected string, received undefined")
	} else {
		is.wallet("body.walletAddress", *b.WalletAddress)
	}
	chainID := is.chainID(b.ChainID)
	if b.Email != nil && !isEmail(*b.Email) {
		is.add("body.email", "Invalid email address")
	}
	if err := is.err(); err != nil {
		return nil, err
	}
	if !h.Service.Config().IsAnonymous() && (b.Email == nil || *b.Email == "") {
		return nil, issues{"[body.email] Email is required when the anonymous plugin option is disabled."}.err()
	}
	// Step 2: verify and sign in
	res, err := h.Service.Verify(ctx, services.VerifyInput{
		Message: *b.Message, Signature: *b.Signature, WalletAddress: *b.WalletAddress, ChainID: chainID, Email: b.Email,
	})
	if err != nil {
		return nil, err
	}
	// Step 3: the session cookie and better-auth's {token, success, user}
	return &siweVerifyOutput{
		SetCookie: h.Service.Kit().SessionCookies(res.Session, false),
		Body: dtos.SiweVerifyResponse{
			Token:   res.Session.Session.Token,
			Success: true,
			User:    dtos.SiweVerifyUser{ID: res.User.ID, WalletAddress: res.WalletAddress, ChainID: res.ChainID},
		},
	}, nil
}
