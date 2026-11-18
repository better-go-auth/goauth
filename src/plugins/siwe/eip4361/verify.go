package eip4361

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// CacaoHeader is the CAIP-74 header ({t: "caip122"}).
type CacaoHeader struct {
	T string `json:"t"`
}

// CacaoPayload is the CAIP-74 payload better-auth fills from the plugin options and the nonce.
type CacaoPayload struct {
	Domain    string   `json:"domain"`
	Aud       string   `json:"aud"`
	Nonce     string   `json:"nonce"`
	Iss       string   `json:"iss"`
	Version   string   `json:"version,omitempty"`
	Iat       string   `json:"iat,omitempty"`
	Nbf       string   `json:"nbf,omitempty"`
	Exp       string   `json:"exp,omitempty"`
	Statement string   `json:"statement,omitempty"`
	RequestID string   `json:"requestId,omitempty"`
	Resources []string `json:"resources,omitempty"`
	Type      string   `json:"type,omitempty"`
}

// CacaoSignature is the CAIP-74 signature ({t: "eip191" | "eip1271", s, m?}).
type CacaoSignature struct {
	T string `json:"t"`
	S string `json:"s"`
	M string `json:"m,omitempty"`
}

// Cacao is the CAIP-74 object better-auth passes to verifyMessage.
type Cacao struct {
	H CacaoHeader    `json:"h"`
	P CacaoPayload   `json:"p"`
	S CacaoSignature `json:"s"`
}

// VerifyArgs are the arguments of verifyMessage (better-auth's SIWEVerifyMessageArgs).
type VerifyArgs struct {
	// Message is the EIP-4361 message the wallet signed.
	Message string
	// Signature is the 0x-prefixed personal_sign signature.
	Signature string
	// Address is the EIP-55 wallet address of the request.
	Address string
	// ChainID is the chain id of the request.
	ChainID int64
	// Cacao carries the expected domain and nonce (better-auth always sets it).
	Cacao *Cacao
}

// Verification failures returned by Verify (all wrap ErrVerification).
var (
	ErrVerification     = errors.New("eip4361: verification failed")
	ErrAddressMismatch  = fmt.Errorf("%w: address mismatch", ErrVerification)
	ErrChainMismatch    = fmt.Errorf("%w: chain id mismatch", ErrVerification)
	ErrDomainMismatch   = fmt.Errorf("%w: domain mismatch", ErrVerification)
	ErrNonceMismatch    = fmt.Errorf("%w: nonce mismatch", ErrVerification)
	ErrMessageExpired   = fmt.Errorf("%w: message expired", ErrVerification)
	ErrMessageNotYet    = fmt.Errorf("%w: message not yet valid", ErrVerification)
	ErrSignerMismatch   = fmt.Errorf("%w: signature was not made by the address", ErrVerification)
	ErrMessageMalformed = fmt.Errorf("%w: malformed message", ErrVerification)
)

// Verify checks an EIP-4361 sign-in for an externally owned account: the message parses (ParseMessage),
// its address and chain id are the request's, its domain and nonce are the expected ones (args.Cacao),
// now lies within its Not Before / Expiration Time window, and the EIP-191 signature recovers to the
// message's address. It returns nil when every check passes.
//
// Smart-contract wallets (EIP-1271) need an RPC call and are not supported; plug a custom verifyMessage
// for them.
func Verify(args VerifyArgs, now time.Time) error {
	// Step 1: the message must follow the EIP-4361 grammar
	msg, err := ParseMessage(args.Message)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMessageMalformed, err)
	}
	// Step 2: the message is about this request's address and chain
	if !strings.EqualFold(msg.Address, args.Address) {
		return ErrAddressMismatch
	}
	if msg.ChainID != args.ChainID {
		return ErrChainMismatch
	}
	// Step 3: the expected domain and nonce
	if args.Cacao != nil {
		if args.Cacao.P.Domain != "" && NormalizeDomain(msg.Domain) != NormalizeDomain(args.Cacao.P.Domain) {
			return ErrDomainMismatch
		}
		if args.Cacao.P.Nonce != "" && msg.Nonce != args.Cacao.P.Nonce {
			return ErrNonceMismatch
		}
	}
	// Step 4: the validity window
	if msg.ExpirationTime != nil && !now.Before(*msg.ExpirationTime) {
		return ErrMessageExpired
	}
	if msg.NotBefore != nil && now.Before(*msg.NotBefore) {
		return ErrMessageNotYet
	}
	// Step 5: the signature must recover to the message's address
	signer, err := RecoverAddress([]byte(args.Message), args.Signature)
	if err != nil {
		return err
	}
	if !strings.EqualFold(signer, msg.Address) {
		return ErrSignerMismatch
	}
	return nil
}
