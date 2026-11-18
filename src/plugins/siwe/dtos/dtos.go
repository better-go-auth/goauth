// Package dtos holds the request and response bodies of the siwe plugin (better-auth wire format).
package dtos

import "time"

// SiweNonceRequest is the body of POST /siwe/nonce and POST /siwe/get-nonce.
type SiweNonceRequest struct {
	WalletAddress *string  `json:"walletAddress,omitempty" doc:"The wallet address (0x + 40 hex digits)"`
	Address       *string  `json:"address,omitempty" doc:"Alias of walletAddress"`
	ChainID       *float64 `json:"chainId,omitempty" doc:"The EIP-155 chain id (default 1)"`
}

// SiweNonceResponse is {"nonce": "..."}.
type SiweNonceResponse struct {
	Nonce string `json:"nonce"`
}

// SiweVerifyRequest is the body of POST /siwe/verify.
type SiweVerifyRequest struct {
	Message       *string  `json:"message,omitempty" doc:"The EIP-4361 message"`
	Signature     *string  `json:"signature,omitempty" doc:"The personal_sign signature of the message"`
	WalletAddress *string  `json:"walletAddress,omitempty" doc:"The wallet address"`
	ChainID       *float64 `json:"chainId,omitempty" doc:"The EIP-155 chain id (default 1)"`
	Email         *string  `json:"email,omitempty" doc:"Email of the new user (required when anonymous is off)"`
}

// SiweVerifyUser is the user member of the verify response.
type SiweVerifyUser struct {
	ID            string `json:"id"`
	WalletAddress string `json:"walletAddress"`
	ChainID       int64  `json:"chainId"`
}

// SiweVerifyResponse is {token, success, user: {id, walletAddress, chainId}}.
type SiweVerifyResponse struct {
	Token   string         `json:"token"`
	Success bool           `json:"success"`
	User    SiweVerifyUser `json:"user"`
}

// SiweErrorBody is better-auth's APIError.fromStatus body: {message, status, code?, error?}.
type SiweErrorBody struct {
	Message string `json:"message"`
	Status  int    `json:"status"`
	Code    string `json:"code,omitempty"`
	Error   string `json:"error,omitempty"`
}

// WalletAddress is a row of the walletAddress table.
type WalletAddress struct {
	ID        string
	UserID    string
	Address   string
	ChainID   int64
	IsPrimary bool
	CreatedAt time.Time
}
