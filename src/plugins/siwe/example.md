# Sign-In with Ethereum (siwe) plugin

Lets users sign in with an Ethereum wallet ([EIP-4361](https://eips.ethereum.org/EIPS/eip-4361)). It is
the Go version of better-auth's `siwe()` plugin and works with the better-auth `siweClient()` plugin.

Runnable example: [src/example/siwe](../../example/siwe/main.go)

```sh
go run ./src/example/siwe     # server on http://localhost:8080, OpenAPI docs at /docs
go test ./src/example/siwe    # the flow below, end to end, with a generated wallet
```

## Setup

```go
import (
	"github.com/better-go-auth/goauth/src/plugins/siwe"
	siweconfig "github.com/better-go-auth/goauth/src/plugins/siwe/config"
)

siwePlugin := siwe.New(siweconfig.SIWEConfig{
	Domain: "example.com", // the host messages must be issued for (default: the BaseURL host)
})

auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
	Conn:       db,
	AuthConfig: config.AuthConfig{BaseURL: "https://example.com"},
	Plugins:    []plugin.Plugin{siwePlugin},
})
```

The plugin declares better-auth's `walletAddress` table (`userId` → user, `address`, `chainId`,
`isPrimary`, `createdAt`). goauth's migrator creates it during `SetupGoAuth`.

Unlike better-auth, `GetNonce` and `VerifyMessage` are optional: by default nonces are 32 random
alphanumeric characters and messages are verified by `eip4361.Verify`, which parses the EIP-4361 message,
checks address, chain id, domain, nonce and the Expiration Time / Not Before window, and recovers the
EIP-191 `personal_sign` signer with secp256k1. Smart-contract wallets (EIP-1271) need a chain call: supply
your own `VerifyMessage` for them.

## Options

| Field | Default | Meaning |
|---|---|---|
| `Domain` | BaseURL host | Domain the messages must name (compared without scheme, path and case) |
| `EmailDomainName` | base URL origin | New users get `<address>@<EmailDomainName>` as email |
| `Anonymous` | true | With `false`, `/siwe/verify` requires `email` (used for new users) |
| `GetNonce` | 32 random `[a-zA-Z0-9]` | Nonce generator |
| `VerifyMessage` | `eip4361.Verify` | Signature check, receives better-auth's `{message, signature, address, chainId, cacao}` |
| `ENSLookup` | none | `{name, avatar}` for new users (name defaults to the address) |
| `ModelName` / `FieldNames` | `walletAddress` | Rename the table or its columns |

Functional options: `siwe.WithDomain`, `WithAnonymous`, `WithGetNonce`, `WithVerifyMessage`,
`WithENSLookup`, `WithEmailDomainName`.

## Endpoints (under `/api/auth`)

| Method | Path | Body | Response |
|---|---|---|---|
| POST | `/siwe/nonce` (alias `/siwe/get-nonce`) | `walletAddress` (or `address`), `chainId?` (default 1) | `{nonce}`, valid 15 minutes |
| POST | `/siwe/verify` | `message`, `signature`, `walletAddress`, `chainId?`, `email?` | `{token, success, user: {id, walletAddress, chainId}}` + session cookie |

On the first sign-in of an address a user is created (name = ENS name or the address, image = ENS
avatar or `""`), with a primary `walletAddress` row and an account `{providerId: "siwe", accountId:
"<address>:<chainId>"}`. The same address on another chain signs in to the same user and gets another
(non-primary) wallet row and account. Addresses are stored EIP-55 checksummed.

## The flow

```go
// a wallet (tests / server-side signers; in the browser this is the user's wallet)
key, _ := secp256k1.GeneratePrivateKey()
address := eip4361.PublicKeyToAddress(key.PubKey())

// 1. POST /api/auth/siwe/nonce {"walletAddress": address, "chainId": 1} → {"nonce": "…"}
// 2. build and sign the message
msg := (&eip4361.Message{
	Domain: "example.com", Address: address, Statement: "Sign in to Example",
	URI: "https://example.com", ChainID: 1, Nonce: nonce, IssuedAt: time.Now(),
}).String()
signature := eip4361.SignPersonalMessage(key, []byte(msg))
// 3. POST /api/auth/siwe/verify {"message": msg, "signature": signature, "walletAddress": address, "chainId": 1}
```

With the official client and viem:

```ts
const client = createAuthClient({ plugins: [siweClient()] });
const { data } = await client.siwe.nonce({ walletAddress: address, chainId: 1 });
const message = createSiweMessage({ domain, address, uri, version: "1", chainId: 1, nonce: data.nonce });
const signature = await walletClient.signMessage({ message });
await client.siwe.verify({ message, signature, walletAddress: address, chainId: 1 });
```

## Errors

`/siwe/verify` errors have better-auth's `{message, status, code?}` body:

| Situation | Status | `code` | `message` |
|---|---|---|---|
| No nonce for the address + chain, or expired / already used | 401 | `UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE` | Unauthorized: Invalid or expired nonce |
| Message nonce / domain / address / chain differ | 401 | `UNAUTHORIZED_SIWE_MESSAGE_MISMATCH` | Unauthorized: SIWE message does not match … |
| Expiration Time passed | 401 | `UNAUTHORIZED_SIWE_MESSAGE_EXPIRED` | Unauthorized: SIWE message has expired |
| Not Before in the future | 401 | `UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID` | Unauthorized: SIWE message is not yet valid |
| Signature invalid (or `VerifyMessage` returned false) | 401 | — | Unauthorized: Invalid SIWE signature |
| Any other failure (`VerifyMessage` error, taken email, …) | 401 | — | Something went wrong. Please try again later. (+ `error`) |

Invalid bodies (bad address, `chainId` ≤ 0, missing email with `Anonymous: false`) are `400
VALIDATION_ERROR` with better-auth's messages.

## The `eip4361` package

`src/plugins/siwe/eip4361` can be used on its own: `ParseMessage` / `Message.String` (EIP-4361),
`LooseParse` (better-auth's lenient parser), `ChecksumAddress` (EIP-55), `HashPersonalMessage` (EIP-191),
`RecoverAddress`, `SignPersonalMessage` and `Verify`. Signatures may be 65-byte `r‖s‖v` (`v` = 27/28 or
0/1) or 64-byte EIP-2098 compact signatures.
