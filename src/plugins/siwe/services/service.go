// Package services implements better-auth's siwe plugin: nonces for wallet addresses and the
// Sign-In with Ethereum (EIP-4361) verification that signs users in, creating them on first use.
package services

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	siweconfig "github.com/better-go-auth/goauth/src/plugins/siwe/config"
	siwedtos "github.com/better-go-auth/goauth/src/plugins/siwe/dtos"
	"github.com/better-go-auth/goauth/src/plugins/siwe/eip4361"
	"github.com/better-go-auth/goauth/src/providers/idgen"
)

// Model is the logical name of the plugin's table.
const Model = "walletAddress"

// Logical field names of the walletAddress table.
const (
	FieldUserID    = "userId"
	FieldAddress   = "address"
	FieldChainID   = "chainId"
	FieldIsPrimary = "isPrimary"
	FieldCreatedAt = "createdAt"
)

// ProviderID is the providerId of the accounts the plugin creates (accountId "<address>:<chainId>").
const ProviderID = "siwe"

// Service implements the siwe endpoints.
type Service struct {
	cfg   siweconfig.SIWEConfig
	kit   *pluginkit.Kit
	store adapter.Adapter

	mu  sync.RWMutex
	now func() time.Time
}

// New builds the service. store is the adapter holding the walletAddress table (InitContext.Adapter).
func New(cfg siweconfig.SIWEConfig, kit *pluginkit.Kit, store adapter.Adapter) *Service {
	return &Service{cfg: cfg, kit: kit, store: store, now: time.Now}
}

// Config returns the configuration.
func (s *Service) Config() siweconfig.SIWEConfig { return s.cfg }

// Kit returns the shared plugin runtime.
func (s *Service) Kit() *pluginkit.Kit { return s.kit }

// SetClock overrides the clock used for nonce and message expiry (tests). nil restores time.Now.
func (s *Service) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now == nil {
		now = time.Now
	}
	s.now = now
}

// clock returns the current time.
func (s *Service) clock() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.now()
}

// ─── errors ──────────────────────────────────────────────────────────────────

// Error builds better-auth's APIError.fromStatus(status, {message, status, code?}) error.
func Error(status int, message, code string) *pluginkit.BodyError {
	return pluginkit.NewBodyError(status, siwedtos.SiweErrorBody{Message: message, Status: status, Code: code})
}

// The errors /siwe/verify answers with.
var (
	ErrEmailRequired   = Error(http.StatusBadRequest, "Email is required when anonymous is disabled.", "")
	ErrInvalidNonce    = Error(http.StatusUnauthorized, "Unauthorized: Invalid or expired nonce", "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE")
	ErrMessageMismatch = Error(http.StatusUnauthorized, "Unauthorized: SIWE message does not match the expected nonce, domain, address, or chain ID", "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH")
	ErrMessageExpired  = Error(http.StatusUnauthorized, "Unauthorized: SIWE message has expired", "UNAUTHORIZED_SIWE_MESSAGE_EXPIRED")
	ErrMessageNotYet   = Error(http.StatusUnauthorized, "Unauthorized: SIWE message is not yet valid", "UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID")
	ErrInvalidSig      = Error(http.StatusUnauthorized, "Unauthorized: Invalid SIWE signature", "")
	ErrInternal        = Error(http.StatusInternalServerError, "Internal Server Error", "")
)

// somethingWentWrong is better-auth's catch-all for non-API errors inside /siwe/verify.
func somethingWentWrong(err error) *pluginkit.BodyError {
	msg := "Unknown error"
	if ae := autherr.AsAuthError(err); ae != nil {
		msg = ae.Message
	} else if err != nil {
		msg = err.Error()
	}
	return pluginkit.NewBodyError(http.StatusUnauthorized, siwedtos.SiweErrorBody{
		Message: "Something went wrong. Please try again later.", Error: msg, Status: http.StatusUnauthorized,
	})
}

// ─── nonce ───────────────────────────────────────────────────────────────────

// Identifier is the verification identifier of a wallet's nonce: "siwe:<checksum address>:<chainId>".
func Identifier(walletAddress string, chainID int64) string {
	return "siwe:" + walletAddress + ":" + strconv.FormatInt(chainID, 10)
}

// Nonce is POST /siwe/nonce: it stores a new nonce for the wallet and chain (valid 15 minutes, replacing
// an older one) and returns it.
func (s *Service) Nonce(ctx context.Context, walletAddress string, chainID int64) (string, error) {
	// Step 1: generate the nonce
	nonce, err := s.newNonce(ctx)
	if err != nil {
		return "", err
	}
	// Step 2: store it for the checksummed address
	address := eip4361.ChecksumAddress(walletAddress)
	if _, err := s.kit.Repos.UpsertVerificationValue(ctx, &models.Verification{
		Base:       models.Base{ID: s.kit.NewID()},
		Identifier: Identifier(address, chainID),
		Value:      nonce,
		ExpiresAt:  s.clock().Add(siweconfig.NonceTTL),
	}); err != nil {
		return "", err
	}
	return nonce, nil
}

// newNonce returns GetNonce's nonce or 32 random alphanumeric characters.
func (s *Service) newNonce(ctx context.Context) (string, error) {
	if s.cfg.GetNonce != nil {
		return s.cfg.GetNonce(ctx)
	}
	return idgen.RandomString(32), nil
}

// ─── verify ──────────────────────────────────────────────────────────────────

// VerifyInput is the input of Verify.
type VerifyInput struct {
	Message       string
	Signature     string
	WalletAddress string
	ChainID       int64
	// Email is the new user's email (required when Anonymous is false); nil = none.
	Email *string
}

// VerifyResult is a successful sign-in.
type VerifyResult struct {
	Session       *dtos.SessionWithUser
	User          *models.User
	WalletAddress string
	ChainID       int64
}

// Verify is POST /siwe/verify: it checks the nonce, the message fields and the signature, then signs the
// wallet's user in (creating the user, the wallet address and a "siwe" account on first sign-in, or
// linking another chain of a known address to its user).
func (s *Service) Verify(ctx context.Context, in VerifyInput) (*VerifyResult, error) {
	// Step 1: anonymous sign-ins may be disabled
	address := eip4361.ChecksumAddress(in.WalletAddress)
	if !s.cfg.IsAnonymous() && in.Email == nil {
		return nil, ErrEmailRequired
	}
	// Step 2: everything else; unexpected errors become better-auth's 401 "Something went wrong"
	res, err := s.verify(ctx, in, address)
	if err != nil {
		var be *pluginkit.BodyError
		if errors.As(err, &be) {
			return nil, be
		}
		if ae := autherr.AsAuthError(err); ae != nil && ae.StatusCode < http.StatusInternalServerError &&
			!errors.Is(err, autherr.ErrFailedToCreateUser) {
			return nil, ae
		}
		return nil, somethingWentWrong(err)
	}
	return res, nil
}

// verify runs the checks and the sign-in of Verify.
func (s *Service) verify(ctx context.Context, in VerifyInput, address string) (*VerifyResult, error) {
	// Step 1: the wallet's live nonce
	identifier := Identifier(address, in.ChainID)
	verification, err := pluginkit.AcceptNotFound(s.kit.Repos.FindVerificationValue(ctx, identifier))
	if err != nil {
		return nil, err
	}
	now := s.clock()
	if verification == nil || now.After(verification.ExpiresAt) {
		return nil, ErrInvalidNonce
	}
	nonce := verification.Value
	// Step 2: the message must carry the nonce, the address, the chain and the configured domain
	fields := eip4361.LooseParse(in.Message)
	domain := s.Domain(ctx)
	if fields.Nonce != nonce ||
		fields.Address == "" || !strings.EqualFold(fields.Address, address) ||
		!fields.HasChainID || fields.ChainID != in.ChainID ||
		fields.Domain == "" || eip4361.NormalizeDomain(fields.Domain) != eip4361.NormalizeDomain(domain) {
		return nil, ErrMessageMismatch
	}
	// Step 3: the message's validity window
	if t, err := time.Parse(time.RFC3339Nano, fields.ExpirationTime); fields.ExpirationTime != "" && err == nil && !now.Before(t) {
		return nil, ErrMessageExpired
	}
	if t, err := time.Parse(time.RFC3339Nano, fields.NotBefore); fields.NotBefore != "" && err == nil && now.Before(t) {
		return nil, ErrMessageNotYet
	}
	// Step 4: the signature (verifyMessage, by default EIP-191 + secp256k1 recovery)
	ok, err := s.verifyMessage(ctx, siweconfig.VerifyMessageArgs{
		Message: in.Message, Signature: in.Signature, Address: address, ChainID: in.ChainID,
		Cacao: &siweconfig.Cacao{
			H: eip4361.CacaoHeader{T: "caip122"},
			P: eip4361.CacaoPayload{Domain: domain, Aud: domain, Nonce: nonce, Iss: domain, Version: "1"},
			S: eip4361.CacaoSignature{T: "eip191", S: in.Signature},
		},
	})
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrInvalidSig
	}
	// Step 5: consume the nonce (atomically: a concurrent request with the same nonce loses)
	consumed, err := s.kit.Repos.DeleteVerificationIfValue(ctx, verification.ID, nonce)
	if err != nil {
		return nil, err
	}
	if !consumed {
		return nil, ErrInvalidNonce
	}
	_ = s.kit.Repos.DeleteVerificationByIdentifier(ctx, identifier)
	// Step 6: the wallet's user: same address + chain, else same address on another chain, else a new user
	user, err := s.signInUser(ctx, in, address)
	if err != nil {
		return nil, err
	}
	// Step 7: the session
	sw, err := s.kit.CreateSession(ctx, user, false)
	if err != nil {
		if errors.Is(err, autherr.ErrFailedToCreateSession) {
			return nil, ErrInternal
		}
		return nil, err
	}
	return &VerifyResult{Session: sw, User: user, WalletAddress: address, ChainID: in.ChainID}, nil
}

// signInUser finds or creates the user of a verified wallet.
func (s *Service) signInUser(ctx context.Context, in VerifyInput, address string) (*models.User, error) {
	// Step 1: the exact wallet (address + chain)
	exact, err := s.findWallet(ctx, []adapter.Where{
		{Field: FieldAddress, Value: address}, {Field: FieldChainID, Value: float64(in.ChainID)},
	})
	if err != nil {
		return nil, err
	}
	var user *models.User
	if exact != nil {
		if user, err = s.findUser(ctx, exact.UserID); err != nil {
			return nil, err
		}
	} else {
		// Step 2: the same address on another chain belongs to the same user
		other, err := s.findWallet(ctx, []adapter.Where{{Field: FieldAddress, Value: address}})
		if err != nil {
			return nil, err
		}
		if other != nil {
			if user, err = s.findUser(ctx, other.UserID); err != nil {
				return nil, err
			}
		}
	}
	// Step 3: a new user with a placeholder (or the given) email, named after the ENS name or the address
	if user == nil {
		created, err := s.createUser(ctx, in, address)
		if err != nil {
			return nil, err
		}
		if err := s.linkWallet(ctx, created.ID, address, in.ChainID, true); err != nil {
			return nil, err
		}
		return created, nil
	}
	// Step 4: a known user signing in on a new chain gets that wallet linked
	if exact == nil {
		if err := s.linkWallet(ctx, user.ID, address, in.ChainID, false); err != nil {
			return nil, err
		}
	}
	return user, nil
}

// createUser creates the user of a new wallet.
func (s *Service) createUser(ctx context.Context, in VerifyInput, address string) (*models.User, error) {
	// Step 1: the email: the given one when anonymous sign-ins are off, else "<address>@<domain>"
	email := address + "@" + s.emailDomain(ctx)
	if !s.cfg.IsAnonymous() && in.Email != nil {
		email = *in.Email
	}
	// Step 2: ENS name and avatar
	name, image := address, ""
	if s.cfg.ENSLookup != nil {
		ens, err := s.cfg.ENSLookup(ctx, siweconfig.ENSLookupArgs{WalletAddress: address})
		if err != nil {
			return nil, err
		}
		if ens != nil {
			if ens.Name != "" {
				name = ens.Name
			}
			image = ens.Avatar
		}
	}
	// Step 3: create it (user hooks run)
	return s.kit.CreateUser(ctx, &models.User{UserDto: models.UserDto{
		Name:  name,
		Email: strings.ToLower(email),
		Image: &image,
		Role:  enums.User,
	}})
}

// linkWallet stores a walletAddress row and the matching "siwe" account.
func (s *Service) linkWallet(ctx context.Context, userID, address string, chainID int64, primary bool) error {
	// Step 1: the wallet address
	if _, err := s.store.Create(ctx, Model, adapter.Record{
		FieldUserID:    userID,
		FieldAddress:   address,
		FieldChainID:   float64(chainID),
		FieldIsPrimary: primary,
		FieldCreatedAt: s.clock(),
	}); err != nil {
		return err
	}
	// Step 2: the account (accountId "<address>:<chainId>")
	_, err := s.kit.Repos.CreateAccount(ctx, &models.Account{
		Base:       models.Base{ID: s.kit.NewID()},
		UserID:     userID,
		ProviderID: ProviderID,
		AccountID:  address + ":" + strconv.FormatInt(chainID, 10),
	})
	return err
}

// findUser loads a user (nil when it no longer exists).
func (s *Service) findUser(ctx context.Context, id string) (*models.User, error) {
	return pluginkit.AcceptNotFound(s.kit.Repos.FindUserByID(ctx, id))
}

// verifyMessage runs VerifyMessage or the default EIP-191 verifier.
func (s *Service) verifyMessage(ctx context.Context, args siweconfig.VerifyMessageArgs) (bool, error) {
	if s.cfg.VerifyMessage != nil {
		return s.cfg.VerifyMessage(ctx, args)
	}
	return eip4361.Verify(args, s.clock()) == nil, nil
}

// Domain is the domain SIWE messages must be issued for: Domain, or the host of the base URL.
func (s *Service) Domain(ctx context.Context) string {
	if s.cfg.Domain != "" {
		return s.cfg.Domain
	}
	if u, err := url.Parse(s.kit.RequestBaseURL(ctx)); err == nil {
		return u.Host
	}
	return ""
}

// emailDomain is EmailDomainName or the origin of the base URL (better-auth's getOrigin(baseURL)).
func (s *Service) emailDomain(ctx context.Context) string {
	if s.cfg.EmailDomainName != "" {
		return s.cfg.EmailDomainName
	}
	if u, err := url.Parse(s.kit.RequestBaseURL(ctx)); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return "null"
}

// ─── wallet addresses ────────────────────────────────────────────────────────

// WalletAddresses returns the wallet addresses linked to a user.
func (s *Service) WalletAddresses(ctx context.Context, userID string) ([]siwedtos.WalletAddress, error) {
	recs, err := s.store.FindMany(ctx, Model, adapter.Query{
		Where: []adapter.Where{{Field: FieldUserID, Value: userID}},
		Sort:  []adapter.SortBy{{Field: FieldCreatedAt}},
	})
	if err != nil {
		return nil, err
	}
	out := make([]siwedtos.WalletAddress, 0, len(recs))
	for _, r := range recs {
		out = append(out, fromRecord(r))
	}
	return out, nil
}

// findWallet loads the first wallet address matching where (nil when there is none).
func (s *Service) findWallet(ctx context.Context, where []adapter.Where) (*siwedtos.WalletAddress, error) {
	rec, err := s.store.FindOne(ctx, Model, where)
	if errors.Is(err, adapter.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	w := fromRecord(rec)
	return &w, nil
}

// fromRecord converts an adapter record to a WalletAddress.
func fromRecord(rec adapter.Record) siwedtos.WalletAddress {
	w := siwedtos.WalletAddress{}
	w.ID, _ = rec["id"].(string)
	w.UserID, _ = rec[FieldUserID].(string)
	w.Address, _ = rec[FieldAddress].(string)
	w.IsPrimary, _ = rec[FieldIsPrimary].(bool)
	w.CreatedAt, _ = rec[FieldCreatedAt].(time.Time)
	switch v := rec[FieldChainID].(type) {
	case float64:
		w.ChainID = int64(v)
	case int64:
		w.ChainID = v
	}
	return w
}
