// Package services implements the passkey (WebAuthn) ceremonies of better-auth's passkey plugin.
package services

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/models"
	modeldtos "github.com/better-go-auth/goauth/src/models/dtos"
	pkconfig "github.com/better-go-auth/goauth/src/plugins/passkey/config"
	"github.com/better-go-auth/goauth/src/plugins/passkey/dtos"
	pkmodels "github.com/better-go-auth/goauth/src/plugins/passkey/models"
	"github.com/better-go-auth/goauth/src/plugins/passkey/repository"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// challengeTimeout is @simplewebauthn's default ceremony timeout (ms).
const challengeTimeout = 60000

// PasskeyService runs the registration and authentication ceremonies and manages stored passkeys.
type PasskeyService struct {
	cfg  pkconfig.PasskeyConfig
	kit  *pluginkit.Kit
	repo repository.IPasskeyRepo
}

// NewPasskeyService creates the passkey service.
func NewPasskeyService(cfg pkconfig.PasskeyConfig, kit *pluginkit.Kit, repo repository.IPasskeyRepo) *PasskeyService {
	return &PasskeyService{cfg: cfg, kit: kit, repo: repo}
}

// Repo returns the passkey repository.
func (s *PasskeyService) Repo() repository.IPasskeyRepo { return s.repo }

// challengeData is the JSON stored in the verification table under the challenge cookie's random ID
// (better-auth: {expectedChallenge, userData, context}).
type challengeData struct {
	ExpectedChallenge string        `json:"expectedChallenge"`
	UserData          challengeUser `json:"userData"`
	Context           *string       `json:"context,omitempty"`
}

type challengeUser struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

// RegisterOptionsQuery is the query of GET /passkey/generate-register-options.
type RegisterOptionsQuery struct {
	AuthenticatorAttachment string
	Name                    string
	Context                 *string
}

// ─── Options ─────────────────────────────────────────────────────────────────

// RegistrationOptions backs GET /passkey/generate-register-options: it resolves the user, builds the
// creation options, stores the challenge and returns the signed challenge cookie.
func (s *PasskeyService) RegistrationOptions(ctx context.Context, q RegisterOptionsQuery) (*dtos.RegistrationOptions, []http.Cookie, error) {
	// Step 1: resolve who the passkey is registered for (session user, or resolveUser without a session)
	user, err := s.resolveRegistrationUser(ctx, q)
	if err != nil {
		return nil, nil, err
	}

	// Step 2: exclude the credentials the user already registered
	existing, err := s.repo.ListByUser(ctx, user.ID)
	if err != nil {
		return nil, nil, err
	}
	exclude := make([]dtos.CredentialDescriptor, 0, len(existing))
	for _, pk := range existing {
		exclude = append(exclude, descriptor(pk))
	}

	// Step 3: resolve the extensions (credProps is always requested, like @simplewebauthn)
	ext, err := s.extensions(ctx, s.cfg.Registration.Extensions, s.cfg.Registration.ExtensionsFunc)
	if err != nil {
		return nil, nil, err
	}
	extensions := map[string]any{}
	for k, v := range ext {
		extensions[k] = v
	}
	extensions["credProps"] = true

	// Step 4: authenticator selection: better-auth defaults, plugin options, then the query's attachment
	sel := dtos.AuthenticatorSelection{ResidentKey: "preferred", UserVerification: "preferred"}
	if a := s.cfg.AuthenticatorSelection; a != nil {
		if a.ResidentKey != "" {
			sel.ResidentKey = a.ResidentKey
		}
		if a.UserVerification != "" {
			sel.UserVerification = a.UserVerification
		}
		if a.AuthenticatorAttachment != "" {
			sel.AuthenticatorAttachment = a.AuthenticatorAttachment
		}
	}
	if q.AuthenticatorAttachment != "" {
		sel.AuthenticatorAttachment = q.AuthenticatorAttachment
	}
	sel.RequireResidentKey = sel.ResidentKey == "required"

	// Step 5: build the options (user.id is a random handle, not the goauth user ID, like better-auth)
	userName := q.Name
	if userName == "" {
		userName = firstNonEmpty(user.Name, user.ID)
	}
	challenge, err := newChallenge()
	if err != nil {
		return nil, nil, err
	}
	params := make([]dtos.CredentialParameter, 0, len(defaultPubKeyCredParams))
	for _, alg := range defaultPubKeyCredParams {
		params = append(params, dtos.CredentialParameter{Alg: alg, Type: "public-key"})
	}
	opts := &dtos.RegistrationOptions{
		Challenge:              challenge,
		RP:                     dtos.RelyingParty{Name: s.rpName(), ID: s.rpID()},
		User:                   dtos.UserEntity{ID: base64.RawURLEncoding.EncodeToString([]byte(randomString(32, lowerDigits))), Name: userName, DisplayName: firstNonEmpty(user.DisplayName, user.Name, user.ID)},
		PubKeyCredParams:       params,
		Timeout:                challengeTimeout,
		Attestation:            "none",
		ExcludeCredentials:     exclude,
		AuthenticatorSelection: sel,
		Extensions:             extensions,
		Hints:                  []string{},
	}

	// Step 6: store the challenge and hand out the signed cookie pointing at it
	cookie, err := s.storeChallenge(ctx, challengeData{
		ExpectedChallenge: challenge,
		UserData:          challengeUser{ID: user.ID, Name: user.Name, DisplayName: user.DisplayName},
		Context:           q.Context,
	})
	if err != nil {
		return nil, nil, err
	}
	return opts, []http.Cookie{cookie}, nil
}

// AuthenticationOptions backs GET /passkey/generate-authenticate-options. With a session the user's
// credentials are listed in allowCredentials; without one the options allow discoverable credentials.
func (s *PasskeyService) AuthenticationOptions(ctx context.Context) (*dtos.AuthenticationOptions, []http.Cookie, error) {
	// Step 1: list the session user's passkeys (none without a session)
	var allow []dtos.CredentialDescriptor
	sw := s.kit.CurrentOrResolve(ctx)
	userID := ""
	if sw != nil {
		userID = sw.User.ID
		existing, err := s.repo.ListByUser(ctx, userID)
		if err != nil {
			return nil, nil, err
		}
		for _, pk := range existing {
			allow = append(allow, descriptor(pk))
		}
	}

	// Step 2: build the options
	ext, err := s.extensions(ctx, s.cfg.Authentication.Extensions, s.cfg.Authentication.ExtensionsFunc)
	if err != nil {
		return nil, nil, err
	}
	challenge, err := newChallenge()
	if err != nil {
		return nil, nil, err
	}
	opts := &dtos.AuthenticationOptions{
		RPID:             s.rpID(),
		Challenge:        challenge,
		AllowCredentials: allow,
		Timeout:          challengeTimeout,
		UserVerification: "preferred",
		Extensions:       ext,
	}

	// Step 3: store the challenge and hand out the signed cookie
	cookie, err := s.storeChallenge(ctx, challengeData{ExpectedChallenge: challenge, UserData: challengeUser{ID: userID}})
	if err != nil {
		return nil, nil, err
	}
	return opts, []http.Cookie{cookie}, nil
}

// ─── Verification ────────────────────────────────────────────────────────────

// VerifyRegistration backs POST /passkey/verify-registration: it consumes the challenge, verifies the
// attestation and stores the new passkey.
func (s *PasskeyService) VerifyRegistration(ctx context.Context, body dtos.VerifyRegistrationBody) (*pkmodels.Passkey, error) {
	// Step 1: the expected origin is the configured one or the request's Origin header
	origins := s.expectedOrigins(ctx)
	if len(origins) == 0 {
		return nil, ErrRegistrationRejected
	}

	// Step 2: consume the challenge referenced by the signed cookie
	data, err := s.consumeChallenge(ctx)
	if err != nil {
		return nil, err
	}

	// Step 3: a signed-in user may only finish a registration started for themselves
	sw := s.kit.CurrentOrResolve(ctx)
	if sw != nil && sw.User.ID != "" && data.UserData.ID != sw.User.ID {
		return nil, ErrNotAllowedToRegisterPasskey
	}

	// Step 4: verify the attestation (any failure is better-auth's 500, a bad statement its 400)
	respMap, _ := body.Response.(map[string]any)
	raw, err := json.Marshal(body.Response)
	if err != nil || respMap == nil {
		return nil, ErrRegistrationFailed
	}
	res, err := verifyRegistration(raw, data.ExpectedChallenge, origins, s.rpID())
	if err != nil {
		slog.Error("passkey: failed to verify registration", "error", err)
		if isErr(err, errAttestationStatement) {
			return nil, ErrRegistrationRejected
		}
		return nil, ErrRegistrationFailed
	}

	// Step 5: let the app move the passkey to another user or name it
	targetUserID := data.UserData.ID
	var name *string
	if body.Name != nil {
		if n := strings.TrimSpace(*body.Name); n != "" {
			name = &n
		}
	}
	if hook := s.cfg.Registration.AfterVerification; hook != nil {
		result, err := hook(ctx, pkconfig.RegistrationVerification{
			Request:      s.kit.Request(ctx),
			User:         pkconfig.RegistrationUser{ID: data.UserData.ID, Name: firstNonEmpty(data.UserData.Name, data.UserData.ID), DisplayName: data.UserData.DisplayName},
			CredentialID: res.CredentialID,
			PublicKey:    res.PublicKey,
			AAGUID:       res.AAGUID,
			ClientData:   respMap,
			Context:      data.Context,
		})
		if err != nil {
			return nil, err
		}
		if result != nil {
			if result.UserID != "" {
				if sw != nil && sw.User.ID != "" && result.UserID != sw.User.ID {
					return nil, ErrNotAllowedToRegisterPasskey
				}
				targetUserID = result.UserID
			}
			if n := strings.TrimSpace(result.Name); name == nil && n != "" {
				name = &n
			}
		}
	}

	// Step 6: store the passkey in better-auth's format
	transports := joinTransports(respMap)
	now := time.Now().UTC()
	pk := &pkmodels.Passkey{
		ID:           s.kit.NewID(),
		Name:         name,
		PublicKey:    base64.StdEncoding.EncodeToString(res.PublicKey),
		UserID:       targetUserID,
		CredentialID: res.CredentialID,
		Counter:      int64(res.Counter),
		DeviceType:   res.DeviceType,
		BackedUp:     res.BackedUp,
		Transports:   &transports,
		CreatedAt:    &now,
		AAGUID:       &res.AAGUID,
	}
	if err := s.repo.Create(ctx, pk); err != nil {
		slog.Error("passkey: failed to store passkey", "error", err)
		return nil, ErrRegistrationFailed
	}
	return pk, nil
}

// VerifyAuthentication backs POST /passkey/verify-authentication: it consumes the challenge, verifies the
// assertion against the stored passkey, bumps its counter and signs the user in.
func (s *PasskeyService) VerifyAuthentication(ctx context.Context, body dtos.VerifyAuthenticationBody) (*modeldtos.SessionWithUser, []http.Cookie, error) {
	// Step 1: the expected origin is the configured one or the request's Origin header
	origins := s.expectedOrigins(ctx)
	if len(origins) == 0 {
		return nil, nil, ErrOriginMissing
	}

	// Step 2: consume the challenge referenced by the signed cookie
	data, err := s.consumeChallenge(ctx)
	if err != nil {
		return nil, nil, err
	}

	// Step 3: look the credential up by its base64url ID
	credID, _ := body.Response["id"].(string)
	pk, err := s.repo.FindByCredentialID(ctx, credID)
	if err != nil {
		return nil, nil, err
	}
	if pk == nil || credID == "" {
		return nil, nil, ErrPasskeyUnknown
	}

	// Step 4: verify the assertion (bad signature: 401, anything else: 400, like better-auth)
	publicKey, err := decodeStoredPublicKey(pk.PublicKey)
	if err != nil {
		return nil, nil, ErrAuthenticationFailed
	}
	raw, err := json.Marshal(body.Response)
	if err != nil {
		return nil, nil, ErrAuthenticationFailed
	}
	res, err := verifyAuthentication(raw, data.ExpectedChallenge, origins, s.rpID(), publicKey, uint32(max(pk.Counter, 0)))
	if err != nil {
		slog.Error("passkey: failed to verify authentication", "error", err)
		if isErr(err, errSignature) {
			return nil, nil, ErrAuthenticationUnverified
		}
		return nil, nil, ErrAuthenticationFailed
	}

	// Step 5: app hook (may veto the sign-in)
	if hook := s.cfg.Authentication.AfterVerification; hook != nil {
		if err := hook(ctx, pkconfig.AuthenticationVerification{
			Request: s.kit.Request(ctx), CredentialID: pk.CredentialID, UserID: pk.UserID, NewCounter: res.NewCounter, ClientData: body.Response,
		}); err != nil {
			return nil, nil, err
		}
	}

	// Step 6: remember the new signature counter
	if err := s.repo.UpdateCounter(ctx, pk.ID, int64(res.NewCounter)); err != nil {
		return nil, nil, ErrAuthenticationFailed
	}

	// Step 7: create the session and its cookies
	user, err := pluginkit.AcceptNotFound(s.kit.Repos.FindUserByID(ctx, pk.UserID))
	if err != nil || user == nil {
		return nil, nil, ErrUserNotFound
	}
	sw, err := s.kit.CreateSession(ctx, user, false)
	if err != nil {
		if pluginkit.Code(err) == "FAILED_TO_CREATE_SESSION" {
			return nil, nil, ErrUnableToCreateSession
		}
		return nil, nil, err
	}
	return sw, s.kit.SessionCookies(sw, false), nil
}

// ─── Management ──────────────────────────────────────────────────────────────

// List backs GET /passkey/list-user-passkeys.
func (s *PasskeyService) List(ctx context.Context, userID string) ([]pkmodels.Passkey, error) {
	return s.repo.ListByUser(ctx, userID)
}

// owned is better-auth's requireResourceOwnership: 400 without id, 404 for unknown, forbidden otherwise.
func (s *PasskeyService) owned(ctx context.Context, userID, id string, forbidden error) (*pkmodels.Passkey, error) {
	if id == "" {
		return nil, ErrMissingID
	}
	pk, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if pk == nil {
		return nil, ErrPasskeyNotFound
	}
	if pk.UserID != userID {
		return nil, forbidden
	}
	return pk, nil
}

// Delete backs POST /passkey/delete-passkey.
func (s *PasskeyService) Delete(ctx context.Context, userID, id string) error {
	// Step 1: only the owner may delete the passkey
	if _, err := s.owned(ctx, userID, id, ErrForbidden); err != nil {
		return err
	}
	// Step 2: delete it
	return s.repo.Delete(ctx, id)
}

// Update backs POST /passkey/update-passkey (rename).
func (s *PasskeyService) Update(ctx context.Context, userID, id, name string) (*pkmodels.Passkey, error) {
	// Step 1: only the owner may rename the passkey
	if _, err := s.owned(ctx, userID, id, ErrNotAllowedToRegisterPasskey); err != nil {
		return nil, err
	}
	// Step 2: rename and return the updated row
	pk, err := s.repo.UpdateName(ctx, id, name)
	if err != nil || pk == nil {
		return nil, ErrFailedToUpdatePasskey
	}
	return pk, nil
}

// DeleteUserPasskeys removes every passkey of a deleted user.
func (s *PasskeyService) DeleteUserPasskeys(ctx context.Context, userID string) error {
	return s.repo.DeleteByUser(ctx, userID)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// resolveRegistrationUser is better-auth's resolveRegistrationUser.
func (s *PasskeyService) resolveRegistrationUser(ctx context.Context, q RegisterOptionsQuery) (*pkconfig.RegistrationUser, error) {
	// Step 1: with requireSession the (fresh) session user registers
	sw := s.kit.CurrentOrResolve(ctx)
	if s.cfg.RequireSession() && (sw == nil || sw.User.ID == "") {
		return nil, ErrSessionRequired
	}
	if sw != nil && sw.User.ID != "" {
		name := firstNonEmpty(sw.User.Email, sw.User.ID)
		return &pkconfig.RegistrationUser{ID: sw.User.ID, Name: name, DisplayName: name}, nil
	}
	// Step 2: without a session the app resolves the user
	if s.cfg.Registration.ResolveUser == nil {
		return nil, ErrResolveUserRequired
	}
	u, err := s.cfg.Registration.ResolveUser(ctx, pkconfig.ResolveUserInput{Request: s.kit.Request(ctx), Context: q.Context})
	if err != nil {
		return nil, err
	}
	if u == nil || u.ID == "" || u.Name == "" {
		return nil, ErrResolvedUserInvalid
	}
	return u, nil
}

// storeChallenge saves data in the verification table under a random ID and returns the signed cookie.
func (s *PasskeyService) storeChallenge(ctx context.Context, data challengeData) (http.Cookie, error) {
	// Step 1: serialize the challenge data
	value, err := json.Marshal(data)
	if err != nil {
		return http.Cookie{}, err
	}
	// Step 2: store it for the challenge lifetime under a random identifier
	token := randomString(32, allChars)
	_, err = s.kit.Repos.UpsertVerificationValue(ctx, &models.Verification{
		Base:       models.Base{ID: s.kit.NewID()},
		Identifier: token,
		Value:      string(value),
		ExpiresAt:  time.Now().Add(pkconfig.DefaultChallengeMaxAgeSeconds * time.Second).UTC(),
	})
	if err != nil {
		return http.Cookie{}, err
	}
	// Step 3: sign the identifier into the challenge cookie
	return s.kit.Cookies.SignedCookie(s.cfg.ChallengeCookie(), token, pkconfig.DefaultChallengeMaxAgeSeconds), nil
}

// consumeChallenge reads the challenge cookie and consumes the stored challenge (single use).
func (s *PasskeyService) consumeChallenge(ctx context.Context) (*challengeData, error) {
	// Step 1: the signed cookie carries the verification identifier
	token, ok := s.kit.ReadSignedCookie(ctx, s.cfg.ChallengeCookie())
	if !ok || token == "" {
		return nil, ErrChallengeNotFound
	}
	// Step 2: consume it so a challenge works once
	v, err := pluginkit.AcceptNotFound(s.kit.Repos.ConsumeVerificationValue(ctx, token))
	if err != nil || v == nil || v.IsExpired() {
		return nil, ErrChallengeNotFound
	}
	// Step 3: decode the stored data
	var data challengeData
	if err := json.Unmarshal([]byte(v.Value), &data); err != nil {
		return nil, ErrChallengeNotFound
	}
	return &data, nil
}

// expectedOrigins is better-auth's `options.origin || ctx.headers.get("origin")`.
func (s *PasskeyService) expectedOrigins(ctx context.Context) []string {
	if len(s.cfg.Origin) > 0 {
		return s.cfg.Origin
	}
	if req := s.kit.Request(ctx); req != nil {
		if o := req.Header.Get("Origin"); o != "" {
			return []string{o}
		}
	}
	return nil
}

// rpID is better-auth's getRpID: the option, the BaseURL hostname, or "localhost".
func (s *PasskeyService) rpID() string {
	if s.cfg.RPID != "" {
		return s.cfg.RPID
	}
	if s.kit.Conf.BaseURL != "" {
		if u, err := url.Parse(s.kit.Conf.BaseURL); err == nil && u.Hostname() != "" {
			return u.Hostname()
		}
	}
	return "localhost"
}

// rpName is the option or the app name.
func (s *PasskeyService) rpName() string {
	if s.cfg.RPName != "" {
		return s.cfg.RPName
	}
	return s.kit.Conf.AppName
}

// extensions resolves static or per-request extensions.
func (s *PasskeyService) extensions(ctx context.Context, static map[string]any, fn pkconfig.ExtensionsFunc) (map[string]any, error) {
	if fn != nil {
		return fn(ctx, s.kit.Request(ctx))
	}
	return static, nil
}

// descriptor builds an excludeCredentials / allowCredentials entry. Like better-auth, the stored transports
// are split on commas (an empty string yields [""]).
func descriptor(pk pkmodels.Passkey) dtos.CredentialDescriptor {
	d := dtos.CredentialDescriptor{ID: strings.TrimRight(pk.CredentialID, "="), Type: "public-key"}
	if pk.Transports != nil {
		d.Transports = strings.Split(*pk.Transports, ",")
	}
	return d
}

// joinTransports is better-auth's `resp.response.transports?.join(",") ?? ""`.
func joinTransports(resp map[string]any) string {
	inner, _ := resp["response"].(map[string]any)
	list, _ := inner["transports"].([]any)
	parts := make([]string, 0, len(list))
	for _, t := range list {
		if v, ok := t.(string); ok {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, ",")
}

// newChallenge is @simplewebauthn's generateChallenge: 32 random bytes, base64url.
func newChallenge() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

const (
	lowerDigits = "abcdefghijklmnopqrstuvwxyz0123456789"
	allChars    = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_"
)

// randomString is better-auth's generateRandomString over alphabet.
func randomString(n int, alphabet string) string {
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			panic(err)
		}
		out[i] = alphabet[v.Int64()]
	}
	return string(out)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func isErr(err, target error) bool { return errors.Is(err, target) }
