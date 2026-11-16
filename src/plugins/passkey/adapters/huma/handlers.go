// Package humapasskey mounts the passkey endpoints on Huma.
package humapasskey

import (
	"context"
	"net/http"
	"strings"

	"github.com/better-go-auth/goauth/src/plugins/passkey/dtos"
	pkmodels "github.com/better-go-auth/goauth/src/plugins/passkey/models"
	"github.com/better-go-auth/goauth/src/plugins/passkey/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// Handler serves the passkey endpoints.
type Handler struct {
	Service *services.PasskeyService
	Kit     *pluginkit.Kit
}

// NewHandler creates the passkey HTTP handler.
func NewHandler(svc *services.PasskeyService, kit *pluginkit.Kit) *Handler {
	return &Handler{Service: svc, Kit: kit}
}

// errNameTooSmall is zod's `z.string().trim().min(1)` failure on update-passkey.
var errNameTooSmall = pluginkit.NewError(http.StatusBadRequest, "VALIDATION_ERROR", "[body.name] Too small: expected string to have >=1 characters")

// ─── Options ─────────────────────────────────────────────────────────────────

type registerOptionsInput struct {
	AuthenticatorAttachment string `query:"authenticatorAttachment" enum:"platform,cross-platform" required:"false"`
	Name                    string `query:"name" required:"false"`
	Context                 string `query:"context" required:"false"`
}

type registerOptionsOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      *dtos.RegistrationOptions
}

// GenerateRegisterOptions handles GET /passkey/generate-register-options.
func (h *Handler) GenerateRegisterOptions(ctx context.Context, in *registerOptionsInput) (*registerOptionsOutput, error) {
	// Step 1: map the query (context is only forwarded when sent)
	q := services.RegisterOptionsQuery{AuthenticatorAttachment: in.AuthenticatorAttachment, Name: in.Name}
	if req := h.Kit.Request(ctx); req != nil && req.URL.Query().Has("context") {
		c := in.Context
		q.Context = &c
	}
	// Step 2: build the options and the challenge cookie
	opts, cookies, err := h.Service.RegistrationOptions(ctx, q)
	if err != nil {
		return nil, err
	}
	return &registerOptionsOutput{SetCookie: cookies, Body: opts}, nil
}

type authenticateOptionsOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      *dtos.AuthenticationOptions
}

// GenerateAuthenticateOptions handles GET /passkey/generate-authenticate-options.
func (h *Handler) GenerateAuthenticateOptions(ctx context.Context, _ *struct{}) (*authenticateOptionsOutput, error) {
	opts, cookies, err := h.Service.AuthenticationOptions(ctx)
	if err != nil {
		return nil, err
	}
	return &authenticateOptionsOutput{SetCookie: cookies, Body: opts}, nil
}

// ─── Verification ────────────────────────────────────────────────────────────

type verifyRegistrationInput struct {
	Body dtos.VerifyRegistrationBody
}

type passkeyOutput struct {
	Body *pkmodels.Passkey
}

// VerifyRegistration handles POST /passkey/verify-registration.
func (h *Handler) VerifyRegistration(ctx context.Context, in *verifyRegistrationInput) (*passkeyOutput, error) {
	pk, err := h.Service.VerifyRegistration(ctx, in.Body)
	if err != nil {
		return nil, err
	}
	return &passkeyOutput{Body: pk}, nil
}

type verifyAuthenticationInput struct {
	Body dtos.VerifyAuthenticationBody
}

type verifyAuthenticationOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      *dtos.SessionResponse
}

// VerifyAuthentication handles POST /passkey/verify-authentication.
func (h *Handler) VerifyAuthentication(ctx context.Context, in *verifyAuthenticationInput) (*verifyAuthenticationOutput, error) {
	sw, cookies, err := h.Service.VerifyAuthentication(ctx, in.Body)
	if err != nil {
		return nil, err
	}
	return &verifyAuthenticationOutput{SetCookie: cookies, Body: sw}, nil
}

// ─── Management ──────────────────────────────────────────────────────────────

type listOutput struct {
	Body []pkmodels.Passkey
}

// ListUserPasskeys handles GET /passkey/list-user-passkeys.
func (h *Handler) ListUserPasskeys(ctx context.Context, _ *struct{}) (*listOutput, error) {
	sw := h.Kit.Current(ctx)
	list, err := h.Service.List(ctx, sw.User.ID)
	if err != nil {
		return nil, err
	}
	return &listOutput{Body: list}, nil
}

type deleteInput struct {
	Body dtos.DeletePasskeyBody
}

type statusOutput struct {
	Body dtos.StatusResponse
}

// DeletePasskey handles POST /passkey/delete-passkey.
func (h *Handler) DeletePasskey(ctx context.Context, in *deleteInput) (*statusOutput, error) {
	sw := h.Kit.Current(ctx)
	if err := h.Service.Delete(ctx, sw.User.ID, in.Body.ID); err != nil {
		return nil, err
	}
	return &statusOutput{Body: dtos.StatusResponse{Status: true}}, nil
}

type updateInput struct {
	Body dtos.UpdatePasskeyBody
}

type updateOutput struct {
	Body struct {
		Passkey *pkmodels.Passkey `json:"passkey"`
	}
}

// UpdatePasskey handles POST /passkey/update-passkey.
func (h *Handler) UpdatePasskey(ctx context.Context, in *updateInput) (*updateOutput, error) {
	// Step 1: the name is trimmed and must not be empty (zod: trim().min(1))
	name := strings.TrimSpace(in.Body.Name)
	if name == "" {
		return nil, errNameTooSmall
	}
	// Step 2: rename the caller's passkey
	sw := h.Kit.Current(ctx)
	pk, err := h.Service.Update(ctx, sw.User.ID, in.Body.ID, name)
	if err != nil {
		return nil, err
	}
	out := &updateOutput{}
	out.Body.Passkey = pk
	return out, nil
}
