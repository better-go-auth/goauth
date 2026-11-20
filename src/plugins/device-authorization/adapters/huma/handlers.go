// Package humadevice mounts the device-authorization endpoints on a Huma API.
package humadevice

import (
	"context"
	"net/http"
	"strings"

	modeldtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins/device-authorization/dtos"
	"github.com/better-go-auth/goauth/src/plugins/device-authorization/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// Handler adapts the device-authorization Service to Huma operations.
type Handler struct {
	Service *services.Service
}

// NewHandler builds the Huma handler.
func NewHandler(svc *services.Service) *Handler { return &Handler{Service: svc} }

// ─── validation (better-call / zod messages) ─────────────────────────────────

// issues collects zod style validation issues ("[body.client_id] Invalid input: ...").
type issues []string

// requireString records a missing string field.
func (is *issues) requireString(loc string, v *string) {
	if v == nil {
		*is = append(*is, "["+loc+"] Invalid input: expected string, received undefined")
	}
}

// err returns the 400 VALIDATION_ERROR for the collected issues, or nil.
func (is issues) err() error {
	if len(is) == 0 {
		return nil
	}
	return pluginkit.NewError(http.StatusBadRequest, "VALIDATION_ERROR", strings.Join(is, "; "))
}

// ─── POST /device/code ───────────────────────────────────────────────────────

type deviceCodeInput struct {
	Body struct {
		dtos.DeviceCodeRequest
		_ struct{} `json:"-" additionalProperties:"true"`
	}
}

type deviceCodeOutput struct {
	CacheControl string `header:"Cache-Control"`
	Body         dtos.DeviceCodeResponse
}

// DeviceCode issues a device code and a user code (RFC 8628 §3.1/3.2).
func (h *Handler) DeviceCode(ctx context.Context, in *deviceCodeInput) (*deviceCodeOutput, error) {
	// Step 1: client_id is required
	var is issues
	is.requireString("body.client_id", in.Body.ClientID)
	if err := is.err(); err != nil {
		return nil, err
	}
	// Step 2: create the pending authorization
	res, err := h.Service.RequestCode(ctx, *in.Body.ClientID, in.Body.Scope)
	if err != nil {
		return nil, err
	}
	return &deviceCodeOutput{CacheControl: "no-store", Body: *res}, nil
}

// ─── POST /device/token ──────────────────────────────────────────────────────

type deviceTokenInput struct {
	Body struct {
		dtos.DeviceTokenRequest
		_ struct{} `json:"-" additionalProperties:"true"`
	}
}

type deviceTokenOutput struct {
	CacheControl string `header:"Cache-Control"`
	Pragma       string `header:"Pragma"`
	Body         dtos.DeviceTokenResponse
}

// DeviceToken exchanges an approved device code for a session token (RFC 8628 §3.4/3.5).
func (h *Handler) DeviceToken(ctx context.Context, in *deviceTokenInput) (*deviceTokenOutput, error) {
	// Step 1: the grant type must be the device code grant; device_code and client_id are required
	var is issues
	if in.Body.GrantType == nil || *in.Body.GrantType != dtos.GrantTypeDeviceCode {
		is = append(is, `[body.grant_type] Invalid input: expected "`+dtos.GrantTypeDeviceCode+`"`)
	}
	is.requireString("body.device_code", in.Body.DeviceCode)
	is.requireString("body.client_id", in.Body.ClientID)
	if err := is.err(); err != nil {
		return nil, err
	}
	// Step 2: poll
	res, err := h.Service.Token(ctx, *in.Body.DeviceCode, *in.Body.ClientID)
	if err != nil {
		return nil, err
	}
	return &deviceTokenOutput{CacheControl: "no-store", Pragma: "no-cache", Body: *res}, nil
}

// ─── GET /device ─────────────────────────────────────────────────────────────

type deviceVerifyInput struct {
	UserCode string `query:"user_code" doc:"The user code to verify"`
}

type deviceVerifyOutput struct {
	Body dtos.DeviceVerifyResponse
}

// DeviceVerify checks a user code and claims it for the signed-in user.
func (h *Handler) DeviceVerify(ctx context.Context, in *deviceVerifyInput) (*deviceVerifyOutput, error) {
	// Step 1: user_code is required (an empty query value is a string, like better-call)
	if req := h.Service.Kit().Request(ctx); req != nil && !req.URL.Query().Has("user_code") {
		return nil, issues{"[query.user_code] Invalid input: expected string, received undefined"}.err()
	}
	// Step 2: verify and claim
	res, err := h.Service.Verify(ctx, in.UserCode, h.Service.Kit().Current(ctx))
	if err != nil {
		return nil, err
	}
	return &deviceVerifyOutput{Body: *res}, nil
}

// ─── POST /device/approve, POST /device/deny ─────────────────────────────────

type deviceDecisionInput struct {
	Body struct {
		dtos.DeviceDecisionRequest
		_ struct{} `json:"-" additionalProperties:"true"`
	}
}

type deviceDecisionOutput struct {
	Body dtos.DeviceSuccessResponse
}

// DeviceApprove approves a claimed device code.
func (h *Handler) DeviceApprove(ctx context.Context, in *deviceDecisionInput) (*deviceDecisionOutput, error) {
	return h.decide(ctx, in, h.Service.Approve)
}

// DeviceDeny denies a claimed device code.
func (h *Handler) DeviceDeny(ctx context.Context, in *deviceDecisionInput) (*deviceDecisionOutput, error) {
	return h.decide(ctx, in, h.Service.Deny)
}

// decide validates the body and records the decision.
func (h *Handler) decide(ctx context.Context, in *deviceDecisionInput, fn func(context.Context, string, *modeldtos.SessionWithUser) error) (*deviceDecisionOutput, error) {
	// Step 1: userCode is required
	var is issues
	is.requireString("body.userCode", in.Body.UserCode)
	if err := is.err(); err != nil {
		return nil, err
	}
	// Step 2: the session check happens in the service (better-auth's own 401 body)
	if err := fn(ctx, *in.Body.UserCode, h.Service.Kit().Current(ctx)); err != nil {
		return nil, err
	}
	return &deviceDecisionOutput{Body: dtos.DeviceSuccessResponse{Success: true}}, nil
}
