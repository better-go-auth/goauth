// Package humamultisession mounts the multi-session plugin endpoints on a Huma API.
package humamultisession

import (
	"context"
	"net/http"

	modeldtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/plugins/multi-session/dtos"
	"github.com/better-go-auth/goauth/src/plugins/multi-session/services"
	"github.com/danielgtaylor/huma/v2"
)

// Handler adapts MultiSessionService to Huma operations.
type Handler struct {
	Service *services.MultiSessionService
}

// NewHandler builds the Huma handler.
func NewHandler(svc *services.MultiSessionService) *Handler { return &Handler{Service: svc} }

// ─── GET /multi-session/list-device-sessions ─────────────────────────────────

type listInput struct {
	Cookie string `header:"Cookie"`
}

type listOutput struct {
	Body []modeldtos.SessionWithUser
}

// ListDeviceSessions lists the device's sessions, one per user.
func (h *Handler) ListDeviceSessions(ctx context.Context, in *listInput) (*listOutput, error) {
	return &listOutput{Body: h.Service.ListDeviceSessions(ctx, in.Cookie)}, nil
}

// ─── POST /multi-session/set-active ──────────────────────────────────────────

type sessionTokenInput struct {
	Cookie string `header:"Cookie"`
	Body   struct {
		dtos.SessionTokenInput
		_ struct{} `json:"-" additionalProperties:"true"`
	}
}

type setActiveOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      modeldtos.SessionWithUser
}

// SetActive switches the device's active session.
func (h *Handler) SetActive(ctx context.Context, in *sessionTokenInput) (*setActiveOutput, error) {
	sw, ck, err := h.Service.SetActive(ctx, in.Cookie, in.Body.SessionToken)
	if err != nil {
		// an unknown session still expires its multi-session cookie, like better-auth
		if len(ck) > 0 {
			return nil, huma.ErrorWithHeaders(err, cookieHeaders(ck))
		}
		return nil, err
	}
	return &setActiveOutput{SetCookie: ck, Body: *sw}, nil
}

// ─── POST /multi-session/revoke ──────────────────────────────────────────────

type revokeOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      dtos.StatusResponse
}

// Revoke deletes one of the device's sessions.
func (h *Handler) Revoke(ctx context.Context, in *sessionTokenInput) (*revokeOutput, error) {
	ck, err := h.Service.Revoke(ctx, in.Cookie, h.Service.Kit().Current(ctx), in.Body.SessionToken)
	if err != nil {
		return nil, err
	}
	return &revokeOutput{SetCookie: ck, Body: dtos.StatusResponse{Status: true}}, nil
}

func cookieHeaders(cs []http.Cookie) http.Header {
	h := http.Header{}
	for _, c := range cs {
		if v := c.String(); v != "" {
			h.Add("Set-Cookie", v)
		}
	}
	return h
}
