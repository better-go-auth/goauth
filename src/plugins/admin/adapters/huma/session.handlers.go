package humaadmin

import (
	"context"

	humaauth "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/models/dtos"

	// svcinterfaces "github.com/better-go-auth/goauth/core/services/interfaces"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	admindtos "github.com/better-go-auth/goauth/src/plugins/admin/dtos"
)

// ListUserSessions handles POST /api/auth/admin/list-user-sessions.
func (h *AdminHandler) ListUserSessions(ctx context.Context, input *ListUserSessionsInput) (*ListUserSessionsOutput, error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}

	sessions, err := h.Admin.ListUserSessions(ctx, input.Body, session.User.ID)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return &ListUserSessionsOutput{
		Body: admindtos.AdminListUserSessionsResponse{Sessions: sessions},
	}, nil
}

// RevokeUserSession handles POST /api/auth/admin/revoke-user-session.
func (h *AdminHandler) RevokeUserSession(ctx context.Context, input *RevokeUserSessionInput) (*RevokeUserSessionOutput, error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	if err := h.Admin.RevokeUserSession(ctx, input.Body, session.User.ID); err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return &RevokeUserSessionOutput{
		Body: admindtos.AdminStatusResponse{Status: true},
	}, nil
}

// RevokeUserSessions handles POST /api/auth/admin/revoke-user-sessions.
func (h *AdminHandler) RevokeUserSessions(ctx context.Context, input *RevokeUserSessionsInput) (*RevokeUserSessionsOutput, error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	if err := h.Admin.RevokeUserSessions(ctx, input.Body, session.User.ID); err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return &RevokeUserSessionsOutput{
		Body: admindtos.AdminStatusResponse{Status: true},
	}, nil
}

// ImpersonateUser handles POST /api/auth/admin/impersonate-user.
func (h *AdminHandler) ImpersonateUser(ctx context.Context, input *ImpersonateUserInput) (*ImpersonateUserOutput, error) {
	adminSession, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	meta := dtos.RequestMeta{}
	signInResp, err := h.Admin.ImpersonateUser(ctx, input.Body, adminSession.User, meta)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	// cookies := h.EmitSessionCookies(signInResp.User, signInResp.SessionData, true)

	return &ImpersonateUserOutput{
		// SetCookie: cookies,
		Body: dtos.SessionResponse{
			Session: signInResp.SessionData,
			User:    signInResp.User,
		},
	}, nil
}

// StopImpersonating handles POST /api/auth/admin/stop-impersonating.
func (h *AdminHandler) StopImpersonating(ctx context.Context, input *StopImpersonatingInput) (*StopImpersonatingOutput, error) {
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	if err := h.Admin.StopImpersonating(ctx, session.Session.Token); err != nil {
		return nil, humaauth.RespondErr(err)
	}

	// jar := map[string]string{}
	// cookies := h.DeleteSessionCookies(false, jar)

	return &StopImpersonatingOutput{
		// SetCookie: cookies,
		Body: admindtos.AdminStatusResponse{
			Status:  true,
			Message: "Impersonation session terminated successfully",
		},
	}, nil
}
