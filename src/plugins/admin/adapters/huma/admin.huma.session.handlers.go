package humaadmin

import (
	"context"
	"net/http"

	humaauth "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/models/dtos"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	admindtos "github.com/better-go-auth/goauth/src/plugins/admin/dtos"
)

// ListUserSessions handles POST /api/auth/admin/list-user-sessions.
func (h *AdminHandler) ListUserSessions(ctx context.Context, input *humatypes.HumaReqBody[admindtos.AdminListUserSessionsInput]) (*humatypes.HumaRes[admindtos.AdminListUserSessionsResponse], error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humatypes.RespondErr(err)
	}

	sessions, err := h.Admin.ListUserSessions(ctx, input.Body, session.User.ID)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return humatypes.MakeResPtr(&admindtos.AdminListUserSessionsResponse{Sessions: sessions}, 200), nil
}

// RevokeUserSession handles POST /api/auth/admin/revoke-user-session.
func (h *AdminHandler) RevokeUserSession(ctx context.Context, input *humatypes.HumaReqBody[admindtos.AdminRevokeUserSessionInput]) (*humatypes.HumaRes[admindtos.AdminStatusResponse], error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	if err := h.Admin.RevokeUserSession(ctx, input.Body, session.User.ID); err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return humatypes.MakeResPtr(&admindtos.AdminStatusResponse{Status: true}, 200), nil
}

// RevokeUserSessions handles POST /api/auth/admin/revoke-user-sessions.
func (h *AdminHandler) RevokeUserSessions(ctx context.Context, input *humatypes.HumaReqBody[admindtos.AdminRevokeUserSessionsInput]) (*humatypes.HumaRes[admindtos.AdminStatusResponse], error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	if err := h.Admin.RevokeUserSessions(ctx, input.Body, session.User.ID); err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return humatypes.MakeResPtr(&admindtos.AdminStatusResponse{Status: true}, 200), nil
}

// ImpersonateUser handles POST /api/auth/admin/impersonate-user.
func (h *AdminHandler) ImpersonateUser(ctx context.Context, input *humatypes.HumaReqBody[admindtos.AdminImpersonateUserInput]) (*humatypes.HumaRes[dtos.SessionWithUser], error) {
	adminSession, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	meta := dtos.RequestMeta{}
	signInResp, err := h.Admin.ImpersonateUser(ctx, input.Body, &adminSession.User, meta)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	var cookies []http.Cookie
	if h.Cookies != nil && adminSession.Session.Token != "" && signInResp.Token != "" {
		cookies = h.Cookies.AdminSessionCookies(adminSession.Session.Token, signInResp.Token)
	}

	
	// sessionWithUsr:= dtos
	return humatypes.MakeResPtr(dtos.ToSessionWithUser(signInResp.SessionData, signInResp.User), 200, cookies...), nil
}

// StopImpersonating handles POST /api/auth/admin/stop-impersonating.
func (h *AdminHandler) StopImpersonating(ctx context.Context, input *humatypes.HumaReqBody[admindtos.AdminStopImpersonatingInput]) (*humatypes.HumaRes[admindtos.AdminStatusResponse], error) {
	session, err := h.Authenticate(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	if err := h.Admin.StopImpersonating(ctx, session.Session.ID); err != nil {
		return nil, humaauth.RespondErr(err)
	}

	var cookies []http.Cookie
	if h.Cookies != nil {
		adminTok, hasAdmin := h.Cookies.AdminSessionToken(input.Cookie)
		if hasAdmin && adminTok != "" {
			cookies = append(cookies, h.Cookies.SessionCookies(adminTok, false)...)
		}
		cookies = append(cookies, h.Cookies.ExpireAdminSessionCookie())
	}

	return humatypes.MakeResPtr(&admindtos.AdminStatusResponse{
		Status:  true,
		Message: "Impersonation session terminated successfully",
	}, 200, cookies...), nil
}
