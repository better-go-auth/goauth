package humaadmin

import (
	"context"
	"net/http"

	humaadapter "github.com/better-go-auth/goauth/src/app/adapters/huma"
	humaauth "github.com/better-go-auth/goauth/src/common/types"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/models/dtos"
	adminconfig "github.com/better-go-auth/goauth/src/plugins/admin/config"
	admindtos "github.com/better-go-auth/goauth/src/plugins/admin/dtos"
)

// ListUserSessions handles POST /api/auth/admin/list-user-sessions.
func (h *AdminHandler) ListUserSessions(ctx context.Context, input *humatypes.HumaReqBody[admindtos.AdminListUserSessionsInput]) (*humatypes.HumaRes[admindtos.AdminListUserSessionsResponse], error) {
	session, err := h.RequirePermission(ctx, input.AuthHeaders, adminconfig.PermSessionList, adminconfig.ErrNotAllowedToListUsersSessions)
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
	session, err := h.RequirePermission(ctx, input.AuthHeaders, adminconfig.PermSessionRevoke, adminconfig.ErrNotAllowedToRevokeUserSessions)
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
	session, err := h.RequirePermission(ctx, input.AuthHeaders, adminconfig.PermSessionRevoke, adminconfig.ErrNotAllowedToRevokeUserSessions)
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
	adminSession, err := h.RequirePermission(ctx, input.AuthHeaders, adminconfig.PermUserImpersonate, adminconfig.ErrNotAllowedToImpersonateUsers)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	meta := dtos.RequestMeta{}
	signInResp, err := h.Admin.ImpersonateUser(ctx, input.Body, &adminSession.User, meta)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	// keep the admin's own session token in the admin_session cookie (restored by stop-impersonating)
	// and switch the session cookie to the impersonation session, like better-auth
	var cookies []http.Cookie
	if adminToken := h.adminSessionToken(ctx, adminSession, input.AuthHeaders); h.Cookies != nil && adminToken != "" && signInResp.Token != "" {
		cookies = h.Cookies.AdminSessionCookies(adminToken, signInResp.Token)
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

// adminSessionToken returns the caller's own session token: from the resolved session, else the
// verified session cookie, else the bearer token a transport middleware resolved.
func (h *AdminHandler) adminSessionToken(ctx context.Context, session *dtos.SessionWithUser, auth humatypes.AuthHeaders) string {
	// Step 1: the resolved session carries it
	if session != nil && session.Session.Token != "" {
		return session.Session.Token
	}
	// Step 2: the signed session cookie of the request
	if h.Cookies != nil {
		if tok, ok := h.Cookies.SessionToken(auth.Cookie); ok && tok != "" {
			return tok
		}
	}
	// Step 3: a bearer token resolved by the bearer / access-token plugin
	if tok, ok := humaadapter.FromBearerContext(ctx); ok {
		return tok
	}
	return ""
}
