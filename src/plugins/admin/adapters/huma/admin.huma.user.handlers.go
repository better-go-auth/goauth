package humaadmin

import (
	"context"

	humaauth "github.com/better-go-auth/goauth/src/common/types"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	admindtos "github.com/better-go-auth/goauth/src/plugins/admin/dtos"
)

// ListUsers handles POST /api/auth/admin/list-users.
func (h *AdminHandler) ListUsers(ctx context.Context, input *humatypes.HumaReqBody[admindtos.AdminListUsersInput]) (*humatypes.HumaRes[admindtos.AdminListUsersResponse], error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	res, err := h.Admin.ListUsers(ctx, input.Body, session.User.ID)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return humatypes.MakeResPtr(res, 200), nil
}

// CreateUser handles POST /api/auth/admin/create-user.
func (h *AdminHandler) CreateUser(ctx context.Context, input *humatypes.HumaReqBody[admindtos.AdminCreateUserInput]) (*humatypes.HumaRes[admindtos.AdminUserWrapperResponse], error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	user, err := h.Admin.CreateUser(ctx, input.Body, session.User.ID)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return humatypes.MakeResPtr(&admindtos.AdminUserWrapperResponse{User: user}, 200), nil
}

// SetUserRole handles POST /api/auth/admin/set-user-role.
func (h *AdminHandler) SetUserRole(ctx context.Context, input *humatypes.HumaReqBody[admindtos.AdminSetUserRoleInput]) (*humatypes.HumaRes[admindtos.AdminSetUserRoleResponse], error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	user, err := h.Admin.SetUserRole(ctx, input.Body, session.User.ID)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return humatypes.MakeResPtr(&admindtos.AdminSetUserRoleResponse{User: user, Status: true}, 200), nil
}

// SetUserPassword handles POST /api/auth/admin/set-user-password.
func (h *AdminHandler) SetUserPassword(ctx context.Context, input *humatypes.HumaReqBody[admindtos.AdminSetUserPasswordInput]) (*humatypes.HumaRes[admindtos.AdminStatusResponse], error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	if err := h.Admin.SetUserPassword(ctx, input.Body, session.User.ID); err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return humatypes.MakeResPtr(&admindtos.AdminStatusResponse{Status: true}, 200), nil
}

// RemoveUser handles POST /api/auth/admin/remove-user.
func (h *AdminHandler) RemoveUser(ctx context.Context, input *humatypes.HumaReqBody[admindtos.AdminRemoveUserInput]) (*humatypes.HumaRes[admindtos.AdminStatusResponse], error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	if err := h.Admin.RemoveUser(ctx, input.Body, session.User.ID); err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return humatypes.MakeResPtr(&admindtos.AdminStatusResponse{Status: true}, 200), nil
}

// BanUser handles POST /api/auth/admin/ban-user.
func (h *AdminHandler) BanUser(ctx context.Context, input *humatypes.HumaReqBody[admindtos.AdminBanUserInput]) (*humatypes.HumaRes[admindtos.AdminBanUserResponse], error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	user, err := h.Admin.BanUser(ctx, input.Body, session.User.ID)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return humatypes.MakeResPtr(&admindtos.AdminBanUserResponse{User: user, Status: true}, 200), nil
}

// UnbanUser handles POST /api/auth/admin/unban-user.
func (h *AdminHandler) UnbanUser(ctx context.Context, input *humatypes.HumaReqBody[admindtos.AdminUnbanUserInput]) (*humatypes.HumaRes[admindtos.AdminUnbanUserResponse], error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	user, err := h.Admin.UnbanUser(ctx, input.Body, session.User.ID)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return humatypes.MakeResPtr(&admindtos.AdminUnbanUserResponse{User: user, Status: true}, 200), nil
}
