package humaadmin

import (
	"context"

	humaauth "github.com/better-go-auth/goauth/src/common/types"
	admindtos "github.com/better-go-auth/goauth/src/plugins/admin/dtos"
)

// ListUsers handles POST /api/auth/admin/list-users.
func (h *AdminHandler) ListUsers(ctx context.Context, input *ListUsersInput) (*ListUsersOutput, error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	res, err := h.Admin.ListUsers(ctx, input.Body, session.User.ID)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return &ListUsersOutput{Body: *res}, nil
}

// CreateUser handles POST /api/auth/admin/create-user.
func (h *AdminHandler) CreateUser(ctx context.Context, input *CreateUserInput) (*CreateUserOutput, error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	user, err := h.Admin.CreateUser(ctx, input.Body, session.User.ID)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return &CreateUserOutput{
		Body: admindtos.AdminUserWrapperResponse{User: user},
	}, nil
}

// SetUserRole handles POST /api/auth/admin/set-user-role.
func (h *AdminHandler) SetUserRole(ctx context.Context, input *SetUserRoleInput) (*SetUserRoleOutput, error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	user, err := h.Admin.SetUserRole(ctx, input.Body, session.User.ID)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return &SetUserRoleOutput{
		Body: admindtos.AdminSetUserRoleResponse{User: user, Status: true},
	}, nil
}

// SetUserPassword handles POST /api/auth/admin/set-user-password.
func (h *AdminHandler) SetUserPassword(ctx context.Context, input *SetUserPasswordInput) (*SetUserPasswordOutput, error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	if err := h.Admin.SetUserPassword(ctx, input.Body, session.User.ID); err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return &SetUserPasswordOutput{
		Body: admindtos.AdminStatusResponse{Status: true},
	}, nil
}

// RemoveUser handles POST /api/auth/admin/remove-user.
func (h *AdminHandler) RemoveUser(ctx context.Context, input *RemoveUserInput) (*RemoveUserOutput, error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	if err := h.Admin.RemoveUser(ctx, input.Body, session.User.ID); err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return &RemoveUserOutput{
		Body: admindtos.AdminStatusResponse{Status: true},
	}, nil
}

// BanUser handles POST /api/auth/admin/ban-user.
func (h *AdminHandler) BanUser(ctx context.Context, input *BanUserInput) (*BanUserOutput, error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	user, err := h.Admin.BanUser(ctx, input.Body, session.User.ID)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return &BanUserOutput{
		Body: admindtos.AdminBanUserResponse{User: user, Status: true},
	}, nil
}

// UnbanUser handles POST /api/auth/admin/unban-user.
func (h *AdminHandler) UnbanUser(ctx context.Context, input *UnbanUserInput) (*UnbanUserOutput, error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	user, err := h.Admin.UnbanUser(ctx, input.Body, session.User.ID)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return &UnbanUserOutput{
		Body: admindtos.AdminUnbanUserResponse{User: user, Status: true},
	}, nil
}
