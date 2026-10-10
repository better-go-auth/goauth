package humaadmin

import (
	"context"

	humaauth "github.com/better-go-auth/goauth/src/common/types"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/models/dtos"
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

// ListUsersQueryInput wraps query params and auth headers for GET /api/auth/admin/list-users.
type ListUsersQueryInput struct {
	humatypes.AuthHeaders
	admindtos.AdminListUsersQuery
}

// ListUsersQuery handles GET /api/auth/admin/list-users.
func (h *AdminHandler) ListUsersQuery(ctx context.Context, input *ListUsersQueryInput) (*humatypes.HumaRes[admindtos.AdminListUsersResponse], error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	body := admindtos.AdminListUsersInput{}
	if input.Limit > 0 {
		body.Limit = &input.Limit
	}
	if input.Offset > 0 {
		body.Offset = &input.Offset
	}
	if input.SearchValue != "" {
		body.SearchValue = &input.SearchValue
	}
	if input.SearchField != "" {
		body.SearchField = &input.SearchField
	}
	if input.SortBy != "" {
		body.SortBy = &input.SortBy
	}
	if input.SortDirection != "" {
		body.SortDirection = &input.SortDirection
	}
	if input.FilterField != "" {
		body.FilterField = &input.FilterField
	}
	if input.FilterOperator != "" {
		body.FilterOperator = &input.FilterOperator
	}
	if input.FilterValue != "" {
		body.FilterValue = &input.FilterValue
	}

	res, err := h.Admin.ListUsers(ctx, body, session.User.ID)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return humatypes.MakeResPtr(res, 200), nil
}

// GetUserInput wraps query params and auth headers for GET /api/auth/admin/get-user.
type GetUserInput struct {
	humatypes.AuthHeaders
	admindtos.AdminGetUserInput
}

// GetUser handles GET /api/auth/admin/get-user.
func (h *AdminHandler) GetUser(ctx context.Context, input *GetUserInput) (*humatypes.HumaRes[dtos.UserResponse], error) {
	_, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	userID := input.ID
	if userID == "" {
		userID = input.UserID
	}

	user, err := h.Admin.GetUser(ctx, userID)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return humatypes.MakeResPtr(user, 200), nil
}

// UpdateUser handles POST /api/auth/admin/update-user.
func (h *AdminHandler) UpdateUser(ctx context.Context, input *humatypes.HumaReqBody[admindtos.AdminUpdateUserInput]) (*humatypes.HumaRes[admindtos.AdminUserWrapperResponse], error) {
	_, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	user, err := h.Admin.UpdateUser(ctx, input.Body)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return humatypes.MakeResPtr(&admindtos.AdminUserWrapperResponse{User: user}, 200), nil
}

// HasPermission handles POST /api/auth/admin/has-permission.
func (h *AdminHandler) HasPermission(ctx context.Context, input *humatypes.HumaReqBody[admindtos.AdminHasPermissionInput]) (*humatypes.HumaRes[admindtos.AdminHasPermissionResponse], error) {
	session, err := h.RequireAdmin(ctx, input.AuthHeaders)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}

	res, err := h.Admin.HasPermission(ctx, input.Body, &session.User)
	if err != nil {
		return nil, humaauth.RespondErr(err)
	}
	return humatypes.MakeResPtr(res, 200), nil
}

