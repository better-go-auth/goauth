package humaadmin

import (
	"net/http"

	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/models/dtos"
	admindtos "github.com/better-go-auth/goauth/src/plugins/admin/dtos"
)

// HumaReqEmpty represents an empty request payload with auth headers.
type HumaReqEmpty struct {
	humatypes.AuthHeaders
}

// ─── User Management Types ───────────────────────────────────────────────────

type ListUsersInput struct {
	humatypes.AuthHeaders
	Body admindtos.AdminListUsersInput
}

type ListUsersOutput struct {
	Body admindtos.AdminListUsersResponse
}

type CreateUserInput struct {
	humatypes.AuthHeaders
	Body admindtos.AdminCreateUserInput
}

type CreateUserOutput struct {
	Body admindtos.AdminUserWrapperResponse
}

type SetUserRoleInput struct {
	humatypes.AuthHeaders
	Body admindtos.AdminSetUserRoleInput
}

type SetUserRoleOutput struct {
	Body admindtos.AdminSetUserRoleResponse
}

type SetUserPasswordInput struct {
	humatypes.AuthHeaders
	Body admindtos.AdminSetUserPasswordInput
}

type SetUserPasswordOutput struct {
	Body admindtos.AdminStatusResponse
}

type RemoveUserInput struct {
	humatypes.AuthHeaders
	Body admindtos.AdminRemoveUserInput
}

type RemoveUserOutput struct {
	Body admindtos.AdminStatusResponse
}

// ─── Moderation & Ban Types ──────────────────────────────────────────────────

type BanUserInput struct {
	humatypes.AuthHeaders
	Body admindtos.AdminBanUserInput
}

type BanUserOutput struct {
	Body admindtos.AdminBanUserResponse
}

type UnbanUserInput struct {
	humatypes.AuthHeaders
	Body admindtos.AdminUnbanUserInput
}

type UnbanUserOutput struct {
	Body admindtos.AdminUnbanUserResponse
}

// ─── Impersonation Types ─────────────────────────────────────────────────────

type ImpersonateUserInput struct {
	humatypes.AuthHeaders
	Body admindtos.AdminImpersonateUserInput
}

type ImpersonateUserOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      dtos.SessionResponse
}

type StopImpersonatingInput struct {
	humatypes.AuthHeaders
	Body admindtos.AdminStopImpersonatingInput
}

type StopImpersonatingOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      admindtos.AdminStatusResponse
}

// ─── Session Control Types ───────────────────────────────────────────────────

type ListUserSessionsInput struct {
	humatypes.AuthHeaders
	Body admindtos.AdminListUserSessionsInput
}

type ListUserSessionsOutput struct {
	Body admindtos.AdminListUserSessionsResponse
}

type RevokeUserSessionInput struct {
	humatypes.AuthHeaders
	Body admindtos.AdminRevokeUserSessionInput
}

type RevokeUserSessionOutput struct {
	Body admindtos.AdminStatusResponse
}

type RevokeUserSessionsInput struct {
	humatypes.AuthHeaders
	Body admindtos.AdminRevokeUserSessionsInput
}

type RevokeUserSessionsOutput struct {
	Body admindtos.AdminStatusResponse
}
