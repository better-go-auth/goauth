package config

import (
	"net/http"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
)

// Admin plugin error codes (better-auth plugins/admin/error-codes.ts), used by the permission checks.
var (
	ErrNotAllowedToChangeRole         = autherr.Err(http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE", "You are not allowed to change users role")
	ErrNotAllowedToCreateUsers        = autherr.Err(http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS", "You are not allowed to create users")
	ErrNotAllowedToListUsers          = autherr.Err(http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS", "You are not allowed to list users")
	ErrNotAllowedToListUsersSessions  = autherr.Err(http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS", "You are not allowed to list users sessions")
	ErrNotAllowedToBanUsers           = autherr.Err(http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS", "You are not allowed to ban users")
	ErrNotAllowedToImpersonateUsers   = autherr.Err(http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS", "You are not allowed to impersonate users")
	ErrNotAllowedToRevokeUserSessions = autherr.Err(http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS", "You are not allowed to revoke users sessions")
	ErrNotAllowedToDeleteUsers        = autherr.Err(http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS", "You are not allowed to delete users")
	ErrNotAllowedToSetUsersPassword   = autherr.Err(http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD", "You are not allowed to set users password")
	ErrNotAllowedToGetUser            = autherr.Err(http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_GET_USER", "You are not allowed to get user")
	ErrNotAllowedToUpdateUsers        = autherr.Err(http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS", "You are not allowed to update users")
	ErrNotAllowedToSetUsersEmail      = autherr.Err(http.StatusForbidden, "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL", "You are not allowed to update users email")
	ErrNotAllowedToSetNonExistentRole = autherr.Err(http.StatusBadRequest, "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE", "You are not allowed to set a non-existent role value")
	ErrCannotImpersonateAdmins        = autherr.Err(http.StatusForbidden, "YOU_CANNOT_IMPERSONATE_ADMINS", "You cannot impersonate admins")
)
