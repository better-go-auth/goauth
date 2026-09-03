// Package dtos contains request/response DTOs for better-go-auth endpoints.
// Response shapes match better-auth's API for client-side compatibility.
package dtos

// ─── Auth DTOs ────────────────────────────────────────────────────────────────

// SignUpEmailInput matches better-auth POST /sign-up/email body.
type SignUpEmailInput struct {
	Email       string  `json:"email"                 validate:"required,email"`
	Password    string  `json:"password"              validate:"required,min=8,max=128"`
	Name        string  `json:"name"                  validate:"required,min=1"`
	Image       *string `json:"image,omitempty"`
	CallbackURL *string `json:"callbackURL,omitempty"`
	// RememberMe defaults to true; explicit false creates a 1-day session and
	// sets the dont_remember cookie (Better Auth semantics).
	RememberMe *bool `json:"rememberMe,omitempty"`
}

// SignInEmailInput matches better-auth POST /sign-in/email body.
type SignInEmailInput struct {
	Email       string  `json:"email"                 validate:"required,email"`
	Password    string  `json:"password"              validate:"required"`
	RememberMe  *bool   `json:"rememberMe,omitempty"`
	CallbackURL *string `json:"callbackURL,omitempty"`
}

// SignOutInput matches better-auth POST /sign-out body.
type SignOutInput struct{}

// ChangePasswordInput matches better-auth POST /change-password body.
type ChangePasswordInput struct {
	NewPassword         string `json:"newPassword"                   validate:"required,min=8,max=128"`
	CurrentPassword     string `json:"currentPassword"               validate:"required"`
	RevokeOtherSessions bool   `json:"revokeOtherSessions,omitempty"`
}

// ChangeEmailInput matches better-auth POST /change-email body.
type ChangeEmailInput struct {
	NewEmail    string  `json:"newEmail"              validate:"required,email"`
	CallbackURL *string `json:"callbackURL,omitempty"`
}

// SendVerificationEmailInput matches better-auth POST /send-verification-email body.
type SendVerificationEmailInput struct {
	Email       string `json:"email"                 validate:"required,email"`
	CallbackURL string `json:"callbackURL,omitempty"`
}

// VerifyEmailInput matches better-auth GET /verify-email query.
type VerifyEmailInput struct {
	Token       string  `query:"token"       json:"token"                 validate:"required"`
	CallbackURL *string `query:"callbackURL" json:"callbackURL,omitempty"`
}

// RequestPasswordResetInput matches better-auth POST /forget-password body.
type RequestPasswordResetInput struct {
	Email      string `json:"email"                validate:"required,email"`
	RedirectTo string `json:"redirectTo,omitempty"`
}

// ResetPasswordInput matches better-auth POST /reset-password body.
type ResetPasswordInput struct {
	NewPassword string `json:"newPassword" validate:"required,min=8,max=128"`
	Token       string `json:"token"       validate:"required"`
}

// VerifyPasswordInput matches better-auth POST /verify-password body.
type VerifyPasswordInput struct {
	Password string `json:"password" validate:"required"`
}

// UpdateSessionInput matches better-auth POST /update-session body.
type UpdateSessionInput struct {
	ActiveOrganizationID *string `json:"activeOrganizationId,omitempty"`
}

// UnlinkAccountInput matches better-auth POST /unlink-account body.
type UnlinkAccountInput struct {
	ProviderID string `json:"providerId" validate:"required"`
	AccountID  string `json:"accountId,omitempty"`
}

// LinkSocialInput matches better-auth POST /link-social body.
type LinkSocialInput struct {
	Provider    string  `json:"provider" validate:"required"`
	CallbackURL *string `json:"callbackURL,omitempty"`
}

// DeleteUserInput for POST /delete-user
type DeleteUserInput struct {
	Password    *string `json:"password,omitempty"` // optional if OAuth-only account
	CallbackURL *string `json:"callbackURL,omitempty"`
}

// ─── Session DTOs ──────────────────────────────────────────────────────────────

// RevokeSessionInput matches better-auth POST /revoke-session body.
type RevokeSessionInput struct {
	Token     string `json:"token,omitempty"`
	SessionID string `json:"sessionId,omitempty"`
}

// ─── User DTOs ────────────────────────────────────────────────────────────────

// UpdateUserInput matches better-auth POST /update-user body.
type UpdateUserInput struct {
	Name        *string `json:"name,omitempty"`
	Image       *string `json:"image,omitempty"`
	DisplayName *string `json:"displayName,omitempty"`
	Bio         *string `json:"bio,omitempty"`
	PhoneNumber *string `json:"phoneNumber,omitempty"`
}

// ─── Admin DTOs ───────────────────────────────────────────────────────────────

// BanUserInput matches better-auth POST /admin/ban-user body.
type BanUserInput struct {
	UserID       string  `json:"userId"                 validate:"required"`
	BanReason    *string `json:"banReason,omitempty"`
	BanExpiresIn *int64  `json:"banExpiresIn,omitempty"` // BanExpiresIn in seconds. 0 = permanent.
}

// UnbanUserInput matches better-auth POST /admin/unban-user body.
type UnbanUserInput struct {
	UserID string `json:"userId" validate:"required"`
}

// SetRoleInput matches better-auth POST /admin/set-role body.
type SetRoleInput struct {
	UserID string `json:"userId" validate:"required"`
	Role   string `json:"role"   validate:"required"`
}

// ListUsersInput matches better-auth GET /admin/list-users query.
type ListUsersInput struct {
	Limit          int    `query:"limit"                    json:"limit,omitempty"`
	Offset         int    `query:"offset"                   json:"offset,omitempty"`
	SortBy         string `query:"sortBy"                   json:"sortBy,omitempty"`
	SortDir        string `query:"sortDir"                  json:"sortDir,omitempty"` // "asc" | "desc"
	SearchField    string `query:"searchField"              json:"searchField,omitempty"`
	SearchValue    string `query:"searchValue"              json:"searchValue,omitempty"`
	FilterField    string `query:"filterField"              json:"filterField,omitempty"`
	FilterValue    string `query:"filterValue"              json:"filterValue,omitempty"`
	FilterOperator string `query:"filterOperator,omitempty" json:"filterOperator,omitempty"`
}
