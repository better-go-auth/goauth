package dtos

import (
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/models"
)

// ─── Response DTOs (matching better-auth response shapes) ────────────────────

// UserResponse is the public user object returned by most endpoints.
type UserResponse struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Email         string  `json:"email"`
	EmailVerified bool    `json:"emailVerified"`
	Image         *string `json:"image"`
	Role          string  `json:"role"`
	Banned        bool    `json:"banned"`
	BanReason     *string `json:"banReason,omitempty"`
	BanExpires    *string `json:"banExpires,omitempty"`
	CreatedAt     string  `json:"createdAt"`
	UpdatedAt     string  `json:"updatedAt"`
}

// SessionResponse matches better-auth's GET /get-session response.
type SessionResponse struct {
	Session *SessionData  `json:"session"`
	User    *UserResponse `json:"user"`
	// JWT is set when JWTEnabled is true — a short-lived JWT for external
	// service auth. Mirrors Better Auth's set-auth-jwt header behavior.
	JWT *string `json:"jwt,omitempty"`
	// NeedsRefresh appears on GET /get-session when deferSessionRefresh is
	// enabled (always present in that mode, like Better Auth). Pointer so the
	// key is absent entirely in non-defer mode.
	NeedsRefresh *bool `json:"needsRefresh,omitempty"`
}

// SessionData is the session portion of the session response.
type SessionData struct {
	ID                   string  `json:"id"`
	UserID               string  `json:"userId"`
	Token                string  `json:"token"`
	ExpiresAt            string  `json:"expiresAt"`
	IPAddress            *string `json:"ipAddress"`
	UserAgent            *string `json:"userAgent"`
	ActiveOrganizationID *string `json:"activeOrganizationId"`
	ImpersonatedBy       *string `json:"impersonatedBy,omitempty"`
	CreatedAt            string  `json:"createdAt"`
	UpdatedAt            string  `json:"updatedAt"`
}

// SignUpResponse is returned after a successful sign-up.
// Better Auth always includes "token" (null when auto sign-in is skipped).
type SignUpResponse struct {
	User  any     `json:"user"`
	Token *string `json:"token"`

	// SessionData is populated internally for cookie emission only
	// (never serialized — Better Auth omits it from sign-up responses).
	SessionData *SessionData `json:"-"`
}

type SignInResponse struct {
	User *UserResponse `json:"user"`
	// Token is the session/JWT token to be stored by the client.
	Token    string  `json:"token"`
	Redirect bool    `json:"redirect"`
	URL      *string `json:"url,omitempty"`

	// SessionData is populated internally for cookie emission only.
	SessionData *SessionData       `json:"-"`
	AuthTokens  *models.AuthTokens `json:"authTokens,omitempty"`
}

// StatusResponse is standard response payload for status actions in Better Auth.
type StatusResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message,omitempty"`
}

// VerifyEmailResponse matches GET /verify-email response shape ({ user: User, status: bool }).
type VerifyEmailResponse struct {
	User   *UserResponse `json:"user"`
	Status bool          `json:"status"`
}

// DeleteUserResponse matches POST /delete-user response shape.
type DeleteUserResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// UserWrapperResponse matches endpoints that return { user: User }.
type UserWrapperResponse struct {
	User *UserResponse `json:"user"`
}

// ChangeEmailResponse matches POST /change-email response shape.
type ChangeEmailResponse struct {
	User    *UserResponse `json:"user,omitempty"`
	Status  bool          `json:"status"`
	Message string        `json:"message,omitempty"`
}

type ChangePasswordResponse struct {
	Token *string       `json:"token"`
	User  *UserResponse `json:"user"`
}

// AccountResponse matches better-auth GET /list-accounts item shape.
type AccountResponse struct {
	ID         string   `json:"id"`
	ProviderID string   `json:"providerId"`
	AccountID  string   `json:"accountId"`
	UserID     string   `json:"userId"`
	Scopes     []string `json:"scopes"`
	CreatedAt  string   `json:"createdAt"`
	UpdatedAt  string   `json:"updatedAt"`
}

// UpdateSessionResponse matches better-auth POST /update-session response.
type UpdateSessionResponse struct {
	Session *SessionData `json:"session"`
}

// LinkSocialResponse matches better-auth POST /link-social response.
type LinkSocialResponse struct {
	URL      string `json:"url"`
	Redirect bool   `json:"redirect"`
}

// SuccessResponse is standard response payload for success actions in Better Auth (e.g. sign-out).
type SuccessResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// OkResponse matches endpoints that return { ok: true }.
type OkResponse struct {
	OK bool `json:"ok"`
}

// ListResponse is a generic paginated list response.
type ListResponse[T any] struct {
	Data    []T   `json:"data"`
	Total   int64 `json:"total"`
	HasMore bool  `json:"hasMore"`
	Limit   int   `json:"limit"`
	Offset  int   `json:"offset"`
}

// ─── Converters ──────────────────────────────────────────────────────────────

// FormatTime renders a timestamp in Better Auth's response format (RFC3339 UTC).
func FormatTime(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

func formatTime(t time.Time) string {
	return FormatTime(t)
}
func GetVal(val *string) string {
	if val == nil {
		return ""
	}
	return *val
}

// UserToResponse converts a models.User to a UserResponse DTO.
func UserToResponse(u *models.User) *UserResponse {
	if u == nil {
		return nil
	}
	createdAt := ""
	if u.CreatedAt != nil {
		createdAt = formatTime(*u.CreatedAt)
	}
	updatedAt := ""
	if u.UpdatedAt != nil {
		updatedAt = formatTime(*u.UpdatedAt)
	}
	var banExpires *string
	if u.BanExpires != nil {
		tStr := formatTime(*u.BanExpires)
		banExpires = &tStr
	}

	var image *string
	if u.Image != "" {
		image = &u.Image
	}

	name := strings.TrimSpace(u.GetFullname())
	if name == "" && u.DisplayName != nil {
		name = *u.DisplayName
	}

	return &UserResponse{
		ID:            u.ID,
		Name:          name,
		Email:         GetVal(u.Email),
		EmailVerified: u.EmailVerified,
		Image:         image,
		Role:          u.Role.S(),
		Banned:        u.Banned,
		BanReason:     u.BanReason,
		BanExpires:    banExpires,
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
	}
}

// SessionToData converts a models.Session to a SessionData DTO.
func SessionToData(s *models.Session) *SessionData {
	if s == nil {
		return nil
	}
	createdAt := ""
	if s.CreatedAt != nil {
		createdAt = formatTime(*s.CreatedAt)
	}
	updatedAt := ""
	if s.UpdatedAt != nil {
		updatedAt = formatTime(*s.UpdatedAt)
	}
	ipAddress := normalizeNilable(s.IPAddress)
	userAgent := normalizeNilable(s.UserAgent)
	return &SessionData{
		ID:                   s.ID,
		UserID:               s.UserID,
		Token:                s.SessionId,
		ExpiresAt:            formatTime(s.ExpiresAt),
		IPAddress:            ipAddress,
		UserAgent:            userAgent,
		ActiveOrganizationID: s.ActiveOrgID,
		ImpersonatedBy:       normalizeNilable(s.ImpersonatedBy),
		CreatedAt:            createdAt,
		UpdatedAt:            updatedAt,
	}
}

// SessionsToData converts a slice of models.Session to []SessionData.
func SessionsToData(sessions []models.Session) []SessionData {
	res := make([]SessionData, len(sessions))
	for i := range sessions {
		if d := SessionToData(&sessions[i]); d != nil {
			res[i] = *d
		}
	}
	return res
}

// UsersToResponse converts a slice of models.User to []UserResponse.
func UsersToResponse(users []models.User) []UserResponse {
	res := make([]UserResponse, len(users))
	for i := range users {
		if u := UserToResponse(&users[i]); u != nil {
			res[i] = *u
		}
	}
	return res
}

// ToSessionResponse converts a session and user into Better Auth's SessionResponse.
func ToSessionResponse(s *models.Session, u *models.User) *SessionResponse {
	if s == nil && u == nil {
		return nil
	}
	return &SessionResponse{
		Session: SessionToData(s),
		User:    UserToResponse(u),
	}
}

// normalizeNilable maps empty strings to nil so optional fields serialize as
// null, matching Better Auth responses.
func normalizeNilable(v *string) *string {
	if v == nil || *v == "" {
		return nil
	}
	return v
}

// ResolveOptions mirrors better-auth getSessionFromCtx config knobs.
type ResolveOptions struct {
	DeferRefresh   bool // defer mode + GET: read-only, report needsRefresh
	DisableRefresh bool // dont-remember cookie or ?disableRefresh
}

// SessionState reports what the resolver did for this request.
type SessionState struct {
	Refreshed    bool // expiry was slid forward (writes performed)
	NeedsRefresh bool // refresh was due but deferred
}
