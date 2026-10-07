package dtos

import (
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/providers/idgen"
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
	ImpersonatedBy       *string `json:"impersonatedBy,omitempty"`
	CreatedAt            string  `json:"createdAt"`
	UpdatedAt            string  `json:"updatedAt"`
	ActiveOrganizationID *string `json:"activeOrganizationId,omitempty"`
	ActiveOrgRole        *string `json:"activeOrgRole,omitempty"`
	Role                 string  `json:"role,omitempty"`
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

// AccountResponse matches better-auth GET /list-accounts item shape.
type AccountResponse struct {
	ID         string   `json:"id"`
	ProviderID string   `json:"providerId"`
	AccountID  string   `json:"accountId"`
	UserID     string   `json:"userId"`
	Scopes     []string `json:"scopes"`
	CreatedAt  Time     `json:"createdAt"`
	UpdatedAt  Time     `json:"updatedAt"`
}

// SuccessResponse is standard response payload for success actions in Better Auth (e.g. sign-out).
type SuccessResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
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
	createdAt := formatTime(u.CreatedAt)
	updatedAt := formatTime(u.UpdatedAt)
	var banExpires *string
	if u.BanExpires != nil {
		tStr := formatTime(*u.BanExpires)
		banExpires = &tStr
	}

	name := strings.TrimSpace(u.GetFullname())
	if name == "" && u.DisplayName != nil {
		name = *u.DisplayName
	}

	return &UserResponse{
		ID:            u.ID,
		Name:          name,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Image:         u.Image,
		Role:          u.Role.S(),
		Banned:        u.Banned,
		BanReason:     u.BanReason,
		BanExpires:    banExpires,
		CreatedAt:     createdAt,
		UpdatedAt:     updatedAt,
	}
}

// PublicToken returns the session token when it is a client-held token; legacy JWT sessions store a
// refresh-token hash there, which must never leave the server.
func PublicToken(s *models.Session) string {
	if idgen.IsToken(s.Token) {
		return s.Token
	}
	return ""
}

// SessionToData converts a models.Session to a SessionData DTO.
func SessionToData(s *models.Session) *SessionData {
	if s == nil {
		return nil
	}
	createdAt := formatTime(s.CreatedAt)
	updatedAt := formatTime(s.UpdatedAt)
	ipAddress := normalizeNilable(s.IPAddress)
	userAgent := normalizeNilable(s.UserAgent)
	return &SessionData{
		ID:                   s.ID,
		UserID:               s.UserID,
		Token:                PublicToken(s),
		ExpiresAt:            formatTime(s.ExpiresAt),
		IPAddress:            ipAddress,
		UserAgent:            userAgent,
		ActiveOrganizationID: s.ActiveOrganizationID,
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
