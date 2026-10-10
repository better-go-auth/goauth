package dtos

import (
	"github.com/better-go-auth/goauth/src/models"
)


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





// normalizeNilable maps empty strings to nil so optional fields serialize as
// null, matching Better Auth responses.
// func normalizeNilable(v *string) *string {
// 	if v == nil || *v == "" {
// 		return nil
// 	}
// 	return v
// }




// SessionData is the canonical Better-Auth session shape (unified wire type).
// type SessionData = BetterAuthSession

// // SessionResponse matches better-auth's GET /get-session response.
// type SessionResponse struct {
// 	Session *SessionData  `json:"session"`
// 	User    *UserResponse `json:"user"`
// 	// JWT is set when JWTEnabled is true — a short-lived JWT for external
// 	// service auth. Mirrors Better Auth's set-auth-jwt header behavior.
// 	JWT *string `json:"jwt,omitempty"`
// 	// NeedsRefresh appears on GET /get-session when deferSessionRefresh is
// 	// enabled (always present in that mode, like Better Auth). Pointer so the
// 	// key is absent entirely in non-defer mode.
// 	NeedsRefresh *bool `json:"needsRefresh,omitempty"`
// }




// FormatTime renders a timestamp in Better Auth's response format (RFC3339 UTC).
// func FormatTime(t time.Time) string {
// 	return t.UTC().Format(time.RFC3339)
// }


