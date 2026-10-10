package dtos

import (
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/providers/idgen"
)

// Time marshals as better-auth's ISO-8601 timestamp with millisecond precision ("2006-01-02T15:04:05.000Z").
type Time time.Time

const isoMillis = "2006-01-02T15:04:05.000Z07:00"

func (t Time) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Time(t).UTC().Format(isoMillis) + `"`), nil
}

func (t *Time) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		*t = Time{}
		return nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return err
	}
	*t = Time(parsed)
	return nil
}

// UserResponse is better-auth's core user shape plus admin/plugin fields.
type UserResponse struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Email         string  `json:"email"`
	EmailVerified bool    `json:"emailVerified"`
	Image         *string `json:"image"`
	CreatedAt     Time    `json:"createdAt"`
	UpdatedAt     Time    `json:"updatedAt"`

	// Admin and organization plugin fields
	Role       string  `json:"role,omitempty"`
	Banned     bool    `json:"banned,omitempty"`
	BanReason  *string `json:"banReason,omitempty"`
	BanExpires *Time   `json:"banExpires,omitempty"`
}

// SessionData is better-auth's core session shape plus the admin/organization plugin fields.
type SessionData struct {
	ID                     string  `json:"id"`
	UserID                 string  `json:"userId"`
	Token                  string  `json:"token"`
	ExpiresAt              Time    `json:"expiresAt"`
	IPAddress              *string `json:"ipAddress"`
	UserAgent              *string `json:"userAgent"`
	CreatedAt              Time    `json:"createdAt"`
	UpdatedAt              Time    `json:"updatedAt"`
	ImpersonatedBy         *string `json:"impersonatedBy,omitempty"`
	ActiveOrganizationID   *string `json:"activeOrganizationId,omitempty"`
	ActiveOrganizationRole *string `json:"activeOrganizationRole,omitempty"`

	// Role         string  `json:"role,omitempty"`//TODO: role usually don't exist on the session: it is on the user
	ActiveTeamID *string `json:"activeTeamId,omitempty"`
	// goauth device fields, settable through update-session
	DeviceToken *string `json:"deviceToken,omitempty"`
	DeviceID    *string `json:"deviceId,omitempty"`
	DeviceName  *string `json:"deviceName,omitempty"`
	DeviceType  *string `json:"deviceType,omitempty"`
}

// SessionWithUser is the body of GET /get-session.
type SessionWithUser struct {
	Session SessionData  `json:"session"`
	User    UserResponse `json:"user"`
}

// UserFromModel converts a goauth user to the better-auth shape.
func UserFromModel(u *models.User) UserResponse {
	if u == nil {
		return UserResponse{}
	}
	var role string
	if u.Role != "" && u.Role != enums.User {
		role = u.Role.S()
	}
	out := UserResponse{
		ID:            u.ID,
		Name:          u.DisplayNameOrFull(),
		Email:         u.GetEmail(),
		EmailVerified: u.EmailVerified,
		Image:         u.Image,
		CreatedAt:     Time(u.CreatedAt),
		UpdatedAt:     Time(u.UpdatedAt),
		Role:          role,
		Banned:        u.Banned,
		BanReason:     u.BanReason,
	}
	if u.BanExpires != nil {
		t := Time(*u.BanExpires)
		out.BanExpires = &t
	}
	return out
}

// SessionFromModel converts a goauth session row to the better-auth shape.
func SessionFromModel(s *models.Session) SessionData {
	if s == nil {
		return SessionData{}
	}
	out := SessionData{
		ID:                     s.ID,
		UserID:                 s.UserID,
		ExpiresAt:              Time(s.ExpiresAt),
		IPAddress:              s.IPAddress,
		UserAgent:              s.UserAgent,
		ImpersonatedBy:         s.ImpersonatedBy,
		ActiveOrganizationID:   s.ActiveOrganizationID,
		ActiveOrganizationRole: s.ActiveOrganizationRole,
		ActiveTeamID:           s.ActiveTeamID,
		Token:                  PublicToken(s),
		CreatedAt:              Time(s.CreatedAt),
		UpdatedAt:              Time(s.UpdatedAt),
		DeviceID:               s.DeviceID,
		DeviceName:             s.DeviceName,
		DeviceType:             s.DeviceType,
	}
	if s.DeviceToken != "" {
		out.DeviceToken = &s.DeviceToken
	}
	return out
}

// UsersToResponse converts a slice of models.User to []UserResponse.
func UsersToResponse(users []models.User) []UserResponse {
	res := make([]UserResponse, len(users))
	for i := range users {
		res[i] = UserFromModel(&users[i])
	}
	return res
}

// SessionsToData converts a slice of models.Session to []SessionData.
func SessionsToData(sessions []models.Session) []SessionData {
	res := make([]SessionData, len(sessions))
	for i := range sessions {
		res[i] = SessionFromModel(&sessions[i])
	}
	return res
}

// ToSessionResponse converts a session and user into Better Auth's SessionResponse.
func ToSessionResponse(s *models.Session, u *models.User) *SessionWithUser {
	if s == nil && u == nil {
		return nil
	}
	
	return &SessionWithUser{
		Session: SessionFromModel(s),
		User:    UserFromModel(u),
	}
}

func ToSessionWithUser(s *SessionData, u *UserResponse) *SessionWithUser {
	var user UserResponse
	if u != nil {
		user = *u
	}
	var sess SessionData
	if s != nil {
		sess = *s
	}
	return &SessionWithUser{
		Session: sess,
		User:    user,
	}
}

// PublicToken returns the session token when it is a client-held token; legacy JWT sessions store a
// refresh-token hash there, which must never leave the server.
func PublicToken(s *models.Session) string {
	if s == nil {
		return ""
	}
	if idgen.IsToken(s.Token) {
		return s.Token
	}
	return ""
}
