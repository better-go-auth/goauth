package dtos

import (
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/models"
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

// BetterAuthUser is better-auth's core user shape.
type BetterAuthUser struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Email         string  `json:"email"`
	EmailVerified bool    `json:"emailVerified"`
	Image         *string `json:"image"`
	CreatedAt     Time    `json:"createdAt"`
	UpdatedAt     Time    `json:"updatedAt"`
}

// BetterAuthSession is better-auth's core session shape plus the admin/organization plugin fields.
type BetterAuthSession struct {
	ID                   string  `json:"id"`
	UserID               string  `json:"userId"`
	Token                string  `json:"token"`
	ExpiresAt            Time    `json:"expiresAt"`
	IPAddress            *string `json:"ipAddress"`
	UserAgent            *string `json:"userAgent"`
	CreatedAt            Time    `json:"createdAt"`
	UpdatedAt            Time    `json:"updatedAt"`
	ImpersonatedBy       *string `json:"impersonatedBy,omitempty"`
	ActiveOrganizationID *string `json:"activeOrganizationId,omitempty"`
	ActiveTeamID         *string `json:"activeTeamId,omitempty"`
}

// SessionWithUser is the body of GET /get-session.
type SessionWithUser struct {
	Session BetterAuthSession `json:"session"`
	User    BetterAuthUser    `json:"user"`
}

// UserFromModel converts a goauth user to the better-auth shape.
func UserFromModel(u *models.User) BetterAuthUser {
	out := BetterAuthUser{
		ID:            u.ID,
		Name:          u.DisplayNameOrFull(),
		Email:         u.GetEmail(),
		EmailVerified: u.EmailVerified,
		Image:         u.Image,
		CreatedAt:     Time(u.CreatedAt),
		UpdatedAt:     Time(u.UpdatedAt),
	}
	return out
}

// SessionFromModel converts a goauth session row to the better-auth shape.
func SessionFromModel(s *models.Session) BetterAuthSession {
	out := BetterAuthSession{
		ID:                   s.ID,
		UserID:               s.UserID,
		ExpiresAt:            Time(s.ExpiresAt),
		IPAddress:            s.IPAddress,
		UserAgent:            s.UserAgent,
		ImpersonatedBy:       s.ImpersonatedBy,
		ActiveOrganizationID: s.ActiveOrganizationID,
		ActiveTeamID:         s.ActiveTeamID,
		Token:                s.Token,
		CreatedAt:            Time(s.CreatedAt),
		UpdatedAt:            Time(s.UpdatedAt),
	}
	return out
}
