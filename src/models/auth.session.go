package models

import (
	"time"

	"github.com/better-go-auth/goauth/src/common/dtos"
)

// Session is better-auth's `session` model plus goauth extras.
type Session struct {
	// ===== better-auth fields =====
	Base `mapstructure:",squash" ` // id, createdAt, updatedAt
	// Token is the raw better-auth session token, or the SHA-256 hash of the refresh JWT for legacy JWT sessions.
	Token     string    `json:"-"         gorm:"uniqueIndex;not null;size:255" bun:"token,notnull"`
	UserID    string    `json:"userId"    gorm:"not null;index"       bun:"user_id,notnull"`
	ExpiresAt time.Time `json:"expiresAt" gorm:"not null"             bun:"expires_at,notnull"`
	IPAddress *string   `json:"ipAddress"                             bun:"ip_address"`
	UserAgent *string   `json:"userAgent"                             bun:"user_agent"`
	// admin plugin
	ImpersonatedBy *string `json:"impersonatedBy,omitempty" bun:"impersonated_by"`
	// organization plugin
	ActiveOrganizationID *string `json:"activeOrganizationId,omitempty" bun:"active_organization_id"`
	ActiveTeamID         *string `json:"activeTeamId,omitempty"         bun:"active_team_id"`

	// ===== goauth fields (not in better-auth) =====
	// ActiveOrganizationRole caches the member role of ActiveOrganizationID for JWT claims.
	ActiveOrganizationRole *string    `json:"-"                      bun:"active_organization_role"`
	DeviceToken            string     `json:"deviceToken,omitempty"  bun:"device_token"` // push notifications
	DeviceID               *string    `json:"deviceId,omitempty"     bun:"device_id"`
	DeviceName             *string    `json:"deviceName,omitempty"   bun:"device_name"`
	DeviceType             *string    `json:"deviceType,omitempty"   bun:"device_type"` // mobile, desktop, tablet
	LastUsedAt             *time.Time `json:"lastUsedAt,omitempty"   bun:"last_used_at"`
	User                   *User      `json:"user,omitempty"         gorm:"foreignKey:UserID" bun:"rel:belongs-to,join:user_id=id"`
}
type SessionFilter struct {
	ID          string `query:"id"`
	ActiveOrgID string `query:"-"`
	OrgRoleID   string `query:"-"`

	UserId string `query:"user_id"`
	Token  string `query:"token"`
}
type SessionQuery struct {
	dtos.PaginationInput
}

func (Session) TableName() string { return "auth_sessions" }
