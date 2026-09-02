package models

import (
	"time"

	"github.com/birukbelay/gocmn/src/dtos"
)

// Session will be put on redis,
type Session struct {
	Base      `mapstructure:",squash" `
	SessionId string    `gorm:"uniqueIndex;not null" `
	UserID    string    `gorm:"not null"`
	ExpiresAt time.Time `json:"expiresAt"                                         bun:"expires_at,notnull"`
	//
	HashedRefresh string `gorm:"not null" json:"-"`

	//we use when the admin block the user, we dont delete the session, we just blacklist it
	Blacklisted   *bool `gorm:"default:false" json:"-"`
	BlacklistedOn *time.Time
	// Revocation
	RevokedAt  *time.Time `json:"revokedAt"   bun:"revoked_at"`
	LastUsedAt *time.Time `json:"lastUsedAt"  bun:"last_used_at"`
	Role       string     `gorm:"not null" json:"-"`
	//relationships
	User *User `json:"user,omitempty" gorm:"foreignKey:UserID"  bun:"rel:belongs-to,join:user_id=id"`

	DeviceToken string `json:"deviceToken"   bun:"device_token"` // used for push notification
	// Device info (fingerprinting for multi-device management)
	IPAddress  *string `json:"ipAddress"  gorm:"size:45"   bun:"ip_address"`
	UserAgent  *string `json:"userAgent"  gorm:"type:text"  bun:"user_agent"`
	DeviceId   *string `json:"deviceId"   gorm:"size:255"   bun:"device_id"`
	DeviceName *string `json:"deviceName" gorm:"size:100"  bun:"device_name"`
	DeviceType *string `json:"deviceType" gorm:"size:50"   bun:"device_type"` // mobile, desktop, tablet
	//=======================   Plugin Fields ================
	//
	//==============================================================

	// For organizations: the org the user is currently scoped to.
	ActiveOrgID *string `json:"activeOrgId" gorm:"size:26" bun:"active_org_id"`
	OrgRoleID   *string `json:"-"`

	// Impersonation: populated with admin's userId when impersonating
	ImpersonatedBy *string `json:"impersonatedBy,omitempty" gorm:"size:26" bun:"impersonated_by"`
}
type SessionFilter struct {
	CompanyID     string `query:"-"`
	CompanyRoleID string `query:"-"`
	SessionId     string `query:"session_id"`
	UserId        string `query:"user_id"`
	HashedRefresh string `query:"hashed_refresh"`
	Blacklisted   bool   `query:"blacklisted"`
}
type SessionQuery struct {
	dtos.PaginationInput
	Blacklisted bool `query:"blacklisted"`
}
