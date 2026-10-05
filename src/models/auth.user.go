package models

import (
	"fmt"
	"strings"
	"time"

	Imdl "github.com/better-go-auth/goauth/src/common/dtos"

	"github.com/better-go-auth/goauth/src/models/enums"
	"gorm.io/gorm"
)

type User struct {
	Base    `mapstructure:",squash" ` // id, createdAt, updatedAt
	UserDto `mapstructure:",squash" `

	// ===== goauth fields (not in better-auth) =====
	LastSeen  *time.Time     `json:"last_seen,omitempty" doc:"last time user is seen"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`

	Sessions []Session `json:"sessions,omitempty" gorm:"foreignKey:UserID"`
	Tokens   []string  `json:"tokens,omitempty" gorm:"-"`
}

type UserDto struct {
	// ===== better-auth fields =====
	Name          string  `json:"name,omitempty"  gorm:"not null;default:''"  bun:"name,notnull"`
	Email         *string `json:"email,omitempty" gorm:"uniqueIndex;size:255" format:"email"`
	EmailVerified bool    `json:"emailVerified"   gorm:"default:false"        bun:"email_verified,default:false"`
	Image         string  `json:"image,omitempty"`
	// admin plugin
	Role       enums.Role `json:"role"       gorm:"default:user"`
	Banned     bool       `json:"banned"     gorm:"default:false" bun:"banned,default:false"`
	BanReason  *string    `json:"banReason"      bun:"ban_reason"`
	BanExpires *time.Time `json:"banExpires"                      bun:"ban_expires"`

	// ===== goauth fields (not in better-auth) =====
	FirstName     string              `json:"firstName,omitempty" minLength:"1"`
	LastName      string              `json:"lastName,omitempty"`
	Username      string              `json:"username,omitempty"`
	DisplayName   *string             `json:"displayName,omitempty"  bun:"display_name"`
	Bio           *string             `json:"bio,omitempty"          bun:"bio"`
	DateOfBirth   *time.Time          `json:"dateOfBirth,omitempty"  bun:"date_of_birth"`
	Gender        *string             `json:"gender,omitempty"       bun:"gender"`
	Locale        string              `json:"locale,omitempty"       gorm:"default:en" bun:"locale,default:en"`
	Timezone      *string             `json:"timezone,omitempty"     bun:"timezone"`
	Active        *bool               `json:"active,omitempty"       gorm:"index:idx_users_lookup,priority:4"` // can the user login
	AccountStatus enums.AccountStatus `json:"-"`
	LastLoginIP   *string             `json:"lastLoginIP,omitempty"  bun:"last_login_ip"`
	LastLoginAt   *time.Time          `json:"lastLoginAt,omitempty"`

}


func (u *User) GetFullname() string {
	return u.FirstName + " " + u.LastName
}

// DisplayNameOrFull returns Name, falling back to "FirstName LastName".
func (u *UserDto) DisplayNameOrFull() string {
	if u.Name != "" {
		return u.Name
	}
	return strings.TrimSpace(u.FirstName + " " + u.LastName)
}

// BeforeSave keeps Name populated for rows created through legacy first/last name APIs.
func (u *User) BeforeSave(tx *gorm.DB) error {
	if u.Name == "" {
		u.Name = u.DisplayNameOrFull()
	}
	return nil
}

func (u *User) GetEmail() string {
	if u.Email != nil {
		return *u.Email
	}
	return ""
}

// AnonymizeEmail generates a unique, non-colliding placeholder email for soft-deleted users.
func AnonymizeEmail(userID string, t time.Time) string {
	return fmt.Sprintf("deleted_%s_%d@deleted.local", userID, t.Unix())
}

// BeforeDelete hook ensures the user's email is anonymized on deletion to prevent unique index conflicts.
func (u *User) BeforeDelete(tx *gorm.DB) error {
	if u.ID != "" {
		now := time.Now().UTC()
		tombstone := AnonymizeEmail(u.ID, now)
		tx.Statement.SetColumn("email", tombstone)
	}
	return nil
}

type UserFilter struct {
	ID            string              `query:"id"`
	FirstName     string              `query:"firstName"`
	LastName      string              `query:"lastName"`
	Email         string              `query:"email"`
	Role          enums.Role          `query:"role" enum:"user,admin"`
	Username      string              `query:"username"`
	AccountStatus enums.AccountStatus `query:"account_status"`
	CompanyID     string              `query:"company_id"`

	// Availability    Availability        `query:"availability,omitempty"  enum:"Available,NotAvailable,OnMission"`
	Country string `query:"country"`
}

type UserQuery struct {
	Imdl.PaginationInput `mapstructure:",squash"`
	UserFilter           `mapstructure:",squash"`
	Query                string   `query:"q"`
	Like                 string   `query:"_like"`
	SelectedFields       []string `query:"_select" enum:"first_name,last_name,email,avatar,company_id,company_role_id,company_role_name,account_status,id,created_at,updated_at"`
	Sort                 string   `query:"_sort" enum:"first_name,last_name,email,avatar,company_id,account_status,created_at,updated_at"`
}

// func (q UserQuery) GetFilter() (f UserFilter, pagi Imdl.PaginationInput, opt *generic.Opt) {
// 	q.PaginationInput.SortBy = q.Sort
// 	q.Select = q.SelectedFields
// 	q.PaginationInput.Query = q.Query
// 	q.PaginationInput.Like = q.Like
// 	q.PaginationInput.TxtSearchCols = []string{"first_name", "last_name"}
// 	q.PaginationInput.PrefixColLike = "first_name"
// 	return q.UserFilter, q.PaginationInput, &generic.Opt{Preloads: []string{"CompanyRole"}}
// }

func (User) TableName() string { return "auth_users" }

// type IntUsr interface {
// 	GetID() string
// 	GetRole() string
// 	GetPwd() string
// 	GetStatus() enums.AccountStatus
// 	GetCompanyId() string
// 	GetInfo() string
// }
