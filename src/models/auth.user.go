package models

import (
	"fmt"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/models/enums"
)

type User struct {
	Base    `mapstructure:",squash" ` // id, createdAt, updatedAt
	UserDto `mapstructure:",squash" `

	// ===== goauth fields (not in better-auth) =====
	LastSeen  *time.Time `json:"last_seen,omitempty" doc:"last time user is seen"`
	DeletedAt *time.Time `json:"deletedAt,omitempty" gorm:"index" bun:"deleted_at,soft_delete"`

	Sessions []Session `json:"sessions,omitempty" gorm:"foreignKey:UserID"`
	Tokens   []string  `json:"tokens,omitempty" gorm:"-"`

	// Extra holds the values of runtime fields (config additionalFields, plugin schema fields) keyed by
	// field name. Read them with schema.Get[T](user, "field").
	Extra map[string]any `json:"-" gorm:"-" bun:"-" mapstructure:"-"`
}

type UserDto struct {
	// ===== better-auth fields =====
	Name          string  `json:"name,omitempty"  gorm:"not null;default:''"           bun:"name,notnull"`
	Email         string  `json:"email"           gorm:"not null;uniqueIndex;size:255" format:"email"`
	EmailVerified bool    `json:"emailVerified"   gorm:"not null;default:false"        bun:"email_verified,default:false"`
	Image         *string `json:"image"`
	// admin plugin
	Role       enums.Role `json:"role"       gorm:"default:user"`
	Banned     bool       `json:"banned"     gorm:"default:false" bun:"banned,default:false"`
	BanReason  *string    `json:"banReason"      bun:"ban_reason"`
	BanExpires *time.Time `json:"banExpires"                      bun:"ban_expires"`

	// Phone-number plugin fields (better-auth `phoneNumber` / `phoneNumberVerified`).
	// PhoneNumber is unique but nullable: users without a phone keep NULL.
	PhoneNumber         *string `json:"phoneNumber,omitempty"  gorm:"uniqueIndex;size:64" bun:"phone_number,unique"`
	PhoneNumberVerified bool    `json:"phoneNumberVerified"    gorm:"not null;default:false" bun:"phone_number_verified,default:false"`

	// Two-factor plugin field (better-auth `twoFactorEnabled`).
	TwoFactorEnabled bool `json:"twoFactorEnabled" gorm:"not null;default:false" bun:"two_factor_enabled,default:false"`

	// Username plugin fields (better-auth `username` / `displayUsername`).
	// Username is unique but nullable: users without a username keep NULL (never "").
	Username        *string `json:"username,omitempty"        gorm:"uniqueIndex;size:255" bun:"username,unique"`
	DisplayUsername *string `json:"displayUsername,omitempty" bun:"display_username"`

	// Anonymous plugin field (better-auth `isAnonymous`).
	IsAnonymous bool `json:"isAnonymous" gorm:"not null;default:false" bun:"is_anonymous,default:false"`

	// ===== goauth fields (not in better-auth) =====
	FirstName   string     `json:"firstName,omitempty" minLength:"1"`
	LastName    string     `json:"lastName,omitempty"`
	DisplayName *string    `json:"displayName,omitempty"  bun:"display_name"`
	Bio         *string    `json:"bio,omitempty"          bun:"bio"`
	DateOfBirth *time.Time `json:"dateOfBirth,omitempty"  bun:"date_of_birth"`
	Gender      *string    `json:"gender,omitempty"       bun:"gender"`
	Locale      string     `json:"locale,omitempty"       gorm:"default:en" bun:"locale,default:en"`
	Timezone    *string    `json:"timezone,omitempty"     bun:"timezone"`
	// Active        *bool               `json:"active,omitempty"       gorm:"index:idx_users_lookup,priority:4"` // Deprecated: use Banned/BanReason/BanExpires. Kept for migration compat.
	// AccountStatus enums.AccountStatus `json:"-"` // Deprecated: folded into Banned.
	LastLoginIP *string    `json:"lastLoginIP,omitempty"  bun:"last_login_ip"`
	LastLoginAt *time.Time `json:"lastLoginAt,omitempty"`
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

// PrepareSave keeps Name populated for rows created through legacy first/last name APIs
// and stores emails lowercased, as better-auth does.
func (u *User) PrepareSave() {
	if u.Name == "" {
		u.Name = u.DisplayNameOrFull()
	}
	u.Email = strings.ToLower(strings.TrimSpace(u.Email))
}

func (u *User) GetEmail() string {
	return u.Email
}

// AnonymizeEmail generates a unique, non-colliding placeholder email for soft-deleted users.
func AnonymizeEmail(userID string, t time.Time) string {
	return fmt.Sprintf("deleted_%s_%d@deleted.local", userID, t.Unix())
}

// (the legacy UserFilter / UserQuery with first_name, account_status and company_id query parameters were
// removed: user listing goes through repo_interfaces.UserFilter and the admin plugin's list-users)

// func (q UserQuery) GetFilter() (f UserFilter, pagi Imdl.PaginationInput, opt *generic.Opt) {
// 	q.PaginationInput.SortBy = q.Sort
// 	q.Select = q.SelectedFields
// 	q.PaginationInput.Query = q.Query
// 	q.PaginationInput.Like = q.Like
// 	q.PaginationInput.TxtSearchCols = []string{"first_name", "last_name"}
// 	q.PaginationInput.PrefixColLike = "first_name"
// 	return q.UserFilter, q.PaginationInput, &generic.Opt{Preloads: []string{"CompanyRole"}}
// }

// type IntUsr interface {
// 	GetID() string
// 	GetRole() string
// 	GetPwd() string
// 	GetStatus() enums.AccountStatus
// 	GetCompanyId() string
// 	GetInfo() string
// }
