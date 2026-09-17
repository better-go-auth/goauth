package models

import (
	"time"

	Imdl "github.com/birukbelay/gocmn/src/dtos"
	"github.com/birukbelay/gocmn/src/generic"

	"github.com/better-go-auth/goauth/src/models/enums"
)

type User struct {
	Base    `mapstructure:",squash" `
	UserDto `mapstructure:",squash" `

	LastSeen *time.Time `json:"last_seen,omitempty" doc:"last time user is seen"`

	Sessions []Session `json:"sessions,omitempty" gorm:"foreignKey:UserID"`
	Tokens   []string  `json:"tokens,omitempty" gorm:"-"`
}

type UserDto struct {
	FirstName     string     `json:"firstName,omitempty" minLength:"1"`
	LastName      string     `json:"lastName,omitempty" `
	Email         *string    `json:"email,omitempty" format:"email"  gorm:"uniqueIndex" `
	EmailVerified bool       `json:"emailVerified"  gorm:"default:false"                  bun:"email_verified,default:false"`
	Password      string     `json:"-" `
	Role          enums.Role `gorm:"default:UNVERIFIED_PERSON" json:"role" ` //this is the company-level role,

	Active        *bool               `json:"active,omitempty"  gorm:"index:idx_users_lookup,priority:4"` //can the user login
	AccountStatus enums.AccountStatus `json:"-" `
	//admin related fields
	Banned     bool       `json:"banned"    gorm:"default:false"               bun:"banned,default:false"`
	BanReason  *string    `json:"banReason" gorm:"type:text"                   bun:"ban_reason"`
	BanExpires *time.Time `json:"banExpires"                               bun:"ban_expires"`

	//meta
	LastLoginIP *string    `json:"lastLoginIP,omitempty"    gorm:"size:45"             bun:"last_login_ip"`
	LastLoginAt *time.Time `json:"lastLoginAt,omitempty" `
	//Extra better auth fields
	DisplayName *string    `json:"displayName,omitempty"                   bun:"display_name"`
	Image       string     `json:"image,omitempty" `
	Bio         *string    `json:"bio,omitempty"                          bun:"bio"`
	DateOfBirth *time.Time `json:"dateOfBirth,omitempty"                                   bun:"date_of_birth"`
	Gender      *string    `json:"gender,omitempty"           gorm:"size:20"               bun:"gender"`
	Locale      string     `json:"locale,omitempty"           gorm:"default:en;size:10"    bun:"locale,default:en"`
	Timezone    *string    `json:"timezone,omitempty"                       bun:"timezone"`
	//====================  Plugin  fields ===========================|
	Username string `json:"username,omitempty"`
	//company related
	ActiveOrgId *string `json:"company_id" gorm:"index:idx_users_lookup,priority:1"`
}

func (u *UserDto) SetOnCreate(key string) {
	u.ActiveOrgId = &key
}

func (u *User) GetFullname() string {
	return u.FirstName + " " + u.LastName
}

func (u *User) GetEmail() string {
	if u.Email != nil {
		return *u.Email
	}
	return ""
}

type UserFilter struct {
	ID            string              `query:"id"`
	FirstName     string              `query:"firstName"`
	LastName      string              `query:"lastName"`
	Email         string              `query:"email"`
	Role          enums.Role          `query:"role" enum:"OPERATOR,RESPONDER,CLIENT"`
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

func (q UserQuery) GetFilter() (f UserFilter, pagi Imdl.PaginationInput, opt *generic.Opt) {
	q.PaginationInput.SortBy = q.Sort
	q.Select = q.SelectedFields
	q.PaginationInput.Query = q.Query
	q.PaginationInput.Like = q.Like
	q.PaginationInput.TxtSearchCols = []string{"first_name", "last_name"}
	q.PaginationInput.PrefixColLike = "first_name"
	return q.UserFilter, q.PaginationInput, &generic.Opt{Preloads: []string{"CompanyRole"}}
}

func (User) TableName() string { return "auth_users" }

// type IntUsr interface {
// 	GetID() string
// 	GetRole() string
// 	GetPwd() string
// 	GetStatus() enums.AccountStatus
// 	GetCompanyId() string
// 	GetInfo() string
// }
