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
	// Company     Company     `json:"-" gorm:"foreignKey:CompanyID"`
	// CompanyRole CompanyRole `gorm:"foreignKey:CompanyRoleID;constraint:OnUpdate:CASCADE,OnDelete:SET NULL;"`

	//misison related

	LastSeen *time.Time `json:"last_seen,omitempty" doc:"last time user is seen"`

	// Sessions       []Session       `json:"sessions,omitempty" gorm:"many2many:user_sessions;"`
	Tokens []string `json:"tokens,omitempty" gorm:"-"`
}

type UserDto struct {
	FirstName     string  `json:"firstName,omitempty" minLength:"1"`
	LastName      string  `json:"lastName,omitempty" `
	Email         *string `json:"email,omitempty" format:"email"  gorm:"uniqueIndex" `
	EmailVerified bool    `json:"emailVerified"  gorm:"default:false"                  bun:"email_verified,default:false"`

	Username string `json:"username,omitempty"`
	Avatar   string `json:"avatar,omitempty" `
	Active   *bool  `json:"active,omitempty"  gorm:"index:idx_users_lookup,priority:4"` //can the user login
	//meta
	LastLoginIP *string    `json:"lastLoginIP"    gorm:"size:45"             bun:"last_login_ip"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty" `
	//
	Password string     `json:"-" `
	Role     enums.Role `gorm:"default:UNVERIFIED_PERSON" json:"role" ` //this is the company-level role,

	AccountStatus enums.AccountStatus `json:"-" `

	//admin related fields
	Banned     bool       `json:"banned"    gorm:"default:false"               bun:"banned,default:false"`
	BanReason  *string    `json:"banReason" gorm:"type:text"                   bun:"ban_reason"`
	BanExpires *time.Time `json:"banExpires"                               bun:"ban_expires"`

	//company related
	ActiveCompanyId *string `json:"company_id" gorm:"index:idx_users_lookup,priority:1"`
	//Extra better auth fields
	DisplayName *string    `json:"displayName"      gorm:"size:150"              bun:"display_name"`
	Bio         *string    `json:"bio"              gorm:"type:text"             bun:"bio"`
	DateOfBirth *time.Time `json:"dateOfBirth"                                   bun:"date_of_birth"`
	Gender      *string    `json:"gender"           gorm:"size:20"               bun:"gender"`
	Locale      string     `json:"locale"           gorm:"default:en;size:10"    bun:"locale,default:en"`
	Timezone    *string    `json:"timezone"         gorm:"size:50"               bun:"timezone"`
}

func (u *UserDto) SetOnCreate(key string) {
	u.ActiveCompanyId = &key
}

func (u *User) GetFullname() string {
	return u.FirstName + " " + u.LastName
}


type UserFilter struct {
	ID              string              `query:"id"`
	FName           string              `query:"fName"`
	LName           string              `query:"lName" `
	Email           string              `query:"email"`
	Role            enums.Role          `query:"role" enum:"OPERATOR,RESPONDER,CLIENT"`
	Username        string              `query:"username"`
	AccountStatus   enums.AccountStatus `query:"account_status"`
	CompanyID       string              `query:"company_id"`
	CompanyRoleName string              `query:"company_role_name" ` //driver, securtity
	CompanyRoleID   string              `query:"company_role_id" `
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

type IntUsr interface {
	GetID() string
	GetRole() string
	GetPwd() string
	GetStatus() enums.AccountStatus
	GetCompanyId() string
	GetInfo() string
}

func GetID[T IntUsr](t T) string {
	return t.GetID()
}
func (u UserDto) GetInfo() string {
	return *u.Email
}
func (u UserDto) GetRole() string {
	return string(u.Role)
}
func (u UserDto) GetPwd() string {
	return u.Password
}
func (u UserDto) GetStatus() enums.AccountStatus {
	return u.AccountStatus
}

func (u UserDto) GetCompanyId() string {
	if u.ActiveCompanyId != nil {
		return *u.ActiveCompanyId
	}
	return ""
}
