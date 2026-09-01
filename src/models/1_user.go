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
	FirstName string  `json:"firstName,omitempty" minLength:"1"`
	LastName  string  `json:"lastName,omitempty" `
	Email     *string `json:"email,omitempty" format:"email"  gorm:"uniqueIndex" `
	Username  string  `json:"username,omitempty"`
	Avatar    string  `json:"avatar,omitempty" `
	CompanyID *string `json:"company_id" gorm:"index:idx_users_lookup,priority:1"`
	Active    *bool   `json:"active,omitempty"  gorm:"index:idx_users_lookup,priority:4"` //can the user login
	//
	Password string     `json:"-" `
	Role     enums.Role `gorm:"default:UNVERIFIED_PERSON" json:"role" ` //this is the company-level role,
	// GlobalRole enums.GlobalRole `gorm:"default:USER" json:"global_role,omitempty"`
	// Country    string           `json:"country,omitempty"`

	// CompanyRoleName string  `json:"company_role_name,omitempty" ` //driver, securtity
	// CompanyRoleID   *string `json:"company_role_id,omitempty"  gorm:"index:idx_users_lookup,priority:2"`
	//used to set the users status to pending verification on email verification
	//TODO: this is doing same thing as active, and
	// is actually useless, bcs we are checking if admins can create company using role
	//user can login even if account status is not active, like `verified`
	AccountStatus enums.AccountStatus `json:"-" `
	LastLoginAt   *time.Time          `json:"last_login_at,omitempty" `
}

func (u *UserDto) SetOnCreate(key string) {
	u.CompanyID = &key
}

func (u *User) GetFullname() string {
	return u.FirstName + " " + u.LastName
}

// cant update the email, accountstatus
type UserUpdateDto struct {
	FirstName string `json:"firsName,omitempty"`
	LastName  string `json:"lastName,omitempty" `
	Username  string `json:"username,omitempty"`
	Avatar    string `json:"avatar,omitempty" `
	Active    *bool  `json:"active,omitempty"` //if false will not be alloed to login

	Role            enums.Role          ` json:"role,omitempty" enum:"COMPANY_ADMIN,OPERATOR,RESPONDER,CLIENT" `
	CompanyRoleName string              `json:"company_role_name,omitempty" `                    // should admis be able to update this                    //driver, securtity
	CompanyRoleID   *string             `json:"company_role_id,omitempty" `                      //TODO should admins be able to update other companies roleID
	AccountStatus   enums.AccountStatus `json:"account_status,omitempty" enum:"active,disabled"` //will only be allowed to disable and enable
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
type AvailableUsersFilter struct {
	Role          enums.Role `query:"role" enum:"OPERATOR,RESPONDER,CLIENT" `
	CompanyRoleID string     `query:"company_role_id"`
	Country       string     `query:"country"`
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
	if u.CompanyID != nil {
		return *u.CompanyID
	}
	return ""
}
