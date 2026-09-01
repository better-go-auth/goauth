package models

import "github.com/better-go-auth/goauth/src/models/enums"

// cant update the email, accountstatus
type AdminUserUpdateDto struct {
	FirstName string  `json:"firsName,omitempty"`
	LastName  string  `json:"lastName,omitempty" `
	Username  string  `json:"username,omitempty"`
	Image     *string `json:"image,omitempty"                        bun:"image"`
	Active    *bool   `json:"active,omitempty"` //if false will not be alloed to login

	Role enums.Role ` json:"role,omitempty" enum:"COMPANY_ADMIN,OPERATOR,RESPONDER,CLIENT" `

	AccountStatus enums.AccountStatus `json:"account_status,omitempty" enum:"active,banned"` //will only be allowed to disable and enable
}

// this is for when the admin manually creates the user
type AdminRegisterUsersInput struct {
	FirstName string     `json:"fName" binding:"required,min=2" `
	LastName  string     `json:"lName" `
	Email     string     `json:"email" binding:"required,email" `
	Role      enums.Role `default:"RESPONDER" json:"role" enum:"OPERATOR,RESPONDER,CLIENT"`
	Avatar    string     `json:"avatar,omitempty" `
}
