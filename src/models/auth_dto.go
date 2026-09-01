package models

import "github.com/better-go-auth/goauth/src/models/enums"

type RegisterClientInput struct {
	FirstName string `json:"fName" binding:"required,min=2" `
	LastName  string `json:"lName" `
	Email     string `json:"email" binding:"required,email" `
	Password  string `json:"password" binding:"required,min=6"`
	Avatar    string `json:"avatar,omitempty" `
	Country   string `json:"country,omitempty"`
}

// this is for when the admin manually creates the user
type AdminRegisterUsersInput struct {
	FirstName string     `json:"fName" binding:"required,min=2" `
	LastName  string     `json:"lName" `
	Email     string     `json:"email" binding:"required,email" `
	Role      enums.Role `default:"RESPONDER" json:"role" enum:"OPERATOR,RESPONDER,CLIENT"`
	Avatar    string     `json:"avatar,omitempty" `
}

// ProfileUpdateDto This is Used for creating and updating the user
type ProfileUpdateDto struct {
	FirstName string `json:"first_name,omitempty" minLength:"1"`
	LastName  string `json:"last_name,omitempty" `
	// Email     string `json:"email,omitempty" format:"email"`
	Avatar string `json:"avatar,omitempty" `
}

// PasswordUpdateDto This is Used for creating and updating the user
type PasswordUpdateDto struct {
	OldPassword string `json:"old_password,omitempty" minLength:"6"`
	NewPassword string `json:"new_password,omitempty" minLength:"6"`
}

type ChangeEmailReqDto struct {
	Password string `json:"password" minLength:"6"`
	NewEmail string `json:"new_email,omitempty" minLength:"6"`
}

type VerifyEmailDto struct {
	Code string `json:"code" `
}
