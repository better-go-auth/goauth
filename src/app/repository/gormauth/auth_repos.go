package gormauth

import (
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"gorm.io/gorm"
)

// NewAuthRepos creates a complete suite of GORM-backed repositories implementing IAuthRepos.
func NewAuthRepos(db *gorm.DB) repo_interfaces.IAuthRepos {
	return &repo_interfaces.AuthRepos{
		IUserRepo:         NewUserRepo(db),
		IOAuthAccountRepo: NewAccountRepo(db),
		ISessionRepo:      NewSessionRepo(db),
		IVerificationRepo: NewVerificationRepo(db),
	}
}
