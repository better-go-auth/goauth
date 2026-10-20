package gormauth

import (
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"gorm.io/gorm"
)

type RepoOption func(*RepoConfig)

type RepoConfig struct {
	GenerateID func() string
}

func WithGenerateID(fn func() string) RepoOption {
	return func(c *RepoConfig) {
		c.GenerateID = fn
	}
}

// NewAuthRepos creates a complete suite of GORM-backed repositories implementing IAuthRepos.
func NewAuthRepos(db *gorm.DB, opts ...RepoOption) repo_interfaces.IAuthRepos {
	return &repo_interfaces.AuthRepos{
		IUserRepo:         NewUserRepo(db, opts...),
		IOAuthAccountRepo: NewAccountRepo(db, opts...),
		ISessionRepo:      NewSessionRepo(db, opts...),
		IVerificationRepo: NewVerificationRepo(db, opts...),
	}
}
