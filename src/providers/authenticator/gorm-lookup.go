package authenticator

import (
	"context"

	"github.com/better-go-auth/goauth/src/models"
	"gorm.io/gorm"
)

// gormSessionLookup wraps a *gorm.DB to satisfy SessionLookupRepo for backward compatibility.
type gormSessionLookup struct {
	db *gorm.DB
}

func (g *gormSessionLookup) GetSessionByToken(ctx context.Context, token string) (*models.Session, error) {
	var sess models.Session
	err := g.db.WithContext(ctx).Where("session_id = ? OR hashed_token = ?", token, token).First(&sess).Error
	return &sess, err
}

func (g *gormSessionLookup) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	var user models.User
	err := g.db.WithContext(ctx).Where("id = ?", id).First(&user).Error
	return &user, err
}

// NewDefaultAuthenticatorWithDB is a backward-compatible wrapper that takes a *gorm.DB.
func NewDefaultAuthenticatorWithDB(accessSecret string, db *gorm.DB) AuthenticateFunc {
	if db == nil {
		return NewDefaultAuthenticator(accessSecret, nil)
	}
	return NewDefaultAuthenticator(accessSecret, &gormSessionLookup{db: db})
}
