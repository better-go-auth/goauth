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

func (g *gormSessionLookup) FindSession(ctx context.Context, token string) (*models.Session, error) {
	var sess models.Session
	err := g.db.WithContext(ctx).Where(&models.Session{Token: token}, "Token").First(&sess).Error
	return &sess, err
}

func (g *gormSessionLookup) FindUserByID(ctx context.Context, id string) (*models.User, error) {
	var user models.User
	err := g.db.WithContext(ctx).Where(&models.User{Base: models.Base{ID: id}}, "ID").First(&user).Error
	return &user, err
}

// NewDefaultAuthenticatorWithDB is a backward-compatible wrapper that takes a *gorm.DB.
func NewDefaultAuthenticatorWithDB(accessSecret string, db *gorm.DB) AuthenticateFunc {
	if db == nil {
		return NewDefaultAuthenticator(accessSecret, nil)
	}
	return NewDefaultAuthenticator(accessSecret, &gormSessionLookup{db: db})
}
