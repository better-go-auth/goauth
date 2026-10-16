package repository

import (
	"context"
	"errors"

	"github.com/better-go-auth/goauth/src/models/migration"
	jwtmodels "github.com/better-go-auth/goauth/src/plugins/jwt/models"
	"gorm.io/gorm"
)

// IJwksRepo defines the repository interface for storing and retrieving JWKS keys.
// The embedded Migrator allows the plugin to obtain its schema migrator directly
// from the repo without needing a separate *gorm.DB handle.
type IJwksRepo interface {
	Migrator() migration.IMigrator
	GetAllKeys(ctx context.Context) ([]jwtmodels.JWK, error)
	GetLatestKey(ctx context.Context) (*jwtmodels.JWK, error)
	CreateJWK(ctx context.Context, jwk *jwtmodels.JWK) error
}

type gormJwksRepo struct {
	db       *gorm.DB
	migrator migration.IMigrator
}

// NewGormJwksRepo creates a new GORM-backed JWKS repository.
func NewGormJwksRepo(db *gorm.DB) IJwksRepo {
	return &gormJwksRepo{db: db, migrator: jwtmodels.NewMigrator(db)}
}

func (r *gormJwksRepo) Migrator() migration.IMigrator { return r.migrator }

func (r *gormJwksRepo) GetAllKeys(ctx context.Context) ([]jwtmodels.JWK, error) {
	var keys []jwtmodels.JWK
	if err := r.db.WithContext(ctx).Order("created_at desc").Find(&keys).Error; err != nil {
		return nil, err
	}
	return keys, nil
}

func (r *gormJwksRepo) GetLatestKey(ctx context.Context) (*jwtmodels.JWK, error) {
	var key jwtmodels.JWK
	err := r.db.WithContext(ctx).Order("created_at desc").First(&key).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &key, nil
}

func (r *gormJwksRepo) CreateJWK(ctx context.Context, jwk *jwtmodels.JWK) error {
	return r.db.WithContext(ctx).Create(jwwkSafe(jwk)).Error
}

func jwwkSafe(jwk *jwtmodels.JWK) *jwtmodels.JWK {
	return jwk
}
