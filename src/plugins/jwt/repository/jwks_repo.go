package repository

import (
	"context"
	"errors"

	"github.com/better-go-auth/goauth/src/plugins/jwt/models"
	"gorm.io/gorm"
)

// IJwksRepo defines the repository interface for storing and retrieving JWKS keys.
type IJwksRepo interface {
	GetAllKeys(ctx context.Context) ([]models.JWK, error)
	GetLatestKey(ctx context.Context) (*models.JWK, error)
	CreateJWK(ctx context.Context, jwk *models.JWK) error
}

type gormJwksRepo struct {
	db *gorm.DB
}

// NewGormJwksRepo creates a new GORM-backed JWKS repository.
func NewGormJwksRepo(db *gorm.DB) IJwksRepo {
	return &gormJwksRepo{db: db}
}

func (r *gormJwksRepo) GetAllKeys(ctx context.Context) ([]models.JWK, error) {
	var keys []models.JWK
	if err := r.db.WithContext(ctx).Order("created_at desc").Find(&keys).Error; err != nil {
		return nil, err
	}
	return keys, nil
}

func (r *gormJwksRepo) GetLatestKey(ctx context.Context) (*models.JWK, error) {
	var key models.JWK
	err := r.db.WithContext(ctx).Order("created_at desc").First(&key).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &key, nil
}

func (r *gormJwksRepo) CreateJWK(ctx context.Context, jwk *models.JWK) error {
	return r.db.WithContext(ctx).Create(jwwkSafe(jwk)).Error
}

func jwwkSafe(jwk *models.JWK) *models.JWK {
	return jwk
}
