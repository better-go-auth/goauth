// Package repository stores passkeys with GORM.
package repository

import (
	"context"
	"errors"

	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/models/migration"
	pkmodels "github.com/better-go-auth/goauth/src/plugins/passkey/models"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// IPasskeyRepo is the storage of the passkey plugin. Find methods return (nil, nil) when nothing matches.
type IPasskeyRepo interface {
	// Migrator returns the schema migrator of the passkey table.
	Migrator() migration.IMigrator
	Create(ctx context.Context, pk *pkmodels.Passkey) error
	FindByID(ctx context.Context, id string) (*pkmodels.Passkey, error)
	FindByCredentialID(ctx context.Context, credentialID string) (*pkmodels.Passkey, error)
	ListByUser(ctx context.Context, userID string) ([]pkmodels.Passkey, error)
	// UpdateCounter stores the signature counter reported by the last assertion.
	UpdateCounter(ctx context.Context, id string, counter int64) error
	// UpdateName renames a passkey and returns the updated row.
	UpdateName(ctx context.Context, id, name string) (*pkmodels.Passkey, error)
	Delete(ctx context.Context, id string) error
	// DeleteByUser removes every passkey of a user (user deletion cleanup).
	DeleteByUser(ctx context.Context, userID string) error
}

type gormPasskeyRepo struct {
	db       *gorm.DB
	migrator migration.IMigrator
}

// NewGormPasskeyRepo creates a GORM-backed passkey repository. Queries join the transaction stored in ctx.
func NewGormPasskeyRepo(db *gorm.DB) IPasskeyRepo {
	return &gormPasskeyRepo{db: db, migrator: pkmodels.NewMigrator(db)}
}

func (r *gormPasskeyRepo) Migrator() migration.IMigrator { return r.migrator }

func (r *gormPasskeyRepo) conn(ctx context.Context) *gorm.DB { return gormutil.GetDB(ctx, r.db) }

// col resolves the column of a Passkey field through its gorm tags.
func (r *gormPasskeyRepo) col(field string) clause.Column {
	return gormutil.Col(r.db, &pkmodels.Passkey{}, field)
}

func (r *gormPasskeyRepo) Create(ctx context.Context, pk *pkmodels.Passkey) error {
	return r.conn(ctx).Create(pk).Error
}

func (r *gormPasskeyRepo) findOne(ctx context.Context, field, value string) (*pkmodels.Passkey, error) {
	var pk pkmodels.Passkey
	err := r.conn(ctx).Where(clause.Eq{Column: r.col(field), Value: value}).Take(&pk).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &pk, nil
}

func (r *gormPasskeyRepo) FindByID(ctx context.Context, id string) (*pkmodels.Passkey, error) {
	return r.findOne(ctx, "ID", id)
}

func (r *gormPasskeyRepo) FindByCredentialID(ctx context.Context, credentialID string) (*pkmodels.Passkey, error) {
	return r.findOne(ctx, "CredentialID", credentialID)
}

func (r *gormPasskeyRepo) ListByUser(ctx context.Context, userID string) ([]pkmodels.Passkey, error) {
	out := []pkmodels.Passkey{}
	err := r.conn(ctx).
		Where(clause.Eq{Column: r.col("UserID"), Value: userID}).
		Order(clause.OrderByColumn{Column: r.col("CreatedAt")}).
		Find(&out).Error
	return out, err
}

func (r *gormPasskeyRepo) UpdateCounter(ctx context.Context, id string, counter int64) error {
	return r.conn(ctx).Model(&pkmodels.Passkey{}).
		Where(clause.Eq{Column: r.col("ID"), Value: id}).
		Update(r.col("Counter").Name, counter).Error
}

func (r *gormPasskeyRepo) UpdateName(ctx context.Context, id, name string) (*pkmodels.Passkey, error) {
	// Step 1: rename the row
	res := r.conn(ctx).Model(&pkmodels.Passkey{}).
		Where(clause.Eq{Column: r.col("ID"), Value: id}).
		Update(r.col("Name").Name, name)
	if res.Error != nil {
		return nil, res.Error
	}
	// Step 2: return the updated row like better-auth's adapter.update
	return r.FindByID(ctx, id)
}

func (r *gormPasskeyRepo) Delete(ctx context.Context, id string) error {
	return r.conn(ctx).Where(clause.Eq{Column: r.col("ID"), Value: id}).Delete(&pkmodels.Passkey{}).Error
}

func (r *gormPasskeyRepo) DeleteByUser(ctx context.Context, userID string) error {
	return r.conn(ctx).Where(clause.Eq{Column: r.col("UserID"), Value: userID}).Delete(&pkmodels.Passkey{}).Error
}
