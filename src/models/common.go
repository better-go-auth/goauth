package models

import (
	"time"

	"github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/providers/idgen"
	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/gorm"
)

// func Ptr[T any](value T) *T {
// 	return &value
// }

type Base struct {
	ID        string    `gorm:"primarykey" json:"id,omitempty"`
	CreatedAt time.Time `gorm:"not null" json:"createdAt"`
	UpdatedAt time.Time `gorm:"not null" json:"updatedAt"`
}

func (m *Base) BeforeCreate(tx *gorm.DB) (err error) {
	if m.ID == "" {
		m.ID = NewID()
	}
	return nil
}

func (b Base) GetID() string {
	return b.ID
}

type SDBase struct {
	ID        string         `gorm:"primarykey" json:"id,omitempty"`
	CreatedAt time.Time      `gorm:"not null" json:"createdAt"`
	UpdatedAt time.Time      `gorm:"not null" json:"updatedAt"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

func (m *SDBase) BeforeCreate(tx *gorm.DB) (err error) {
	if m.ID == "" {
		m.ID = NewID()
	}
	return nil
}

func (b SDBase) GetID() string {
	return b.ID
}

type OperationAccessDto struct {
	OperationId  consts.OperationId `gorm:"primaryKey" json:"operation_id"`
	AllowedRoles pq.StringArray     `gorm:"type:text[]" json:"allowedRoles,omitempty"`
	GroupName    string
	Description  string
	OrgID        *string
	// CompanyID    *string // Deprecated: use OrgID instead
}

// NewID generates a 32-char alphanumeric ID (better-auth default).
// Override via SetIDGenerator or Advanced.GenerateID; use idgen.ULID for legacy 26-char ULIDs.
var idGenerator = func() string { return idgen.GenerateID() }

// SetIDGenerator replaces the generator used for new record IDs (nil restores 32-char default).
func SetIDGenerator(fn func() string) {
	if fn == nil {
		fn = func() string { return idgen.GenerateID() }
	}
	idGenerator = fn
}

func NewID() string {
	return idGenerator()
}

func NewSecureId() string {
	return uuid.New().String()
}
