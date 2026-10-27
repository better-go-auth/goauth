package models

import (
	"time"

	"github.com/better-go-auth/goauth/src/common/consts"
	"github.com/better-go-auth/goauth/src/providers/idgen"
	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Base defines standard primary key and timestamp fields across domain entities.
type Base struct {
	ID        string    `gorm:"primarykey" bun:"id,pk" json:"id,omitempty"`
	CreatedAt time.Time `gorm:"not null" bun:"created_at,notnull" json:"createdAt"`
	UpdatedAt time.Time `gorm:"not null" bun:"updated_at,notnull" json:"updatedAt"`
}

// EnsureID assigns an ID if not already populated.
func (m *Base) EnsureID() {
	if m.ID == "" {
		m.ID = NewID()
	}
}

func (b Base) GetID() string {
	return b.ID
}

// SDBase defines soft-deletable base entity fields with pure Go types (*time.Time).
type SDBase struct {
	ID        string     `gorm:"primarykey" bun:"id,pk" json:"id,omitempty"`
	CreatedAt time.Time  `gorm:"not null" bun:"created_at,notnull" json:"createdAt"`
	UpdatedAt time.Time  `gorm:"not null" bun:"updated_at,notnull" json:"updatedAt"`
	DeletedAt *time.Time `gorm:"index" bun:"deleted_at,soft_delete" json:"deletedAt,omitempty"`
}

// EnsureID assigns an ID if not already populated.
func (m *SDBase) EnsureID() {
	if m.ID == "" {
		m.ID = NewID()
	}
}

func (b SDBase) GetID() string {
	return b.ID
}

type OperationAccessDto struct {
	OperationId  consts.OperationId `gorm:"primaryKey" bun:"operation_id,pk" json:"operation_id"`
	AllowedRoles pq.StringArray     `gorm:"type:text[]" bun:"allowed_roles" json:"allowedRoles,omitempty"`
	GroupName    string             `bun:"group_name"`
	Description  string             `bun:"description"`
	OrgID        *string            `bun:"org_id"`
	// CompanyID    *string // Deprecated: use OrgID instead
}

// NewID generates a 32-char alphanumeric ID (better-auth default).
func NewID() string {
	return idgen.GenerateID()
}

func NewSecureId() string {
	return uuid.New().String()
}
