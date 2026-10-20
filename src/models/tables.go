package models

import (
	"sync"

	"gorm.io/gorm/schema"
)

// better-auth model names; tables are named after them unless overridden.
const (
	ModelUser             = "user"
	ModelSession          = "session"
	ModelAccount          = "account"
	ModelVerification     = "verification"
	ModelOrganization     = "organization"
	ModelMember           = "member"
	ModelInvitation       = "invitation"
	ModelTeam             = "team"
	ModelTeamMember       = "teamMember"
	ModelOrganizationRole = "organizationRole"
	ModelJWKS             = "jwks"
)

var (
	tableMu        sync.RWMutex
	tablePrefix    string
	tableOverrides = map[string]string{}
)

// SetTableNames sets the global prefix and per-model overrides (model -> table).
// Deprecated: For multi-tenant applications, use NewNamingStrategy bound to a specific *gorm.DB instead.
func SetTableNames(prefix string, overrides map[string]string) {
	tableMu.Lock()
	defer tableMu.Unlock()
	tablePrefix = prefix
	tableOverrides = map[string]string{}
	for model, table := range overrides {
		if table != "" {
			tableOverrides[model] = table
		}
	}
}

// NamingStrategy implements schema.Namer with per-model overrides and prefixes
// for instance-scoped multi-tenant GORM connections.
type NamingStrategy struct {
	schema.NamingStrategy
	overrides map[string]string
}

// NewNamingStrategy constructs an instance-scoped schema.Namer for GORM.
func NewNamingStrategy(prefix string, overrides map[string]string) *NamingStrategy {
	ov := make(map[string]string, len(overrides))
	for k, v := range overrides {
		if v != "" {
			ov[k] = v
		}
	}
	return &NamingStrategy{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix:   prefix,
			SingularTable: true,
		},
		overrides: ov,
	}
}

// TableName returns the table name for a model under this NamingStrategy.
func (ns *NamingStrategy) TableName(model string) string {
	if t, ok := ns.overrides[model]; ok {
		return ns.TablePrefix + t
	}
	return ns.TablePrefix + model
}

// ResolveTableName resolves a model's table name using the provided namer if available,
// falling back to the global table configuration.
func ResolveTableName(namer schema.Namer, model string) string {
	if ns, ok := namer.(*NamingStrategy); ok {
		return ns.TableName(model)
	}
	if namer != nil {
		tableMu.RLock()
		ov, hasOv := tableOverrides[model]
		tableMu.RUnlock()
		if hasOv {
			return namer.TableName(ov)
		}
		return namer.TableName(model)
	}
	return TableName(model)
}

// TableName returns the table used for a better-auth model name from global configuration.
func TableName(model string) string {
	tableMu.RLock()
	defer tableMu.RUnlock()
	if t, ok := tableOverrides[model]; ok {
		return tablePrefix + t
	}
	return tablePrefix + model
}
