package models

import (
	"sync"
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

// TableNamer abstracts table name resolution across ORMs (e.g., GORM schema.Namer, Bun, or custom namers).
type TableNamer interface {
	TableName(table string) string
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

// ResolveTableName resolves a model's table name using the provided namer if available,
// falling back to the global table configuration.
func ResolveTableName(namer TableNamer, model string) string {
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
