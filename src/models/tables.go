package models

import "sync"

// better-auth model names; tables are named after them unless overridden.
const (
	ModelUser         = "user"
	ModelSession      = "session"
	ModelAccount      = "account"
	ModelVerification = "verification"
	ModelOrganization = "organization"
	ModelMember       = "member"
	ModelInvitation   = "invitation"
)

var (
	tableMu        sync.RWMutex
	tablePrefix    string
	tableOverrides = map[string]string{}
)

// SetTableNames sets the prefix and per-model overrides (model -> table).
// It must run before the models are first queried: GORM caches TableName() per *gorm.DB.
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

// TableName returns the table used for a better-auth model name.
func TableName(model string) string {
	tableMu.RLock()
	defer tableMu.RUnlock()
	if t, ok := tableOverrides[model]; ok {
		return tablePrefix + t
	}
	return tablePrefix + model
}
