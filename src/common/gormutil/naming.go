package gormutil

import (
	"strings"

	"gorm.io/gorm/schema"
)

// defaultModelMapping maps Go struct type names to canonical better-auth model identifiers.
var defaultModelMapping = map[string]string{
	"User":             "user",
	"Session":          "session",
	"Account":          "account",
	"Verification":     "verification",
	"Organization":     "organization",
	"Member":           "member",
	"Invitation":       "invitation",
	"Team":             "team",
	"TeamMember":       "teamMember",
	"OrganizationRole": "organizationRole",
	"JWK":              "jwks",
	"TwoFactor":        "twoFactor",
	"Passkey":          "passkey",
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
	// 1. Direct match on model string (e.g., "user", "organizationRole")
	if t, ok := ns.overrides[model]; ok {
		return ns.TablePrefix + t
	}

	// 2. Lookup canonical model name from struct type name (e.g., "User" -> "user")
	if canonical, ok := defaultModelMapping[model]; ok {
		if t, ok := ns.overrides[canonical]; ok {
			return ns.TablePrefix + t
		}
		return ns.TablePrefix + canonical
	}

	// 3. Lowercase fallback (e.g., "USER" -> "user")
	lower := strings.ToLower(model)
	if t, ok := ns.overrides[lower]; ok {
		return ns.TablePrefix + t
	}

	return ns.TablePrefix + model
}
