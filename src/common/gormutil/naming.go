package gormutil

import (
	"strings"

	goauthschema "github.com/better-go-auth/goauth/src/schema"
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

// camelColumnExceptions are better-auth plugin columns whose camelCase name is not the plain conversion of
// GORM's snake_case name, keyed by logical model name, then snake_case column.
var camelColumnExceptions = map[string]map[string]string{
	"passkey": {"credential_id": "credentialID"},
}

// NamingStrategy implements schema.Namer with per-model overrides and prefixes
// for instance-scoped multi-tenant GORM connections. With WithRegistry it also follows the schema
// registry's column names (ColumnCase, Fields renames) for every GORM model.
type NamingStrategy struct {
	schema.NamingStrategy
	overrides map[string]string
	// columns maps a registry table to GORM's snake_case column name → the registry's column
	columns map[string]map[string]string
	// camel converts the columns of tables the registry doesn't know (GORM plugin tables) to camelCase
	camel bool
	// exceptions maps a physical table to its camelColumnExceptions
	exceptions map[string]map[string]string
}

// NamingOption configures NewNamingStrategy.
type NamingOption func(*NamingStrategy)

// WithRegistry makes GORM use the registry's column names: for the registry's tables every Go field maps
// to its registry column (so ColumnCase, Fields renames and the registry agree with GORM), and with
// ColumnCase camel the tables of GORM-only models (plugin structs) use better-auth's camelCase columns.
func WithRegistry(reg *goauthschema.Registry) NamingOption {
	return func(ns *NamingStrategy) {
		if reg == nil {
			return
		}
		// Step 1: registry tables: GORM's snake name of a field (SnakeCase of the field name) → column
		ns.columns = map[string]map[string]string{}
		for _, m := range reg.Models() {
			cols := map[string]string{}
			for _, f := range m.Fields() {
				cols[goauthschema.SnakeCase(f.Name)] = f.Column
			}
			ns.columns[m.Table()] = cols
		}
		// Step 2: camelCase for the other tables, with better-auth's irregular names
		ns.camel = reg.ColumnCase() == goauthschema.Camel
		ns.exceptions = map[string]map[string]string{}
		for model, ex := range camelColumnExceptions {
			ns.exceptions[ns.TableName(model)] = ex
		}
	}
}

// NewNamingStrategy constructs an instance-scoped schema.Namer for GORM.
func NewNamingStrategy(prefix string, overrides map[string]string, opts ...NamingOption) *NamingStrategy {
	ov := make(map[string]string, len(overrides))
	for k, v := range overrides {
		if v != "" {
			ov[k] = v
		}
	}
	ns := &NamingStrategy{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix:   prefix,
			SingularTable: true,
		},
		overrides: ov,
	}
	for _, o := range opts {
		o(ns)
	}
	return ns
}

// ColumnName returns the column of Go field column on table: the registry's column for registry tables,
// camelCase for other tables when the registry is camel case, GORM's snake_case otherwise.
func (ns *NamingStrategy) ColumnName(table, column string) string {
	snake := ns.NamingStrategy.ColumnName(table, column)
	// Step 1: tables of the registry use its columns
	if cols, ok := ns.columns[table]; ok {
		if c, ok := cols[snake]; ok {
			return c
		}
	}
	if !ns.camel {
		return snake
	}
	// Step 2: other tables in camel case: better-auth's irregular names, else the plain conversion
	if c, ok := ns.exceptions[table][snake]; ok {
		return c
	}
	return CamelFromSnake(snake)
}

// CamelFromSnake converts a snake_case column ("user_id") to camelCase ("userId").
func CamelFromSnake(s string) string {
	parts := strings.Split(s, "_")
	var b strings.Builder
	for i, p := range parts {
		if p == "" {
			continue
		}
		if i > 0 && b.Len() > 0 {
			b.WriteString(strings.ToUpper(p[:1]) + p[1:])
		} else {
			b.WriteString(p)
		}
	}
	return b.String()
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
