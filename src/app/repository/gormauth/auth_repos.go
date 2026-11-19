package gormauth

import (
	"github.com/better-go-auth/goauth/src/app/repository/adapterrepo"
	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/schema"
	"gorm.io/gorm"
)

type RepoOption func(*RepoConfig)

type RepoConfig struct {
	GenerateID func() string
	// Registry lets updates use better-auth field names of runtime fields (plugin SchemaProvider fields such
	// as last-login-method's lastLoginMethod): they are written to the field's column. The hand-written
	// repositories don't read or insert runtime fields; SetupGoAuth refuses User/Session/Account/Verification
	// AdditionalFields with GORMRepositories.
	Registry *schema.Registry
}

// WithRegistry resolves update keys that are registry field names (see RepoConfig.Registry).
func WithRegistry(reg *schema.Registry) RepoOption {
	return func(c *RepoConfig) {
		c.Registry = reg
	}
}

// updateKeys converts an update map to keys GORM understands: Go field names of the model's struct stay,
// registry field names become the struct's Go field name or, for runtime fields, their column.
func updateKeys(reg *schema.Registry, model string, data map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(data))
	for k, v := range data {
		switch goName, static := adapterrepo.GoFieldName(model, k); {
		case static:
			k = goName
		case reg != nil:
			if col := reg.Column(model, k); col != "" {
				k = col
			}
		}
		out[k] = v
	}
	return out
}

func WithGenerateID(fn func() string) RepoOption {
	return func(c *RepoConfig) {
		c.GenerateID = fn
	}
}

// NewAuthRepos creates a complete suite of GORM-backed repositories implementing IAuthRepos.
func NewAuthRepos(db *gorm.DB, opts ...RepoOption) repo_interfaces.IAuthRepos {
	gormutil.RegisterCallbacks(db)
	return &repo_interfaces.AuthRepos{
		IUserRepo:         NewUserRepo(db, opts...),
		IOAuthAccountRepo: NewAccountRepo(db, opts...),
		ISessionRepo:      NewSessionRepo(db, opts...),
		IVerificationRepo: NewVerificationRepo(db, opts...),
	}
}
