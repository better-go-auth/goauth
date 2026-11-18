package config

import (
	"strings"

	"github.com/better-go-auth/goauth/src/schema"
)

// SchemaOptions returns the schema.Options described by this configuration: column case, table prefix and
// renames, the id strategy (Advanced.Database.IDFormat), the rateLimit table (RateLimit.Storage "database"),
// and the per-model ModelName / Fields / AdditionalFields of user, session, account, verification and
// rateLimit. Plugin schemas are not part of the configuration; the caller appends them to Plugins.
func (c *AuthConfig) SchemaOptions() schema.Options {
	// Step 1: global naming
	opts := schema.Options{
		ColumnCase:  c.GoAuth.ColumnCase,
		TablePrefix: c.GoAuth.TablePrefix,
		TableNames:  c.GoAuth.TableNames,
		Models:      map[string]schema.ModelOptions{},
		IDs:         c.Advanced.Database.IDStrategy(),
		// the rateLimit table exists only with the "database" storage (better-auth's getAuthTables)
		RateLimit: c.RateLimit.CustomStorage == nil && strings.EqualFold(c.RateLimit.Storage, "database"),
	}
	// Step 2: per-model options (only models that set something, so Build reports nothing spurious)
	add := func(model, modelName string, fields map[string]string, extra map[string]schema.Field) {
		if modelName == "" && len(fields) == 0 && len(extra) == 0 {
			return
		}
		opts.Models[model] = schema.ModelOptions{ModelName: modelName, Fields: fields, AdditionalFields: extra}
	}
	add(schema.ModelUser, c.User.ModelName, c.User.Fields, c.User.AdditionalFields)
	add(schema.ModelSession, c.Session.ModelName, c.Session.Fields, c.Session.AdditionalFields)
	add(schema.ModelAccount, c.Account.ModelName, c.Account.Fields, c.Account.AdditionalFields)
	add(schema.ModelVerification, c.Verification.ModelName, c.Verification.Fields, c.Verification.AdditionalFields)
	if opts.RateLimit {
		add(schema.ModelRateLimit, c.RateLimit.ModelName, c.RateLimit.Fields, nil)
	}
	return opts
}
