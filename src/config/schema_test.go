package config

import (
	"testing"

	"github.com/better-go-auth/goauth/src/schema"
	"github.com/stretchr/testify/require"
)

func TestSchemaOptions(t *testing.T) {
	cfg := AuthConfig{
		User: UserOptions{
			ModelName:        "users",
			Fields:           map[string]string{"emailVerified": "is_verified"},
			AdditionalFields: map[string]schema.Field{"loyaltyTier": {Type: schema.String, Default: "bronze"}},
		},
		Session:      Session{AdditionalFields: map[string]schema.Field{"region": {Type: schema.String}}},
		Account:      AccountOptions{Fields: map[string]string{"userId": "owner_id"}},
		Verification: VerificationOptions{ModelName: "verifications"},
		GoAuth:       GoAuthConfig{TablePrefix: "auth_", ColumnCase: schema.Camel},
	}
	// Step 1: the options carry every model setting
	opts := cfg.SchemaOptions()
	require.Equal(t, schema.Camel, opts.ColumnCase)
	require.Len(t, opts.Models, 4)

	// Step 2: they build the expected registry
	reg, err := schema.Build(opts)
	require.NoError(t, err)
	require.Equal(t, "auth_users", reg.Table("user"))
	require.Equal(t, "is_verified", reg.Column("user", "emailVerified"))
	require.Equal(t, "loyaltyTier", reg.Column("user", "loyaltyTier"))
	require.Equal(t, "region", reg.Column("session", "region"))
	require.Equal(t, "owner_id", reg.Column("account", "userId"))
	require.Equal(t, "auth_verifications", reg.Table("verification"))

	// Step 3: an empty configuration sets no model options (and builds the default snake registry)
	empty := (&AuthConfig{}).SchemaOptions()
	require.Empty(t, empty.Models)
	reg, err = schema.Build(empty)
	require.NoError(t, err)
	require.Equal(t, "email_verified", reg.Column("user", "emailVerified"))
}
