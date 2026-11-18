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

func TestIDFormatsAndMigrationModes(t *testing.T) {
	// Step 1: better-auth's generateId values
	for format, want := range map[string]schema.IDStrategy{"": schema.IDApplication, "uuid": schema.IDApplication, IDFormatDatabase: schema.IDDatabase, IDFormatSerial: schema.IDSerial} {
		d := AdvancedDatabase{IDFormat: format}
		require.Equal(t, want, d.IDStrategy(), format)
		gen, err := d.IDGenerator()
		require.NoError(t, err)
		if want.DatabaseGenerated() {
			require.Empty(t, gen(), "the database creates ids")
		} else {
			require.NotEmpty(t, gen())
		}
	}
	_, err := AdvancedDatabase{IDFormat: IDFormatSerial, GenerateID: func() string { return "x" }}.IDGenerator()
	require.Error(t, err)
	// Step 2: the registry gets the strategy and the rateLimit table
	cfg := &AuthConfig{Advanced: Advanced{Database: AdvancedDatabase{IDFormat: IDFormatSerial}}, RateLimit: RateLimitOptions{Storage: "database", ModelName: "rate_limits"}}
	opts := cfg.SchemaOptions()
	require.Equal(t, schema.IDSerial, opts.IDs)
	require.True(t, opts.RateLimit)
	require.Equal(t, "rate_limits", opts.Models[schema.ModelRateLimit].ModelName)
	require.False(t, (&AuthConfig{}).SchemaOptions().RateLimit)
	// Step 3: migration modes
	for in, want := range map[MigrationMode]MigrationMode{"": MigrationsAuto, "AUTO": MigrationsAuto, "verify": MigrationsVerify, "off": MigrationsOff} {
		got, err := MigrationsOptions{Mode: in}.EffectiveMode()
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	_, err = MigrationsOptions{Mode: "sometimes"}.EffectiveMode()
	require.Error(t, err)
}
