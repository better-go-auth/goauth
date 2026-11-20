package render_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/schema/render"
	"github.com/stretchr/testify/require"
)

func TestPrisma_Golden(t *testing.T) {
	for name, reg := range goldenRegistries(t) {
		for _, provider := range render.PrismaProviders {
			if provider == render.PrismaMongoDB && reg.IDStrategy() == schema.IDSerial {
				continue
			}
			t.Run(name+"/"+provider, func(t *testing.T) {
				out, err := render.Prisma(reg, provider)
				require.NoError(t, err)
				golden(t, name+"."+provider+".prisma", out)
			})
		}
	}
}

func TestPrisma_Rules(t *testing.T) {
	reg := pluginRegistry(t, schema.IDApplication)
	// Step 1: provider aliases and errors
	for in, want := range map[string]string{"postgres": "postgresql", "pg": "postgresql", "sqlite3": "sqlite", "mariadb": "mysql", "mongo": "mongodb"} {
		got, err := render.ParsePrismaProvider(in)
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	_, err := render.Prisma(reg, "oracle")
	require.Error(t, err)
	_, err = render.Prisma(pluginRegistry(t, schema.IDSerial), "mongodb")
	require.Error(t, err)
	// Step 2: better-auth's shapes
	out, err := render.Prisma(reg, "postgresql")
	require.NoError(t, err)
	require.Contains(t, out, "model Users {")
	require.Contains(t, out, "  sessions            Session[]\n")
	require.Contains(t, out, "users                  Users     @relation(fields: [userId], references: [id], onDelete: Cascade)")
	require.Contains(t, out, "@@unique([email])")
	require.Contains(t, out, "@@index([userId])")
	require.Contains(t, out, `@@map("users")`)
	require.Contains(t, out, "createdAt DateTime @default(now())")
	// Step 3: several references to one model get named relations
	multi := schema.MustBuild(schema.Options{Plugins: []schema.Plugin{{ID: "org", Schema: schema.PluginSchema{
		"invitation": {Fields: map[string]schema.Field{
			"inviterId": {Type: schema.String, Required: true, References: &schema.Reference{Model: "user", Field: "id"}},
			"inviteeId": {Type: schema.String, References: &schema.Reference{Model: "user", Field: "id", OnDelete: schema.SetNull}},
			"parentId":  {Type: schema.String, References: &schema.Reference{Model: "invitation", Field: "id"}},
		}},
	}}}})
	out, err = render.Prisma(multi, "postgresql")
	require.NoError(t, err)
	require.Contains(t, out, `  inviter           User         @relation("Invitation_inviter", fields: [inviter_id], references: [id], onDelete: Cascade)`)
	require.Contains(t, out, `  invitee           User?        @relation("Invitation_invitee", fields: [invitee_id], references: [id], onDelete: SetNull)`)
	require.Contains(t, out, `  parent            Invitation?  @relation("Invitation_parent", fields: [parent_id], references: [id], onDelete: Cascade)`)
	require.Contains(t, out, `  invitationParents Invitation[] @relation("Invitation_parent")`)
	require.Contains(t, out, `  invitationInviters    Invitation[] @relation("Invitation_inviter")`)
	prismaValidate(t, "postgresql", "multi.postgresql.prisma", out)
}

// prismaURLs are dummy datasource URLs (`prisma validate` checks the URL's protocol).
var prismaURLs = map[string]string{
	render.PrismaPostgreSQL: "postgresql://user@localhost/db",
	render.PrismaMySQL:      "mysql://user@localhost/db",
	render.PrismaSQLite:     "file:./dev.db",
	render.PrismaMongoDB:    "mongodb://localhost/db",
}

// prismaBinary returns the prisma CLI ($GOAUTH_PRISMA_BIN, or prisma in PATH), or "" when there is none.
func prismaBinary() string {
	if bin := os.Getenv("GOAUTH_PRISMA_BIN"); bin != "" {
		return bin
	}
	bin, _ := exec.LookPath("prisma")
	return bin
}

// prismaValidate runs `prisma validate` and `prisma format` on a schema (skipped without a prisma CLI):
// the schema must be valid and already formatted.
func prismaValidate(t *testing.T, provider, name, schemaText string) {
	t.Helper()
	bin := prismaBinary()
	if bin == "" {
		t.Log("prisma CLI not found (set GOAUTH_PRISMA_BIN or put prisma in PATH); skipping validation")
		return
	}
	file := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(file, []byte(schemaText), 0o644))
	env := append(os.Environ(), "DATABASE_URL="+prismaURLs[provider], "CHECKPOINT_DISABLE=1", "PRISMA_HIDE_UPDATE_MESSAGE=1")
	// Step 1: valid
	cmd := exec.Command(bin, "validate", "--schema", file)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	// Step 2: formatted (prisma format leaves it unchanged)
	cmd = exec.Command(bin, "format", "--schema", file)
	cmd.Env = env
	out, err = cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	formatted, err := os.ReadFile(file)
	require.NoError(t, err)
	require.Equal(t, schemaText, string(formatted), "prisma format changed the schema")
}

// TestPrisma_Validate checks every golden schema with the prisma CLI when it is available.
func TestPrisma_Validate(t *testing.T) {
	if prismaBinary() == "" {
		t.Skip("prisma CLI not found (set GOAUTH_PRISMA_BIN or put prisma in PATH)")
	}
	for name, reg := range goldenRegistries(t) {
		for _, provider := range render.PrismaProviders {
			if provider == render.PrismaMongoDB && reg.IDStrategy() == schema.IDSerial {
				continue
			}
			t.Run(name+"/"+provider, func(t *testing.T) {
				out, err := render.Prisma(reg, provider)
				require.NoError(t, err)
				prismaValidate(t, provider, name+"."+provider+".prisma", out)
			})
		}
	}
}
