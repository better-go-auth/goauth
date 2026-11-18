package storagee2e

import (
	"context"
	"errors"
	"net/http"
	"testing"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/adapter/gormadapter/gormtest"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/migration"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/require"
)

// notesPlugin declares a table and a user field with SchemaProvider and stores notes through
// InitContext.Adapter: the shape every new table-backed plugin follows.
type notesPlugin struct {
	store adapter.Adapter
	reg   *schema.Registry
}

var _ plugin.SchemaProvider = (*notesPlugin)(nil)

func (p *notesPlugin) ID() string                       { return "notes" }
func (p *notesPlugin) Migrator() migration.IMigrator    { return nil }
func (p *notesPlugin) Services() map[string]any         { return nil }
func (p *notesPlugin) Routes() []plugin.RouteDescriptor { return nil }

// Schema declares the note table (referencing user) and a user field.
func (p *notesPlugin) Schema() schema.PluginSchema {
	return schema.PluginSchema{
		"note": {Fields: map[string]schema.Field{
			"userId": {Type: schema.String, Required: true, References: &schema.Reference{Model: schema.ModelUser, Field: "id"}, Index: true},
			"body":   {Type: schema.String, Required: true},
			"pinned": {Type: schema.Boolean, Default: false},
		}},
		schema.ModelUser: {Fields: map[string]schema.Field{"noteCount": {Type: schema.Integer, Default: 0}}},
	}
}

type noteInput struct {
	Body struct {
		UserID string `json:"userId"`
		Body   string `json:"body"`
	}
}

type noteOutput struct {
	Body map[string]any
}

// Init keeps the adapter and registry and mounts POST /notes.
func (p *notesPlugin) Init(ictx *plugin.InitContext) error {
	p.store, p.reg = ictx.Adapter, ictx.Schema
	if p.store == nil || p.reg == nil {
		return errors.New("notes: no adapter")
	}
	huma.Register(ictx.Api, huma.Operation{OperationID: "notes_create", Method: http.MethodPost, Path: "/api/auth/notes"},
		func(ctx context.Context, in *noteInput) (*noteOutput, error) {
			rec, err := p.store.Create(ctx, "note", adapter.Record{"userId": in.Body.UserID, "body": in.Body.Body})
			if err != nil {
				return nil, err
			}
			return &noteOutput{Body: rec}, nil
		})
	return nil
}

// TestSchemaProviderPluginTables: a plugin table is created by the registry migrator (named by the column
// case, ids by the id strategy), used through the adapter, and reported by verify mode.
func TestSchemaProviderPluginTables(t *testing.T) {
	for _, dialect := range gormtest.Dialects {
		t.Run(string(dialect), func(t *testing.T) {
			db := openDB(t, dialect, "e2e_plugin")
			prefix := prefixFor(dialect, "e2e_plugin")
			cfg := func(c *config.AuthConfig) {
				c.GoAuth.TablePrefix = prefix
				c.GoAuth.ColumnCase = schema.Camel
				c.Advanced.Database.IDFormat = config.IDFormatSerial
			}
			p := &notesPlugin{}
			s := server(t, db, cfg, p)
			body := signUpInAndGetSession(t, s, "notes@example.com")

			// Step 1: the table and the user column exist, in camel case
			require.Subset(t, columnsOf(t, db, prefix+"note"), []string{"id", "userId", "body", "pinned"})
			require.Contains(t, columnsOf(t, db, prefix+"user"), "noteCount")

			// Step 2: the plugin writes through the adapter (serial ids, defaults)
			res := s.Post(t, "/api/auth/notes", map[string]any{"userId": body.User.ID, "body": "hello"})
			require.Equal(t, http.StatusOK, res.Status, string(res.Body))
			var note map[string]any
			res.JSON(t, &note)
			require.Equal(t, "1", note["id"])
			require.Equal(t, body.User.ID, note["userId"])
			require.Equal(t, false, note["pinned"])

			// Step 3: the generated SQL contains the plugin table, and verify mode reports it when missing
			opts := goauth.GoAuthOptions{Conn: db, Plugins: []plugin.Plugin{&notesPlugin{}}}
			cfg(&opts.AuthConfig)
			reg, err := goauth.Schema(opts)
			require.NoError(t, err)
			_, ok := reg.Model("note")
			require.True(t, ok)
			require.NoError(t, db.Migrator().DropTable(prefix+"note"))
			_, err = setup(db, func(c *config.AuthConfig) {
				cfg(c)
				c.GoAuth.Migrations.Mode = config.MigrationsVerify
			}, &notesPlugin{})
			require.ErrorContains(t, err, "add table "+prefix+"note")
		})
	}
}
