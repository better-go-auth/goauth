// Package schemaparity compares goauth's database schema with better-auth's own (1.6.16): with
// GoAuth.ColumnCase "camel" a goauth database must be usable by a TypeScript better-auth server and the
// other way round, for the core tables and every plugin goauth implements.
package schemaparity_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/config"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/admin"
	"github.com/better-go-auth/goauth/src/plugins/anonymous"
	anonconfig "github.com/better-go-auth/goauth/src/plugins/anonymous/config"
	"github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	deviceauthorization "github.com/better-go-auth/goauth/src/plugins/device-authorization"
	daconfig "github.com/better-go-auth/goauth/src/plugins/device-authorization/config"
	emailotp "github.com/better-go-auth/goauth/src/plugins/email-otp"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
	jwtplugin "github.com/better-go-auth/goauth/src/plugins/jwt"
	jwtconfig "github.com/better-go-auth/goauth/src/plugins/jwt/config"
	magiclink "github.com/better-go-auth/goauth/src/plugins/magic-link"
	magiclinkconfig "github.com/better-go-auth/goauth/src/plugins/magic-link/config"
	multisession "github.com/better-go-auth/goauth/src/plugins/multi-session"
	msconfig "github.com/better-go-auth/goauth/src/plugins/multi-session/config"
	onetimetoken "github.com/better-go-auth/goauth/src/plugins/one-time-token"
	ottconfig "github.com/better-go-auth/goauth/src/plugins/one-time-token/config"
	"github.com/better-go-auth/goauth/src/plugins/org"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/better-go-auth/goauth/src/plugins/passkey"
	pkconfig "github.com/better-go-auth/goauth/src/plugins/passkey/config"
	phonenumber "github.com/better-go-auth/goauth/src/plugins/phone-number"
	phoneconfig "github.com/better-go-auth/goauth/src/plugins/phone-number/config"
	"github.com/better-go-auth/goauth/src/plugins/siwe"
	siweconfig "github.com/better-go-auth/goauth/src/plugins/siwe/config"
	twofactor "github.com/better-go-auth/goauth/src/plugins/two-factor"
	tfconfig "github.com/better-go-auth/goauth/src/plugins/two-factor/config"
	"github.com/better-go-auth/goauth/src/plugins/username"
	usernameconfig "github.com/better-go-auth/goauth/src/plugins/username/config"
	"github.com/better-go-auth/goauth/src/providers/ratelimit"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/schema/render"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// dump is the JSON of client/schema-dump.mjs (and the same shape read from goauth's database).
type dump struct {
	Tables map[string]table `json:"tables"`
	// Defaults lists, per table, the columns better-auth's adapter always fills (fields with a defaultValue)
	Defaults map[string][]string `json:"defaults"`
	Passkey  bool                `json:"passkey"`
}

// filled reports whether better-auth writes column of table on every insert.
func (d dump) filled(table, column string) bool {
	for _, c := range d.Defaults[table] {
		if c == column {
			return true
		}
	}
	return false
}

type table struct {
	Columns     []column `json:"columns"`
	Indexes     []index  `json:"indexes"`
	ForeignKeys []fk     `json:"foreignKeys"`
}

type column struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	NotNull bool   `json:"notnull"`
	PK      bool   `json:"pk"`
	Default *string
}

type index struct {
	Name    string   `json:"name"`
	Unique  bool     `json:"unique"`
	Columns []string `json:"columns"`
}

type fk struct {
	From     string `json:"from"`
	Table    string `json:"table"`
	To       string `json:"to"`
	OnDelete string `json:"onDelete"`
}

func (t table) column(name string) (column, bool) {
	for _, c := range t.Columns {
		if c.Name == name {
			return c, true
		}
	}
	return column{}, false
}

// uniqueOn reports whether a unique index (or the primary key) covers exactly cols.
func (t table) uniqueOn(cols ...string) bool {
	for _, i := range t.Indexes {
		if i.Unique && strings.Join(i.Columns, ",") == strings.Join(cols, ",") {
			return true
		}
	}
	return false
}

// betterAuthSchema runs better-auth's own migrations through client/schema-dump.mjs.
func betterAuthSchema(t *testing.T) dump {
	t.Helper()
	out := compattest.RunNodeClient(t, compattest.ClientDir("client"), "schema-dump.mjs", "http://unused")
	var d dump
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(out)), &d), out)
	return d
}

// plugins returns every goauth plugin that has a better-auth counterpart, configured like schema-dump.mjs.
func plugins(t *testing.T, db *gorm.DB) []plugin.Plugin {
	t.Helper()
	adminPlugin, err := admin.NewWithGorm(db)
	require.NoError(t, err)
	orgPlugin, err := org.NewWithGorm(db, orgconfig.OrgConfig{
		Teams:                &orgconfig.TeamsConfig{Enabled: true},
		DynamicAccessControl: &orgconfig.DynamicAccessControlConfig{Enabled: true},
	})
	require.NoError(t, err)
	return []plugin.Plugin{
		adminPlugin,
		anonymous.New(anonconfig.AnonymousConfig{}),
		bearer.New(bearerconfig.BearerConfig{}),
		deviceauthorization.New(daconfig.DeviceAuthorizationConfig{}),
		emailotp.New(emailotpconfig.EmailOTPConfig{SendVerificationOTP: func(emailotpconfig.SendVerificationOTPData, *http.Request) error { return nil }}),
		jwtplugin.New(jwtconfig.JWTConfig{}),
		magiclink.New(magiclinkconfig.MagicLinkConfig{SendMagicLink: func(magiclinkconfig.SendMagicLinkData, *http.Request) error { return nil }}),
		multisession.New(msconfig.MultiSessionConfig{}),
		onetimetoken.New(ottconfig.OneTimeTokenConfig{}),
		orgPlugin,
		passkey.New(pkconfig.PasskeyConfig{RPID: "localhost", RPName: "parity", Origin: []string{"http://localhost:3000"}}),
		phonenumber.New(phoneconfig.PhoneNumberConfig{SendOTP: func(phoneconfig.OTPData, *http.Request) error { return nil }}),
		siwe.New(siweconfig.SIWEConfig{Domain: "localhost:3000"}),
		twofactor.New(tfconfig.Config{Issuer: "parity"}),
		username.New(usernameconfig.UsernameConfig{}),
	}
}

// goauthSchema starts goauth (camel case, every plugin, database rate limits) on a fresh SQLite database
// and reads the schema it created.
func goauthSchema(t *testing.T) dump {
	t.Helper()
	// Step 1: goauth on a new database
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:parity_%s?mode=memory&cache=shared", uuid.NewString())), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	opts := goauth.GoAuthOptions{
		Conn:    db,
		Plugins: plugins(t, db),
		AuthConfig: config.AuthConfig{
			BaseURL: "http://localhost:3000", Secret: compattest.TestSecret,
			GoAuth:    config.GoAuthConfig{ColumnCase: schema.Camel},
			RateLimit: config.RateLimitOptions{Storage: ratelimit.StorageDatabase},
		},
	}
	_, err = goauth.SetupGoAuth(context.Background(), humago.New(http.NewServeMux(), apiConfig()), opts)
	require.NoError(t, err)
	// Step 2: tables, columns (with defaults), indexes, foreign keys
	return readSchema(t, db)
}

// readSchema reads every table of a SQLite database in the dump shape.
func readSchema(t *testing.T, db *gorm.DB) dump {
	t.Helper()
	var names []string
	require.NoError(t, db.Raw("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'").Scan(&names).Error)
	d := dump{Tables: map[string]table{}}
	for _, name := range names {
		var tb table
		var cols []struct {
			Name      string
			Type      string
			NotNull   int `gorm:"column:notnull"`
			PK        int `gorm:"column:pk"`
			DfltValue *string
		}
		require.NoError(t, db.Raw(fmt.Sprintf("PRAGMA table_info(%q)", name)).Scan(&cols).Error)
		for _, c := range cols {
			tb.Columns = append(tb.Columns, column{Name: c.Name, Type: c.Type, NotNull: c.NotNull == 1, PK: c.PK > 0, Default: c.DfltValue})
		}
		var idxs []struct {
			Name   string
			Unique int
		}
		require.NoError(t, db.Raw(fmt.Sprintf("PRAGMA index_list(%q)", name)).Scan(&idxs).Error)
		for _, i := range idxs {
			var ic []struct{ Name string }
			require.NoError(t, db.Raw(fmt.Sprintf("PRAGMA index_info(%q)", i.Name)).Scan(&ic).Error)
			ix := index{Name: i.Name, Unique: i.Unique == 1}
			for _, c := range ic {
				ix.Columns = append(ix.Columns, c.Name)
			}
			tb.Indexes = append(tb.Indexes, ix)
		}
		for _, c := range tb.Columns {
			if c.PK {
				tb.Indexes = append(tb.Indexes, index{Name: "pk", Unique: true, Columns: []string{c.Name}})
			}
		}
		var fks []struct {
			From     string
			Table    string
			To       string
			OnDelete string `gorm:"column:on_delete"`
		}
		require.NoError(t, db.Raw(fmt.Sprintf("PRAGMA foreign_key_list(%q)", name)).Scan(&fks).Error)
		for _, f := range fks {
			tb.ForeignKeys = append(tb.ForeignKeys, fk{From: f.From, Table: f.Table, To: f.To, OnDelete: f.OnDelete})
		}
		d.Tables[name] = tb
	}
	return d
}

// apiConfig is Huma's default configuration with schema names qualified by package: several plugins
// declare response types of the same name (SuccessResponse, StatusResponse), which Huma's default namer
// rejects when those plugins are installed together.
func apiConfig() huma.Config {
	cfg := huma.DefaultConfig("parity", "1")
	cfg.Components.Schemas = huma.NewMapRegistry("#/components/schemas/", func(t reflect.Type, hint string) string {
		name := huma.DefaultSchemaNamer(t, hint)
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
			t = t.Elem()
		}
		pkg := t.PkgPath()
		if i := strings.LastIndex(pkg, "/src/"); i >= 0 {
			pkg = pkg[i+5:]
		}
		return strings.NewReplacer("/", "_", "-", "_", ".", "_").Replace(pkg) + "_" + name
	})
	return cfg
}

// category groups SQLite declared types the way values are stored (better-auth's matchType for sqlite).
func category(sqlType string) string {
	t := strings.ToLower(sqlType)
	switch {
	case strings.Contains(t, "date") || strings.Contains(t, "time"):
		return "date"
	case strings.Contains(t, "int") || t == "numeric" || t == "boolean" || t == "real" || strings.Contains(t, "double"):
		return "number"
	}
	return "string"
}

// diff compares the schemas. Hard problems break a TypeScript better-auth server sharing the database (a
// missing table or column, an incompatible type, a NOT NULL column it doesn't fill, a missing unique
// constraint it relies on); notes are differences that don't.
func diff(ba, ga dump) (hard, notes []string) {
	tables := make([]string, 0, len(ba.Tables))
	for name := range ba.Tables {
		tables = append(tables, name)
	}
	sort.Strings(tables)
	for _, name := range tables {
		bt := ba.Tables[name]
		gt, ok := ga.Tables[name]
		if !ok {
			hard = append(hard, fmt.Sprintf("table %s is missing", name))
			continue
		}
		// Step 1: better-auth's columns: present, same kind, nullability
		for _, bc := range bt.Columns {
			gc, ok := gt.column(bc.Name)
			if !ok {
				hard = append(hard, fmt.Sprintf("%s.%s is missing", name, bc.Name))
				continue
			}
			if category(bc.Type) != category(gc.Type) {
				hard = append(hard, fmt.Sprintf("%s.%s: type %s, better-auth %s", name, bc.Name, gc.Type, bc.Type))
			}
			switch {
			case gc.NotNull && !bc.NotNull && gc.Default == nil && !ba.filled(name, bc.Name):
				hard = append(hard, fmt.Sprintf("%s.%s is NOT NULL without default; better-auth leaves it nullable", name, bc.Name))
			case gc.NotNull != bc.NotNull:
				notes = append(notes, fmt.Sprintf("%s.%s: NOT NULL %v, better-auth %v", name, bc.Name, gc.NotNull, bc.NotNull))
			}
		}
		// Step 2: goauth-only columns must not stop better-auth's inserts
		for _, gc := range gt.Columns {
			if _, ok := bt.column(gc.Name); ok {
				continue
			}
			if gc.NotNull && gc.Default == nil {
				hard = append(hard, fmt.Sprintf("%s.%s (goauth only) is NOT NULL without default", name, gc.Name))
			} else {
				notes = append(notes, fmt.Sprintf("%s.%s: goauth-only column", name, gc.Name))
			}
		}
		// Step 3: unique constraints and indexes
		for _, bi := range bt.Indexes {
			if bi.Unique && !gt.uniqueOn(bi.Columns...) {
				hard = append(hard, fmt.Sprintf("%s: no unique index on %v", name, bi.Columns))
			}
			if !bi.Unique && !hasIndex(gt, bi.Columns) {
				notes = append(notes, fmt.Sprintf("%s: no index on %v", name, bi.Columns))
			}
		}
		for _, gi := range gt.Indexes {
			if gi.Unique && !bt.uniqueOn(gi.Columns...) {
				notes = append(notes, fmt.Sprintf("%s: goauth-only unique index on %v", name, gi.Columns))
			}
		}
		// Step 4: foreign keys
		for _, bf := range bt.ForeignKeys {
			if !hasFK(gt, bf) {
				notes = append(notes, fmt.Sprintf("%s.%s: no foreign key to %s.%s (on delete %s)", name, bf.From, bf.Table, bf.To, bf.OnDelete))
			}
		}
	}
	for name := range ga.Tables {
		if _, ok := ba.Tables[name]; !ok {
			notes = append(notes, fmt.Sprintf("table %s: goauth only", name))
		}
	}
	sort.Strings(notes)
	return hard, notes
}

func hasIndex(t table, cols []string) bool {
	for _, i := range t.Indexes {
		if len(i.Columns) > 0 && i.Columns[0] == cols[0] {
			return true
		}
	}
	return false
}

func hasFK(t table, f fk) bool {
	for _, g := range t.ForeignKeys {
		if g.From == f.From && g.Table == f.Table && g.To == f.To && strings.EqualFold(g.OnDelete, f.OnDelete) {
			return true
		}
	}
	return false
}

// knownGaps are differences of plugins that still create their tables from GORM structs: fixing them
// means changing GORM tags, which makes GORM's AutoMigrate alter (on SQLite: rebuild) the tables of every
// existing deployment. They disappear when the plugins declare their tables through SchemaProvider
// (missing-tasks 2.9). Organization rows written by a TypeScript server fail on the goauth-only NOT NULL
// updatedAt columns until then.
var knownGaps = map[string]bool{
	"invitation.updatedAt (goauth only) is NOT NULL without default":                         true,
	"member.updatedAt (goauth only) is NOT NULL without default":                             true,
	"organization.updatedAt (goauth only) is NOT NULL without default":                       true,
	"teamMember.updatedAt (goauth only) is NOT NULL without default":                         true,
	"organizationRole.updatedAt is NOT NULL without default; better-auth leaves it nullable": true,
	"team.updatedAt is NOT NULL without default; better-auth leaves it nullable":             true,
	"teamMember.createdAt is NOT NULL without default; better-auth leaves it nullable":       true,
}

// TestCamelSchemaMatchesBetterAuth checks that goauth with ColumnCase camel creates every table and column
// better-auth 1.6.16 creates (core, every implemented plugin, rateLimit) with compatible types, no NOT NULL
// column a TypeScript server wouldn't fill, and better-auth's unique constraints. Remaining differences are
// logged (go test -v).
func TestCamelSchemaMatchesBetterAuth(t *testing.T) {
	ba := betterAuthSchema(t)
	require.True(t, ba.Passkey, "client-passkey/node_modules is needed for the passkey table")
	ga := goauthSchema(t)
	hard, notes := diff(ba, ga)
	for _, n := range notes {
		t.Log("difference:", n)
	}
	var unexpected []string
	for _, h := range hard {
		if knownGaps[h] {
			t.Log("known gap (missing-tasks 2.9):", h)
			continue
		}
		unexpected = append(unexpected, h)
	}
	require.Empty(t, unexpected, "goauth's camel schema breaks a better-auth server sharing the database")
}

// TestRenderedCamelSchemaMatchesBetterAuth runs goauth's generated desired-state SQL (what Atlas, goose
// and golang-migrate users get from goauth.GenerateSQL) for camel case on SQLite and compares the
// registry's tables with better-auth's: this path has no GORM involved and no known gaps.
func TestRenderedCamelSchemaMatchesBetterAuth(t *testing.T) {
	ba := betterAuthSchema(t)
	// Step 1: goauth's SQL, executed on a fresh database
	sql, err := goauth.GenerateSQL(goauth.GoAuthOptions{AuthConfig: config.AuthConfig{
		GoAuth:    config.GoAuthConfig{ColumnCase: schema.Camel},
		RateLimit: config.RateLimitOptions{Storage: ratelimit.StorageDatabase},
	}}, render.SQLite)
	require.NoError(t, err)
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:rendered_%s?mode=memory&cache=shared", uuid.NewString())), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	_, err = sqlDB.Exec(sql)
	require.NoError(t, err)
	// Step 2: compare the registry's tables only (plugin tables still come from GORM structs)
	ga := readSchema(t, db)
	registryTables := map[string]bool{"user": true, "session": true, "account": true, "verification": true, "rateLimit": true}
	for name := range ba.Tables {
		if !registryTables[name] {
			delete(ba.Tables, name)
		}
	}
	hard, notes := diff(ba, ga)
	for _, n := range notes {
		t.Log("difference:", n)
	}
	require.Empty(t, hard)
}
