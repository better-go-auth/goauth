// Package additionalfields tests better-auth's additionalFields end to end through goauth's HTTP API: input
// parsing (create vs update, defaults, required, input:false, validators, transforms, types, unknown keys),
// output (every returned field, null when unset, returned:false hidden), the cookie cache and secondary
// storage round trips, database hooks and plugin schema fields.
package additionalfields

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/adapter/gormadapter/gormtest"
	"github.com/better-go-auth/goauth/src/config"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/schema"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
	"github.com/better-go-auth/goauth/src/tests/helpers"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const password = "Password123!"

// tierCounter feeds the function default of the "tier" field.
var tierCounter atomic.Int64

// userFields are the user additionalFields every test server declares (better-auth's DBFieldAttribute
// variants).
func userFields() map[string]schema.Field {
	f := schema.Bool(false)
	return map[string]schema.Field{
		// value default
		"plan": {Type: schema.String, Default: "free"},
		// function default (evaluated per create)
		"tier": {Type: schema.String, Default: func() any { return "t" + strconv.FormatInt(tierCounter.Add(1), 10) }},
		// input:false with a default: always the default on create, rejected on update
		"credits": {Type: schema.Number, Input: f, Default: 10},
		// input:false without a default: rejected when set to a truthy value
		"verifiedPro": {Type: schema.Boolean, Input: f},
		// validator (better-auth's validator.input) converting the value
		"age": {Type: schema.Integer, Validate: func(v any) (any, error) {
			if n, _ := v.(int64); n < 18 {
				return nil, errors.New("age must be at least 18")
			}
			return v, nil
		}},
		// transform (better-auth's transform.input)
		"handle": {Type: schema.String, TransformIn: func(v any) any {
			if s, ok := v.(string); ok {
				return strings.ToLower(s)
			}
			return v
		}},
		"color":    {Type: schema.String, Enum: []string{"red", "blue"}},
		"birthday": {Type: schema.Date},
		"tags":     {Type: schema.StringArray},
		"prefs":    {Type: schema.JSON},
		// never part of the output
		"secretNote": {Type: schema.String, Returned: f},
	}
}

// sessionFields are the session additionalFields of the test servers.
func sessionFields() map[string]schema.Field {
	return map[string]schema.Field{
		"deviceLabel": {Type: schema.String},
		"trusted":     {Type: schema.Boolean, Input: schema.Bool(false), Default: false},
	}
}

// newServer starts goauth with the test additionalFields, the given plugins (none by default) and extra config.
func newServer(t *testing.T, cfg func(*config.AuthConfig), plugins ...plugin.Plugin) *compattest.Server {
	t.Helper()
	return compattest.NewServer(t, compattest.WithDB(openDB(t)), compattest.WithConfig(func(c *config.AuthConfig) {
		c.User.AdditionalFields = userFields()
		c.Session.AdditionalFields = sessionFields()
		if cfg != nil {
			cfg(c)
		}
	}), func(o *goauth.GoAuthOptions) { o.Plugins = plugins })
}

// jsonBody decodes a response body into a generic map.
func jsonBody(t *testing.T, res *compattest.Response) map[string]any {
	t.Helper()
	var out map[string]any
	res.JSON(t, &out)
	return out
}

// object returns body[key] as an object.
func object(t *testing.T, body map[string]any, key string) map[string]any {
	t.Helper()
	m, ok := body[key].(map[string]any)
	require.True(t, ok, "%s is not an object: %v", key, body)
	return m
}

// signUp posts /sign-up/email with extra body fields.
func signUp(t *testing.T, s *compattest.Server, email string, extra map[string]any) *compattest.Response {
	t.Helper()
	body := map[string]any{"email": email, "password": password, "name": "Test User"}
	for k, v := range extra {
		body[k] = v
	}
	return s.Post(t, "/api/auth/sign-up/email", body)
}

// requireError checks a better-auth error response.
func requireError(t *testing.T, res *compattest.Response, status int, code, message string) {
	t.Helper()
	require.Equal(t, status, res.Status, string(res.Body))
	body := jsonBody(t, res)
	require.Equal(t, code, body["code"], string(res.Body))
	if message != "" {
		require.Equal(t, message, body["message"], string(res.Body))
	}
}

// getSession returns the /get-session body.
func getSession(t *testing.T, s *compattest.Server) map[string]any {
	t.Helper()
	res := s.Get(t, "/api/auth/get-session")
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	return jsonBody(t, res)
}

// openDB opens a private database for one server: in-memory SQLite, or its own Postgres schema when
// TEST_DATABASE_URL points at Postgres (servers of one test process must not share tables: their
// additionalFields differ).
func openDB(t *testing.T) *gorm.DB {
	t.Helper()
	if strings.HasPrefix(os.Getenv("TEST_DATABASE_URL"), "postgres") {
		ns := "af_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
		db := gormtest.OpenIsolated(t, helpers.DBTypePostgres, ns)
		t.Cleanup(func() { _ = db.Exec("DROP SCHEMA IF EXISTS " + ns + " CASCADE").Error })
		return db
	}
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:af_%s?mode=memory&cache=shared", uuid.NewString())), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	return db
}

// withPlugins replaces the default plugins of compattest.NewServer.
func withPlugins(plugins ...plugin.Plugin) compattest.Option {
	return func(o *goauth.GoAuthOptions) { o.Plugins = plugins }
}

// signInAdmin signs up email, gives it the admin role in the database and signs in again.
func signInAdmin(t *testing.T, s *compattest.Server, email string) {
	t.Helper()
	require.Equal(t, http.StatusOK, signUp(t, s, email, nil).Status)
	reg := s.Auth.Schema()
	require.NoError(t, s.DB.Table(reg.Table(schema.ModelUser)).Where(reg.Column(schema.ModelUser, "email")+" = ?", email).
		Update(reg.Column(schema.ModelUser, "role"), "admin").Error)
	res := s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": email, "password": password})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
}
