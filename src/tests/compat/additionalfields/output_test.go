package additionalfields

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/plugins/admin"
	"github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	"github.com/better-go-auth/goauth/src/schema"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
	"github.com/stretchr/testify/require"
)

// TestOutputEveryEndpoint: sign-up, sign-in, get-session and list-sessions all return the additional fields.
func TestOutputEveryEndpoint(t *testing.T) {
	s := newServer(t, nil)
	res := signUp(t, s, "out@example.com", map[string]any{"plan": "pro", "age": 21})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	require.Equal(t, "pro", object(t, jsonBody(t, res), "user")["plan"])

	// Step 1: sign-in response
	require.Equal(t, http.StatusOK, s.Post(t, "/api/auth/sign-out", map[string]any{}).Status)
	res = s.Post(t, "/api/auth/sign-in/email", map[string]any{"email": "out@example.com", "password": password})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	user := object(t, jsonBody(t, res), "user")
	require.Equal(t, "pro", user["plan"])
	require.EqualValues(t, 21, user["age"])
	require.Contains(t, user, "birthday")

	// Step 2: get-session (user and session additional fields)
	sess := getSession(t, s)
	require.Equal(t, "pro", object(t, sess, "user")["plan"])
	require.Equal(t, false, object(t, sess, "session")["trusted"])

	// Step 3: the columns are real (a TypeScript server sharing the database reads them)
	reg := s.Auth.Schema()
	var plan string
	require.NoError(t, s.DB.Table(reg.Table(schema.ModelUser)).Select(reg.Column(schema.ModelUser, "plan")).
		Where(reg.Column(schema.ModelUser, "email")+" = ?", "out@example.com").Row().Scan(&plan))
	require.Equal(t, "pro", plan)
}

// TestCookieCacheCarriesAdditionalFields: every cookie cache strategy stores the additional fields in
// session_data and get-session answers from it.
func TestCookieCacheCarriesAdditionalFields(t *testing.T) {
	for _, strategy := range []config.CookieCacheStrategy{config.CookieCacheStrategyCompact, config.CookieCacheStrategyJwt, config.CookieCacheStrategyJwe} {
		t.Run(string(strategy), func(t *testing.T) {
			on := true
			s := newServer(t, func(c *config.AuthConfig) {
				c.Session.CookieCache = &config.CookieCache{Enabled: &on, Strategy: strategy, MaxAge: time.Minute}
			})
			res := signUp(t, s, "cache@example.com", map[string]any{"plan": "gold", "birthday": "1999-12-31T00:00:00.000Z"})
			require.Equal(t, http.StatusOK, res.Status, string(res.Body))
			data := res.Cookie("better-auth.session_data")
			require.NotNil(t, data, "session_data cookie")

			// Step 1: the cookie decodes with the extras in their Go types
			cached, err := s.Auth.Cookies().ReadSessionData("better-auth.session_data=" + data.Value)
			require.NoError(t, err)
			require.Equal(t, "gold", cached.User.Extra["plan"])
			require.Equal(t, time.Date(1999, 12, 31, 0, 0, 0, 0, time.UTC), cached.User.Extra["birthday"])
			require.Equal(t, false, cached.Session.Extra["trusted"])

			// Step 2: change the row behind the cache: get-session still answers from the cookie
			reg := s.Auth.Schema()
			require.NoError(t, s.DB.Table(reg.Table(schema.ModelUser)).Where(reg.Column(schema.ModelUser, "email")+" = ?", "cache@example.com").
				Update(reg.Column(schema.ModelUser, "plan"), "changed-in-db").Error)
			user := object(t, getSession(t, s), "user")
			require.Equal(t, "gold", user["plan"])
			require.Equal(t, "1999-12-31T00:00:00.000Z", user["birthday"])
		})
	}
}

// TestSecondaryStorageCarriesAdditionalFields: sessions stored only in secondary storage keep the
// additional fields, in better-auth's {session, user} JSON a TypeScript server reads.
func TestSecondaryStorageCarriesAdditionalFields(t *testing.T) {
	store, err := memory.NewSecondaryStorage()
	require.NoError(t, err)
	s := compattest.NewServer(t, compattest.WithDB(openDB(t)), compattest.WithSecondaryStorage(store), compattest.WithConfig(func(c *config.AuthConfig) {
		c.User.AdditionalFields = userFields()
		c.Session.AdditionalFields = sessionFields()
		c.Session.StoreSessionInDatabase = false
	}))
	res := signUp(t, s, "store@example.com", map[string]any{"plan": "silver"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	token, _ := jsonBody(t, res)["token"].(string)
	require.NotEmpty(t, token)

	// Step 1: the raw secondary storage value
	raw, ok, err := store.Get(t.Context(), token)
	require.NoError(t, err)
	require.True(t, ok)
	var stored map[string]map[string]any
	require.NoError(t, json.Unmarshal([]byte(raw.(string)), &stored))
	require.Equal(t, "silver", stored["user"]["plan"])
	require.Equal(t, false, stored["session"]["trusted"])

	// Step 2: get-session reads it back; update-user refreshes the cached user copy
	require.Equal(t, "silver", object(t, getSession(t, s), "user")["plan"])
	require.Equal(t, http.StatusOK, s.Post(t, "/api/auth/update-user", map[string]any{"plan": "platinum"}).Status)
	raw, _, _ = store.Get(t.Context(), token)
	require.True(t, strings.Contains(raw.(string), `"plan":"platinum"`), raw)
	require.Equal(t, "platinum", object(t, getSession(t, s), "user")["plan"])

	// Step 3: a session written by a TypeScript server (extra keys, ISO dates) is read with its fields
	ts := `{"session":{"id":"ts-session","token":"tstoken000000000000000000000000","userId":"` + object(t, getSession(t, s), "user")["id"].(string) +
		`","expiresAt":"` + time.Now().Add(time.Hour).UTC().Format(time.RFC3339) + `","createdAt":"2026-01-01T00:00:00.000Z","updatedAt":"2026-01-01T00:00:00.000Z","ipAddress":"","userAgent":"","deviceLabel":"ts","trusted":true},` +
		`"user":{"id":"x","name":"TS","email":"ts@example.com","emailVerified":true,"image":null,"createdAt":"2026-01-01T00:00:00.000Z","updatedAt":"2026-01-01T00:00:00.000Z","plan":"ts-plan","birthday":"2001-02-03T00:00:00.000Z"}}`
	require.NoError(t, store.Set(t.Context(), "tstoken000000000000000000000000", ts, time.Hour))
	sw, err := s.Auth.Sessions().Get(t.Context(), "tstoken000000000000000000000000")
	require.NoError(t, err)
	require.NotNil(t, sw)
	require.Equal(t, "ts-plan", sw.User.Extra["plan"])
	require.Equal(t, time.Date(2001, 2, 3, 0, 0, 0, 0, time.UTC), sw.User.Extra["birthday"])
	require.Equal(t, "ts", sw.Session.Extra["deviceLabel"])
}

// TestAdminEndpointsUseAdditionalFields: admin create-user stores body.data (better-auth spreads it into the
// new user), list-users / get-user / update-user return and change the additional fields.
func TestAdminEndpointsUseAdditionalFields(t *testing.T) {
	db := openDB(t)
	adminPlugin, err := admin.NewWithGorm(db)
	require.NoError(t, err)
	s := compattest.NewServer(t, compattest.WithDB(db), compattest.WithConfig(func(c *config.AuthConfig) {
		c.User.AdditionalFields = userFields()
	}), withPlugins(adminPlugin))
	signInAdmin(t, s, "boss@example.com")

	// Step 1: create-user with data (additional fields typed, unknown keys ignored, role from the body)
	res := s.Post(t, "/api/auth/admin/create-user", map[string]any{
		"email": "new@example.com", "password": password, "name": "New", "role": "user",
		"data": map[string]any{"plan": "enterprise", "age": 50, "birthday": "1980-05-06T00:00:00.000Z", "junk": 1},
	})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	created := object(t, jsonBody(t, res), "user")
	require.Equal(t, "enterprise", created["plan"])
	require.EqualValues(t, 50, created["age"])
	require.Equal(t, "1980-05-06T00:00:00.000Z", created["birthday"])
	require.Equal(t, "user", created["role"])
	require.Equal(t, false, created["banned"])
	require.NotContains(t, created, "junk")
	// a value that doesn't fit its field is a validation error
	res = s.Post(t, "/api/auth/admin/create-user", map[string]any{
		"email": "bad@example.com", "password": password, "name": "Bad", "data": map[string]any{"age": "x"},
	})
	requireError(t, res, 400, "VALIDATION_ERROR", "")

	// Step 2: list-users returns the additional fields of every user
	res = s.Get(t, "/api/auth/admin/list-users")
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	var list struct {
		Users []map[string]any `json:"users"`
	}
	res.JSON(t, &list)
	found := false
	for _, u := range list.Users {
		require.Contains(t, u, "plan")
		if u["email"] == "new@example.com" {
			found = true
			require.Equal(t, "enterprise", u["plan"])
		}
	}
	require.True(t, found, string(res.Body))

	// Step 3: update-user with data (field names, camelCase core fields included)
	res = s.Post(t, "/api/auth/admin/update-user", map[string]any{"userId": created["id"], "data": map[string]any{"plan": "free", "emailVerified": true}})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	updated := object(t, jsonBody(t, res), "user")
	require.Equal(t, "free", updated["plan"])
	require.Equal(t, true, updated["emailVerified"])
}

// TestRoleIsNotAllowedOnSignUp reconciles the input:false error with better-auth 1.6.16: parseInputData
// spreads BASE_ERROR_CODES.FIELD_NOT_ALLOWED and only replaces the message.
func TestRoleIsNotAllowedOnSignUp(t *testing.T) {
	db := openDB(t)
	adminPlugin, err := admin.NewWithGorm(db)
	require.NoError(t, err)
	s := compattest.NewServer(t, compattest.WithDB(db), withPlugins(adminPlugin))
	requireError(t, signUp(t, s, "role@example.com", map[string]any{"role": "admin"}), 400, "FIELD_NOT_ALLOWED", "role is not allowed to be set")
	require.Equal(t, http.StatusOK, signUp(t, s, "role@example.com", nil).Status)
	requireError(t, s.Post(t, "/api/auth/update-user", map[string]any{"role": "admin"}), 400, "FIELD_NOT_ALLOWED", "role is not allowed to be set")
	requireError(t, s.Post(t, "/api/auth/update-user", map[string]any{"banned": true}), 400, "FIELD_NOT_ALLOWED", "banned is not allowed to be set")
}
