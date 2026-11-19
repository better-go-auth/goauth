package additionalfields

import (
	"net/http"
	"testing"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/stretchr/testify/require"
)

// TestSignUpParsesAdditionalFields covers better-auth's parseInputData rules on create through
// POST /sign-up/email, one rule per case.
func TestSignUpParsesAdditionalFields(t *testing.T) {
	s := newServer(t, nil)
	cases := []struct {
		name    string
		extra   map[string]any
		status  int
		code    string
		message string
		check   func(t *testing.T, user map[string]any)
	}{
		{name: "defaults on create", extra: nil, status: 200, check: func(t *testing.T, u map[string]any) {
			require.Equal(t, "free", u["plan"])
			require.Regexp(t, `^t\d+$`, u["tier"])
			require.EqualValues(t, 10, u["credits"])
			// optional fields without a value are null, returned:false fields are absent
			for _, k := range []string{"verifiedPro", "age", "handle", "color", "birthday", "tags", "prefs"} {
				v, ok := u[k]
				require.True(t, ok, "%s missing: %v", k, u)
				require.Nil(t, v, k)
			}
			require.NotContains(t, u, "secretNote")
		}},
		{name: "values of every type", extra: map[string]any{
			"plan": "pro", "age": 30, "handle": "MiXeD", "color": "red", "birthday": "2000-01-02T03:04:05.678Z",
			"tags": []string{"a", "b"}, "prefs": map[string]any{"dark": true}, "secretNote": "hidden",
		}, status: 200, check: func(t *testing.T, u map[string]any) {
			require.Equal(t, "pro", u["plan"])
			require.EqualValues(t, 30, u["age"])
			require.Equal(t, "mixed", u["handle"], "transform.input")
			require.Equal(t, "red", u["color"])
			require.Equal(t, "2000-01-02T03:04:05.678Z", u["birthday"])
			require.Equal(t, []any{"a", "b"}, u["tags"])
			require.Equal(t, map[string]any{"dark": true}, u["prefs"])
			require.NotContains(t, u, "secretNote")
		}},
		{name: "input false with default takes the default", extra: map[string]any{"credits": 999}, status: 200,
			check: func(t *testing.T, u map[string]any) { require.EqualValues(t, 10, u["credits"]) }},
		{name: "input false falsy value is dropped", extra: map[string]any{"verifiedPro": false}, status: 200,
			check: func(t *testing.T, u map[string]any) { require.Nil(t, u["verifiedPro"]) }},
		{name: "input false truthy value", extra: map[string]any{"verifiedPro": true}, status: 400,
			code: "FIELD_NOT_ALLOWED", message: "verifiedPro is not allowed to be set"},
		{name: "validator error", extra: map[string]any{"age": 12}, status: 400,
			code: "VALIDATION_ERROR", message: "age must be at least 18"},
		{name: "type error", extra: map[string]any{"age": "old"}, status: 400, code: "VALIDATION_ERROR"},
		{name: "enum error", extra: map[string]any{"color": "green"}, status: 400, code: "VALIDATION_ERROR"},
		{name: "date error", extra: map[string]any{"birthday": "not a date"}, status: 400, code: "VALIDATION_ERROR"},
		{name: "array element error", extra: map[string]any{"tags": []any{"a", 1}}, status: 400, code: "VALIDATION_ERROR"},
		{name: "unknown keys are ignored", extra: map[string]any{"junk": "x", "nested": map[string]any{"a": 1}}, status: 200,
			check: func(t *testing.T, u map[string]any) {
				require.NotContains(t, u, "junk")
				require.NotContains(t, u, "nested")
			}},
		{name: "core input:false fields are not settable", extra: map[string]any{"emailVerified": true}, status: 200,
			check: func(t *testing.T, u map[string]any) { require.Equal(t, false, u["emailVerified"]) }},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s.Jar.SetCookies(nil, nil)
			res := signUp(t, s, "parse"+string(rune('a'+i))+"@example.com", tc.extra)
			if tc.status != http.StatusOK {
				requireError(t, res, tc.status, tc.code, tc.message)
				return
			}
			require.Equal(t, http.StatusOK, res.Status, string(res.Body))
			user := object(t, jsonBody(t, res), "user")
			tc.check(t, user)
			// the session returns the stored values (the database round trip)
			sess := getSession(t, s)
			stored := object(t, sess, "user")
			require.Equal(t, user["id"], stored["id"])
			tc.check(t, stored)
		})
	}
}

// TestSignUpRequiredField: a required additional field without default must be sent on sign-up, but not on
// update-user (better-auth checks required fields on create only).
func TestSignUpRequiredField(t *testing.T) {
	s := newServer(t, func(c *config.AuthConfig) {
		c.User.AdditionalFields["company"] = schema.Field{Type: schema.String, Required: true}
	})
	requireError(t, signUp(t, s, "req@example.com", nil), 400, "MISSING_FIELD", "company is required")
	res := signUp(t, s, "req@example.com", map[string]any{"company": "ACME"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	require.Equal(t, "ACME", object(t, jsonBody(t, res), "user")["company"])
	// update without the required field is fine
	res = s.Post(t, "/api/auth/update-user", map[string]any{"plan": "team"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	require.Equal(t, "ACME", object(t, getSession(t, s), "user")["company"])
}

// TestUpdateUserParsesAdditionalFields covers the update rules of POST /update-user.
func TestUpdateUserParsesAdditionalFields(t *testing.T) {
	s := newServer(t, nil)
	res := signUp(t, s, "update@example.com", map[string]any{"plan": "pro"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	tier := object(t, jsonBody(t, res), "user")["tier"]

	// Step 1: additional fields are updatable; defaults are not applied on update
	res = s.Post(t, "/api/auth/update-user", map[string]any{"handle": "NEW", "age": 40, "tags": []string{"x"}})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	require.Equal(t, map[string]any{"status": true}, jsonBody(t, res))
	user := object(t, getSession(t, s), "user")
	require.Equal(t, "new", user["handle"])
	require.EqualValues(t, 40, user["age"])
	require.Equal(t, []any{"x"}, user["tags"])
	require.Equal(t, "pro", user["plan"], "default must not overwrite on update")
	require.Equal(t, tier, user["tier"], "function default must not run on update")

	// Step 2: null clears an optional field
	res = s.Post(t, "/api/auth/update-user", map[string]any{"handle": nil})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	require.Nil(t, object(t, getSession(t, s), "user")["handle"])

	// Step 3: errors
	requireError(t, s.Post(t, "/api/auth/update-user", map[string]any{"credits": 5}), 400, "FIELD_NOT_ALLOWED", "credits is not allowed to be set")
	requireError(t, s.Post(t, "/api/auth/update-user", map[string]any{"verifiedPro": true}), 400, "FIELD_NOT_ALLOWED", "verifiedPro is not allowed to be set")
	requireError(t, s.Post(t, "/api/auth/update-user", map[string]any{"age": 3}), 400, "VALIDATION_ERROR", "age must be at least 18")
	requireError(t, s.Post(t, "/api/auth/update-user", map[string]any{"color": "pink"}), 400, "VALIDATION_ERROR", "")
	// unknown keys and falsy input:false values are dropped: nothing to update
	requireError(t, s.Post(t, "/api/auth/update-user", map[string]any{"junk": 1, "credits": 0}), 400, "NO_FIELDS_TO_UPDATE", "No fields to update")
	// returned:false fields are writable (input) but never returned
	res = s.Post(t, "/api/auth/update-user", map[string]any{"secretNote": "s"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	require.NotContains(t, object(t, getSession(t, s), "user"), "secretNote")
	stored, err := s.Auth.Repositories().FindUserByEmail(t.Context(), "update@example.com")
	require.NoError(t, err)
	got, ok := schema.Get[string](stored, "secretNote")
	require.True(t, ok)
	require.Equal(t, "s", got)
}

// TestUpdateUserRejectUnknownFields: User.GoAuth.RejectUnknownUpdateFields keeps goauth's strict mode for keys
// that are not user fields; known fields still follow the parse rules.
func TestUpdateUserRejectUnknownFields(t *testing.T) {
	s := newServer(t, func(c *config.AuthConfig) { c.User.GoAuth.RejectUnknownUpdateFields = true })
	require.Equal(t, http.StatusOK, signUp(t, s, "strict@example.com", nil).Status)
	requireError(t, s.Post(t, "/api/auth/update-user", map[string]any{"junk": 1}), 400, "FIELD_NOT_ALLOWED", "Field junk is not allowed to be set")
	res := s.Post(t, "/api/auth/update-user", map[string]any{"plan": "pro", "bio": "goauth profile field"})
	require.Equal(t, http.StatusOK, res.Status, string(res.Body))
	user := object(t, getSession(t, s), "user")
	require.Equal(t, "pro", user["plan"])
	// goauth's own profile columns appear once set
	require.Equal(t, "goauth profile field", user["bio"])
}

// TestUpdateSessionParsesAdditionalFields covers POST /update-session with session additionalFields.
func TestUpdateSessionParsesAdditionalFields(t *testing.T) {
	for name, cfg := range map[string]func(*config.AuthConfig){
		"database":       nil,
		"secondary only": func(c *config.AuthConfig) { c.Session.StoreSessionInDatabase = false },
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t, cfg)
			require.Equal(t, http.StatusOK, signUp(t, s, "sess@example.com", nil).Status)
			// Step 1: defaults on create, null when unset
			sess := object(t, getSession(t, s), "session")
			require.Equal(t, false, sess["trusted"])
			require.Contains(t, sess, "deviceLabel")
			require.Nil(t, sess["deviceLabel"])

			// Step 2: update returns the session and persists it
			res := s.Post(t, "/api/auth/update-session", map[string]any{"deviceLabel": "Work laptop", "token": "ignored"})
			require.Equal(t, http.StatusOK, res.Status, string(res.Body))
			require.Equal(t, "Work laptop", object(t, jsonBody(t, res), "session")["deviceLabel"])
			require.Equal(t, "Work laptop", object(t, getSession(t, s), "session")["deviceLabel"])
			// list-sessions carries the field too
			res = s.Get(t, "/api/auth/list-sessions")
			require.Equal(t, http.StatusOK, res.Status, string(res.Body))
			var list []map[string]any
			res.JSON(t, &list)
			require.Len(t, list, 1)
			require.Equal(t, "Work laptop", list[0]["deviceLabel"])
			require.Equal(t, false, list[0]["trusted"])

			// Step 3: input:false and type errors, nothing writable
			requireError(t, s.Post(t, "/api/auth/update-session", map[string]any{"trusted": true}), 400, "FIELD_NOT_ALLOWED", "trusted is not allowed to be set")
			requireError(t, s.Post(t, "/api/auth/update-session", map[string]any{"deviceLabel": 5}), 400, "VALIDATION_ERROR", "")
			requireError(t, s.Post(t, "/api/auth/update-session", map[string]any{"userId": "x"}), 400, "NO_FIELDS_TO_UPDATE", "No fields to update")
		})
	}
}
