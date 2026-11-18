package schema_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/stretchr/testify/require"
)

// errCode returns the better-auth code and message of err ("" when it isn't an AuthError).
func errCode(err error) (string, string, int) {
	var ae *autherr.AuthError
	if errors.As(err, &ae) {
		return string(ae.Code), ae.Message, ae.StatusCode
	}
	return "", "", 0
}

// TestParseInputData mirrors better-auth's parseInputData rules (better-auth/dist/db/schema.mjs).
func TestParseInputData(t *testing.T) {
	counter := 0
	fields := map[string]schema.Field{
		"tier":     {Type: schema.String, Default: "bronze"},
		"birthday": {Type: schema.Date},
		"nick":     {Type: schema.String, Required: true},
		"secret":   {Type: schema.String, Input: schema.Bool(false)},
		"locked":   {Type: schema.Boolean, Input: schema.Bool(false), Default: false},
		"seq": {Type: schema.Integer, Default: func() any {
			counter++
			return counter
		}},
	}
	type tc struct {
		name    string
		data    map[string]any
		action  schema.Action
		want    map[string]any
		errCode string
		errMsg  string
	}
	birthday := time.Date(1990, 5, 17, 10, 11, 12, 345678000, time.UTC)
	cases := []tc{
		{name: "create applies defaults (value and function)", data: map[string]any{"nick": "n"}, action: schema.ActionCreate,
			want: map[string]any{"tier": "bronze", "nick": "n", "locked": false, "seq": int64(1)}},
		{name: "default action is create", data: map[string]any{"nick": "n"},
			want: map[string]any{"tier": "bronze", "nick": "n", "locked": false, "seq": int64(2)}},
		{name: "required missing on create", data: map[string]any{}, action: schema.ActionCreate,
			errCode: "MISSING_FIELD", errMsg: "nick is required"},
		{name: "update skips defaults and required", data: map[string]any{"tier": "gold"}, action: schema.ActionUpdate,
			want: map[string]any{"tier": "gold"}},
		{name: "unknown keys are dropped", data: map[string]any{"nick": "n", "hacker": true, "role": "admin"}, action: schema.ActionUpdate,
			want: map[string]any{"nick": "n"}},
		{name: "input:false with truthy value", data: map[string]any{"secret": "x"}, action: schema.ActionUpdate,
			errCode: "FIELD_NOT_ALLOWED", errMsg: "secret is not allowed to be set"},
		{name: "input:false with falsy value is dropped", data: map[string]any{"secret": "", "nick": "n"}, action: schema.ActionUpdate,
			want: map[string]any{"nick": "n"}},
		{name: "input:false with null is dropped", data: map[string]any{"secret": nil}, action: schema.ActionUpdate,
			want: map[string]any{}},
		{name: "input:false with default on create gets the default", data: map[string]any{"nick": "n", "locked": true}, action: schema.ActionCreate,
			want: map[string]any{"tier": "bronze", "nick": "n", "locked": false, "seq": int64(3)}},
		{name: "input:false with default on update is rejected when truthy", data: map[string]any{"locked": true}, action: schema.ActionUpdate,
			errCode: "FIELD_NOT_ALLOWED", errMsg: "locked is not allowed to be set"},
		{name: "explicit value wins over default", data: map[string]any{"nick": "n", "tier": "gold", "seq": json.Number("7")}, action: schema.ActionCreate,
			want: map[string]any{"tier": "gold", "nick": "n", "locked": false, "seq": int64(7)}},
		{name: "explicit null is kept (optional field)", data: map[string]any{"birthday": nil}, action: schema.ActionUpdate,
			want: map[string]any{"birthday": nil}},
		{name: "dates parse from RFC 3339 and keep milliseconds", data: map[string]any{"birthday": "1990-05-17T12:11:12.345678+02:00"}, action: schema.ActionUpdate,
			want: map[string]any{"birthday": birthday.Truncate(time.Millisecond)}},
		{name: "wrong type", data: map[string]any{"nick": 5.0}, action: schema.ActionUpdate,
			errCode: "VALIDATION_ERROR", errMsg: "[body.nick] Invalid input: expected string, received number"},
		{name: "invalid date", data: map[string]any{"birthday": "yesterday"}, action: schema.ActionUpdate,
			errCode: "VALIDATION_ERROR", errMsg: "[body.birthday] Invalid input: expected date, received Invalid Date"},
		{name: "fractional integer", data: map[string]any{"seq": 1.5}, action: schema.ActionUpdate,
			errCode: "VALIDATION_ERROR", errMsg: "[body.seq] Invalid input: expected int, received number"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := schema.ParseInputData(fields, c.data, c.action)
			if c.errCode != "" {
				code, msg, status := errCode(err)
				require.Equal(t, c.errCode, code, "error %v", err)
				require.Equal(t, c.errMsg, msg)
				require.Equal(t, 400, status)
				require.Nil(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, c.want, got)
		})
	}
}

func TestParseInputData_ValidatorsAndTransforms(t *testing.T) {
	fields := map[string]schema.Field{
		"age": {Type: schema.Number, Validate: func(v any) (any, error) {
			if v.(float64) < 18 {
				return nil, errors.New("must be an adult")
			}
			return v.(float64) + 0.5, nil
		}},
		"empty": {Type: schema.String, Validate: func(v any) (any, error) { return nil, errors.New("") }},
		"handle": {Type: schema.String, TransformIn: func(v any) any {
			if s, ok := v.(string); ok {
				return strings.ToLower(s)
			}
			return v
		}},
		// a validator wins over a transform, like better-auth
		"both": {Type: schema.String,
			Validate:    func(v any) (any, error) { return "validated", nil },
			TransformIn: func(v any) any { return "transformed" }},
		"plan": {Type: schema.String, Enum: []string{"free", "pro"}},
	}

	// Step 1: validator output replaces the value
	got, err := schema.ParseInputData(fields, map[string]any{"age": 20.0, "handle": "MiXed", "both": "x", "plan": "pro"}, schema.ActionUpdate)
	require.NoError(t, err)
	require.Equal(t, map[string]any{"age": 20.5, "handle": "mixed", "both": "validated", "plan": "pro"}, got)

	// Step 2: validator errors become VALIDATION_ERROR with the validator's message
	_, err = schema.ParseInputData(fields, map[string]any{"age": 12}, schema.ActionUpdate)
	code, msg, _ := errCode(err)
	require.Equal(t, "VALIDATION_ERROR", code)
	require.Equal(t, "must be an adult", msg)
	_, err = schema.ParseInputData(fields, map[string]any{"empty": "x"}, schema.ActionUpdate)
	_, msg, _ = errCode(err)
	require.Equal(t, "Validation Error", msg)

	// Step 3: enum values are checked
	_, err = schema.ParseInputData(fields, map[string]any{"plan": "gold"}, schema.ActionUpdate)
	code, msg, _ = errCode(err)
	require.Equal(t, "VALIDATION_ERROR", code)
	require.Equal(t, `[body.plan] Invalid option: expected one of "free"|"pro"`, msg)
}

func TestParseInputData_TypeCoercion(t *testing.T) {
	fields := map[string]schema.Field{
		"n":    {Type: schema.Number},
		"i":    {Type: schema.Integer},
		"b":    {Type: schema.Boolean},
		"tags": {Type: schema.StringArray},
		"nums": {Type: schema.NumberArray},
		"meta": {Type: schema.JSON},
	}
	// Step 1: JSON-decoded values (float64, []any, map) convert to the canonical Go types
	var body map[string]any
	require.NoError(t, json.Unmarshal([]byte(`{"n":1.5,"i":3,"b":true,"tags":["a","b"],"nums":[1,2.5],"meta":{"k":[1,"x"]}}`), &body))
	got, err := schema.ParseInputData(fields, body, schema.ActionUpdate)
	require.NoError(t, err)
	require.Equal(t, 1.5, got["n"])
	require.Equal(t, int64(3), got["i"])
	require.Equal(t, true, got["b"])
	require.Equal(t, []string{"a", "b"}, got["tags"])
	require.Equal(t, []float64{1, 2.5}, got["nums"])
	require.JSONEq(t, `{"k":[1,"x"]}`, string(got["meta"].(json.RawMessage)))

	// Step 2: mismatches name the field and both types
	for key, bad := range map[string]any{"n": "1", "b": "true", "tags": []any{"a", 1.0}, "nums": "1,2", "i": true} {
		_, err := schema.ParseInputData(fields, map[string]any{key: bad}, schema.ActionUpdate)
		code, msg, _ := errCode(err)
		require.Equal(t, "VALIDATION_ERROR", code, key)
		require.True(t, strings.HasPrefix(msg, "[body."+key+"] Invalid input: expected "), msg)
	}
}

func TestRegistryParseInput_UsesInputFields(t *testing.T) {
	reg := schema.MustBuild(schema.Options{Models: map[string]schema.ModelOptions{
		"user": {AdditionalFields: map[string]schema.Field{
			"loyaltyTier": {Type: schema.String, Default: "bronze", Input: schema.Bool(false)},
			"birthday":    {Type: schema.Date, Required: true},
		}},
	}})
	// Step 1: core fields (name, email, emailVerified) are not parsed here; plugin input:false fields are
	got, err := reg.ParseInput("user", map[string]any{"name": "x", "emailVerified": true, "birthday": "2000-01-02", "firstName": "Ann"}, schema.ActionCreate)
	require.NoError(t, err)
	require.Equal(t, "bronze", got["loyaltyTier"])
	require.Equal(t, time.Date(2000, 1, 2, 0, 0, 0, 0, time.UTC), got["birthday"])
	require.Equal(t, "Ann", got["firstName"])
	require.NotContains(t, got, "name")
	require.NotContains(t, got, "emailVerified")
	require.Equal(t, false, got["banned"], "plugin input:false fields with a default get it on create")
	require.Equal(t, "en", got["locale"])

	// Step 2: role (admin plugin, input:false, no default) can't be set
	_, err = reg.ParseInput("user", map[string]any{"role": "admin", "birthday": "2000-01-02"}, schema.ActionCreate)
	code, msg, _ := errCode(err)
	require.Equal(t, "FIELD_NOT_ALLOWED", code)
	require.Equal(t, "role is not allowed to be set", msg)

	// Step 3: required additional field
	_, err = reg.ParseInput("user", map[string]any{}, schema.ActionCreate)
	_, msg, _ = errCode(err)
	require.Equal(t, "birthday is required", msg)

	_, err = reg.ParseInput("nope", nil, schema.ActionCreate)
	require.Error(t, err)
}

func TestParseOutputAndBuildOutput(t *testing.T) {
	reg := schema.MustBuild(schema.Options{Models: map[string]schema.ModelOptions{
		"user": {AdditionalFields: map[string]schema.Field{
			"loyaltyTier": {Type: schema.String, Default: "bronze"},
			"secretNote":  {Type: schema.String, Returned: schema.Bool(false)},
			"nickname":    {Type: schema.String},
		}},
	}})
	data := map[string]any{"id": "u1", "name": "Ann", "email": "a@x.com", "secretNote": "hidden", "custom": 1, "lastLoginIP": "1.2.3.4"}

	// Step 1: ParseOutput drops only returned:false fields
	out := reg.ParseOutput("user", data)
	require.NotContains(t, out, "secretNote")
	require.NotContains(t, out, "lastLoginIP")
	require.Equal(t, 1, out["custom"], "unknown keys are kept")
	require.Equal(t, "hidden", data["secretNote"], "input is not modified")
	require.Nil(t, reg.ParseOutput("user", nil))

	// Step 2: BuildOutput lists every returned field: values, defaults, null for missing optional fields
	built := reg.BuildOutput("user", data)
	require.Equal(t, "u1", built["id"])
	require.Equal(t, "bronze", built["loyaltyTier"])
	require.Contains(t, built, "nickname")
	require.Nil(t, built["nickname"])
	require.Contains(t, built, "image")
	require.Equal(t, false, built["emailVerified"])
	require.NotContains(t, built, "secretNote")
	require.NotContains(t, built, "custom")
	require.Nil(t, reg.BuildOutput("nope", data))
}
