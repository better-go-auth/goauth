package render_test

import (
	"encoding/json"
	"testing"

	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/schema/render"
	"github.com/stretchr/testify/require"
)

func TestMongo_Golden(t *testing.T) {
	cases := map[string]*schema.Registry{
		"core_snake":   schema.MustBuild(schema.Options{}),
		"plugin_camel": pluginRegistry(t, schema.IDApplication),
	}
	for name, reg := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := render.Mongo(reg)
			require.NoError(t, err)
			require.True(t, json.Valid([]byte(out)))
			golden(t, name+".mongo.json", out)
		})
	}
}

// TestMongoCollections checks the Mongo-specific rules: camelCase keys under snake case, partial unique
// indexes for optional unique fields, TTL indexes, and explicit renames kept.
func TestMongoCollections(t *testing.T) {
	reg := schema.MustBuild(schema.Options{Models: map[string]schema.ModelOptions{
		schema.ModelUser: {Fields: map[string]string{"emailVerified": "is_verified"}},
	}})
	byName := map[string]render.MongoCollection{}
	for _, c := range render.MongoCollections(reg, render.MongoOptions{}) {
		byName[c.Model] = c
	}
	find := func(model string, fields ...string) render.MongoIndex {
		t.Helper()
		for _, idx := range byName[model].Indexes {
			if len(idx.Fields) == len(fields) && idx.Fields[0] == fields[0] {
				return idx
			}
		}
		t.Fatalf("no index on %s %v", model, fields)
		return render.MongoIndex{}
	}
	// Step 1: email is required and unique: a plain unique index on the camelCase key
	email := find(schema.ModelUser, "email")
	require.True(t, email.Unique)
	require.Empty(t, email.Partial)
	// Step 2: phoneNumber is optional and unique: partial on its string type
	phone := find(schema.ModelUser, "phoneNumber")
	require.Equal(t, []string{"phoneNumber"}, phone.Keys)
	require.Equal(t, []render.MongoPartial{{Key: "phoneNumber", Types: []string{"string"}}}, phone.Partial)
	// Step 3: TTL indexes on verification and session expiresAt
	for _, m := range []string{schema.ModelVerification, schema.ModelSession} {
		ttl := find(m, "expiresAt")
		require.NotNil(t, ttl.ExpireAfterSeconds, m)
		require.Zero(t, *ttl.ExpireAfterSeconds)
	}
	for _, c := range render.MongoCollections(reg, render.MongoOptions{NoTTL: true}) {
		for _, idx := range c.Indexes {
			require.Nil(t, idx.ExpireAfterSeconds)
		}
	}
	// Step 4: keys
	user, _ := reg.Model(schema.ModelUser)
	f, _ := user.Field("emailVerified")
	require.Equal(t, "is_verified", render.MongoField(reg, f), "explicit renames are kept")
	f, _ = user.Field("createdAt")
	require.Equal(t, "createdAt", render.MongoField(reg, f), "camelCase is forced")
	f, _ = user.Field("id")
	require.Equal(t, "_id", render.MongoField(reg, f))
}
