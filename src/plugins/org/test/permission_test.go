package org_test

import (
	"testing"

	orgmodels "github.com/better-go-auth/goauth/src/plugins/org/models"
	"github.com/stretchr/testify/require"
)

// TestPermission_Unit tests the Permission type methods, serialization, and deserialization.
func TestPermission_Unit(t *testing.T) {
	t.Run("Value serialization", func(t *testing.T) {
		// Step 1: Nil permission should serialize to "{}" to prevent DB NOT NULL violations
		var nilPerm orgmodels.Permission
		val, err := nilPerm.Value()
		require.NoError(t, err)
		require.Equal(t, "{}", val)

		// Step 2: Empty permission should serialize to "{}"
		emptyPerm := orgmodels.Permission{}
		val, err = emptyPerm.Value()
		require.NoError(t, err)
		require.Equal(t, "{}", val)

		// Step 3: Populated permission should serialize to JSON string
		perm := orgmodels.Permission{
			"project": []string{"create", "read"},
		}
		val, err = perm.Value()
		require.NoError(t, err)
		require.JSONEq(t, `{"project":["create","read"]}`, val.(string))
	})

	t.Run("Scan deserialization", func(t *testing.T) {
		// Step 1: Scan nil value
		var p orgmodels.Permission
		err := p.Scan(nil)
		require.NoError(t, err)
		require.NotNil(t, p)
		require.Empty(t, p)

		// Step 2: Scan empty byte slice
		err = p.Scan([]byte(""))
		require.NoError(t, err)
		require.Empty(t, p)

		// Step 3: Scan "null" string
		err = p.Scan("null")
		require.NoError(t, err)
		require.Empty(t, p)

		// Step 4: Scan string JSON
		err = p.Scan(`{"project":["read","delete"]}`)
		require.NoError(t, err)
		require.Equal(t, []string{"read", "delete"}, p["project"])

		// Step 5: Scan byte slice JSON
		err = p.Scan([]byte(`{"billing":["read"]}`))
		require.NoError(t, err)
		require.Equal(t, []string{"read"}, p["billing"])

		// Step 6: Scan invalid type should error
		err = p.Scan(12345)
		require.Error(t, err)
	})

	t.Run("UnmarshalJSON handles both object and stringified JSON", func(t *testing.T) {
		// Step 1: Unmarshal direct JSON object
		var p1 orgmodels.Permission
		err := p1.UnmarshalJSON([]byte(`{"project":["read","write"]}`))
		require.NoError(t, err)
		require.Equal(t, []string{"read", "write"}, p1["project"])

		// Step 2: Unmarshal stringified JSON
		var p2 orgmodels.Permission
		err = p2.UnmarshalJSON([]byte(`"{\"project\":[\"admin\"]}"`))
		require.NoError(t, err)
		require.Equal(t, []string{"admin"}, p2["project"])
	})

	t.Run("HasAction wildcard and resource evaluation", func(t *testing.T) {
		perm := orgmodels.Permission{
			"project": []string{"read", "update"},
			"billing": []string{"*"},
		}

		// Step 1: Direct match
		require.True(t, perm.HasAction("project", "read"))
		require.True(t, perm.HasAction("project", "update"))
		require.False(t, perm.HasAction("project", "delete"))

		// Step 2: Wildcard action on specific resource
		require.True(t, perm.HasAction("billing", "read"))
		require.True(t, perm.HasAction("billing", "delete"))
		require.True(t, perm.HasAction("billing", "anything"))

		// Step 3: Non-existent resource
		require.False(t, perm.HasAction("users", "read"))

		// Step 4: Wildcard resource allows actions across all resources
		wildcardPerm := orgmodels.Permission{
			"*": []string{"read"},
		}
		require.True(t, wildcardPerm.HasAction("users", "read"))
		require.True(t, wildcardPerm.HasAction("billing", "read"))
		require.False(t, wildcardPerm.HasAction("billing", "write"))

		// Step 5: Full super-admin wildcard (* -> *)
		superPerm := orgmodels.Permission{
			"*": []string{"*"},
		}
		require.True(t, superPerm.HasAction("any_resource", "any_action"))

		// Step 6: Nil permission safely returns false
		var nilPerm orgmodels.Permission
		require.False(t, nilPerm.HasAction("project", "read"))
	})

	t.Run("ParsePermission helper", func(t *testing.T) {
		// Step 1: Parse from Permission type directly
		orig := orgmodels.Permission{"doc": []string{"read"}}
		p, err := orgmodels.ParsePermission(orig)
		require.NoError(t, err)
		require.Equal(t, orig, p)

		// Step 2: Parse from map[string][]string
		m := map[string][]string{"doc": {"write"}}
		p, err = orgmodels.ParsePermission(m)
		require.NoError(t, err)
		require.Equal(t, orgmodels.Permission(m), p)

		// Step 3: Parse from raw JSON string
		s := `{"doc":["read","write"]}`
		p, err = orgmodels.ParsePermission(s)
		require.NoError(t, err)
		require.Equal(t, []string{"read", "write"}, p["doc"])

		// Step 4: Parse from byte slice
		b := []byte(`{"doc":["delete"]}`)
		p, err = orgmodels.ParsePermission(b)
		require.NoError(t, err)
		require.Equal(t, []string{"delete"}, p["doc"])

		// Step 5: Invalid string produces error
		_, err = orgmodels.ParsePermission("invalid-json")
		require.Error(t, err)
	})
}

// TestOperations_Unit tests the Operations type methods, serialization, and deserialization.
func TestOperations_Unit(t *testing.T) {
	t.Run("Value serialization", func(t *testing.T) {
		// Step 1: Nil operations should serialize to "[]"
		var nilOps orgmodels.Operations
		val, err := nilOps.Value()
		require.NoError(t, err)
		require.Equal(t, "[]", val)

		// Step 2: Empty operations should serialize to "[]"
		emptyOps := orgmodels.Operations{}
		val, err = emptyOps.Value()
		require.NoError(t, err)
		require.Equal(t, "[]", val)

		// Step 3: Populated operations should serialize to JSON array string
		ops := orgmodels.Operations{"createProject", "readProject"}
		val, err = ops.Value()
		require.NoError(t, err)
		require.JSONEq(t, `["createProject","readProject"]`, val.(string))
	})

	t.Run("Scan deserialization", func(t *testing.T) {
		// Step 1: Scan nil value
		var ops orgmodels.Operations
		err := ops.Scan(nil)
		require.NoError(t, err)
		require.NotNil(t, ops)
		require.Empty(t, ops)

		// Step 2: Scan empty byte slice
		err = ops.Scan([]byte(""))
		require.NoError(t, err)
		require.Empty(t, ops)

		// Step 3: Scan "null" string
		err = ops.Scan("null")
		require.NoError(t, err)
		require.Empty(t, ops)

		// Step 4: Scan string JSON array
		err = ops.Scan(`["deployApp", "rollbackApp"]`)
		require.NoError(t, err)
		require.Equal(t, orgmodels.Operations{"deployApp", "rollbackApp"}, ops)

		// Step 5: Scan byte slice JSON array
		err = ops.Scan([]byte(`["deleteOrg"]`))
		require.NoError(t, err)
		require.Equal(t, orgmodels.Operations{"deleteOrg"}, ops)

		// Step 6: Scan invalid type should error
		err = ops.Scan(999)
		require.Error(t, err)
	})

	t.Run("UnmarshalJSON handles direct and stringified JSON", func(t *testing.T) {
		// Step 1: Direct JSON array
		var ops1 orgmodels.Operations
		err := ops1.UnmarshalJSON([]byte(`["op1","op2"]`))
		require.NoError(t, err)
		require.Equal(t, orgmodels.Operations{"op1", "op2"}, ops1)

		// Step 2: Stringified JSON array
		var ops2 orgmodels.Operations
		err = ops2.UnmarshalJSON([]byte(`"[\"opA\", \"opB\"]"`))
		require.NoError(t, err)
		require.Equal(t, orgmodels.Operations{"opA", "opB"}, ops2)
	})

	t.Run("HasOp evaluation", func(t *testing.T) {
		// Step 1: Direct match evaluation
		ops := orgmodels.Operations{"viewDashboard", "exportReport"}
		require.True(t, ops.HasOp("viewDashboard"))
		require.True(t, ops.HasOp("exportReport"))
		require.False(t, ops.HasOp("deleteDashboard"))

		// Step 2: Wildcard match evaluation
		wildcardOps := orgmodels.Operations{"*"}
		require.True(t, wildcardOps.HasOp("anything"))
		require.True(t, wildcardOps.HasOp("deleteOrg"))

		// Step 3: Empty operations evaluation safely returns false
		var emptyOps orgmodels.Operations
		require.False(t, emptyOps.HasOp("any"))
	})

	t.Run("ParseOperations helper", func(t *testing.T) {
		// Step 1: Parse from Operations directly
		p1, err := orgmodels.ParseOperations(orgmodels.Operations{"a", "b"})
		require.NoError(t, err)
		require.Len(t, p1, 2)

		// Step 2: Parse from []string
		p2, err := orgmodels.ParseOperations([]string{"x", "y"})
		require.NoError(t, err)
		require.Equal(t, orgmodels.Operations{"x", "y"}, p2)

		// Step 3: Parse from JSON array string
		p3, err := orgmodels.ParseOperations(`["one", "two"]`)
		require.NoError(t, err)
		require.Equal(t, orgmodels.Operations{"one", "two"}, p3)

		// Step 4: Parse from []any slice
		p4, err := orgmodels.ParseOperations([]any{"item1", "item2"})
		require.NoError(t, err)
		require.Equal(t, orgmodels.Operations{"item1", "item2"}, p4)
	})
}
