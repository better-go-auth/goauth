package adapterrepo

import (
	"sync"
	"testing"

	"github.com/better-go-auth/goauth/src/common/gormutil"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/stretchr/testify/require"
	gormschema "gorm.io/gorm/schema"
)

// TestBindingCoversModels: every column GORM persists for the core Go models is bound to the registry field
// stored in that same column, and every core registry field has a Go field, so nothing is silently dropped
// or renamed when the generic repositories replace the GORM ones.
func TestBindingCoversModels(t *testing.T) {
	reg := schema.MustBuild(schema.Options{})
	for model, sample := range bindingSamples {
		// Step 1: GORM's columns of the Go struct
		s, err := gormschema.Parse(sample, &sync.Map{}, gormutil.NewNamingStrategy("", nil))
		require.NoError(t, err)
		gormCols := map[string]string{}
		for _, f := range s.Fields {
			if f.DBName != "" {
				gormCols[f.Name] = f.DBName
			}
		}
		// Step 2: the binding maps each of them to the registry field with the same column
		b, err := newBinding(reg, model, sample)
		require.NoError(t, err)
		require.Len(t, b.fields, len(gormCols), model)
		for goName, col := range gormCols {
			i, ok := b.byGo[goName]
			require.True(t, ok, "%s.%s is not bound", model, goName)
			require.Equal(t, col, reg.Column(model, b.fields[i].field), "%s.%s", model, goName)
		}
		// Step 3: and every core registry field has a Go field
		m, _ := reg.Model(model)
		require.Len(t, m.Fields(), len(b.fields), model)
	}
}
