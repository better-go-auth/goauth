package schema

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// ModelOptions are better-auth's per-model options (`user.modelName`, `user.fields`, `user.additionalFields`).
type ModelOptions struct {
	// ModelName renames the table (better-auth's modelName). It wins over GoAuth TableNames.
	ModelName string
	// Fields renames columns: logical field name → column name, used as is (better-auth's `fields`).
	Fields map[string]string
	// AdditionalFields adds fields (better-auth's additionalFields); they override core fields of the same name.
	AdditionalFields map[string]Field
}

// Plugin is one installed plugin's schema contribution.
type Plugin struct {
	// ID is the plugin ID; it becomes the Owner of every field the plugin declares.
	ID string
	// Schema is the plugin's models (fields for existing models, or new models).
	Schema PluginSchema
}

// Options configure Build.
type Options struct {
	// ColumnCase picks the column naming for fields without an explicit column name (default Snake).
	ColumnCase ColumnCase
	// TablePrefix is prepended to every table name (goauth's GoAuth.TablePrefix).
	TablePrefix string
	// TableNames renames tables per logical model name (goauth's GoAuth.TableNames).
	TableNames map[string]string
	// Models holds the per-model options keyed by logical model name ("user", "session", "account",
	// "verification" or a plugin model). Options for unknown models are an error.
	Models map[string]ModelOptions
	// Plugins are merged after the configuration, in order; later plugins win on conflicts.
	Plugins []Plugin
	// InstalledPlugins, when non-nil, drops the plugin-owned columns of the core models (role, phoneNumber,
	// twoFactorEnabled, ...) whose plugin is not listed. nil keeps them all (today's behaviour, where the
	// Go models always carry those columns).
	InstalledPlugins []string
	// IDs decides who creates primary keys (default IDApplication). Renderers, migrators and adapters read
	// it from the registry, so every model of one registry uses the same strategy.
	IDs IDStrategy
	// RateLimit adds better-auth's rateLimit model (key, count, lastRequest), used by the rate limiter's
	// "database" storage. Rename it like the core models through Models["rateLimit"].
	RateLimit bool
}

// Registry is the built, immutable schema: models, tables, fields and columns.
type Registry struct {
	columnCase ColumnCase
	ids        IDStrategy
	models     map[string]*ResolvedModel
	order      []string
}

// modelDraft is a model while Build merges its sources.
type modelDraft struct {
	name      string
	modelName string
	fields    map[string]Field
	indexes   []Index
}

// Build merges the core models, configuration (Options.Models) and plugin schemas, resolves every table and
// column name once, and validates the result. Merge order follows better-auth's getFields: core →
// additionalFields → plugin fields (later wins).
func Build(opts Options) (*Registry, error) {
	// Step 1: normalise the column case
	cc, err := opts.ColumnCase.normalize()
	if err != nil {
		return nil, err
	}
	ids, err := opts.IDs.normalize()
	if err != nil {
		return nil, err
	}

	// Step 2: start from the core models
	drafts := map[string]*modelDraft{}
	var order []string
	for name, m := range Core() {
		drafts[name] = &modelDraft{name: name, fields: m.Fields, indexes: m.Indexes}
	}
	order = append(order, ModelUser, ModelSession, ModelAccount, ModelVerification)
	if opts.RateLimit {
		rl := rateLimitModel()
		drafts[ModelRateLimit] = &modelDraft{name: ModelRateLimit, fields: rl.Fields}
		order = append(order, ModelRateLimit)
	}

	// Step 3: drop plugin-owned core columns of plugins that are not installed
	if opts.InstalledPlugins != nil {
		installed := map[string]bool{}
		for _, id := range opts.InstalledPlugins {
			installed[id] = true
		}
		for _, d := range drafts {
			for name, f := range d.fields {
				if f.Owner != OwnerCore && f.Owner != OwnerGoAuth && !installed[f.Owner] {
					delete(d.fields, name)
				}
			}
		}
	}

	// Step 4: configuration additionalFields
	for _, model := range sortedModelOptionKeys(opts.Models) {
		mo := opts.Models[model]
		d, ok := drafts[model]
		if !ok && len(mo.AdditionalFields) > 0 {
			return nil, fmt.Errorf("schema: additionalFields for unknown model %q", model)
		}
		for name, f := range mo.AdditionalFields {
			f.Owner = OwnerConfig
			d.fields[name] = f
		}
	}

	// Step 5: plugin schemas (new models become new tables)
	for _, p := range opts.Plugins {
		if p.ID == "" {
			return nil, errors.New("schema: plugin schema without an ID")
		}
		for _, model := range sortedSchemaKeys(p.Schema) {
			pm := p.Schema[model]
			d, ok := drafts[model]
			if !ok {
				d = &modelDraft{name: model, fields: map[string]Field{}}
				drafts[model] = d
				order = append(order, model)
			}
			if pm.ModelName != "" {
				d.modelName = pm.ModelName
			}
			for name, f := range pm.Fields {
				f.Owner = p.ID
				d.fields[name] = f
			}
			for _, idx := range pm.Indexes {
				idx.Owner = p.ID
				idx.Fields = append([]string(nil), idx.Fields...)
				d.indexes = append(d.indexes, idx)
			}
		}
	}

	// Step 6: unknown models in the options are configuration mistakes
	for model := range opts.Models {
		if _, ok := drafts[model]; !ok {
			return nil, fmt.Errorf("schema: options for unknown model %q", model)
		}
	}

	// Step 7: resolve table and column names
	reg := &Registry{columnCase: cc, ids: ids, models: map[string]*ResolvedModel{}, order: order}
	coreOrd := coreOrder()
	for _, name := range order {
		rm, err := resolveModel(drafts[name], opts, cc, coreOrd[name])
		if err != nil {
			return nil, err
		}
		reg.models[name] = rm
	}

	// Step 8: cross-model validation (tables, references, indexes)
	if err := reg.validate(); err != nil {
		return nil, err
	}
	return reg, nil
}

// MustBuild is Build for static configurations; it panics on error.
func MustBuild(opts Options) *Registry {
	reg, err := Build(opts)
	if err != nil {
		panic(err)
	}
	return reg
}

// resolveModel computes the table name, the field order and every column name of one model.
func resolveModel(d *modelDraft, opts Options, cc ColumnCase, coreOrd []string) (*ResolvedModel, error) {
	if d.name == "" {
		return nil, errors.New("schema: model without a name")
	}
	mo := opts.Models[d.name]

	// Step 1: every model has an id
	if _, ok := d.fields["id"]; !ok {
		nf := idField()
		nf.field.Owner = OwnerCore
		d.fields["id"] = nf.field
	}

	// Step 2: table name: ModelOptions.ModelName > TableNames > plugin modelName > logical name, then prefix
	table := d.name
	switch {
	case mo.ModelName != "":
		table = mo.ModelName
	case opts.TableNames[d.name] != "":
		table = opts.TableNames[d.name]
	case d.modelName != "":
		table = d.modelName
	}
	table = opts.TablePrefix + table

	// Step 3: field order: id, core order, then the remaining fields by name
	seen := map[string]bool{"id": true}
	names := []string{"id"}
	for _, n := range coreOrd {
		if _, ok := d.fields[n]; ok && !seen[n] {
			names = append(names, n)
			seen[n] = true
		}
	}
	for _, n := range sortedKeys(d.fields) {
		if !seen[n] {
			names = append(names, n)
		}
	}

	// Step 4: renames in Fields must point at existing fields
	for field := range mo.Fields {
		if _, ok := d.fields[field]; !ok {
			return nil, fmt.Errorf("schema: %s: fields rename for unknown field %q", d.name, field)
		}
	}

	// Step 5: resolve and validate each field; columns must be unique (case-insensitively, like MySQL)
	rm := &ResolvedModel{name: d.name, table: table, byName: map[string]int{}, byColumn: map[string]int{}}
	lowerCols := map[string]string{}
	for _, n := range names {
		f := d.fields[n]
		if n == "" {
			return nil, fmt.Errorf("schema: %s: field without a name", d.name)
		}
		if err := f.validate(d.name, n); err != nil {
			return nil, err
		}
		col := cc.column(n)
		if f.FieldName != "" {
			col = f.FieldName
		}
		if rename := mo.Fields[n]; rename != "" {
			col = rename
		}
		if n == "id" {
			col = "id"
		}
		if other, dup := lowerCols[strings.ToLower(col)]; dup {
			return nil, fmt.Errorf("schema: %s: fields %q and %q both use column %q", d.name, other, n, col)
		}
		lowerCols[strings.ToLower(col)] = n
		rm.byName[n] = len(rm.fields)
		rm.byColumn[col] = len(rm.fields)
		rm.fields = append(rm.fields, ResolvedField{Field: f, Name: n, Column: col})
	}

	// Step 6: multi-column indexes must use existing fields (indexes over dropped fields go with them)
	for _, idx := range d.indexes {
		missing := false
		for _, fn := range idx.Fields {
			if _, ok := d.fields[fn]; !ok {
				missing = true
			}
		}
		if missing {
			if opts.InstalledPlugins != nil && idx.Owner != OwnerCore && idx.Owner != OwnerGoAuth {
				continue
			}
			return nil, fmt.Errorf("schema: %s: index %q uses unknown fields %v", d.name, idx.Name, idx.Fields)
		}
		if len(idx.Fields) == 0 {
			return nil, fmt.Errorf("schema: %s: index %q has no fields", d.name, idx.Name)
		}
		rm.indexes = append(rm.indexes, idx)
	}
	return rm, nil
}

// validate checks what spans several models: unique table names and valid references.
func (r *Registry) validate() error {
	tables := map[string]string{}
	for _, name := range r.order {
		m := r.models[name]
		// Step 1: two models can't share a table
		key := strings.ToLower(m.table)
		if other, dup := tables[key]; dup {
			return fmt.Errorf("schema: models %q and %q both use table %q", other, name, m.table)
		}
		tables[key] = name
		// Step 2: references must point at an existing model and field
		for _, f := range m.fields {
			if f.References == nil {
				continue
			}
			target, ok := r.models[f.References.Model]
			if !ok {
				return fmt.Errorf("schema: %s.%s references unknown model %q", name, f.Name, f.References.Model)
			}
			if !target.Has(f.References.Field) {
				return fmt.Errorf("schema: %s.%s references unknown field %s.%s", name, f.Name, f.References.Model, f.References.Field)
			}
		}
	}
	return nil
}

// ColumnCase returns the column naming the registry was built with.
func (r *Registry) ColumnCase() ColumnCase { return r.columnCase }

// IDStrategy returns who creates primary keys (Options.IDs, default IDApplication).
func (r *Registry) IDStrategy() IDStrategy { return r.ids }

// Model returns the resolved model with logical name name.
func (r *Registry) Model(name string) (*ResolvedModel, bool) {
	m, ok := r.models[name]
	return m, ok
}

// Models returns every model: user, session, account, verification, then plugin models in plugin order.
func (r *Registry) Models() []*ResolvedModel {
	out := make([]*ResolvedModel, len(r.order))
	for i, n := range r.order {
		out[i] = r.models[n]
	}
	return out
}

// Table returns the table of model, or "" when the model is unknown.
func (r *Registry) Table(model string) string {
	if m, ok := r.models[model]; ok {
		return m.table
	}
	return ""
}

// Column returns the column of model.field, or "" when either is unknown.
func (r *Registry) Column(model, field string) string {
	if m, ok := r.models[model]; ok {
		return m.Column(field)
	}
	return ""
}

func sortedModelOptionKeys(m map[string]ModelOptions) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedSchemaKeys(m PluginSchema) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
