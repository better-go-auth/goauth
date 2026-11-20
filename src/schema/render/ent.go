package render

import (
	"fmt"
	"go/format"
	"go/token"
	"sort"
	"strconv"
	"strings"

	"github.com/better-go-auth/goauth/src/schema"
)

// EntOptions configure Ent.
type EntOptions struct {
	// Package is the package clause of the schema files (default "schema", Ent's ./ent/schema directory).
	Package string
	// Migrate lets Ent's migration (client.Schema.Create, Atlas through entc) manage the tables. By default
	// every schema is annotated with entsql.Skip: Ent queries goauth's tables but leaves creating and
	// altering them to goauth's migrator (or render.SQL / render.HCL).
	Migrate bool
}

// Ent returns Ent schema files (entgo.io/ent v0.14) for reg: file name → gofmt'd Go source, one file per
// model (user.go, session.go, ..., ratelimit.go, plugin models). Each schema is named after the exported Go
// name of the model (User, Session, Account, Verification, RateLimit), maps to its table with
// entsql.Annotation{Table: ...} and lists one field per column: Ent field names are the snake_case logical
// names (email_verified) with StorageKey set to the registry's column, ids are field.String("id") (or
// field.Int64("id") for serial ids), fields that are not required are Optional (and Nillable when Ent
// allows it), unique single fields are Unique(), constant defaults become Default(...), dates defaulting to
// the current time Default(time.Now) and dates with an OnUpdate UpdateDefault(time.Now). With Migrate,
// non-unique and multi-column indexes are listed in Indexes() with the names of render.SQL; skipped schemas
// have no Indexes() (indexes only drive Ent's migration, and entc v0.14.3 crashes on indexes of skipped
// tables).
//
// References are plain foreign-key fields (user_id) with a comment, not Ent edges: edges would need the
// back-references on the referenced schemas and Ent's edge-field rules, and goauth's migrator already
// creates the foreign keys.
func Ent(reg *schema.Registry, opts EntOptions) (map[string]string, error) {
	// Step 1: options
	pkg := opts.Package
	if pkg == "" {
		pkg = "schema"
	}
	if !token.IsIdentifier(pkg) {
		return nil, fmt.Errorf("render: ent: invalid package name %q", pkg)
	}
	out := map[string]string{}
	types := map[string]string{}
	// Step 2: one file per model
	for _, m := range reg.Models() {
		name := GoName(m.Name())
		file := strings.ToLower(name) + ".go"
		if other, dup := types[file]; dup {
			return nil, fmt.Errorf("render: ent: models %q and %q both become schema %s", other, m.Name(), name)
		}
		types[file] = m.Name()
		src, err := entSchema(reg, m, name, pkg, opts.Migrate)
		if err != nil {
			return nil, err
		}
		out[file] = src
	}
	return out, nil
}

// EntFileNames returns the file names of Ent's output in a stable order.
func EntFileNames(files map[string]string) []string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// entSchema renders the schema file of one model.
func entSchema(reg *schema.Registry, m *schema.ResolvedModel, name, pkg string, migrate bool) (string, error) {
	imports := map[string]bool{"entgo.io/ent": true, "entgo.io/ent/dialect/entsql": true, "entgo.io/ent/schema": true, "entgo.io/ent/schema/field": true}
	var body strings.Builder
	// Step 1: the type and its annotations
	fmt.Fprintf(&body, "// %s holds the schema of goauth's %q model (table %q).\n", name, m.Name(), m.Table())
	fmt.Fprintf(&body, "type %s struct {\n\tent.Schema\n}\n\n", name)
	if migrate {
		fmt.Fprintf(&body, "// Annotations of %s: its table.\n", name)
		fmt.Fprintf(&body, "func (%s) Annotations() []schema.Annotation {\n\treturn []schema.Annotation{\n\t\tentsql.Annotation{Table: %q},\n\t}\n}\n\n", name, m.Table())
	} else {
		fmt.Fprintf(&body, "// Annotations of %s: its table, skipped by Ent's migration (goauth's migrator manages it).\n", name)
		fmt.Fprintf(&body, "func (%s) Annotations() []schema.Annotation {\n\treturn []schema.Annotation{\n\t\tentsql.Annotation{Table: %q, Skip: true},\n\t}\n}\n\n", name, m.Table())
	}
	// Step 2: fields
	fieldNames := map[string]string{}
	seen := map[string]string{}
	fmt.Fprintf(&body, "// Fields of %s.\n", name)
	fmt.Fprintf(&body, "func (%s) Fields() []ent.Field {\n\treturn []ent.Field{\n", name)
	for _, f := range m.Fields() {
		fn := entFieldName(f)
		if other, dup := seen[fn]; dup {
			return "", fmt.Errorf("render: ent: %s: fields %q and %q both become Ent field %q", m.Name(), other, f.Name, fn)
		}
		seen[fn] = f.Name
		fieldNames[f.Name] = fn
		if f.References != nil {
			target, _ := reg.Model(f.References.Model)
			action := strings.ToUpper(string(f.References.OnDelete))
			if action == "" {
				action = "CASCADE"
			}
			fmt.Fprintf(&body, "\t\t// %s references %s(%s) ON DELETE %s.\n", fn, target.Table(), target.Column(f.References.Field), action)
		}
		body.WriteString("\t\t" + entField(reg, f, fn, imports) + ",\n")
	}
	body.WriteString("\t}\n}\n")
	// Step 3: indexes that are not a unique field, only for tables Ent migrates (they only drive Ent's
	// migration, and entc v0.14 fails on indexes of skipped tables)
	var indexes []string
	for _, idx := range m.IndexSpecs() {
		if !migrate || (idx.Unique && len(idx.Fields) == 1) {
			continue
		}
		cols := make([]string, len(idx.Fields))
		for i, f := range idx.Fields {
			cols[i] = strconv.Quote(fieldNames[f])
		}
		ix := "index.Fields(" + strings.Join(cols, ", ") + ")"
		if idx.Unique {
			ix += ".Unique()"
		}
		indexes = append(indexes, ix+".StorageKey("+strconv.Quote(idx.Name)+")")
	}
	if len(indexes) > 0 {
		imports["entgo.io/ent/schema/index"] = true
		fmt.Fprintf(&body, "\n// Indexes of %s.\n", name)
		fmt.Fprintf(&body, "func (%s) Indexes() []ent.Index {\n\treturn []ent.Index{\n", name)
		for _, ix := range indexes {
			body.WriteString("\t\t" + ix + ",\n")
		}
		body.WriteString("\t}\n}\n")
	}
	// Step 4: header, imports (standard library first) and gofmt
	var b strings.Builder
	b.WriteString("// Code generated by goauth schema --format ent; DO NOT EDIT.\n\n")
	b.WriteString("package " + pkg + "\n\n")
	b.WriteString("import (\n")
	var std, ext []string
	for imp := range imports {
		if strings.Contains(imp, ".") {
			ext = append(ext, imp)
		} else {
			std = append(std, imp)
		}
	}
	sort.Strings(std)
	sort.Strings(ext)
	for _, imp := range std {
		b.WriteString("\t" + strconv.Quote(imp) + "\n")
	}
	if len(std) > 0 {
		b.WriteString("\n")
	}
	for _, imp := range ext {
		b.WriteString("\t" + strconv.Quote(imp) + "\n")
	}
	b.WriteString(")\n\n")
	b.WriteString(body.String())
	src, err := format.Source([]byte(b.String()))
	if err != nil {
		return "", fmt.Errorf("render: ent: format %s: %w", name, err)
	}
	return string(src), nil
}

// entFieldName is the Ent field name of f: "id", or its logical name in snake_case.
func entFieldName(f schema.ResolvedField) string {
	if f.Type == schema.ID {
		return "id"
	}
	return schema.SnakeCase(f.Name)
}

// entField renders the field.<Type>(...) builder chain of f.
func entField(reg *schema.Registry, f schema.ResolvedField, name string, imports map[string]bool) string {
	q := strconv.Quote(name)
	serial := reg.IDStrategy() == schema.IDSerial
	// Step 1: the primary key
	if f.Type == schema.ID {
		if serial {
			return "field.Int64(" + q + ")"
		}
		return "field.String(" + q + ")"
	}
	// Step 2: the builder for the logical type
	var b string
	nillable := true
	switch {
	case f.HoldsID() && serial:
		b = "field.Int64(" + q + ")"
	case f.Type == schema.Number:
		b = "field.Float(" + q + ")"
	case f.Type == schema.Integer:
		b = "field.Int64(" + q + ")"
	case f.Type == schema.Boolean:
		b = "field.Bool(" + q + ")"
	case f.Type == schema.Date:
		b = "field.Time(" + q + ")"
	case f.Type == schema.JSON:
		imports["encoding/json"] = true
		b, nillable = "field.JSON("+q+", json.RawMessage{})", false
	case f.Type == schema.StringArray:
		b, nillable = "field.Strings("+q+")", false
	case f.Type == schema.NumberArray:
		b, nillable = "field.Floats("+q+")", false
	default:
		b = "field.String(" + q + ")"
	}
	b += ".StorageKey(" + strconv.Quote(f.Column) + ")"
	// Step 3: optional, unique and defaults
	if !f.Required {
		b += ".Optional()"
		if nillable {
			b += ".Nillable()"
		}
	}
	if f.Unique {
		b += ".Unique()"
	}
	if nowDefault(f) {
		imports["time"] = true
		b += ".Default(time.Now)"
	} else if def := entDefault(f); def != "" && !f.Unique && !(f.HoldsID() && serial) {
		b += ".Default(" + def + ")"
	}
	if f.Type == schema.Date && f.OnUpdate != nil {
		imports["time"] = true
		b += ".UpdateDefault(time.Now)"
	}
	return b
}

// entDefault renders a constant default as a Go literal of the field's type ("" when there is none).
func entDefault(f schema.ResolvedField) string {
	if !staticDefault(f) {
		return ""
	}
	v, err := schema.Normalize(f.Type, f.Default)
	if err != nil || v == nil {
		return ""
	}
	switch x := v.(type) {
	case bool:
		return strconv.FormatBool(x)
	case string:
		return strconv.Quote(x)
	case float64:
		s := strconv.FormatFloat(x, 'g', -1, 64)
		if !strings.ContainsAny(s, ".eE") {
			s += ".0"
		}
		return s
	case int64:
		return strconv.FormatInt(x, 10)
	case []string:
		quoted := make([]string, len(x))
		for i, s := range x {
			quoted[i] = strconv.Quote(s)
		}
		return "[]string{" + strings.Join(quoted, ", ") + "}"
	case []float64:
		vals := make([]string, len(x))
		for i, n := range x {
			vals[i] = strconv.FormatFloat(n, 'g', -1, 64)
		}
		return "[]float64{" + strings.Join(vals, ", ") + "}"
	}
	return ""
}
