package render

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/better-go-auth/goauth/src/schema"
)

// DefaultHCLSchema returns the schema (namespace) name HCL uses for dialect d: "public" on Postgres, "main"
// on SQLite and "goauth" on MySQL, where a schema is a database. With a schema-bound Atlas URL
// (mysql://…/app) the name in the HCL must be the database's name: use HCLSchema to pick it.
func DefaultHCLSchema(d Dialect) string {
	switch d {
	case MySQL:
		return "goauth"
	case SQLite:
		return "main"
	}
	return "public"
}

// HCL returns the desired-state schema of reg in Atlas' HCL schema language (https://atlasgo.io/atlas-schema/hcl)
// for dialect d, in the schema DefaultHCLSchema(d). It describes the same tables, columns, defaults,
// primary keys, foreign keys and indexes as SQL, for `atlas schema apply --to file://goauth.hcl` and
// `atlas migrate diff --to file://goauth.hcl`.
func HCL(reg *schema.Registry, d Dialect) (string, error) {
	return HCLSchema(reg, d, "")
}

// HCLSchema is HCL with an explicit schema (namespace) name; "" means DefaultHCLSchema(d).
func HCLSchema(reg *schema.Registry, d Dialect, schemaName string) (string, error) {
	// Step 1: validate the inputs
	if err := d.valid(); err != nil {
		return "", err
	}
	if schemaName == "" {
		schemaName = DefaultHCLSchema(d)
	}
	var b strings.Builder
	// Step 2: the header comment and the schema block
	fmt.Fprintf(&b, "# goauth schema, %s, Atlas HCL. Generated from goauth's schema registry (core models,\n"+
		"# additionalFields and plugin schemas); regenerate instead of editing.\n\n", d)
	fmt.Fprintf(&b, "schema %s {\n}\n", hclString(schemaName))
	// Step 3: one table block per model, referenced tables first
	for _, m := range schema.DependencyOrder(reg) {
		b.WriteString("\n")
		writeHCLTable(&b, reg, m, d, schemaName)
	}
	return b.String(), nil
}

// hclBlock collects the lines of one HCL block so that consecutive attributes get aligned "=" signs, like
// `atlas schema inspect` (hclwrite) prints them.
type hclBlock struct {
	indent string
	lines  []hclLine
}

// hclLine is an attribute (key = value) or a raw line (a nested block's header, body or closing brace).
type hclLine struct {
	key, value string
	raw        string
}

// attr adds an attribute line.
func (h *hclBlock) attr(key, value string) {
	h.lines = append(h.lines, hclLine{key: key, value: value})
}

// raw adds a line printed as is.
func (h *hclBlock) raw(line string) {
	h.lines = append(h.lines, hclLine{raw: line})
}

// write prints the lines; each run of consecutive attributes is aligned on its longest key.
func (h *hclBlock) write(b *strings.Builder) {
	for i := 0; i < len(h.lines); {
		// Step 1: raw lines are printed as they are
		if h.lines[i].raw != "" {
			b.WriteString(h.indent + h.lines[i].raw + "\n")
			i++
			continue
		}
		// Step 2: find the run of attributes and its widest key
		j, width := i, 0
		for ; j < len(h.lines) && h.lines[j].raw == ""; j++ {
			width = max(width, len(h.lines[j].key))
		}
		for _, l := range h.lines[i:j] {
			fmt.Fprintf(b, "%s%-*s = %s\n", h.indent, width, l.key, l.value)
		}
		i = j
	}
}

// writeHCLTable renders one table block: columns, primary key, foreign keys, indexes.
func writeHCLTable(b *strings.Builder, reg *schema.Registry, m *schema.ResolvedModel, d Dialect, schemaName string) {
	fmt.Fprintf(b, "table %s {\n", hclString(m.Table()))
	tbl := &hclBlock{indent: "  "}
	tbl.attr("schema", hclRef("schema", schemaName))
	var pk string
	// Step 1: columns in registry order
	for _, f := range m.Fields() {
		tbl.raw("column " + hclString(f.Column) + " {")
		col := &hclBlock{indent: "    "}
		if f.Type == schema.ID {
			pk = f.Column
			hclIDColumn(col, reg.IDStrategy(), d)
		} else {
			hclColumn(col, reg, f, d)
		}
		for _, l := range col.lines {
			tbl.lines = append(tbl.lines, prefixed(l, "  "))
		}
		tbl.raw("}")
	}
	// Step 2: the primary key
	tbl.raw("primary_key {")
	tbl.raw("  columns = [" + hclRef("column", pk) + "]")
	tbl.raw("}")
	// Step 3: foreign keys, named like the SQL constraints
	for _, f := range m.Fields() {
		if f.References == nil {
			continue
		}
		target, _ := reg.Model(f.References.Model)
		tbl.raw("foreign_key " + hclString(foreignKeyName(m, f)) + " {")
		fk := &hclBlock{indent: "    "}
		fk.attr("columns", "["+hclRef("column", f.Column)+"]")
		fk.attr("ref_columns", "["+hclRef("table", target.Table())+hclRef(".column", target.Column(f.References.Field))+"]")
		fk.attr("on_update", "NO_ACTION")
		fk.attr("on_delete", hclAction(f.References.OnDelete))
		for _, l := range fk.lines {
			tbl.lines = append(tbl.lines, prefixed(l, "  "))
		}
		tbl.raw("}")
	}
	// Step 4: indexes (the names of render.SQL)
	for _, idx := range m.IndexSpecs() {
		tbl.raw("index " + hclString(idx.Name) + " {")
		ib := &hclBlock{indent: "    "}
		if idx.Unique {
			ib.attr("unique", "true")
		}
		cols := make([]string, len(idx.Columns))
		for i, c := range idx.Columns {
			cols[i] = hclRef("column", c)
		}
		ib.attr("columns", "["+strings.Join(cols, ", ")+"]")
		for _, l := range ib.lines {
			tbl.lines = append(tbl.lines, prefixed(l, "  "))
		}
		tbl.raw("}")
	}
	tbl.write(b)
	b.WriteString("}\n")
}

// prefixed indents a nested block's line one more level, keeping attributes as attributes so that they
// are still aligned among themselves (raw lines of different blocks never mix with them).
func prefixed(l hclLine, indent string) hclLine {
	if l.raw != "" {
		return hclLine{raw: indent + l.raw}
	}
	return hclLine{key: indent + l.key, value: l.value}
}

// hclIDColumn renders the primary key column for the id strategy (the same types and defaults as SQL).
func hclIDColumn(col *hclBlock, ids schema.IDStrategy, d Dialect) {
	switch ids {
	case schema.IDSerial:
		// Step 1: integer identities. SQLite's "integer PRIMARY KEY AUTOINCREMENT" (the rowid, as SQL renders
		// it) is nullable for Atlas: inserting NULL takes the next rowid
		col.attr("null", strconv.FormatBool(d == SQLite))
		switch d {
		case Postgres:
			col.attr("type", "bigint")
			col.raw("identity {")
			col.raw("  generated = BY_DEFAULT")
			col.raw("}")
		case MySQL:
			col.attr("type", "bigint")
			col.attr("auto_increment", "true")
		default:
			col.attr("type", "integer")
			col.attr("auto_increment", "true")
		}
	case schema.IDDatabase:
		// Step 2: database-generated strings
		col.attr("null", "false")
		switch d {
		case Postgres:
			col.attr("type", "text")
			col.attr("default", `sql("gen_random_uuid()::text")`)
		case MySQL:
			col.attr("type", "varchar(36)")
			col.attr("default", `sql("(uuid())")`)
		default:
			col.attr("type", "text")
			col.attr("default", `sql("lower(hex(randomblob(16)))")`)
		}
	default:
		// Step 3: application-generated strings
		col.attr("null", "false")
		col.attr("type", pick(d, "text", "varchar(255)", "text"))
	}
}

// hclColumn renders a (non primary key) column: nullability, type (plus charset and collation of MySQL's
// unique strings) and default.
func hclColumn(col *hclBlock, reg *schema.Registry, f schema.ResolvedField, d Dialect) {
	col.attr("null", strconv.FormatBool(!f.Required))
	// Step 1: the type, written the way Atlas spells it
	typ := ColumnType(reg, f, d)
	charset, collate := "", ""
	if i := strings.Index(typ, " CHARACTER SET "); i >= 0 {
		rest := strings.Fields(typ[i:])
		typ, charset, collate = typ[:i], rest[2], rest[4]
	}
	switch typ {
	case "double precision":
		typ = "double_precision"
	case "boolean":
		if d == MySQL {
			typ = "bool"
		}
	}
	col.attr("type", typ)
	if charset != "" {
		col.attr("charset", hclString(charset))
		col.attr("collate", hclString(collate))
	}
	// Step 2: the default
	if def := hclDefault(f, d); def != "" {
		col.attr("default", def)
	}
}

// hclDefault renders the default of a column like defaultClause: the current time as an SQL expression,
// constants as HCL literals (booleans are 0/1 on SQLite).
func hclDefault(f schema.ResolvedField, d Dialect) string {
	// Step 1: the current time
	if nowDefault(f) {
		if d == MySQL {
			return `sql("CURRENT_TIMESTAMP(3)")`
		}
		return `sql("CURRENT_TIMESTAMP")`
	}
	if !staticDefault(f) {
		return ""
	}
	// Step 2: constants of scalar types
	v, err := schema.Normalize(f.Type, f.Default)
	if err != nil || v == nil {
		return ""
	}
	switch x := v.(type) {
	case bool:
		if d == SQLite {
			if x {
				return "1"
			}
			return "0"
		}
		return strconv.FormatBool(x)
	case string:
		return hclString(x)
	case float64:
		return strconv.FormatFloat(x, 'g', -1, 64)
	case int64:
		return strconv.FormatInt(x, 10)
	}
	return ""
}

// hclAction renders a referential action (CASCADE by default, like better-auth).
func hclAction(a schema.OnDelete) string {
	if a == "" {
		return "CASCADE"
	}
	return strings.ReplaceAll(strings.ToUpper(string(a)), " ", "_")
}

// foreignKeyName is the name of the foreign key constraint of f (fk_<table>_<snake field>), as in SQL.
func foreignKeyName(m *schema.ResolvedModel, f schema.ResolvedField) string {
	return strings.Replace(schema.IndexName(m.Table(), schema.SnakeCase(f.Name)), "idx_", "fk_", 1)
}

// hclString quotes s as an HCL string literal (template sequences escaped).
func hclString(s string) string {
	q := strconv.Quote(s)
	q = strings.ReplaceAll(q, "${", "$${")
	return strings.ReplaceAll(q, "%{", "%%{")
}

// hclIdent matches names that can follow a "." in an HCL traversal.
var hclIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*$`)

// hclRef renders a reference to a named block: prefix.name (column.userId, table.users) when the name is
// an HCL identifier, prefix["name"] otherwise (column["my col"]).
func hclRef(prefix, name string) string {
	if hclIdent.MatchString(name) {
		return prefix + "." + name
	}
	return prefix + "[" + hclString(name) + "]"
}
