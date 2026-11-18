// Package render turns a schema.Registry into DDL: the full desired state (CREATE TABLE / CREATE INDEX with
// foreign keys) and the additive statements of a schema.Plan, for Postgres, MySQL and SQLite.
//
// It is the only place where a logical type becomes a column type (doc 04 §6.3, plan 02 §4.5). The same
// output drives goauth's own migrator (Migrations.Mode auto / verify), `goauth schema` (Atlas declarative,
// versioned and external_schema workflows) and `goauth migrate generate` (goose, golang-migrate). Like the
// schema package it imports no ORM or driver.
package render

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/better-go-auth/goauth/src/schema"
)

// Dialect is a SQL dialect.
type Dialect string

const (
	Postgres Dialect = "postgres"
	MySQL    Dialect = "mysql"
	SQLite   Dialect = "sqlite"
)

// Dialects lists the supported dialects.
var Dialects = []Dialect{Postgres, MySQL, SQLite}

// ParseDialect accepts a dialect name and its usual aliases (postgresql, pg, pgx, sqlite3, mariadb).
func ParseDialect(name string) (Dialect, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "postgres", "postgresql", "pg", "pgx":
		return Postgres, nil
	case "mysql", "mariadb":
		return MySQL, nil
	case "sqlite", "sqlite3":
		return SQLite, nil
	}
	return "", fmt.Errorf("render: unknown dialect %q (use postgres, mysql or sqlite)", name)
}

// valid reports whether d is a supported dialect.
func (d Dialect) valid() error {
	for _, x := range Dialects {
		if d == x {
			return nil
		}
	}
	return fmt.Errorf("render: unknown dialect %q (use postgres, mysql or sqlite)", d)
}

// Quote quotes an identifier ("name" on Postgres and SQLite, `name` on MySQL).
func (d Dialect) Quote(ident string) string {
	if d == MySQL {
		return "`" + strings.ReplaceAll(ident, "`", "``") + "`"
	}
	return `"` + strings.ReplaceAll(ident, `"`, `""`) + `"`
}

// SQL returns the desired-state schema of reg: every table in dependency order with its columns, primary
// key and foreign keys, then every index. Statements end with ";" and are separated by blank lines.
func SQL(reg *schema.Registry, d Dialect) (string, error) {
	stmts, err := Statements(reg, d)
	if err != nil {
		return "", err
	}
	return join(header(d, "desired state"), stmts), nil
}

// Statements returns the statements of SQL without the header and terminators.
func Statements(reg *schema.Registry, d Dialect) ([]string, error) {
	if err := d.valid(); err != nil {
		return nil, err
	}
	var tables, indexes []string
	for _, m := range schema.DependencyOrder(reg) {
		// Step 1: CREATE TABLE
		tables = append(tables, createTable(reg, m, d))
		// Step 2: its indexes, after every table
		for _, idx := range m.IndexSpecs() {
			indexes = append(indexes, createIndex(m.Table(), idx, d))
		}
	}
	return append(tables, indexes...), nil
}

// PlanSQL returns the additive statements of plan (empty when the plan is empty).
func PlanSQL(plan *schema.Plan, d Dialect) (string, error) {
	stmts, err := PlanStatements(plan, d)
	if err != nil || len(stmts) == 0 {
		return "", err
	}
	return join(header(d, "additive migration"), stmts), nil
}

// PlanStatements returns one or more statements per change of plan, in plan order. Columns are added
// NOT NULL only when they have a default the dialect accepts in ADD COLUMN; other required columns are
// added nullable (the adapter enforces required values on writes).
func PlanStatements(plan *schema.Plan, d Dialect) ([]string, error) {
	if err := d.valid(); err != nil {
		return nil, err
	}
	if plan.Empty() {
		return nil, nil
	}
	reg := plan.Registry
	if reg == nil {
		return nil, fmt.Errorf("render: plan without a registry")
	}
	var out []string
	for _, c := range plan.Changes {
		m, ok := reg.Model(c.Model)
		if !ok {
			return nil, fmt.Errorf("render: plan change for unknown model %q", c.Model)
		}
		switch c.Kind {
		case schema.AddTable:
			out = append(out, createTable(reg, m, d))
		case schema.AddColumn:
			out = append(out, addColumn(reg, m, c.Field, d)...)
		case schema.AddIndex:
			out = append(out, createIndex(m.Table(), c.Index, d))
		default:
			return nil, fmt.Errorf("render: unknown change kind %q", c.Kind)
		}
	}
	return out, nil
}

// AddColumnNotNull reports whether an added column is NOT NULL: it is required and has a default the
// dialect accepts in ADD COLUMN (a constant, or the current time on Postgres and MySQL).
func AddColumnNotNull(f schema.ResolvedField, d Dialect) bool {
	return f.Required && defaultClause(f, d, true) != ""
}

// header is the comment at the top of generated SQL.
func header(d Dialect, what string) string {
	return fmt.Sprintf("-- goauth schema, %s, %s. Generated from goauth's schema registry (core models,\n"+
		"-- additionalFields and plugin schemas); regenerate instead of editing.\n", d, what)
}

// join terminates and joins statements.
func join(head string, stmts []string) string {
	var b strings.Builder
	b.WriteString(head)
	for _, s := range stmts {
		b.WriteString("\n")
		b.WriteString(s)
		b.WriteString(";\n")
	}
	return b.String()
}

// createTable renders CREATE TABLE for m: columns in registry order, the primary key, foreign keys.
func createTable(reg *schema.Registry, m *schema.ResolvedModel, d Dialect) string {
	var lines []string
	// Step 1: columns
	for _, f := range m.Fields() {
		lines = append(lines, "  "+columnDef(reg, f, d, false))
	}
	// Step 2: foreign keys as table constraints
	for _, f := range m.Fields() {
		if f.References == nil {
			continue
		}
		lines = append(lines, "  "+foreignKey(reg, m, f, d))
	}
	return fmt.Sprintf("CREATE TABLE %s (\n%s\n)", d.Quote(m.Table()), strings.Join(lines, ",\n"))
}

// addColumn renders ALTER TABLE … ADD COLUMN (plus the foreign key on MySQL, which can't declare it inline).
func addColumn(reg *schema.Registry, m *schema.ResolvedModel, f schema.ResolvedField, d Dialect) []string {
	def := columnDef(reg, f, d, true)
	// Step 1: Postgres and SQLite take the reference inline
	if f.References != nil && d != MySQL {
		def += " " + references(reg, f, d)
	}
	out := []string{fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s", d.Quote(m.Table()), def)}
	// Step 2: MySQL adds the foreign key as a constraint
	if f.References != nil && d == MySQL {
		out = append(out, fmt.Sprintf("ALTER TABLE %s ADD %s", d.Quote(m.Table()), foreignKey(reg, m, f, d)))
	}
	return out
}

// columnDef renders "<column> <type> [constraints]". alter = ADD COLUMN (stricter rules for NOT NULL).
func columnDef(reg *schema.Registry, f schema.ResolvedField, d Dialect, alter bool) string {
	col := d.Quote(f.Column)
	// Step 1: the primary key
	if f.Type == schema.ID {
		return col + " " + idColumn(reg.IDStrategy(), d)
	}
	parts := []string{col, ColumnType(reg, f, d)}
	// Step 2: NOT NULL (on ADD COLUMN only with a default) and DEFAULT
	def := defaultClause(f, d, alter)
	if f.Required && (!alter || def != "") {
		parts = append(parts, "NOT NULL")
	}
	if def != "" {
		parts = append(parts, def)
	}
	return strings.Join(parts, " ")
}

// idColumn renders the type and constraints of the primary key for the id strategy.
func idColumn(ids schema.IDStrategy, d Dialect) string {
	switch ids {
	case schema.IDSerial:
		switch d {
		case Postgres:
			return "bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY"
		case MySQL:
			return "bigint NOT NULL AUTO_INCREMENT PRIMARY KEY"
		default:
			return "integer PRIMARY KEY AUTOINCREMENT"
		}
	case schema.IDDatabase:
		switch d {
		case Postgres:
			return "text NOT NULL DEFAULT gen_random_uuid()::text PRIMARY KEY"
		case MySQL:
			return "varchar(36) NOT NULL DEFAULT (uuid()) PRIMARY KEY"
		default:
			return "text NOT NULL DEFAULT (lower(hex(randomblob(16)))) PRIMARY KEY"
		}
	}
	if d == MySQL {
		return "varchar(255) NOT NULL PRIMARY KEY"
	}
	return "text NOT NULL PRIMARY KEY"
}

// ColumnType returns the physical type of a (non primary key) field in dialect d:
//
//	logical    postgres          mysql                                 sqlite
//	string     text              text, varchar(255) when unique,       text
//	                             indexed, sortable, defaulted or a
//	                             reference (unique: utf8mb4_bin)
//	number     double precision  double                                real
//	integer    bigint            bigint                                integer
//	boolean    boolean           boolean                               integer
//	date       timestamptz       datetime(3)                           datetime
//	json/[]    jsonb             json                                  text
//
// Fields holding an id (references to "id") follow the id strategy: bigint (integer on SQLite) for serial.
func ColumnType(reg *schema.Registry, f schema.ResolvedField, d Dialect) string {
	// Step 1: references to an id follow the primary key's type
	if f.HoldsID() && reg.IDStrategy() == schema.IDSerial {
		if d == SQLite {
			return "integer"
		}
		return "bigint"
	}
	switch f.Type {
	case schema.Number:
		return pick(d, "double precision", "double", "real")
	case schema.Integer:
		return pick(d, "bigint", "bigint", "integer")
	case schema.Boolean:
		return pick(d, "boolean", "boolean", "integer")
	case schema.Date:
		return pick(d, "timestamptz", "datetime(3)", "datetime")
	case schema.JSON, schema.StringArray, schema.NumberArray:
		return pick(d, "jsonb", "json", "text")
	}
	// Step 2: strings; MySQL can only index bounded varchar columns, and compares unique values exactly
	if d != MySQL {
		return "text"
	}
	if f.Unique {
		return "varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin"
	}
	if f.Index || f.Sortable || f.References != nil || f.HoldsID() || inMultiIndex(reg, f) || staticDefault(f) {
		return "varchar(255)"
	}
	return "text"
}

// inMultiIndex reports whether f is part of a multi-column index of its model.
func inMultiIndex(reg *schema.Registry, f schema.ResolvedField) bool {
	for _, m := range reg.Models() {
		mf, ok := m.Field(f.Name)
		if !ok || mf.Column != f.Column {
			continue
		}
		for _, idx := range m.Indexes() {
			for _, fn := range idx.Fields {
				if fn == f.Name {
					return true
				}
			}
		}
	}
	return false
}

func pick(d Dialect, pg, my, lite string) string {
	switch d {
	case Postgres:
		return pg
	case MySQL:
		return my
	}
	return lite
}

// staticDefault reports whether f has a constant default (not a function).
func staticDefault(f schema.ResolvedField) bool {
	if !f.HasDefault() {
		return false
	}
	_, isFunc := f.Default.(func() any)
	return !isFunc
}

// nowDefault reports whether f is a date defaulting to the current time (createdAt-like fields).
func nowDefault(f schema.ResolvedField) bool {
	if f.Type != schema.Date || !f.HasDefault() {
		return false
	}
	fn, ok := f.Default.(func() any)
	if !ok {
		return false
	}
	_, isTime := fn().(time.Time)
	return isTime
}

// defaultClause renders DEFAULT for constant defaults of scalar types and the current time for dates
// (better-auth renders CURRENT_TIMESTAMP for date defaults). SQLite's ADD COLUMN only accepts constants.
func defaultClause(f schema.ResolvedField, d Dialect, alter bool) string {
	// Step 1: the current time
	if nowDefault(f) {
		switch {
		case d == MySQL:
			return "DEFAULT CURRENT_TIMESTAMP(3)"
		case d == SQLite && alter:
			return ""
		default:
			return "DEFAULT CURRENT_TIMESTAMP"
		}
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
				return "DEFAULT 1"
			}
			return "DEFAULT 0"
		}
		return "DEFAULT " + strconv.FormatBool(x)
	case string:
		return "DEFAULT '" + strings.ReplaceAll(x, "'", "''") + "'"
	case float64:
		return "DEFAULT " + strconv.FormatFloat(x, 'g', -1, 64)
	case int64:
		return "DEFAULT " + strconv.FormatInt(x, 10)
	}
	return ""
}

// references renders "REFERENCES <table> (<column>) ON DELETE <action>".
func references(reg *schema.Registry, f schema.ResolvedField, d Dialect) string {
	target, _ := reg.Model(f.References.Model)
	action := strings.ToUpper(string(f.References.OnDelete))
	if action == "" {
		action = "CASCADE"
	}
	return fmt.Sprintf("REFERENCES %s (%s) ON DELETE %s", d.Quote(target.Table()), d.Quote(target.Column(f.References.Field)), action)
}

// foreignKey renders a named FOREIGN KEY table constraint.
func foreignKey(reg *schema.Registry, m *schema.ResolvedModel, f schema.ResolvedField, d Dialect) string {
	name := strings.Replace(schema.IndexName(m.Table(), schema.SnakeCase(f.Name)), "idx_", "fk_", 1)
	return fmt.Sprintf("CONSTRAINT %s FOREIGN KEY (%s) %s", d.Quote(name), d.Quote(f.Column), references(reg, f, d))
}

// createIndex renders CREATE [UNIQUE] INDEX.
func createIndex(table string, idx schema.IndexSpec, d Dialect) string {
	cols := make([]string, len(idx.Columns))
	for i, c := range idx.Columns {
		cols[i] = d.Quote(c)
	}
	kind := "INDEX"
	if idx.Unique {
		kind = "UNIQUE INDEX"
	}
	return fmt.Sprintf("CREATE %s %s ON %s (%s)", kind, d.Quote(idx.Name), d.Quote(table), strings.Join(cols, ", "))
}
