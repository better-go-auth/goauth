package render

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/better-go-auth/goauth/src/schema"
)

// Prisma providers accepted by Prisma (the datasource's provider).
const (
	PrismaPostgreSQL = "postgresql"
	PrismaMySQL      = "mysql"
	PrismaSQLite     = "sqlite"
	PrismaMongoDB    = "mongodb"
)

// PrismaProviders lists the providers Prisma renders.
var PrismaProviders = []string{PrismaPostgreSQL, PrismaMySQL, PrismaSQLite, PrismaMongoDB}

// ParsePrismaProvider accepts a Prisma provider or a dialect alias (postgres, pg, sqlite3, mariadb, mongo).
func ParsePrismaProvider(name string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "postgresql", "postgres", "pg", "pgx":
		return PrismaPostgreSQL, nil
	case "mysql", "mariadb":
		return PrismaMySQL, nil
	case "sqlite", "sqlite3":
		return PrismaSQLite, nil
	case "mongodb", "mongo":
		return PrismaMongoDB, nil
	}
	return "", fmt.Errorf("render: unknown prisma provider %q (use postgresql, mysql, sqlite or mongodb)", name)
}

// Prisma returns a schema.prisma for reg, following better-auth's Prisma generator (`npx @better-auth/cli
// generate` with the Prisma adapter): a prisma-client-js generator and a datasource for provider
// (postgresql, mysql, sqlite or mongodb), then one model per registry model, named after its table with
// the first letter upper-cased and mapped to the table with @@map. Prisma field names are the registry's
// columns. Like better-auth it renders @id (Int @default(autoincrement()) for serial ids, @map("_id") on
// MongoDB), @default(now()) for creation times, @updatedAt, @@unique([field]) for unique fields, relation
// fields with onDelete next to each foreign key plus the back-relations (sessions Session[]), @@index for
// indexed fields (with length: 191 on MySQL strings) and @db.Text for MySQL strings.
//
// Differences from better-auth, all following goauth's logical types: number is Float (better-auth: Int),
// integer is BigInt, number[] is Float[]; JSON and arrays stored as strings on MySQL are @db.Text; database
// ids get the database default of render.SQL (dbgenerated); multi-column indexes and unique constraints
// (account's providerId + accountId, plugin indexes) are rendered; every date defaulting to the current
// time gets @default(now()) and every date with an OnUpdate gets @updatedAt (better-auth: only the fields
// named createdAt / updatedAt); several references to one model, and self references, get named
// relations. MongoDB keeps better-auth's String ids for every id strategy.
func Prisma(reg *schema.Registry, provider string) (string, error) {
	// Step 1: the provider
	provider, err := ParsePrismaProvider(provider)
	if err != nil {
		return "", err
	}
	if provider == PrismaMongoDB && reg.IDStrategy() == schema.IDSerial {
		return "", fmt.Errorf("render: prisma: MongoDB has no auto-increment ids (id strategy %q)", schema.IDSerial)
	}
	p := &prismaRenderer{reg: reg, provider: provider}
	// Step 2: model names, field names and relations of every model
	if err := p.plan(); err != nil {
		return "", err
	}
	var b strings.Builder
	// Step 3: header, generator and datasource (better-auth's getNewPrisma)
	b.WriteString("// goauth schema, Prisma (" + provider + "). Generated from goauth's schema registry (core models,\n" +
		"// additionalFields and plugin schemas); regenerate instead of editing.\n\n")
	b.WriteString("generator client {\n  provider = \"prisma-client-js\"\n}\n\n")
	url := `env("DATABASE_URL")`
	if provider == PrismaSQLite {
		url = `"file:./dev.db"`
	}
	fmt.Fprintf(&b, "datasource db {\n  provider = %q\n  url      = %s\n}\n", provider, url)
	// Step 4: one model per registry model, in registry order
	for _, m := range reg.Models() {
		b.WriteString("\n")
		p.writeModel(&b, m)
	}
	return b.String(), nil
}

// prismaRenderer holds the names computed before rendering.
type prismaRenderer struct {
	reg      *schema.Registry
	provider string
	// models maps logical model names to Prisma model names.
	models map[string]string
	// fields maps model → logical field → Prisma field name.
	fields map[string]map[string]string
	// relations maps model → logical fk field → its relation field.
	relations map[string]map[string]prismaRelation
	// backs maps a referenced model to its back-relation fields, in registry order.
	backs map[string][]prismaBack
}

// prismaRelation is the relation field next to a foreign key.
type prismaRelation struct {
	name  string // field name ("user")
	label string // relation name, "" unless the relation is ambiguous
}

// prismaBack is a back-relation field (sessions Session[]).
type prismaBack struct {
	name, typ, label string
}

// prismaIdent matches names Prisma accepts for models and fields.
var prismaIdent = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

// plan computes model names, field names, relation fields and back-relations.
func (p *prismaRenderer) plan() error {
	p.models = map[string]string{}
	p.fields = map[string]map[string]string{}
	p.relations = map[string]map[string]prismaRelation{}
	p.backs = map[string][]prismaBack{}
	taken := map[string]map[string]bool{}
	seenModels := map[string]string{}
	// Step 1: model names (capitalized table) and field names (columns, or the logical name with @map)
	for _, m := range p.reg.Models() {
		name := prismaModelName(m.Table())
		if !prismaIdent.MatchString(name) {
			return fmt.Errorf("render: prisma: table %q of model %q is not a valid Prisma model name", m.Table(), m.Name())
		}
		if other, dup := seenModels[strings.ToLower(name)]; dup {
			return fmt.Errorf("render: prisma: models %q and %q both become Prisma model %q", other, m.Name(), name)
		}
		seenModels[strings.ToLower(name)] = m.Name()
		p.models[m.Name()] = name
		p.fields[m.Name()] = map[string]string{}
		taken[m.Name()] = map[string]bool{}
		for _, f := range m.Fields() {
			fn := f.Column
			if !prismaIdent.MatchString(fn) {
				fn = f.Name
			}
			if !prismaIdent.MatchString(fn) {
				return fmt.Errorf("render: prisma: %s.%s: column %q is not a valid Prisma field name", m.Name(), f.Name, f.Column)
			}
			p.fields[m.Name()][f.Name] = fn
			taken[m.Name()][fn] = true
		}
	}
	// Step 2: relation fields next to each foreign key; several references to one model (or to the model
	// itself) need named relations
	for _, m := range p.reg.Models() {
		p.relations[m.Name()] = map[string]prismaRelation{}
		refs := map[string]int{}
		for _, f := range m.Fields() {
			if f.References != nil {
				refs[f.References.Model]++
			}
		}
		for _, f := range m.Fields() {
			if f.References == nil {
				continue
			}
			target, _ := p.reg.Model(f.References.Model)
			ambiguous := refs[f.References.Model] > 1 || f.References.Model == m.Name()
			rel := prismaRelation{name: strings.ToLower(target.Table())}
			if ambiguous || taken[m.Name()][rel.name] || !prismaIdent.MatchString(rel.name) {
				rel.name = relationFieldName(p.fields[m.Name()][f.Name])
			}
			rel.name = uniqueName(taken[m.Name()], rel.name)
			if ambiguous {
				rel.label = p.models[m.Name()] + "_" + rel.name
			}
			p.relations[m.Name()][f.Name] = rel
		}
	}
	// Step 3: back-relations on the referenced models: one per referencing model like better-auth
	// (sessions Session[], or session Session? when the foreign key is unique), one per named relation
	for _, m := range p.reg.Models() {
		done := map[string]bool{}
		for _, f := range m.Fields() {
			if f.References == nil {
				continue
			}
			rel := p.relations[m.Name()][f.Name]
			if rel.label == "" && done[f.References.Model] {
				continue
			}
			done[f.References.Model] = true
			related := p.models[m.Name()]
			name, typ := strings.ToLower(related)+"s", related+"[]"
			if f.Unique {
				name, typ = strings.ToLower(related), related+"?"
			}
			if rel.label != "" {
				name = strings.ToLower(related) + capitalize(rel.name) + "s"
				if f.Unique {
					name = strings.ToLower(related) + capitalize(rel.name)
				}
			}
			name = uniqueName(taken[f.References.Model], name)
			p.backs[f.References.Model] = append(p.backs[f.References.Model], prismaBack{name: name, typ: typ, label: rel.label})
		}
	}
	return nil
}

// prismaModelName is better-auth's capitalizeFirstLetter(modelName).
func prismaModelName(table string) string { return capitalize(table) }

// capitalize upper-cases the first letter of s.
func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// relationFieldName derives a relation field name from its foreign key ("inviterId" → "inviter").
func relationFieldName(fk string) string {
	for _, suffix := range []string{"_id", "Id", "ID"} {
		if n := strings.TrimSuffix(fk, suffix); n != fk && n != "" {
			return n
		}
	}
	return fk + "Rel"
}

// uniqueName returns name, or name with a number appended, that is not in taken, and marks it taken.
func uniqueName(taken map[string]bool, name string) string {
	out := name
	for i := 2; taken[out]; i++ {
		out = name + strconv.Itoa(i)
	}
	taken[out] = true
	return out
}

// prismaField is one line of a model: name, type and attributes.
type prismaField struct {
	name, typ string
	attrs     []string
}

// writeModel renders one model block, aligned like `prisma format`.
func (p *prismaRenderer) writeModel(b *strings.Builder, m *schema.ResolvedModel) {
	var fields []prismaField
	var uniques, indexes []string
	// Step 1: scalar fields, each foreign key followed by its relation field
	for _, f := range m.Fields() {
		fn := p.fields[m.Name()][f.Name]
		if f.Type == schema.ID {
			fields = append(fields, p.idField(fn, f))
			continue
		}
		pf := prismaField{name: fn, typ: p.fieldType(f)}
		pf.attrs = append(pf.attrs, p.defaultAttr(f)...)
		if f.Type == schema.Date && f.OnUpdate != nil {
			pf.attrs = append(pf.attrs, "@updatedAt")
		}
		if p.dbText(f) {
			pf.attrs = append(pf.attrs, "@db.Text")
		}
		if fn != f.Column {
			pf.attrs = append(pf.attrs, fmt.Sprintf("@map(%s)", prismaString(f.Column)))
		}
		fields = append(fields, pf)
		if f.References != nil {
			fields = append(fields, p.relationField(m, f))
		}
		// Step 2: single-column unique constraints and indexes (better-auth: @@unique first, then @@index)
		if f.Unique {
			uniques = append(uniques, fmt.Sprintf("@@unique([%s])", fn))
		} else if f.Index {
			indexes = append(indexes, fmt.Sprintf("@@index([%s])", p.indexColumn(m, f.Name)))
		}
	}
	// Step 3: back-relations
	for _, back := range p.backs[m.Name()] {
		pf := prismaField{name: back.name, typ: back.typ}
		if back.label != "" {
			pf.attrs = []string{fmt.Sprintf("@relation(%s)", prismaString(back.label))}
		}
		fields = append(fields, pf)
	}
	// Step 4: multi-column indexes; `prisma format` puts every @@unique before every @@index
	for _, idx := range m.Indexes() {
		cols := make([]string, len(idx.Fields))
		for i, fn := range idx.Fields {
			cols[i] = p.indexColumn(m, fn)
		}
		if idx.Unique {
			uniques = append(uniques, fmt.Sprintf("@@unique([%s])", strings.Join(cols, ", ")))
		} else {
			indexes = append(indexes, fmt.Sprintf("@@index([%s])", strings.Join(cols, ", ")))
		}
	}
	blocks := append(append(uniques, indexes...), fmt.Sprintf("@@map(%s)", prismaString(m.Table())))
	// Step 5: print, names and types padded to the widest of the model
	nameW, typW := 0, 0
	for _, f := range fields {
		nameW, typW = max(nameW, len(f.name)), max(typW, len(f.typ))
	}
	fmt.Fprintf(b, "model %s {\n", p.models[m.Name()])
	for _, f := range fields {
		if len(f.attrs) == 0 {
			fmt.Fprintf(b, "  %-*s %s\n", nameW, f.name, f.typ)
			continue
		}
		fmt.Fprintf(b, "  %-*s %-*s %s\n", nameW, f.name, typW, f.typ, strings.Join(f.attrs, " "))
	}
	b.WriteString("\n")
	for _, blk := range blocks {
		b.WriteString("  " + blk + "\n")
	}
	b.WriteString("}\n")
}

// idField renders the primary key for the provider and id strategy.
func (p *prismaRenderer) idField(name string, f schema.ResolvedField) prismaField {
	pf := prismaField{name: name, typ: "String", attrs: []string{"@id"}}
	// Step 1: MongoDB stores the id in _id
	if p.provider == PrismaMongoDB {
		pf.attrs = append(pf.attrs, `@map("_id")`)
		return pf
	}
	switch p.reg.IDStrategy() {
	case schema.IDSerial:
		// Step 2: auto-increment integers
		pf.typ = "Int"
		pf.attrs = append(pf.attrs, "@default(autoincrement())")
	case schema.IDDatabase:
		// Step 3: the database default of render.SQL
		switch p.provider {
		case PrismaPostgreSQL:
			pf.attrs = append(pf.attrs, `@default(dbgenerated("gen_random_uuid()::text"))`)
		case PrismaMySQL:
			pf.attrs = append(pf.attrs, `@default(dbgenerated("(uuid())"))`, "@db.VarChar(36)")
		default:
			pf.attrs = append(pf.attrs, `@default(dbgenerated("lower(hex(randomblob(16)))"))`)
		}
	}
	if name != f.Column {
		pf.attrs = append(pf.attrs, fmt.Sprintf("@map(%s)", prismaString(f.Column)))
	}
	return pf
}

// fieldType is better-auth's getType: the Prisma type of a field, "?" when it is optional.
func (p *prismaRenderer) fieldType(f schema.ResolvedField) string {
	stringy := p.provider == PrismaMySQL || p.provider == PrismaSQLite
	var typ string
	// Step 1: references to an id follow the id's type
	switch {
	case f.HoldsID():
		typ = "String"
		if p.reg.IDStrategy() == schema.IDSerial && p.provider != PrismaMongoDB {
			typ = "Int"
		}
	case f.Type == schema.Number:
		typ = "Float"
	case f.Type == schema.Integer:
		typ = "BigInt"
	case f.Type == schema.Boolean:
		typ = "Boolean"
	case f.Type == schema.Date:
		typ = "DateTime"
	case f.Type == schema.JSON:
		typ = "Json"
		if stringy {
			typ = "String"
		}
	case f.Type == schema.StringArray, f.Type == schema.NumberArray:
		// Step 2: lists can't be optional; MySQL and SQLite store them as JSON strings
		if !stringy {
			if f.Type == schema.StringArray {
				return "String[]"
			}
			return "Float[]"
		}
		typ = "String"
	default:
		typ = "String"
	}
	if !f.Required {
		typ += "?"
	}
	return typ
}

// defaultAttr renders @default: now() for dates defaulting to the current time (without OnUpdate), and
// constants (strings not on MySQL, whose text columns take no default, like better-auth).
func (p *prismaRenderer) defaultAttr(f schema.ResolvedField) []string {
	// Step 1: the current time
	if nowDefault(f) {
		if f.OnUpdate != nil {
			return nil
		}
		return []string{"@default(now())"}
	}
	if !staticDefault(f) {
		return nil
	}
	// Step 2: constants
	v, err := schema.Normalize(f.Type, f.Default)
	if err != nil || v == nil {
		return nil
	}
	switch x := v.(type) {
	case bool:
		return []string{"@default(" + strconv.FormatBool(x) + ")"}
	case float64:
		return []string{"@default(" + strconv.FormatFloat(x, 'g', -1, 64) + ")"}
	case int64:
		return []string{"@default(" + strconv.FormatInt(x, 10) + ")"}
	case string:
		if p.provider == PrismaMySQL {
			return nil
		}
		return []string{"@default(" + prismaString(x) + ")"}
	}
	// Step 3: lists and JSON
	if p.provider == PrismaMySQL {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	if f.Type != schema.JSON && p.provider != PrismaSQLite {
		// Prisma list defaults are list literals: ["a", "b"] / [1, 2]
		return []string{"@default(" + strings.ReplaceAll(string(raw), ",", ", ") + ")"}
	}
	return []string{"@default(" + prismaString(string(raw)) + ")"}
}

// dbText reports whether a MySQL string column is @db.Text: better-auth's rule (strings that are neither
// unique nor references), plus JSON and arrays stored as strings.
func (p *prismaRenderer) dbText(f schema.ResolvedField) bool {
	if p.provider != PrismaMySQL || f.Unique || f.References != nil || f.HoldsID() {
		return false
	}
	switch f.Type {
	case schema.String, schema.JSON, schema.StringArray, schema.NumberArray:
		return true
	}
	return false
}

// indexColumn renders a field inside @@index / @@unique; MySQL needs a prefix length on text columns
// (better-auth adds length: 191 to every indexed MySQL string but integer and UUID references).
func (p *prismaRenderer) indexColumn(m *schema.ResolvedModel, field string) string {
	f, _ := m.Field(field)
	fn := p.fields[m.Name()][field]
	if p.provider != PrismaMySQL || f.Type != schema.String || f.Unique {
		return fn
	}
	if f.HoldsID() && p.reg.IDStrategy().DatabaseGenerated() {
		return fn
	}
	return fn + "(length: 191)"
}

// relationField renders the relation field next to the foreign key f.
func (p *prismaRenderer) relationField(m *schema.ResolvedModel, f schema.ResolvedField) prismaField {
	rel := p.relations[m.Name()][f.Name]
	target, _ := p.reg.Model(f.References.Model)
	typ := p.models[target.Name()]
	if !f.Required {
		typ += "?"
	}
	args := fmt.Sprintf("fields: [%s], references: [%s], onDelete: %s",
		p.fields[m.Name()][f.Name], p.fields[target.Name()][f.References.Field], prismaAction(f.References.OnDelete))
	if rel.label != "" {
		args = prismaString(rel.label) + ", " + args
	}
	return prismaField{name: rel.name, typ: typ, attrs: []string{"@relation(" + args + ")"}}
}

// prismaAction maps a referential action to Prisma's (Cascade by default, like better-auth).
func prismaAction(a schema.OnDelete) string {
	switch a {
	case schema.NoAction:
		return "NoAction"
	case schema.SetNull:
		return "SetNull"
	case schema.SetDefault:
		return "SetDefault"
	case schema.Restrict:
		return "Restrict"
	}
	return "Cascade"
}

// prismaString quotes s as a Prisma string literal.
func prismaString(s string) string { return strconv.Quote(s) }
