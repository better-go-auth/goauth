package render

import (
	"bytes"
	"encoding/json"

	"github.com/better-go-auth/goauth/src/schema"
)

// MongoIDKey is the document key of the primary key.
const MongoIDKey = "_id"

// MongoField returns the document key of a field on MongoDB (doc 04 §5.3): "_id" for the primary key, the
// column when the field was renamed explicitly (Field.FieldName or the model's Fields option), and otherwise
// the logical field name, so documents use better-auth's camelCase keys whatever GoAuth.ColumnCase says.
func MongoField(reg *schema.Registry, f schema.ResolvedField) string {
	if f.Type == schema.ID {
		return MongoIDKey
	}
	def := f.Name
	if reg.ColumnCase() != schema.Camel {
		def = schema.SnakeCase(f.Name)
	}
	if f.Column != def {
		return f.Column
	}
	return f.Name
}

// MongoBSONTypes returns the BSON $type names a stored value of f has: ids and references to ids are
// ObjectIds (or strings for ids that aren't ObjectId hex strings), JSON is stored as text (better-auth's
// mongodb adapter does the same), arrays are arrays.
func MongoBSONTypes(f schema.ResolvedField) []string {
	if f.HoldsID() {
		return []string{"objectId", "string"}
	}
	switch f.Type {
	case schema.Number, schema.Integer:
		return []string{"number"}
	case schema.Boolean:
		return []string{"bool"}
	case schema.Date:
		return []string{"date"}
	case schema.StringArray, schema.NumberArray:
		return []string{"array"}
	}
	return []string{"string"}
}

// MongoOptions configure MongoCollections.
type MongoOptions struct {
	// NoTTL leaves out the TTL indexes on verification.expiresAt and session.expiresAt.
	NoTTL bool
}

// MongoCollection is one collection with the indexes goauth needs.
type MongoCollection struct {
	// Model is the logical model, Name the collection.
	Model   string       `json:"model"`
	Name    string       `json:"collection"`
	Indexes []MongoIndex `json:"indexes"`
}

// MongoIndex is one index of a collection (ascending keys).
type MongoIndex struct {
	Name string `json:"name"`
	// Keys are the document keys in index order; Fields the logical fields.
	Keys   []string `json:"-"`
	Fields []string `json:"fields"`
	Unique bool     `json:"unique,omitempty"`
	// Partial restricts the index to documents where every key has one of the listed BSON types
	// (partialFilterExpression {key: {$type: ...}}): unique indexes over optional fields, so documents without
	// a value never conflict, like NULLs in SQL.
	Partial []MongoPartial `json:"-"`
	// ExpireAfterSeconds makes the index a TTL index (documents are deleted once the date has passed).
	ExpireAfterSeconds *int32 `json:"expireAfterSeconds,omitempty"`
}

// MongoPartial is one key of a partial filter expression.
type MongoPartial struct {
	Key   string
	Types []string
}

// MarshalJSON writes the index like MongoDB's createIndexes command: ordered "key" and
// "partialFilterExpression" documents.
func (i MongoIndex) MarshalJSON() ([]byte, error) {
	type plain MongoIndex
	base, err := json.Marshal(plain(i))
	if err != nil {
		return nil, err
	}
	// Step 1: the ordered key document
	var b bytes.Buffer
	b.WriteString(`{"key":{`)
	for n, k := range i.Keys {
		if n > 0 {
			b.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		b.Write(kb)
		b.WriteString(":1")
	}
	b.WriteString("}")
	// Step 2: the partial filter expression
	if len(i.Partial) > 0 {
		b.WriteString(`,"partialFilterExpression":{`)
		for n, p := range i.Partial {
			if n > 0 {
				b.WriteByte(',')
			}
			kb, _ := json.Marshal(p.Key)
			b.Write(kb)
			var tb []byte
			if len(p.Types) == 1 {
				tb, _ = json.Marshal(p.Types[0])
			} else {
				tb, _ = json.Marshal(p.Types)
			}
			b.WriteString(`:{"$type":`)
			b.Write(tb)
			b.WriteString("}")
		}
		b.WriteString("}")
	}
	// Step 3: the other attributes
	b.WriteByte(',')
	b.Write(base[1:])
	return b.Bytes(), nil
}

// ttlModels are the models whose expiresAt gets a TTL index (doc 04 §5.3).
var ttlModels = map[string]bool{schema.ModelVerification: true, schema.ModelSession: true}

// MongoCollections returns every collection of reg with its indexes: one per unique / indexed field and
// per multi-field index (named like the SQL indexes), unique indexes over optional fields made partial, and
// TTL indexes on verification.expiresAt and session.expiresAt (an existing plain index on that field
// becomes the TTL index).
func MongoCollections(reg *schema.Registry, opts MongoOptions) []MongoCollection {
	var out []MongoCollection
	for _, m := range reg.Models() {
		c := MongoCollection{Model: m.Name(), Name: m.Table(), Indexes: []MongoIndex{}}
		// Step 1: the registry's indexes
		for _, spec := range m.IndexSpecs() {
			idx := MongoIndex{Name: spec.Name, Fields: spec.Fields, Unique: spec.Unique}
			nullable := false
			for _, fn := range spec.Fields {
				f, _ := m.Field(fn)
				idx.Keys = append(idx.Keys, MongoField(reg, f))
				if !f.Required {
					nullable = true
				}
			}
			if spec.Unique && nullable {
				for n, fn := range spec.Fields {
					f, _ := m.Field(fn)
					idx.Partial = append(idx.Partial, MongoPartial{Key: idx.Keys[n], Types: MongoBSONTypes(f)})
				}
			}
			c.Indexes = append(c.Indexes, idx)
		}
		// Step 2: TTL on expiresAt
		if f, ok := m.Field("expiresAt"); ok && ttlModels[m.Name()] && !opts.NoTTL && f.Type == schema.Date {
			zero := int32(0)
			found := false
			for n := range c.Indexes {
				if len(c.Indexes[n].Fields) == 1 && c.Indexes[n].Fields[0] == "expiresAt" && !c.Indexes[n].Unique {
					c.Indexes[n].ExpireAfterSeconds = &zero
					found = true
				}
			}
			if !found {
				c.Indexes = append(c.Indexes, MongoIndex{
					Name: schema.IndexName(m.Table(), "expires_at"), Keys: []string{MongoField(reg, f)}, Fields: []string{"expiresAt"},
					ExpireAfterSeconds: &zero,
				})
			}
		}
		out = append(out, c)
	}
	return out
}

// Mongo returns the collections and indexes of reg as indented JSON (MongoCollections with TTL indexes), for
// ops scripts and reviews; the mongo adapter's migrator creates exactly these.
func Mongo(reg *schema.Registry) (string, error) {
	b, err := json.MarshalIndent(MongoCollections(reg, MongoOptions{}), "", "  ")
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}
