// Package mongoadapter is the MongoDB adapter.Backend (doc 04 §5.3), on the official driver
// (go.mongodb.org/mongo-driver/v2). It follows better-auth's mongodb adapter:
//
//   - one collection per model (the registry's table name), documents keyed by the registry's field names
//     in camelCase whatever GoAuth.ColumnCase says (explicit renames are kept), the primary key in "_id";
//
//   - ids are ObjectIds by default, exposed as 24-character hex strings ("id"); fields referencing an id
//     (session.userId, ...) are stored as ObjectIds too. Ids that aren't ObjectId hex strings (an explicit
//     id, a custom generator) are stored as strings. WithStringIDs stores every id as a string;
//
//   - Where becomes a filter: escaped $regex for contains / starts_with / ends_with, the "i" option for
//     case-insensitive comparisons, SQL's NULL semantics for ne / not_in;
//
//   - UpdateMany and DeleteMany report counts, so compare-and-swap and atomic consume work;
//
//   - transactions use sessions when the deployment supports them (replica set, sharded cluster); on a
//     standalone server Transaction runs fn without atomicity and logs a warning once;
//
//   - duplicate keys (E11000) become *adapter.UniqueError;
//
//   - the Migrator creates collections and indexes from the registry (src/schema/render MongoCollections):
//     partial unique indexes for optional unique fields and TTL indexes on verification.expiresAt and
//     session.expiresAt; the Introspector reads them back with listIndexes.
//
//     client, _ := mongo.Connect(options.Client().ApplyURI(uri))
//     auth, err := goauth.SetupGoAuth(ctx, api, goauth.GoAuthOptions{
//     AuthConfig: cfg,
//     Adapter:    mongoadapter.New(client.Database("app")),
//     })
package mongoadapter

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/schema/render"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Option configures New.
type Option func(*config)

type config struct {
	stringIDs bool
	noTTL     bool
}

// WithStringIDs stores ids and references as strings instead of ObjectIds (and generates no ObjectIds):
// use it to keep ids from a SQL database or a custom generator.
func WithStringIDs() Option { return func(c *config) { c.stringIDs = true } }

// WithoutTTL leaves out the TTL indexes on verification.expiresAt and session.expiresAt.
func WithoutTTL() Option { return func(c *config) { c.noTTL = true } }

// txState is shared by every binding of one backend: whether the deployment supports transactions, and
// the once-only warning when it doesn't.
type txState struct {
	once      sync.Once
	supported bool
	warn      sync.Once
}

// Backend is the MongoDB implementation of adapter.Backend. New returns it unbound (an adapter.Binder);
// Bind returns the adapter for a registry.
type Backend struct {
	db  *mongo.Database
	cfg config
	tx  *txState
	// set by Bind
	reg    *schema.Registry
	tables map[string]*table
}

// table maps the columns of one model to document keys.
type table struct {
	model   *schema.ResolvedModel
	keys    map[string]string // column → document key
	columns map[string]string // document key → column
	ids     map[string]bool   // columns holding an id
}

var (
	_ adapter.Backend             = (*Backend)(nil)
	_ adapter.Binder              = (*Backend)(nil)
	_ adapter.IDInserter          = (*Backend)(nil)
	_ adapter.IDGeneratorProvider = (*Backend)(nil)
	_ adapter.Introspector        = (*Backend)(nil)
	_ adapter.Migrator            = (*Backend)(nil)
)

// New returns an unbound backend on db; pass it as GoAuthOptions.Adapter, or Bind it to a registry.
func New(db *mongo.Database, opts ...Option) *Backend {
	b := &Backend{db: db, tx: &txState{}}
	for _, o := range opts {
		o(&b.cfg)
	}
	return b
}

// NewAdapter returns the adapter for reg on db (New + Bind).
func NewAdapter(db *mongo.Database, reg *schema.Registry, opts ...Option) (adapter.Adapter, error) {
	return New(db, opts...).Bind(reg)
}

// NewObjectIDHex returns a new ObjectId as a hex string (the default id generator).
func NewObjectIDHex() string { return bson.NewObjectID().Hex() }

// DefaultIDGenerator returns NewObjectIDHex, or nil with WithStringIDs (adapter.IDGeneratorProvider).
func (b *Backend) DefaultIDGenerator() func() string {
	if b.cfg.stringIDs {
		return nil
	}
	return NewObjectIDHex
}

// Bind returns the adapter for reg (adapter.Binder). Ids are ObjectId hex strings unless opts (or
// WithStringIDs) say otherwise; the serial id strategy is not supported.
func (b *Backend) Bind(reg *schema.Registry, opts ...adapter.Option) (adapter.Adapter, error) {
	if reg.IDStrategy() == schema.IDSerial {
		return nil, errors.New("mongoadapter: the serial id strategy needs a SQL database (use the default ObjectIds or IDFormat database)")
	}
	// Step 1: a bound copy with the column ↔ key maps of every model
	nb := &Backend{db: b.db, cfg: b.cfg, tx: b.tx, reg: reg, tables: map[string]*table{}}
	for _, m := range reg.Models() {
		t := &table{model: m, keys: map[string]string{}, columns: map[string]string{}, ids: map[string]bool{}}
		for _, f := range m.Fields() {
			key := render.MongoField(reg, f)
			t.keys[f.Column] = key
			t.columns[key] = f.Column
			t.ids[f.Column] = f.HoldsID()
		}
		nb.tables[m.Table()] = t
	}
	// Step 2: ObjectId ids by default; options passed in (e.g. the application's generator) win
	if gen := nb.DefaultIDGenerator(); gen != nil {
		opts = append([]adapter.Option{adapter.WithIDGenerator(gen)}, opts...)
	}
	return adapter.New(reg, nb, opts...), nil
}

// Database returns the database.
func (b *Backend) Database() *mongo.Database { return b.db }

// ID returns "mongo".
func (b *Backend) ID() string { return "mongo" }

// Capabilities: arrays, dates and booleans are native BSON; JSON is stored as text (better-auth's
// supportsJSON: false).
func (b *Backend) Capabilities() adapter.Capabilities {
	return adapter.Capabilities{Arrays: true, Dates: true, Booleans: true}
}

// table returns the mapping of a table (the backend must be bound).
func (b *Backend) table(name string) (*table, error) {
	if b.tables == nil {
		return nil, errors.New("mongoadapter: the backend is not bound to a schema registry (use Bind or NewAdapter)")
	}
	t, ok := b.tables[name]
	if !ok {
		return nil, fmt.Errorf("mongoadapter: no model for collection %q", name)
	}
	return t, nil
}

// ─── values ──────────────────────────────────────────────────────────────────

// storeID turns an id (or a reference to one) into its stored form: an ObjectId for ObjectId hex strings.
func (b *Backend) storeID(v any) any {
	if s, ok := v.(string); ok && !b.cfg.stringIDs {
		if oid, err := bson.ObjectIDFromHex(s); err == nil {
			return oid
		}
	}
	return v
}

// value converts a storage value of column to its BSON form.
func (b *Backend) value(t *table, column string, v any) any {
	if t.ids[column] {
		return b.storeID(v)
	}
	return v
}

// toDoc converts a row to a document.
func (b *Backend) toDoc(t *table, row adapter.Row) bson.D {
	doc := make(bson.D, 0, len(row))
	for col, v := range row {
		doc = append(doc, bson.E{Key: t.keys[col], Value: b.value(t, col, v)})
	}
	return doc
}

// fromDoc converts a document to a row (keys the registry doesn't know are ignored).
func fromDoc(t *table, doc bson.M) adapter.Row {
	row := adapter.Row{}
	for k, v := range doc {
		if col, ok := t.columns[k]; ok {
			row[col] = plain(v)
		}
	}
	return row
}

// plain converts BSON values to the Go values the factory decodes.
func plain(v any) any {
	switch x := v.(type) {
	case bson.ObjectID:
		return x.Hex()
	case bson.DateTime:
		return x.Time().UTC()
	case int32:
		return int64(x)
	case bson.A:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = plain(e)
		}
		return out
	case bson.D:
		m := make(map[string]any, len(x))
		for _, e := range x {
			m[e.Key] = plain(e.Value)
		}
		return m
	case bson.M:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[k] = plain(e)
		}
		return m
	}
	return v
}

// ─── filters ─────────────────────────────────────────────────────────────────

// filter translates conditions: (every And condition) AND (any Or condition).
func (b *Backend) filter(t *table, cs []adapter.Cond) bson.D {
	var and, or bson.A
	for _, c := range cs {
		if c.Connector == adapter.Or {
			or = append(or, b.cond(t, c))
		} else {
			and = append(and, b.cond(t, c))
		}
	}
	if len(or) > 0 {
		and = append(and, bson.D{{Key: "$or", Value: or}})
	}
	if len(and) == 0 {
		return bson.D{}
	}
	return bson.D{{Key: "$and", Value: and}}
}

// regex returns an anchored, escaped, optionally case-insensitive pattern.
func regex(prefix, value, suffix string, insensitive bool) bson.Regex {
	opts := ""
	if insensitive {
		opts = "i"
	}
	return bson.Regex{Pattern: prefix + regexp.QuoteMeta(value) + suffix, Options: opts}
}

// cond translates one condition. Like SQL, comparisons never match missing or null values.
func (b *Backend) cond(t *table, c adapter.Cond) bson.D {
	key := t.keys[c.Column]
	one := func(v any) bson.D { return bson.D{{Key: key, Value: v}} }
	// Step 1: NULL tests (a missing key is null)
	if c.Value == nil && (c.Op == adapter.Eq || c.Op == adapter.Ne) {
		if c.Op == adapter.Eq {
			return one(nil)
		}
		return one(bson.D{{Key: "$ne", Value: nil}})
	}
	// Step 2: case-insensitive comparisons on strings (never on ids, like better-auth)
	insensitive := c.Insensitive && c.Type == schema.String && !t.ids[c.Column]
	switch c.Op {
	case adapter.Eq:
		if s, ok := c.Value.(string); ok && insensitive {
			return one(regex("^", s, "$", true))
		}
		return one(b.value(t, c.Column, c.Value))
	case adapter.Ne:
		if s, ok := c.Value.(string); ok && insensitive {
			return one(bson.D{{Key: "$not", Value: regex("^", s, "$", true)}, {Key: "$ne", Value: nil}})
		}
		return one(bson.D{{Key: "$nin", Value: bson.A{b.value(t, c.Column, c.Value), nil}}})
	case adapter.Lt, adapter.Lte, adapter.Gt, adapter.Gte:
		return one(bson.D{{Key: "$" + string(c.Op), Value: b.value(t, c.Column, c.Value)}})
	case adapter.In, adapter.NotIn:
		// Step 3: lists; NULL elements never match, an empty not_in matches every non-null value
		vals := bson.A{}
		list, _ := c.Value.([]any)
		for _, v := range list {
			if v == nil {
				continue
			}
			if s, ok := v.(string); ok && insensitive {
				vals = append(vals, regex("^", s, "$", true))
				continue
			}
			vals = append(vals, b.value(t, c.Column, v))
		}
		if c.Op == adapter.In {
			return one(bson.D{{Key: "$in", Value: vals}})
		}
		return one(bson.D{{Key: "$nin", Value: append(vals, nil)}})
	case adapter.Contains:
		return one(regex("", fmt.Sprint(c.Value), "", c.Insensitive))
	case adapter.StartsWith:
		return one(regex("^", fmt.Sprint(c.Value), "", c.Insensitive))
	case adapter.EndsWith:
		return one(regex("", fmt.Sprint(c.Value), "$", c.Insensitive))
	}
	return bson.D{}
}

// ─── CRUD ────────────────────────────────────────────────────────────────────

// Insert adds one document.
func (b *Backend) Insert(ctx context.Context, name string, row adapter.Row) error {
	t, err := b.table(name)
	if err != nil {
		return err
	}
	_, err = b.db.Collection(name).InsertOne(ctx, b.toDoc(t, row))
	return translate(t, err)
}

// InsertReturningID inserts a document without an id and returns the id MongoDB generated as a hex string
// (adapter.IDInserter, id strategy database). With WithStringIDs the id is a new ObjectId's hex string.
func (b *Backend) InsertReturningID(ctx context.Context, name string, row adapter.Row, idColumn string, _ bool) (any, error) {
	t, err := b.table(name)
	if err != nil {
		return nil, err
	}
	doc := b.toDoc(t, row)
	if b.cfg.stringIDs {
		doc = append(doc, bson.E{Key: render.MongoIDKey, Value: NewObjectIDHex()})
	}
	res, err := b.db.Collection(name).InsertOne(ctx, doc)
	if err != nil {
		return nil, translate(t, err)
	}
	return plain(res.InsertedID), nil
}

// Select returns the matching documents.
func (b *Backend) Select(ctx context.Context, name string, q adapter.Select) ([]adapter.Row, error) {
	t, err := b.table(name)
	if err != nil {
		return nil, err
	}
	// Step 1: sort, limit, skip, projection
	opts := options.Find()
	if len(q.Order) > 0 {
		sort := bson.D{}
		for _, o := range q.Order {
			dir := 1
			if o.Desc {
				dir = -1
			}
			sort = append(sort, bson.E{Key: t.keys[o.Column], Value: dir})
		}
		opts.SetSort(sort)
	}
	if q.Limit > 0 {
		opts.SetLimit(int64(q.Limit))
	}
	if q.Offset > 0 {
		opts.SetSkip(int64(q.Offset))
	}
	if len(q.Columns) > 0 {
		proj := bson.D{}
		for _, c := range q.Columns {
			proj = append(proj, bson.E{Key: t.keys[c], Value: 1})
		}
		opts.SetProjection(proj)
	}
	// Step 2: find and convert
	cur, err := b.db.Collection(name).Find(ctx, b.filter(t, q.Where), opts)
	if err != nil {
		return nil, err
	}
	var docs []bson.M
	if err := cur.All(ctx, &docs); err != nil {
		return nil, err
	}
	out := make([]adapter.Row, len(docs))
	for i, d := range docs {
		out[i] = fromDoc(t, d)
	}
	return out, nil
}

// Count counts the matching documents.
func (b *Backend) Count(ctx context.Context, name string, where []adapter.Cond) (int64, error) {
	t, err := b.table(name)
	if err != nil {
		return 0, err
	}
	return b.db.Collection(name).CountDocuments(ctx, b.filter(t, where))
}

// Update sets fields on every matching document and returns how many matched (so a compare-and-swap
// reports 1 even when the new value equals the old one, like SQL).
func (b *Backend) Update(ctx context.Context, name string, where []adapter.Cond, set adapter.Row) (int64, error) {
	t, err := b.table(name)
	if err != nil {
		return 0, err
	}
	res, err := b.db.Collection(name).UpdateMany(ctx, b.filter(t, where), bson.D{{Key: "$set", Value: b.toDoc(t, set)}})
	if err != nil {
		return 0, translate(t, err)
	}
	return res.MatchedCount, nil
}

// Delete removes every matching document and returns how many were removed.
func (b *Backend) Delete(ctx context.Context, name string, where []adapter.Cond) (int64, error) {
	t, err := b.table(name)
	if err != nil {
		return 0, err
	}
	res, err := b.db.Collection(name).DeleteMany(ctx, b.filter(t, where))
	if err != nil {
		return 0, err
	}
	return res.DeletedCount, nil
}

// ─── transactions ────────────────────────────────────────────────────────────

// SupportsTransactions reports whether the deployment runs transactions (a replica set or a sharded
// cluster). The answer is asked once, with the hello command.
func (b *Backend) SupportsTransactions(ctx context.Context) bool {
	b.tx.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		var hello struct {
			SetName string `bson:"setName"`
			Msg     string `bson:"msg"`
		}
		if err := b.db.Client().Database("admin").RunCommand(ctx, bson.D{{Key: "hello", Value: 1}}).Decode(&hello); err != nil {
			return
		}
		b.tx.supported = hello.SetName != "" || hello.Msg == "isdbgrid"
	})
	return b.tx.supported
}

// Transaction runs fn in a MongoDB transaction: calls made with the ctx passed to fn use its session. A
// session already in ctx (an outer Transaction, or the application's mongo.NewSessionContext) is joined.
// Without transaction support fn runs without atomicity and a warning is logged once (better-auth).
func (b *Backend) Transaction(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	if mongo.SessionFromContext(ctx) != nil {
		return fn(ctx)
	}
	// Step 1: standalone servers have no transactions
	if !b.SupportsTransactions(ctx) {
		b.tx.warn.Do(func() {
			logger.Warn("mongoadapter: this MongoDB deployment doesn't support transactions (it isn't a replica set " +
				"or sharded cluster); goauth's multi-step writes run without atomicity")
		})
		return fn(ctx)
	}
	// Step 2: a session with a transaction
	sess, err := b.db.Client().StartSession()
	if err != nil {
		return err
	}
	defer sess.EndSession(context.WithoutCancel(ctx))
	if err := sess.StartTransaction(); err != nil {
		return err
	}
	// Step 3: abort on error or panic, commit otherwise
	defer func() {
		if p := recover(); p != nil {
			_ = sess.AbortTransaction(context.WithoutCancel(ctx))
			panic(p)
		}
	}()
	if err := fn(mongo.NewSessionContext(ctx, sess)); err != nil {
		_ = sess.AbortTransaction(context.WithoutCancel(ctx))
		return err
	}
	return sess.CommitTransaction(ctx)
}

// ─── errors ──────────────────────────────────────────────────────────────────

// dupKeyRe finds the keys of E11000's "dup key: { a: "x", b: 1 }".
var (
	dupKeyRe   = regexp.MustCompile(`dup key: \{(.*)\}`)
	dupFieldRe = regexp.MustCompile(`(?:^|,)\s*([A-Za-z0-9_.$]+):`)
)

// translate turns a duplicate-key error (E11000) into *adapter.UniqueError with the index's columns.
func translate(t *table, err error) error {
	if err == nil || !mongo.IsDuplicateKeyError(err) {
		return err
	}
	ue := &adapter.UniqueError{Err: err}
	if m := dupKeyRe.FindStringSubmatch(err.Error()); m != nil {
		for _, f := range dupFieldRe.FindAllStringSubmatch(m[1], -1) {
			if col, ok := t.columns[f[1]]; ok {
				ue.Columns = append(ue.Columns, col)
			}
		}
	}
	return ue
}
