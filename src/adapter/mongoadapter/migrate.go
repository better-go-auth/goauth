package mongoadapter

import (
	"context"
	"errors"
	"fmt"

	"github.com/better-go-auth/goauth/src/schema"
	"github.com/better-go-auth/goauth/src/schema/render"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Inspect reads every collection of the database with its indexes (adapter.Introspector). Collections have
// no columns; index columns are document keys.
func (b *Backend) Inspect(ctx context.Context) (*schema.Snapshot, error) {
	names, err := b.db.ListCollectionNames(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	return b.InspectCollections(ctx, names...)
}

// InspectCollections reads the given collections (those that exist) with their indexes.
func (b *Backend) InspectCollections(ctx context.Context, names ...string) (*schema.Snapshot, error) {
	// Step 1: which collections exist
	existing, err := b.db.ListCollectionNames(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, n := range existing {
		have[n] = true
	}
	// Step 2: their indexes
	snap := &schema.Snapshot{}
	for _, name := range names {
		if !have[name] {
			continue
		}
		cur, err := b.db.Collection(name).Indexes().List(ctx)
		if err != nil {
			return nil, fmt.Errorf("mongoadapter: indexes of %s: %w", name, err)
		}
		var specs []struct {
			Name   string `bson:"name"`
			Key    bson.D `bson:"key"`
			Unique bool   `bson:"unique"`
		}
		if err := cur.All(ctx, &specs); err != nil {
			return nil, err
		}
		t := schema.TableSnapshot{Name: name}
		for _, s := range specs {
			idx := schema.IndexSnapshot{Name: s.Name, Unique: s.Unique, Primary: s.Name == "_id_"}
			for _, k := range s.Key {
				idx.Columns = append(idx.Columns, k.Key)
			}
			t.Indexes = append(t.Indexes, idx)
		}
		snap.Tables = append(snap.Tables, t)
	}
	return snap, nil
}

// Plan returns the collections and indexes of reg the database lacks (adapter.Migrator). Documents need no
// columns, so a plan only has AddTable and AddIndex changes; an index counts as present when an index over
// the same keys exists (whatever its name and options).
func (b *Backend) Plan(ctx context.Context, reg *schema.Registry) (*schema.Plan, error) {
	// Step 1: inspect the registry's collections
	cols := render.MongoCollections(reg, render.MongoOptions{NoTTL: b.cfg.noTTL})
	names := make([]string, len(cols))
	for i, c := range cols {
		names[i] = c.Name
	}
	snap, err := b.InspectCollections(ctx, names...)
	if err != nil {
		return nil, err
	}
	// Step 2: missing collections, then missing indexes
	plan := &schema.Plan{Registry: reg}
	var indexes []schema.Change
	for _, c := range cols {
		t, ok := snap.Table(c.Name)
		if !ok {
			plan.Changes = append(plan.Changes, schema.Change{Kind: schema.AddTable, Model: c.Model, Table: c.Name})
		}
		for _, idx := range c.Indexes {
			if ok && t.HasIndex(idx.Keys, idx.Unique) {
				continue
			}
			indexes = append(indexes, schema.Change{Kind: schema.AddIndex, Model: c.Model, Table: c.Name, Index: schema.IndexSpec{
				Name: idx.Name, Fields: idx.Fields, Columns: idx.Keys, Unique: idx.Unique,
			}})
		}
	}
	plan.Changes = append(plan.Changes, indexes...)
	return plan, nil
}

// Apply creates the collections and indexes of plan (adapter.Migrator); indexes get their partial filter
// and TTL options from render.MongoCollections. Nothing is ever dropped.
func (b *Backend) Apply(ctx context.Context, plan *schema.Plan) error {
	if plan.Empty() {
		return nil
	}
	// Step 1: the index definitions by collection and name
	defs := map[string]render.MongoIndex{}
	for _, c := range render.MongoCollections(plan.Registry, render.MongoOptions{NoTTL: b.cfg.noTTL}) {
		for _, idx := range c.Indexes {
			defs[c.Name+"\x00"+idx.Name] = idx
		}
	}
	for _, c := range plan.Changes {
		switch c.Kind {
		case schema.AddTable:
			// Step 2: collections (one created concurrently is fine)
			err := b.db.CreateCollection(ctx, c.Table)
			var ce mongo.CommandError
			if err != nil && !(errors.As(err, &ce) && ce.Code == 48) {
				return fmt.Errorf("goauth migrations: create collection %s: %w", c.Table, err)
			}
		case schema.AddIndex:
			// Step 3: indexes
			idx, ok := defs[c.Table+"\x00"+c.Index.Name]
			if !ok {
				return fmt.Errorf("goauth migrations: no index %s on %s in the registry", c.Index.Name, c.Table)
			}
			if _, err := b.db.Collection(c.Table).Indexes().CreateOne(ctx, indexModel(idx)); err != nil {
				return fmt.Errorf("goauth migrations: create index %s on %s: %w", idx.Name, c.Table, err)
			}
		default:
			return fmt.Errorf("goauth migrations: mongoadapter can't apply %s", c)
		}
	}
	return nil
}

// indexModel turns a rendered index into the driver's model.
func indexModel(idx render.MongoIndex) mongo.IndexModel {
	keys := bson.D{}
	for _, k := range idx.Keys {
		keys = append(keys, bson.E{Key: k, Value: 1})
	}
	opts := options.Index().SetName(idx.Name)
	if idx.Unique {
		opts.SetUnique(true)
	}
	if len(idx.Partial) > 0 {
		filter := bson.D{}
		for _, p := range idx.Partial {
			var types any = p.Types[0]
			if len(p.Types) > 1 {
				types = p.Types
			}
			filter = append(filter, bson.E{Key: p.Key, Value: bson.D{{Key: "$type", Value: types}}})
		}
		opts.SetPartialFilterExpression(filter)
	}
	if idx.ExpireAfterSeconds != nil {
		opts.SetExpireAfterSeconds(*idx.ExpireAfterSeconds)
	}
	return mongo.IndexModel{Keys: keys, Options: opts}
}
