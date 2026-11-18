package adapter

import (
	"context"
	"errors"
)

// FindOneJoined loads the first record of model matching where together with related records: each Join
// stores its result under the join's Model key (a Record or nil, or []Record when Many). It uses the
// adapter's Joiner capability when there is one and otherwise runs one query per join, like better-auth's
// fallback join.
func FindOneJoined(ctx context.Context, a Adapter, model string, where []Where, joins []Join) (Record, error) {
	if j, ok := a.(Joiner); ok {
		return j.FindOneJoined(ctx, model, where, joins)
	}
	// Step 1: the base record
	base, err := a.FindOne(ctx, model, where)
	if err != nil {
		return nil, err
	}
	// Step 2: one query per join on RefField = base[Field]
	for _, j := range joins {
		cond := []Where{{Field: j.RefField, Value: base[j.Field]}}
		if !j.Many {
			rel, err := a.FindOne(ctx, j.Model, cond)
			if errors.Is(err, ErrNotFound) {
				base[j.Model] = nil
				continue
			}
			if err != nil {
				return nil, err
			}
			base[j.Model] = rel
			continue
		}
		limit := j.Limit
		if limit <= 0 {
			limit = 100
		}
		rels, err := a.FindMany(ctx, j.Model, Query{Where: cond, Limit: limit})
		if err != nil {
			return nil, err
		}
		base[j.Model] = rels
	}
	return base, nil
}
