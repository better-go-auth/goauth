package sqladapter

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/schema"
)

// builder collects the arguments of one statement and renders placeholders and conditions for a dialect.
type builder struct {
	d    Dialect
	args []any
}

func (b *Backend) builder() *builder { return &builder{d: b.d} }

// arg adds an argument and returns its placeholder: $n on Postgres, ? elsewhere.
func (q *builder) arg(v any) string {
	q.args = append(q.args, v)
	if q.d == Postgres {
		return "$" + strconv.Itoa(len(q.args))
	}
	return "?"
}

// where renders (every And condition) AND (any Or condition); "" when there are none.
func (q *builder) where(cs []adapter.Cond) string {
	var and, or []string
	for _, c := range cs {
		if c.Connector == adapter.Or {
			or = append(or, q.cond(c))
		} else {
			and = append(and, q.cond(c))
		}
	}
	if len(or) > 0 {
		and = append(and, "("+strings.Join(or, " OR ")+")")
	}
	return strings.Join(and, " AND ")
}

// cond renders one condition.
func (q *builder) cond(c adapter.Cond) string {
	col := q.d.Quote(c.Column)
	// Step 1: NULL tests
	if c.Value == nil && (c.Op == adapter.Eq || c.Op == adapter.Ne) {
		if c.Op == adapter.Eq {
			return col + " IS NULL"
		}
		return col + " IS NOT NULL"
	}
	// Step 2: case-insensitive comparisons lower both sides (strings only)
	lower := c.Insensitive && (c.Type == schema.String || c.Type == schema.ID)
	if lower && (c.Op == adapter.Eq || c.Op == adapter.Ne) {
		op := "="
		if c.Op == adapter.Ne {
			op = "<>"
		}
		return fmt.Sprintf("LOWER(%s) %s LOWER(%s)", col, op, q.arg(c.Value))
	}
	switch c.Op {
	case adapter.Eq:
		return col + " = " + q.arg(c.Value)
	case adapter.Ne:
		return col + " <> " + q.arg(c.Value)
	case adapter.Lt:
		return col + " < " + q.arg(c.Value)
	case adapter.Lte:
		return col + " <= " + q.arg(c.Value)
	case adapter.Gt:
		return col + " > " + q.arg(c.Value)
	case adapter.Gte:
		return col + " >= " + q.arg(c.Value)
	case adapter.In, adapter.NotIn:
		return q.in(col, c, lower)
	case adapter.Contains, adapter.StartsWith, adapter.EndsWith:
		return q.like(col, c)
	}
	return "1 = 1"
}

// in renders IN / NOT IN. Empty lists are constant (SQL has no empty IN list); NULL elements never match.
func (q *builder) in(col string, c adapter.Cond, lower bool) string {
	var vals []any
	list, _ := c.Value.([]any)
	for _, v := range list {
		if v != nil {
			vals = append(vals, v)
		}
	}
	if len(vals) == 0 {
		if c.Op == adapter.In {
			return "1 = 0"
		}
		return col + " IS NOT NULL"
	}
	marks := make([]string, len(vals))
	for i, v := range vals {
		if s, ok := v.(string); ok && lower {
			v = strings.ToLower(s)
		}
		marks[i] = q.arg(v)
	}
	if lower {
		col = "LOWER(" + col + ")"
	}
	op := " IN "
	if c.Op == adapter.NotIn {
		op = " NOT IN "
	}
	return col + op + "(" + strings.Join(marks, ", ") + ")"
}

// like renders an escaped pattern match. Case-insensitive patterns lower both sides; case-sensitive ones
// need a binary comparison on MySQL and GLOB on SQLite, whose LIKE ignores case.
func (q *builder) like(col string, c adapter.Cond) string {
	s := fmt.Sprint(c.Value)
	if c.Insensitive {
		return fmt.Sprintf("LOWER(%s) LIKE LOWER(%s) ESCAPE '!'", col, q.arg(adapter.LikePattern(c.Op, s)))
	}
	switch q.d {
	case SQLite:
		return fmt.Sprintf("%s GLOB %s", col, q.arg(globPattern(c.Op, s)))
	case MySQL:
		return fmt.Sprintf("CAST(%s AS BINARY) LIKE CAST(%s AS BINARY) ESCAPE '!'", col, q.arg(adapter.LikePattern(c.Op, s)))
	}
	return fmt.Sprintf("%s LIKE %s ESCAPE '!'", col, q.arg(adapter.LikePattern(c.Op, s)))
}

// globPattern builds a SQLite GLOB pattern: the metacharacters * ? [ in value match themselves.
func globPattern(op adapter.Op, value string) string {
	esc := strings.NewReplacer("[", "[[]", "*", "[*]", "?", "[?]").Replace(value)
	switch op {
	case adapter.StartsWith:
		return esc + "*"
	case adapter.EndsWith:
		return "*" + esc
	}
	return "*" + esc + "*"
}
