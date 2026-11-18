package schema

import (
	"fmt"
	"strings"
)

// IDStrategy decides who creates primary keys (better-auth's advanced.database.generateId).
type IDStrategy string

const (
	// IDApplication is the default: goauth (or the configured generator) creates string IDs before insert.
	// The id column and every column referencing it are text.
	IDApplication IDStrategy = "application"
	// IDDatabase is better-auth's `generateId: false`: the database creates the id. Generated DDL gives the
	// id column a database default (a UUID on Postgres and MySQL, random hex on SQLite) that may be replaced
	// by any other default; the adapter reads the new id back after the insert.
	IDDatabase IDStrategy = "database"
	// IDSerial is better-auth's `generateId: "serial"`: auto-increment integer ids. The id column and every
	// column referencing an id (session.userId, ...) are integers; Go code still sees the ids as strings.
	IDSerial IDStrategy = "serial"
)

// normalize returns the effective strategy ("" = IDApplication) or an error for unknown values.
func (s IDStrategy) normalize() (IDStrategy, error) {
	switch IDStrategy(strings.ToLower(string(s))) {
	case "", IDApplication:
		return IDApplication, nil
	case IDDatabase:
		return IDDatabase, nil
	case IDSerial:
		return IDSerial, nil
	}
	return "", fmt.Errorf("schema: unknown id strategy %q (use %q, %q or %q)", s, IDApplication, IDDatabase, IDSerial)
}

// DatabaseGenerated reports whether the database creates ids (IDDatabase or IDSerial).
func (s IDStrategy) DatabaseGenerated() bool { return s == IDDatabase || s == IDSerial }

// HoldsID reports whether the field stores a record id: the primary key, or a reference to another
// model's id (better-auth's `references.field === "id"`). Under IDSerial these fields are integers.
func (f Field) HoldsID() bool {
	return f.Type == ID || (f.References != nil && f.References.Field == "id")
}
