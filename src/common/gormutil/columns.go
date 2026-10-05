package gormutil

import (
	"fmt"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Col resolves the column of Go field `field` on model through the model's gorm tags,
// so queries never spell column names and follow any column renaming.
func Col(db *gorm.DB, model any, field string) clause.Column {
	stmt := &gorm.Statement{DB: db}
	if err := stmt.Parse(model); err != nil {
		panic(fmt.Sprintf("gormutil: parse %T: %v", model, err))
	}
	f := stmt.Schema.LookUpField(field)
	if f == nil {
		panic(fmt.Sprintf("gormutil: %T has no field %q", model, field))
	}
	return clause.Column{Name: f.DBName}
}

// ColNames returns the column names of the given Go fields on model.
func ColNames(db *gorm.DB, model any, fields ...string) []string {
	names := make([]string, len(fields))
	for i, f := range fields {
		names[i] = Col(db, model, f).Name
	}
	return names
}

// OrderBy orders by the column of Go field `field` on model.
func OrderBy(db *gorm.DB, model any, field string, desc bool) clause.OrderByColumn {
	return clause.OrderByColumn{Column: Col(db, model, field), Desc: desc}
}

// ILike matches the column of Go field `field` case-insensitively against a LIKE pattern.
func ILike(db *gorm.DB, model any, field, pattern string) clause.Expression {
	return clause.Expr{SQL: "LOWER(?) LIKE LOWER(?)", Vars: []any{Col(db, model, field), pattern}}
}

// IEq matches the column of Go field `field` case-insensitively.
func IEq(db *gorm.DB, model any, field, value string) clause.Expression {
	return clause.Expr{SQL: "LOWER(?) = LOWER(?)", Vars: []any{Col(db, model, field), value}}
}
