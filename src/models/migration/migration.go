package migration

import "context"

// IMigrator defines the interface for running auth schema migrations.
// Implement this for any database or ORM.
type IMigrator interface {
	// Migrate runs all pending migrations to create/update auth tables.
	Migrate(ctx context.Context) error
}
