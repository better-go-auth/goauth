package core_migration

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	"github.com/better-go-auth/goauth/src/models"
)

// TestMigrateDropsUserProviderIndex upgrades a database created with the legacy unique
// (user_id, provider_id) index and checks two accounts of one provider can then be linked.
func TestMigrateDropsUserProviderIndex(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:acc_%s?mode=memory&cache=shared", uuid.NewString())), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	// Step 1: current schema plus the legacy index
	if err := NewGORMAdminMigrator(db).Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE UNIQUE INDEX idx_user_provider ON ? (user_id, provider_id)", clause.Table{Name: models.ResolveTableName(db.NamingStrategy, models.ModelAccount)}).Error; err != nil {
		t.Fatal(err)
	}
	// Step 2: migrating again drops it
	if err := NewGORMAdminMigrator(db).Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if db.Migrator().HasIndex(&models.Account{}, "idx_user_provider") {
		t.Fatal("idx_user_provider must be dropped")
	}
	// Step 3: two GitHub accounts for one user
	for _, id := range []string{"gh-1", "gh-2"} {
		if err := db.Create(&models.Account{UserID: "u1", AccountID: id, ProviderID: models.ProvGithub}).Error; err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
}
