package core_migration

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/better-go-auth/goauth/src/models"
)

// TestMigrateNullsEmptyUsernames upgrades a database where username was a plain column holding "" for
// users without a username, and checks the unique username index can then be created.
func TestMigrateNullsEmptyUsernames(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:uname_%s?mode=memory&cache=shared", uuid.NewString())), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	// Step 1: current schema, then drop the unique index to simulate the legacy column
	if err := NewGORMAdminMigrator(db).Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrator().DropIndex(&models.User{}, "Username"); err != nil {
		t.Fatal(err)
	}
	// Step 2: two legacy users stored with username = ""
	for _, id := range []string{"u1", "u2"} {
		u := &models.User{Base: models.Base{ID: id}}
		u.Email, u.Name = id+"@example.com", id
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
		if err := db.Model(&models.User{}).Where("id = ?", id).UpdateColumn("username", "").Error; err != nil {
			t.Fatal(err)
		}
	}
	// Step 3: migrating again turns "" into NULL and restores the unique index
	if err := NewGORMAdminMigrator(db).Migrate(ctx); err != nil {
		t.Fatalf("migrate with legacy empty usernames: %v", err)
	}
	var empty int64
	if err := db.Model(&models.User{}).Where("username = ?", "").Count(&empty).Error; err != nil {
		t.Fatal(err)
	}
	if empty != 0 {
		t.Fatalf("%d users still have an empty username", empty)
	}
	if !db.Migrator().HasIndex(&models.User{}, "Username") {
		t.Fatal("the unique username index must exist")
	}
	// Step 4: the index is unique
	name := "alice"
	if err := db.Model(&models.User{}).Where("id = ?", "u1").UpdateColumn("username", name).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Model(&models.User{}).Where("id = ?", "u2").UpdateColumn("username", name).Error; err == nil {
		t.Fatal("duplicate usernames must be rejected")
	}
}
