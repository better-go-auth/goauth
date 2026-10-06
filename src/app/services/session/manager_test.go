package session

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/gormauth"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	core_migration "github.com/better-go-auth/goauth/src/models/migration/core-migration"
	"github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type fixture struct {
	db   *gorm.DB
	mgr  *Manager
	user *models.User
	now  time.Time
}

func newFixture(t *testing.T, conf config.Session, withStore bool) *fixture {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:sess_%s?mode=memory&cache=shared", uuid.NewString())), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if err := core_migration.NewGORMAdminMigrator(db).Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	email := "s@example.com"
	user := &models.User{UserDto: models.UserDto{FirstName: "Sam", LastName: "Lee", Email: email, Role: "user"}}
	if err := db.Create(user).Error; err != nil {
		t.Fatal(err)
	}

	ac := config.AuthConfig{Session: conf}
	ac.SetDefaults()
	repos := gormauth.NewAuthRepos(db)
	f := &fixture{db: db, user: user, now: time.Now().UTC()}
	var mgr *Manager
	if withStore {
		store, err := memory.NewSecondaryStorage()
		if err != nil {
			t.Fatal(err)
		}
		mgr = NewManager(ac.Session, repos, repos, store, nil)
	} else {
		mgr = NewManager(ac.Session, repos, repos, nil, nil)
	}
	mgr.now = func() time.Time { return f.now }
	f.mgr = mgr
	return f
}

func (f *fixture) rows(t *testing.T) int64 {
	t.Helper()
	var n int64
	f.db.Model(&models.Session{}).Where("user_id = ?", f.user.ID).Count(&n)
	return n
}

func TestCreateGetDeleteDatabase(t *testing.T) {
	f := newFixture(t, config.Session{}, false)
	ctx := context.Background()

	sw, err := f.mgr.Create(ctx, f.user, Meta{IPAddress: "1.2.3.4", UserAgent: "go-test"}, CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sw.Session.Token) != 32 || sw.User.Name != "Sam Lee" || *sw.Session.IPAddress != "1.2.3.4" {
		t.Fatalf("unexpected session %+v", sw)
	}
	if got := time.Time(sw.Session.ExpiresAt).Sub(f.now); got != 7*24*time.Hour {
		t.Fatalf("expiresIn = %v", got)
	}

	got, err := f.mgr.Get(ctx, sw.Session.Token)
	if err != nil || got == nil || got.Session.ID != sw.Session.ID {
		t.Fatalf("get: %+v %v", got, err)
	}
	list, _ := f.mgr.List(ctx, f.user.ID)
	if len(list) != 1 {
		t.Fatalf("list = %d", len(list))
	}

	if err := f.mgr.Delete(ctx, sw.Session.Token); err != nil {
		t.Fatal(err)
	}
	if got, _ := f.mgr.Get(ctx, sw.Session.Token); got != nil || f.rows(t) != 0 {
		t.Fatal("deleted session must be gone")
	}
}

func TestExpiredSessionIsRemoved(t *testing.T) {
	f := newFixture(t, config.Session{}, false)
	ctx := context.Background()
	sw, _ := f.mgr.Create(ctx, f.user, Meta{}, CreateOptions{})

	f.now = f.now.Add(8 * 24 * time.Hour)
	if got, _ := f.mgr.Get(ctx, sw.Session.Token); got != nil {
		t.Fatal("expired session returned")
	}
	if f.rows(t) != 0 {
		t.Fatal("expired row must be deleted")
	}
}

func TestLegacyRowsAreIgnored(t *testing.T) {
	f := newFixture(t, config.Session{}, false)
	refreshHash := strings.Repeat("ab", 32) // legacy rows store a 64-hex refresh-token hash
	legacy := models.Session{Base: models.Base{ID: "legacy-id"}, Token: refreshHash, UserID: f.user.ID, ExpiresAt: f.now.Add(time.Hour)}
	if err := f.db.Create(&legacy).Error; err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{"legacy-id", refreshHash} {
		if got, _ := f.mgr.Get(context.Background(), tok); got != nil {
			t.Fatalf("legacy JWT session must not resolve as a cookie session (%s)", tok)
		}
	}
	if list, _ := f.mgr.List(context.Background(), f.user.ID); len(list) != 0 {
		t.Fatal("legacy JWT session must not be listed with its refresh hash")
	}
}

func TestSlidingRefresh(t *testing.T) {
	f := newFixture(t, config.Session{}, false)
	ctx := context.Background()
	sw, _ := f.mgr.Create(ctx, f.user, Meta{}, CreateOptions{})

	if f.mgr.ShouldRefresh(sw, false) {
		t.Fatal("fresh session must not refresh")
	}
	f.now = f.now.Add(25 * time.Hour)
	if !f.mgr.ShouldRefresh(sw, false) {
		t.Fatal("session older than updateAge must refresh")
	}
	if f.mgr.ShouldRefresh(sw, true) {
		t.Fatal("dont-remember sessions are never refreshed")
	}

	refreshed, err := f.mgr.Refresh(ctx, sw)
	if err != nil || refreshed == nil {
		t.Fatal(err)
	}
	want := f.now.Add(7 * 24 * time.Hour)
	if !time.Time(refreshed.Session.ExpiresAt).Equal(want) {
		t.Fatalf("expiresAt = %v, want %v", time.Time(refreshed.Session.ExpiresAt), want)
	}
	var row models.Session
	f.db.Where("token = ?", sw.Session.Token).Take(&row)
	if !row.ExpiresAt.Equal(want) {
		t.Fatalf("db expires_at = %v", row.ExpiresAt)
	}
	if f.mgr.ShouldRefresh(refreshed, false) {
		t.Fatal("just refreshed session must not refresh again")
	}
}

func TestDisableRefreshAndDontRemember(t *testing.T) {
	f := newFixture(t, config.Session{DisableSessionRefresh: true}, false)
	ctx := context.Background()
	sw, _ := f.mgr.Create(ctx, f.user, Meta{}, CreateOptions{DontRemember: true})
	if got := time.Time(sw.Session.ExpiresAt).Sub(f.now); got != 24*time.Hour {
		t.Fatalf("dont-remember lifetime = %v", got)
	}
	f.now = f.now.Add(23 * time.Hour)
	if f.mgr.ShouldRefresh(sw, false) {
		t.Fatal("DisableSessionRefresh must win")
	}
}

func TestFreshness(t *testing.T) {
	f := newFixture(t, config.Session{}, false)
	sw, _ := f.mgr.Create(context.Background(), f.user, Meta{}, CreateOptions{})
	if !f.mgr.IsFresh(sw) {
		t.Fatal("new session must be fresh")
	}
	f.now = f.now.Add(25 * time.Hour)
	if f.mgr.IsFresh(sw) {
		t.Fatal("session older than freshAge must not be fresh")
	}

	disabled := newFixture(t, config.Session{FreshAge: -1}, false)
	sw2, _ := disabled.mgr.Create(context.Background(), disabled.user, Meta{}, CreateOptions{})
	disabled.now = disabled.now.Add(100 * 24 * time.Hour)
	if !disabled.mgr.IsFresh(sw2) {
		t.Fatal("negative FreshAge disables the check")
	}
}

func TestSecondaryStorageOnly(t *testing.T) {
	off := false
	f := newFixture(t, config.Session{StoreSessionInDatabase: &off}, true)
	ctx := context.Background()

	a, _ := f.mgr.Create(ctx, f.user, Meta{}, CreateOptions{})
	b, _ := f.mgr.Create(ctx, f.user, Meta{}, CreateOptions{})
	if f.rows(t) != 0 {
		t.Fatal("sessions must not be written to the database")
	}
	if got, _ := f.mgr.Get(ctx, a.Session.Token); got == nil || got.User.Email != "s@example.com" {
		t.Fatalf("get from storage: %+v", got)
	}
	if list := f.mgr.activeList(ctx, f.user.ID); len(list) != 2 {
		t.Fatalf("active-sessions index = %+v", list)
	}
	if l, _ := f.mgr.List(ctx, f.user.ID); len(l) != 2 {
		t.Fatalf("list = %d", len(l))
	}

	_ = f.mgr.Delete(ctx, a.Session.Token)
	if got, _ := f.mgr.Get(ctx, a.Session.Token); got != nil {
		t.Fatal("deleted session still readable")
	}
	if list := f.mgr.activeList(ctx, f.user.ID); len(list) != 1 || list[0].Token != b.Session.Token {
		t.Fatalf("index after delete = %+v", list)
	}

	_ = f.mgr.DeleteUserSessions(ctx, f.user.ID)
	if got, _ := f.mgr.Get(ctx, b.Session.Token); got != nil {
		t.Fatal("DeleteUserSessions must revoke all")
	}
}

func TestStorageWithDatabaseFallsBackAndRecaches(t *testing.T) {
	f := newFixture(t, config.Session{}, true)
	ctx := context.Background()
	sw, _ := f.mgr.Create(ctx, f.user, Meta{}, CreateOptions{})
	if f.rows(t) != 1 {
		t.Fatal("default must also store sessions in the database")
	}
	_ = f.mgr.store.Delete(ctx, sw.Session.Token)
	if got, _ := f.mgr.Get(ctx, sw.Session.Token); got == nil {
		t.Fatal("database fallback failed")
	}
	if cached, _ := f.mgr.fromStore(ctx, sw.Session.Token); cached == nil {
		t.Fatal("session must be re-cached after a database read")
	}
}
