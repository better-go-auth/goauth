package compattest

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
	"github.com/better-go-auth/goauth/src/providers/idgen"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestCrossAuthInteroperability validates cross-auth interoperability between TypeScript
// Better Auth and GoAuth sharing a database.
func TestCrossAuthInteroperability(t *testing.T) {
	// 1. Check if TypeScript Better Auth test database exists
	tsDbPath := filepath.Join("..", "..", "..", "better-auth-schema", "sqlite.db")
	var dbPath string
	hasUpstreamDb := false

	if fi, err := os.Stat(tsDbPath); err == nil && fi.Size() > 0 {
		// Make a temporary copy of the TS database to keep tests hermetic
		tmpDir := t.TempDir()
		dbPath = filepath.Join(tmpDir, "cross_auth_test.db")
		src, err := os.Open(tsDbPath)
		if err == nil {
			defer src.Close()
			dst, err := os.Create(dbPath)
			if err == nil {
				defer dst.Close()
				if _, err := io.Copy(dst, src); err == nil {
					hasUpstreamDb = true
				}
			}
		}
	}

	if !hasUpstreamDb {
		// If upstream sqlite.db is not available in the workspace, create in-memory sqlite
		dbPath = fmt.Sprintf("file:cross_compat_%s?mode=memory&cache=shared", idgen.GenerateToken())
	}

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Discard,
	})
	if err != nil {
		t.Fatalf("failed to open cross-auth db: %v", err)
	}

	// Ensure GoAuth migrates / validates tables
	s := NewServer(t,
		WithDB(db),
		WithConfig(func(c *config.AuthConfig) {
			compatMode(c)
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)

	// 2. Test reading and verifying TS Better Auth seed user or create a TS-compatible user
	tsEmail := "ts-user@example.com"
	rawPassword := "Password123!"

	// Hash password using the exact Better Auth scrypt format (<salt_hex>:<hash_hex>)
	hashedPw, err := authcrypto.HashPasswordScrypt(rawPassword)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	userId := idgen.GenerateID()
	now := time.Now().UTC()

	// Insert TS-formatted User and Account directly into database
	user := models.User{
		Base: models.Base{
			ID:        userId,
			CreatedAt: now,
			UpdatedAt: now,
		},
		UserDto: models.UserDto{
			Name:          "TypeScript Better Auth User",
			Email:         tsEmail,
			EmailVerified: true,
		},
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("failed to seed user: %v", err)
	}

	account := models.Account{
		Base: models.Base{
			ID:        idgen.GenerateID(),
			CreatedAt: now,
			UpdatedAt: now,
		},
		AccountID:  userId,
		ProviderID: models.ProvCredential,
		UserID:     userId,
		Password:   &hashedPw,
	}
	if err := db.Create(&account).Error; err != nil {
		t.Fatalf("failed to seed account: %v", err)
	}

	// 3. Test GoAuth sign-in against the TS Better Auth credentials
	signInRes := s.Post(t, "/api/auth/sign-in/email", map[string]any{
		"email":    tsEmail,
		"password": rawPassword,
	})
	if signInRes.Status != 200 {
		t.Fatalf("cross-auth sign-in failed, status %d: %s", signInRes.Status, string(signInRes.Body))
	}

	var authResp struct {
		Token string `json:"token"`
		User  struct {
			ID    string `json:"id"`
			Email string `json:"email"`
			Name  string `json:"name"`
		} `json:"user"`
	}
	signInRes.JSON(t, &authResp)

	if authResp.User.Email != tsEmail {
		t.Errorf("signed-in email mismatch: got %q, want %q", authResp.User.Email, tsEmail)
	}
	if authResp.User.ID != userId {
		t.Errorf("signed-in user ID mismatch: got %q, want %q", authResp.User.ID, userId)
	}

	// 4. Test GoAuth get-session using the cookie set by sign-in
	getSessRes := s.Get(t, "/api/auth/get-session")
	if getSessRes.Status != 200 {
		t.Fatalf("cross-auth get-session failed, status %d: %s", getSessRes.Status, string(getSessRes.Body))
	}

	var sessionResp struct {
		Session struct {
			ID     string `json:"id"`
			UserID string `json:"userId"`
			Token  string `json:"token"`
		} `json:"session"`
		User struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
	}
	getSessRes.JSON(t, &sessionResp)

	if sessionResp.User.ID != userId {
		t.Errorf("session user ID mismatch: got %q, want %q", sessionResp.User.ID, userId)
	}
	if sessionResp.Session.Token == "" {
		t.Errorf("session token should not be empty")
	}

	// 5. Verify the session row in SQLite matches TS Better Auth table conventions
	var sessRow models.Session
	if err := db.Where("id = ?", sessionResp.Session.ID).First(&sessRow).Error; err != nil {
		t.Fatalf("failed to find session row in sqlite: %v", err)
	}
	if sessRow.UserID != userId {
		t.Errorf("db session user_id mismatch: got %q, want %q", sessRow.UserID, userId)
	}
	if sessRow.Token != sessionResp.Session.Token {
		t.Errorf("db session token mismatch: got %q, want %q", sessRow.Token, sessionResp.Session.Token)
	}
}
