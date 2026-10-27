package cookies_test

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/providers/cookies"
)

func sampleSessionWithUser() *dtos.SessionWithUser {
	now := dtos.Time(time.Now().UTC())
	exp := dtos.Time(time.Now().Add(24 * time.Hour).UTC())
	ip := "127.0.0.1"
	ua := "Go-http-client/1.1"

	return &dtos.SessionWithUser{
		Session: dtos.SessionData{
			ID:        "sess_12345",
			UserID:    "user_67890",
			Token:     "tok_abcdef123456",
			ExpiresAt: exp,
			IPAddress: &ip,
			UserAgent: &ua,
			CreatedAt: now,
			UpdatedAt: now,
		},
		User: dtos.UserResponse{
			ID:            "user_67890",
			Name:          "Test User",
			Email:         "test@example.com",
			EmailVerified: true,
			Role:          "user",
			CreatedAt:     now,
			UpdatedAt:     now,
		},
	}
}

func boolPtr(b bool) *bool { return &b }

func TestCookieCache_Strategies(t *testing.T) {
	strategies := []config.CookieCacheStrategy{
		config.CookieCacheStrategyCompact,
		config.CookieCacheStrategyJwt,
		config.CookieCacheStrategyJwe,
	}

	for _, strat := range strategies {
		t.Run(string(strat), func(t *testing.T) {
			cfg := config.AuthConfig{
				Secret:  "secret-thirty-two-chars-long-abc!",
				BaseURL: "http://127.0.0.1:8080",
				Session: config.Session{
					ExpiresIn: 7 * 24 * time.Hour,
					CookieCache: &config.CookieCache{
						Enabled:  boolPtr(true),
						MaxAge:   5 * time.Minute,
						Strategy: strat,
						Version:  "1",
					},
				},
			}
			cfg.SetDefaults()
			mgr := cookies.New(cfg)

			if !mgr.CookieCacheEnabled() {
				t.Fatalf("expected CookieCacheEnabled to be true")
			}

			sw := sampleSessionWithUser()

			// 1. Create session_data cookie
			cookie, err := mgr.CreateSessionDataCookie(sw, false)
			if err != nil {
				t.Fatalf("failed to create session_data cookie: %v", err)
			}
			if cookie.Name != mgr.Name(cookies.CookieSessionData) {
				t.Errorf("cookie name = %q, want %q", cookie.Name, mgr.Name(cookies.CookieSessionData))
			}
			if cookie.Value == "" {
				t.Fatalf("cookie value must not be empty")
			}
			if cookie.MaxAge != 300 {
				t.Errorf("cookie maxAge = %d, want 300", cookie.MaxAge)
			}

			// 2. Read back session_data
			header := fmt.Sprintf("%s=%s", cookie.Name, cookie.Value)
			readSw, err := mgr.ReadSessionData(header)
			if err != nil {
				t.Fatalf("failed to read session_data: %v", err)
			}
			if readSw.Session.ID != sw.Session.ID {
				t.Errorf("read Session.ID = %q, want %q", readSw.Session.ID, sw.Session.ID)
			}
			if readSw.Session.Token != sw.Session.Token {
				t.Errorf("read Session.Token = %q, want %q", readSw.Session.Token, sw.Session.Token)
			}
			if readSw.User.Email != sw.User.Email {
				t.Errorf("read User.Email = %q, want %q", readSw.User.Email, sw.User.Email)
			}

			// 3. Reject tampered cookie
			tamperedHeader := fmt.Sprintf("%s=%s", cookie.Name, cookie.Value+"tampered")
			if _, err := mgr.ReadSessionData(tamperedHeader); err == nil {
				t.Fatalf("tampered cookie must be rejected")
			}
		})
	}
}

func TestCookieCache_VersionInvalidation(t *testing.T) {
	cfg := config.AuthConfig{
		Secret:  "secret-thirty-two-chars-long-abc!",
		BaseURL: "http://127.0.0.1:8080",
		Session: config.Session{
			ExpiresIn: 7 * 24 * time.Hour,
			CookieCache: &config.CookieCache{
				Enabled:  boolPtr(true),
				MaxAge:   5 * time.Minute,
				Strategy: config.CookieCacheStrategyCompact,
				Version:  "1",
			},
		},
	}
	cfg.SetDefaults()
	mgr := cookies.New(cfg)

	sw := sampleSessionWithUser()
	cookie, err := mgr.CreateSessionDataCookie(sw, false)
	if err != nil {
		t.Fatal(err)
	}

	header := fmt.Sprintf("%s=%s", cookie.Name, cookie.Value)

	// Invalidate cache by bumping version to "2"
	cfg.Session.CookieCache.Version = "2"
	mgr2 := cookies.New(cfg)

	if _, err := mgr2.ReadSessionData(header); err == nil {
		t.Fatalf("expected version mismatch error")
	}
}

func TestCookieCache_RefreshAndExpiration(t *testing.T) {
	cfg := config.AuthConfig{
		Secret:  "secret-thirty-two-chars-long-abc!",
		BaseURL: "http://127.0.0.1:8080",
		Session: config.Session{
			ExpiresIn: 7 * 24 * time.Hour,
			CookieCache: &config.CookieCache{
				Enabled:  boolPtr(true),
				MaxAge:   10 * time.Second,
				Strategy: config.CookieCacheStrategyCompact,
				Version:  "1",
				RefreshCache: &config.CookieCacheRefresh{
					Enabled:   true,
					UpdateAge: 8 * time.Second, // refresh when remaining <= 8s (i.e. after 2s elapsed)
				},
			},
		},
	}
	cfg.SetDefaults()
	mgr := cookies.New(cfg)

	sw := sampleSessionWithUser()
	cookie, err := mgr.CreateSessionDataCookie(sw, false)
	if err != nil {
		t.Fatal(err)
	}
	header := fmt.Sprintf("%s=%s", cookie.Name, cookie.Value)

	// Newly minted (remaining ~10s, threshold 8s) -> ShouldRefresh is false
	if mgr.ShouldRefreshCookieCache(header) {
		t.Errorf("newly minted cookie cache should not need refresh yet")
	}

	// SessionCookiesWithData includes session_data
	allCookies := mgr.SessionCookiesWithData(sw, false)
	foundData := false
	for _, c := range allCookies {
		if strings.Contains(c.Name, cookies.CookieSessionData) {
			foundData = true
			break
		}
	}
	if !foundData {
		t.Errorf("expected session_data cookie in SessionCookiesWithData")
	}
}
