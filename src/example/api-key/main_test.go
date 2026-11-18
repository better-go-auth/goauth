package main

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
	apikey "github.com/better-go-auth/goauth/src/plugins/api-key"
)

type keyBody struct {
	ID          string              `json:"id"`
	Key         string              `json:"key"`
	Name        *string             `json:"name"`
	Start       *string             `json:"start"`
	Remaining   *int64              `json:"remaining"`
	Metadata    map[string]any      `json:"metadata"`
	Permissions map[string][]string `json:"permissions"`
}

func TestAPIKeyFlow(t *testing.T) {
	app, keys, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)

	// Step 1: a signed-in user creates a key; the plain key is only returned now
	var signUp struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	c.MustOK(c.SignUp("alice@example.com", "Password123!", "Alice"), &signUp)
	var k keyBody
	c.MustOK(c.Post("/api/auth/api-key/create", map[string]any{"name": "ci", "metadata": map[string]any{"team": "ops"}}), &k)
	if !strings.HasPrefix(k.Key, "ex_") || *k.Start != k.Key[:6] || k.Permissions["reports"][0] != "read" || k.Metadata["team"] != "ops" {
		t.Fatalf("created = %+v", k)
	}

	// Step 2: a script without cookies calls your route with the key
	script := c.Fork()
	var reports ReportsOutput
	script.MustOK(script.Get("/api/example/reports", map[string]string{"x-api-key": k.Key}), &reports.Body)
	if reports.Body.KeyID != k.ID || reports.Body.UserID != signUp.User.ID || len(reports.Body.Reports) != 2 {
		t.Fatalf("reports = %+v", reports.Body)
	}
	if r := script.Get("/api/example/reports"); r.Status != http.StatusUnauthorized {
		t.Fatalf("no key: %d", r.Status)
	}
	if r := script.Get("/api/example/reports", map[string]string{"x-api-key": "ex_wrong"}); r.Status != http.StatusForbidden || r.ErrorCode() != "INVALID_API_KEY" {
		t.Fatalf("short key: %d %s", r.Status, r.Body)
	}

	// Step 3: the key is also a session on goauth's routes (EnableSessionForAPIKeys)
	var session struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	script.MustOK(script.Get("/api/auth/get-session", map[string]string{"x-api-key": k.Key}), &session)
	if session.User.Email != "alice@example.com" {
		t.Fatalf("session = %+v", session)
	}

	// Step 4: the server creates a key with a usage limit and no reports permission (Go API)
	limited, err := keys.CreateAPIKey(context.Background(), apikey.CreateAPIKeyInput{
		UserID: &signUp.User.ID, Name: ptr("one-shot"), Remaining: ptr[int64](1), Permissions: map[string][]string{"billing": {"read"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if r := script.Get("/api/example/reports", map[string]string{"x-api-key": limited.Key}); r.Status != http.StatusUnauthorized || r.ErrorCode() != "KEY_NOT_FOUND" {
		t.Fatalf("missing permission: %d %s", r.Status, r.Body)
	}
	res, err := keys.VerifyAPIKey(context.Background(), apikey.VerifyAPIKeyInput{Key: limited.Key, Permissions: map[string][]string{"billing": {"read"}}})
	if err != nil || !res.Valid || *res.Key.Remaining != 0 {
		t.Fatalf("verify = %+v, %v", res, err)
	}
	res, _ = keys.VerifyAPIKey(context.Background(), apikey.VerifyAPIKeyInput{Key: limited.Key})
	if res.Valid || res.Error.Code != "USAGE_EXCEEDED" {
		t.Fatalf("used up = %+v", res.Error)
	}

	// Step 5: the owner lists, updates and deletes keys with the session cookie
	var list struct {
		APIKeys []keyBody `json:"apiKeys"`
		Total   int       `json:"total"`
	}
	c.MustOK(c.Get("/api/auth/api-key/list"), &list)
	if list.Total != 1 || list.APIKeys[0].Key != "" {
		t.Fatalf("list = %+v", list)
	}
	c.MustOK(c.Post("/api/auth/api-key/update", map[string]any{"keyId": k.ID, "name": "ci-renamed"}), &k)
	if *k.Name != "ci-renamed" {
		t.Fatalf("update = %+v", k)
	}
	c.MustOK(c.Post("/api/auth/api-key/delete", map[string]any{"keyId": k.ID}), nil)
	if r := script.Get("/api/example/reports", map[string]string{"x-api-key": k.Key}); r.Status != http.StatusUnauthorized || r.ErrorCode() != "INVALID_API_KEY" {
		t.Fatalf("deleted key: %d %s", r.Status, r.Body)
	}
}

func ptr[T any](v T) *T { return &v }
