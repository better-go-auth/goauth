package main

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
)

type codeBody struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	Interval                int    `json:"interval"`
}

type oauthError struct {
	Error string `json:"error"`
}

func TestDeviceAuthorizationFlow(t *testing.T) {
	app, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	device := exkit.StartTest(t, app)
	browser := device.Fork()

	// Step 1: the CLI asks for a code and shows user_code + verification_uri
	var code codeBody
	device.MustOK(device.Post("/api/auth/device/code", map[string]any{"client_id": "example-cli", "scope": "read"}), &code)
	if code.VerificationURI != "http://localhost:8080/device" || !strings.Contains(code.VerificationURIComplete, code.UserCode) {
		t.Fatalf("code = %+v", code)
	}
	if r := device.Post("/api/auth/device/code", map[string]any{"client_id": "unknown"}); r.Status != http.StatusBadRequest {
		t.Fatalf("unknown client: %d %s", r.Status, r.Body)
	}

	// Step 2: until the user acts the CLI hears "authorization_pending"
	token := map[string]any{"grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": code.DeviceCode, "client_id": "example-cli"}
	var e oauthError
	device.MustStatus(device.Post("/api/auth/device/token", token), http.StatusBadRequest, &e)
	if e.Error != "authorization_pending" {
		t.Fatalf("poll = %+v", e)
	}

	// Step 3: the user signs in, opens the verification page (claims the code) and approves
	browser.MustOK(browser.SignUp("tv-owner@example.com", "Password123!", "TV Owner"), nil)
	if r := browser.Get("/device?user_code=" + code.UserCode); r.Status != http.StatusOK {
		t.Fatalf("verification page: %d", r.Status)
	}
	browser.MustOK(browser.Get("/api/auth/device?user_code="+code.UserCode), nil)
	browser.MustOK(browser.Post("/api/auth/device/approve", map[string]any{"userCode": code.UserCode}), nil)

	// Step 4: after the polling interval the CLI gets the session token
	time.Sleep(time.Duration(code.Interval) * time.Second)
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	device.MustOK(device.Post("/api/auth/device/token", token), &tok)
	if tok.AccessToken == "" || tok.TokenType != "Bearer" {
		t.Fatalf("token = %+v", tok)
	}

	// Step 5: the CLI calls your API with the token as a bearer token
	var me exkit.MeOutput
	device.MustOK(device.Get("/api/example/me", map[string]string{"Authorization": "Bearer " + tok.AccessToken}), &me.Body)
	if me.Body.Email != "tv-owner@example.com" {
		t.Fatalf("me = %+v", me.Body)
	}
}
