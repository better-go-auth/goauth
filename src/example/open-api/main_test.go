package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
)

func TestOpenAPIFlow(t *testing.T) {
	app, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)

	// Step 1: the document lists the core and plugin auth routes, relative to /api/auth
	var doc struct {
		OpenAPI string                    `json:"openapi"`
		Servers []struct{ URL string }    `json:"servers"`
		Paths   map[string]map[string]any `json:"paths"`
		Comps   struct {
			Schemas map[string]struct {
				Properties map[string]any `json:"properties"`
			} `json:"schemas"`
		} `json:"components"`
	}
	c.MustOK(c.Get("/api/auth/open-api/generate-schema"), &doc)
	if doc.OpenAPI != "3.1.1" || len(doc.Servers) != 1 || doc.Servers[0].URL != app.BaseURL+"/api/auth" {
		t.Fatalf("envelope: %s %+v", doc.OpenAPI, doc.Servers)
	}
	for _, p := range []string{"/sign-up/email", "/sign-in/email", "/get-session", "/sign-in/username"} {
		if doc.Paths[p] == nil {
			t.Fatalf("missing path %s", p)
		}
	}
	if doc.Paths["/api/example/me"] != nil || doc.Paths["/example/me"] != nil {
		t.Fatal("application route documented")
	}
	// the username plugin's user fields are part of the User schema
	if doc.Comps.Schemas["User"].Properties["username"] == nil {
		t.Fatal("User.username missing")
	}

	// Step 2: the Scalar page embeds the document with the configured theme
	r := c.Get("/api/auth/reference")
	page := string(r.Body)
	if r.Status != http.StatusOK || !strings.Contains(page, `theme: "purple"`) || !strings.Contains(page, "@scalar/api-reference") {
		t.Fatalf("reference: %d", r.Status)
	}
}
