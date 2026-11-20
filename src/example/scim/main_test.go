package main

import (
	"net/http"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/example/internal/exkit"
)

func TestSCIMFlow(t *testing.T) {
	app, err := newApp("")
	if err != nil {
		t.Fatal(err)
	}
	c := exkit.StartTest(t, app)

	// Step 1: an admin creates the organization and a SCIM token for the IdP connection
	c.MustOK(c.SignUp("admin@acme.example", "Password123!", "Admin"), nil)
	var orgOut struct {
		ID string `json:"id"`
	}
	c.MustOK(c.Post("/api/auth/organization/create", map[string]any{"name": "Acme", "slug": "acme"}), &orgOut)
	var tok struct {
		SCIMToken string `json:"scimToken"`
	}
	c.MustStatus(c.Post("/api/auth/scim/generate-token", map[string]any{"providerId": "okta", "organizationId": orgOut.ID}), http.StatusCreated, &tok)

	// Step 2: the identity provider uses the token (no cookies)
	idp := c.Fork()
	idp.Headers = map[string]string{"Authorization": "Bearer " + tok.SCIMToken}
	var user struct {
		ID          string `json:"id"`
		UserName    string `json:"userName"`
		DisplayName string `json:"displayName"`
	}
	idp.MustStatus(idp.Post("/api/auth/scim/v2/Users", map[string]any{
		"userName": "jane@acme.example", "externalId": "okta-123", "name": map[string]any{"givenName": "Jane", "familyName": "Doe"},
	}), http.StatusCreated, &user)
	if user.DisplayName != "Jane Doe" || user.UserName != "jane@acme.example" {
		t.Fatalf("provisioned %+v", user)
	}

	// Step 3: list with a filter, then rename with PATCH
	if r := idp.Get(`/api/auth/scim/v2/Users?filter=userName%20eq%20%22jane@acme.example%22`); r.Status != http.StatusOK || !strings.Contains(string(r.Body), `"totalResults":1`) {
		t.Fatalf("list %d %s", r.Status, r.Body)
	}
	idp.MustStatus(idp.Do(http.MethodPatch, "/api/auth/scim/v2/Users/"+user.ID, map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "replace", "path": "name.familyName", "value": "Smith"}},
	}), http.StatusNoContent, nil)
	idp.MustOK(idp.Get("/api/auth/scim/v2/Users/"+user.ID), &user)
	if user.DisplayName != "Jane Smith" {
		t.Fatalf("after patch %+v", user)
	}

	// Step 4: deprovisioning removes the user from the organization
	idp.MustStatus(idp.Do(http.MethodDelete, "/api/auth/scim/v2/Users/"+user.ID, nil), http.StatusNoContent, nil)
	if r := idp.Get("/api/auth/scim/v2/Users/" + user.ID); r.Status != http.StatusNotFound {
		t.Fatalf("after delete %d %s", r.Status, r.Body)
	}

	// Step 5: a wrong token gets the SCIM error format
	bad := c.Fork()
	bad.Headers = map[string]string{"Authorization": "Bearer nope"}
	if r := bad.Get("/api/auth/scim/v2/Users"); r.Status != http.StatusUnauthorized || !strings.Contains(string(r.Body), `"detail":"Invalid SCIM token"`) {
		t.Fatalf("bad token %d %s", r.Status, r.Body)
	}
}
