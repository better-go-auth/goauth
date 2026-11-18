package test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/better-go-auth/goauth/src/plugins/scim/config"
)

func TestGenerateTokenAndConnections(t *testing.T) {
	e := newEnv(t, envOpts{})

	// Step 1: a session is required; provider ids are validated
	apiErr(t, e.generate(t, map[string]any{"providerId": "okta"}), http.StatusUnauthorized, "UNAUTHORIZED", "")
	e.signUp(t, "admin@corp.com")
	apiErr(t, e.generate(t, map[string]any{"providerId": "bad:id"}), http.StatusBadRequest, "", "Provider id contains forbidden characters")
	apiErr(t, e.generate(t, map[string]any{"providerId": "credential"}), http.StatusBadRequest, "", "Provider id collides with a built-in account provider and cannot be used for SCIM")
	apiErr(t, e.generate(t, map[string]any{"providerId": "okta", "organizationId": "org-1"}), http.StatusBadRequest, "", "Restricting a token to an organization requires the organization plugin")

	// Step 2: a personal token: base64url("<24 chars>:okta"), stored in plain text by default
	token := e.mustToken(t, "okta", "")
	parts := decodeToken(t, token)
	if len(parts) != 2 || len(parts[0]) != 24 || parts[1] != "okta" {
		t.Fatalf("token parts %v", parts)
	}
	row := e.providerRow(t, "okta")
	if row["scimToken"] != parts[0] || row["organizationId"] != nil {
		t.Fatalf("stored row %v", row)
	}
	if _, ok := row["userId"]; ok {
		t.Fatalf("userId only exists with providerOwnership: %v", row)
	}
	r := e.scimDo(t, http.MethodGet, "/scim/v2/Users", token, nil)
	if r.Status != http.StatusOK {
		t.Fatalf("token does not work: %d %s", r.Status, r.Body)
	}

	// Step 3: list / get connections
	r = e.s.Get(t, "/api/auth/scim/list-provider-connections")
	if r.Status != http.StatusOK || !strings.Contains(string(r.Body), `"providerId":"okta","organizationId":null`) {
		t.Fatalf("list %d %s", r.Status, r.Body)
	}
	r = e.s.Get(t, "/api/auth/scim/get-provider-connection?providerId=okta")
	if r.Status != http.StatusOK || !strings.Contains(string(r.Body), `"id":"`+row["id"].(string)+`"`) {
		t.Fatalf("get %d %s", r.Status, r.Body)
	}
	apiErr(t, e.s.Get(t, "/api/auth/scim/get-provider-connection?providerId=nope"), http.StatusNotFound, "", "SCIM provider not found")

	// Step 4: regenerating rotates the token (the old one stops working)
	rotated := e.mustToken(t, "okta", "")
	if rotated == token {
		t.Fatal("token not rotated")
	}
	scimErr(t, e.scimDo(t, http.MethodGet, "/scim/v2/Users", token, nil), http.StatusUnauthorized, "Invalid SCIM token", "")
	if r := e.scimDo(t, http.MethodGet, "/scim/v2/Users", rotated, nil); r.Status != http.StatusOK {
		t.Fatalf("rotated token: %d", r.Status)
	}

	// Step 5: delete the connection: the token is invalid afterwards
	r = e.s.Post(t, "/api/auth/scim/delete-provider-connection", map[string]any{"providerId": "okta"})
	if r.Status != http.StatusOK || strings.TrimSpace(string(r.Body)) != `{"success":true}` {
		t.Fatalf("delete %d %s", r.Status, r.Body)
	}
	scimErr(t, e.scimDo(t, http.MethodGet, "/scim/v2/Users", rotated, nil), http.StatusUnauthorized, "Invalid SCIM token", "")
}

func TestSCIMAuthentication(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.signUp(t, "admin@corp.com")
	token := e.mustToken(t, "okta", "")
	parts := decodeToken(t, token)

	// missing, malformed, wrong secret, unknown provider
	scimErr(t, e.scimDo(t, http.MethodGet, "/scim/v2/Users", "", nil), http.StatusUnauthorized, "SCIM token is required", "")
	scimErr(t, e.scimDo(t, http.MethodGet, "/scim/v2/Users", "%%%", nil), http.StatusUnauthorized, "Invalid SCIM token", "")
	forged := encode("wrong-secret-000000000000:okta")
	scimErr(t, e.scimDo(t, http.MethodGet, "/scim/v2/Users/x", forged, nil), http.StatusUnauthorized, "Invalid SCIM token", "")
	scimErr(t, e.scimDo(t, http.MethodGet, "/scim/v2/Users", encode(parts[0]+":other"), nil), http.StatusUnauthorized, "Invalid SCIM token", "")
	scimErr(t, e.scimDo(t, http.MethodGet, "/scim/v2/Users", encode(parts[0]), nil), http.StatusUnauthorized, "Invalid SCIM token", "")
	// the metadata endpoints need no token
	if r := e.scimDo(t, http.MethodGet, "/scim/v2/ServiceProviderConfig", "", nil); r.Status != http.StatusOK {
		t.Fatalf("ServiceProviderConfig %d", r.Status)
	}
}

func TestSCIMUsersCRUD(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.signUp(t, "admin@corp.com")
	token := e.mustToken(t, "okta", "")

	// Step 1: create → 201 + Location + RFC 7643 resource
	r := e.scimDo(t, http.MethodPost, "/scim/v2/Users", token, userBody("ada@corp.com", map[string]any{"externalId": "ext-1"}))
	if r.Status != http.StatusCreated {
		t.Fatalf("create %d %s", r.Status, r.Body)
	}
	res := resource(t, r)
	id := res["id"].(string)
	loc := authBase + "/scim/v2/Users/" + id
	if r.Header.Get("Location") != loc {
		t.Fatalf("Location %q", r.Header.Get("Location"))
	}
	meta := res["meta"].(map[string]any)
	if res["externalId"] != "ext-1" || res["userName"] != "ada@corp.com" || res["displayName"] != "Ada Lovelace" || res["active"] != true ||
		meta["location"] != loc || meta["resourceType"] != "User" || res["schemas"].([]any)[0] != "urn:ietf:params:scim:schemas:core:2.0:User" {
		t.Fatalf("resource %s", r.Body)
	}
	if !strings.HasSuffix(meta["created"].(string), "Z") || len(meta["created"].(string)) != 24 {
		t.Fatalf("created %v", meta["created"])
	}
	if u := e.userByEmail("ada@corp.com"); u == nil || u.Name != "Ada Lovelace" {
		t.Fatalf("user %+v", u)
	}

	// Step 2: duplicates: same externalId, or an existing user with the email (no linking by default)
	scimErr(t, e.scimDo(t, http.MethodPost, "/scim/v2/Users", token, userBody("other@corp.com", map[string]any{"externalId": "ext-1"})), http.StatusConflict, "User already exists", "uniqueness")
	scimErr(t, e.scimDo(t, http.MethodPost, "/scim/v2/Users", token, userBody("admin@corp.com", nil)), http.StatusConflict, "User already exists", "uniqueness")

	// Step 3: emails win over userName; formatted wins over given/family
	r = e.scimDo(t, http.MethodPost, "/scim/v2/Users", token, map[string]any{
		"userName": "grace", "name": map[string]any{"formatted": "  Grace Hopper  ", "givenName": "x"},
		"emails": []any{map[string]any{"value": "g.other@corp.com"}, map[string]any{"value": "Grace@Corp.com", "primary": true}},
	})
	if r.Status != http.StatusCreated || resource(t, r)["userName"] != "grace@corp.com" || resource(t, r)["displayName"] != "Grace Hopper" {
		t.Fatalf("emails create %d %s", r.Status, r.Body)
	}
	grace := resource(t, r)["id"].(string)

	// Step 4: list, with filter (case-insensitive), and filter errors
	r = e.scimDo(t, http.MethodGet, "/scim/v2/Users", token, nil)
	var list struct {
		Schemas      []string         `json:"schemas"`
		TotalResults int              `json:"totalResults"`
		StartIndex   int              `json:"startIndex"`
		ItemsPerPage int              `json:"itemsPerPage"`
		Resources    []map[string]any `json:"Resources"`
	}
	r.JSON(t, &list)
	if list.TotalResults != 2 || list.ItemsPerPage != 2 || list.StartIndex != 1 || list.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:ListResponse" {
		t.Fatalf("list %s", r.Body)
	}
	r = e.scimDo(t, http.MethodGet, `/scim/v2/Users?filter=userName%20eq%20%22ADA@corp.com%22`, token, nil)
	r.JSON(t, &list)
	if list.TotalResults != 1 || list.Resources[0]["id"] != id {
		t.Fatalf("filtered list %s", r.Body)
	}
	scimErr(t, e.scimDo(t, http.MethodGet, `/scim/v2/Users?filter=userName%20ne%20%22x%22`, token, nil), http.StatusBadRequest, `The operator "ne" is not supported`, "invalidFilter")
	scimErr(t, e.scimDo(t, http.MethodGet, `/scim/v2/Users?filter=displayName%20eq%20%22x%22`, token, nil), http.StatusBadRequest, `The attribute "displayName" is not supported`, "invalidFilter")
	scimErr(t, e.scimDo(t, http.MethodGet, `/scim/v2/Users?filter=userName`, token, nil), http.StatusBadRequest, "Invalid filter expression", "invalidFilter")

	// Step 5: get
	if r := e.scimDo(t, http.MethodGet, "/scim/v2/Users/"+id, token, nil); r.Status != http.StatusOK || resource(t, r)["id"] != id {
		t.Fatalf("get %d %s", r.Status, r.Body)
	}
	scimErr(t, e.scimDo(t, http.MethodGet, "/scim/v2/Users/unknown", token, nil), http.StatusNotFound, "User not found", "")

	// Step 6: PUT replaces email, name and externalId
	r = e.scimDo(t, http.MethodPut, "/scim/v2/Users/"+id, token, map[string]any{"userName": "ada.l@corp.com", "externalId": "ext-2", "name": map[string]any{"formatted": "Countess Ada"}})
	if r.Status != http.StatusOK {
		t.Fatalf("put %d %s", r.Status, r.Body)
	}
	if res := resource(t, r); res["userName"] != "ada.l@corp.com" || res["externalId"] != "ext-2" || res["displayName"] != "Countess Ada" {
		t.Fatalf("put resource %s", r.Body)
	}

	// Step 7: delete (personal token): the user is gone
	r = e.scimDo(t, http.MethodDelete, "/scim/v2/Users/"+grace, token, nil)
	if r.Status != http.StatusNoContent {
		t.Fatalf("delete %d %s", r.Status, r.Body)
	}
	if e.userByEmail("grace@corp.com") != nil {
		t.Fatal("user not deleted")
	}
	scimErr(t, e.scimDo(t, http.MethodDelete, "/scim/v2/Users/"+grace, token, nil), http.StatusNotFound, "User not found", "")
}

func TestSCIMPatch(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.signUp(t, "admin@corp.com")
	token := e.mustToken(t, "okta", "")
	r := e.scimDo(t, http.MethodPost, "/scim/v2/Users", token, userBody("ada@corp.com", nil))
	id := resource(t, r)["id"].(string)
	patch := func(ops ...map[string]any) *struct{ status int } {
		rr := e.scimDo(t, http.MethodPatch, "/scim/v2/Users/"+id, token, map[string]any{
			"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}, "Operations": ops,
		})
		if rr.Status != http.StatusNoContent && rr.Status != http.StatusBadRequest {
			t.Fatalf("patch %d %s", rr.Status, rr.Body)
		}
		return &struct{ status int }{rr.Status}
	}
	get := func() map[string]any {
		return resource(t, e.scimDo(t, http.MethodGet, "/scim/v2/Users/"+id, token, nil))
	}

	// Step 1: givenName / familyName rebuild the full name; op defaults to replace and is case-insensitive
	if p := patch(map[string]any{"path": "name.givenName", "value": "Augusta"}); p.status != http.StatusNoContent {
		t.Fatal("givenName patch")
	}
	if get()["displayName"] != "Augusta Lovelace" {
		t.Fatalf("after givenName: %v", get()["displayName"])
	}
	patch(map[string]any{"op": "Replace", "path": "/name/familyName", "value": "King"})
	if get()["displayName"] != "Augusta King" {
		t.Fatalf("after familyName: %v", get()["displayName"])
	}
	// Step 2: a value object without path, nested keys applied in order
	patch(map[string]any{"op": "replace", "value": map[string]any{"name": map[string]any{"formatted": "Ada Byron"}, "userName": "Ada.Byron@corp.com", "externalId": "byron"}})
	if res := get(); res["displayName"] != "Ada Byron" || res["userName"] != "ada.byron@corp.com" || res["externalId"] != "byron" {
		t.Fatalf("after object patch: %v", res)
	}
	// Step 3: "add" of the current value, "remove" and unmapped paths (active=false) change nothing → 400
	r = e.scimDo(t, http.MethodPatch, "/scim/v2/Users/"+id, token, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []any{
			map[string]any{"op": "add", "path": "name.formatted", "value": "Ada Byron"},
			map[string]any{"op": "remove", "path": "name.formatted"},
			map[string]any{"op": "replace", "path": "active", "value": false},
		},
	})
	scimErr(t, r, http.StatusBadRequest, "No valid fields to update", "")
	if e.userByEmail("ada.byron@corp.com") == nil {
		t.Fatal("active=false must not deprovision (better-auth ignores it)")
	}
	// Step 4: validation of the PatchOp body
	r = e.scimDo(t, http.MethodPatch, "/scim/v2/Users/"+id, token, map[string]any{"schemas": []string{"x"}, "Operations": []any{}})
	apiErr(t, r, http.StatusBadRequest, "VALIDATION_ERROR", "[body.schemas] Invalid schemas for PatchOp")
	r = e.scimDo(t, http.MethodPatch, "/scim/v2/Users/"+id, token, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}, "Operations": []any{map[string]any{"op": "move"}}})
	apiErr(t, r, http.StatusBadRequest, "VALIDATION_ERROR", `[body.Operations.0.op] Invalid option: expected one of "replace"|"add"|"remove"`)
}

func TestSCIMUserValidation(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.signUp(t, "admin@corp.com")
	token := e.mustToken(t, "okta", "")
	apiErr(t, e.scimDo(t, http.MethodPost, "/scim/v2/Users", token, map[string]any{"userName": "Ada@corp.com"}), http.StatusBadRequest, "VALIDATION_ERROR", "[body.userName] Invalid lowercase")
	apiErr(t, e.scimDo(t, http.MethodPost, "/scim/v2/Users", token, map[string]any{}), http.StatusBadRequest, "VALIDATION_ERROR", "[body.userName] Invalid input: expected string, received undefined")
	apiErr(t, e.scimDo(t, http.MethodPost, "/scim/v2/Users", token, map[string]any{"userName": "a", "emails": []any{map[string]any{"value": "not-an-email"}}}), http.StatusBadRequest, "VALIDATION_ERROR", "[body.emails.0.value] Invalid email address")
	// the body is validated before the token
	apiErr(t, e.scimDo(t, http.MethodPost, "/scim/v2/Users", "", map[string]any{"userName": "A"}), http.StatusBadRequest, "VALIDATION_ERROR", "")
}

func TestSCIMMetadata(t *testing.T) {
	e := newEnv(t, envOpts{})
	r := e.scimDo(t, http.MethodGet, "/scim/v2/ServiceProviderConfig", "", nil)
	want := `{"patch":{"supported":true},"bulk":{"supported":false},"filter":{"supported":true},"changePassword":{"supported":false},"sort":{"supported":false},"etag":{"supported":false},"authenticationSchemes":[{"name":"OAuth Bearer Token","description":"Authentication scheme using the Authorization header with a bearer token tied to an organization.","specUri":"http://www.rfc-editor.org/info/rfc6750","type":"oauthbearertoken","primary":true}],"schemas":["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],"meta":{"resourceType":"ServiceProviderConfig"}}`
	if strings.TrimSpace(string(r.Body)) != want {
		t.Fatalf("ServiceProviderConfig\n%s", r.Body)
	}
	r = e.scimDo(t, http.MethodGet, "/scim/v2/Schemas", "", nil)
	if !strings.Contains(string(r.Body), `"location":"`+authBase+`/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User"`) || !strings.HasPrefix(string(r.Body), `{"totalResults":1,"itemsPerPage":1,"startIndex":1,"schemas":["urn:ietf:params:scim:api:messages:2.0:ListResponse"],"Resources":[{"id":"urn:ietf:params:scim:schemas:core:2.0:User"`) {
		t.Fatalf("Schemas %s", r.Body)
	}
	if r := e.scimDo(t, http.MethodGet, "/scim/v2/Schemas/urn:ietf:params:scim:schemas:core:2.0:User", "", nil); r.Status != http.StatusOK {
		t.Fatalf("Schema %d %s", r.Status, r.Body)
	}
	scimErr(t, e.scimDo(t, http.MethodGet, "/scim/v2/Schemas/unknown", "", nil), http.StatusNotFound, "Schema not found", "")
	r = e.scimDo(t, http.MethodGet, "/scim/v2/ResourceTypes", "", nil)
	if !strings.Contains(string(r.Body), `"endpoint":"/Users"`) || !strings.Contains(string(r.Body), authBase+"/scim/v2/ResourceTypes/User") {
		t.Fatalf("ResourceTypes %s", r.Body)
	}
	if r := e.scimDo(t, http.MethodGet, "/scim/v2/ResourceTypes/User", "", nil); r.Status != http.StatusOK {
		t.Fatalf("ResourceType %d", r.Status)
	}
	scimErr(t, e.scimDo(t, http.MethodGet, "/scim/v2/ResourceTypes/Group", "", nil), http.StatusNotFound, "Resource type not found", "")
}

func TestSCIMTokenStorageAndHooks(t *testing.T) {
	for _, mode := range []string{config.StoreHashed, config.StoreEncrypted} {
		t.Run(mode, func(t *testing.T) {
			var before, after []string
			e := newEnv(t, envOpts{scim: func(c *config.SCIMConfig) {
				c.StoreSCIMToken.Mode = mode
				c.ProviderOwnership = true
				c.BeforeSCIMTokenGenerated = func(_ context.Context, p config.TokenPayload) error {
					before = append(before, p.User.Email+"|"+p.SCIMToken)
					return nil
				}
				c.AfterSCIMTokenGenerated = func(_ context.Context, p config.TokenPayload) error {
					after = append(after, p.Provider.ProviderID+"|"+p.Provider.UserID)
					return nil
				}
			}})
			userID := e.signUp(t, mode+"-admin@corp.com")
			pid := "okta-" + mode
			token := e.mustToken(t, pid, "")
			base := decodeToken(t, token)[0]
			row := e.providerRow(t, pid)
			if row["scimToken"] == base || row["userId"] != userID {
				t.Fatalf("stored %v", row)
			}
			if r := e.scimDo(t, http.MethodGet, "/scim/v2/Users", token, nil); r.Status != http.StatusOK {
				t.Fatalf("%s token: %d %s", mode, r.Status, r.Body)
			}
			if len(before) != 1 || before[0] != mode+"-admin@corp.com|"+token || len(after) != 1 || after[0] != pid+"|"+userID {
				t.Fatalf("hooks %v %v", before, after)
			}
			// ownership: another user can neither see nor manage the connection
			e.freshBrowser()
			e.signUp(t, mode+"-other@corp.com")
			apiErr(t, e.s.Get(t, "/api/auth/scim/get-provider-connection?providerId="+pid), http.StatusForbidden, "", "You must be the owner to access this provider")
			apiErr(t, e.generate(t, map[string]any{"providerId": pid}), http.StatusForbidden, "", "You must be the owner to access this provider")
		})
	}
	// a hook error aborts generation; canGenerateToken can refuse
	e := newEnv(t, envOpts{scim: func(c *config.SCIMConfig) {
		c.BeforeSCIMTokenGenerated = func(context.Context, config.TokenPayload) error { return errors.New("nope") }
		c.CanGenerateToken = func(_ context.Context, d config.CanGenerateTokenData) (bool, error) {
			return d.ProviderID != "denied", nil
		}
	}})
	e.signUp(t, "hooks-admin@corp.com")
	apiErr(t, e.generate(t, map[string]any{"providerId": "denied"}), http.StatusForbidden, "", "You are not allowed to generate a SCIM token")
	if r := e.generate(t, map[string]any{"providerId": "okta"}); r.Status != http.StatusInternalServerError || e.providerRow(t, "okta") != nil {
		t.Fatalf("hook error: %d %s", r.Status, r.Body)
	}
}

func TestSCIMDefaultProviderAndLinking(t *testing.T) {
	e := newEnv(t, envOpts{scim: func(c *config.SCIMConfig) {
		c.DefaultSCIM = []config.Provider{{ProviderID: "static", SCIMToken: "static-secret"}}
		c.LinkExistingUsers = &config.LinkExistingUsers{TrustedDomains: []string{"Linked.com"}}
	}})
	e.signUp(t, "existing@linked.com")
	e.signUp(t, "existing@other.com")
	token := encode("static-secret:static")
	// Step 1: the configured provider authenticates without a stored row
	scimErr(t, e.scimDo(t, http.MethodGet, "/scim/v2/Users", encode("wrong:static"), nil), http.StatusUnauthorized, "Invalid SCIM token", "")
	// Step 2: linking: only the trusted domain links to the existing user
	r := e.scimDo(t, http.MethodPost, "/scim/v2/Users", token, userBody("existing@linked.com", nil))
	if r.Status != http.StatusCreated || resource(t, r)["id"] != e.userByEmail("existing@linked.com").ID {
		t.Fatalf("link %d %s", r.Status, r.Body)
	}
	scimErr(t, e.scimDo(t, http.MethodPost, "/scim/v2/Users", token, userBody("existing@other.com", nil)), http.StatusConflict, "User already exists", "uniqueness")
}
