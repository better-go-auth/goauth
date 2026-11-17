package access_test

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/better-go-auth/goauth/src/providers/access"
)

// These tests mirror better-auth's src/plugins/access/access.test.ts.

var statements = access.Statements{
	"project": {"create", "update", "delete", "delete-many"},
	"ui":      {"view", "edit", "comment", "hide"},
}

func newAC() *access.AccessControl { return access.NewAccessControl(statements) }

func TestRole_ValidAction(t *testing.T) {
	role1 := newAC().NewRole(access.Statements{"project": {"create", "update", "delete"}, "ui": {"view", "edit", "comment"}})
	res := role1.Authorize(access.Req(map[string][]string{"project": {"create"}}))
	if !res.Success || res.Error != "" {
		t.Fatalf("expected success, got %+v", res)
	}
}

func TestRole_InvalidAction(t *testing.T) {
	role1 := newAC().NewRole(access.Statements{"project": {"create", "update", "delete"}})
	res := role1.Authorize(access.Req(map[string][]string{"project": {"delete-many"}}))
	if res.Success || res.Error != `unauthorized to access resource "project"` {
		t.Fatalf("unexpected %+v", res)
	}
}

func TestRole_UnknownResource(t *testing.T) {
	role1 := newAC().NewRole(access.Statements{"project": {"create"}})
	res := role1.Authorize(access.Req(map[string][]string{"ui": {"view"}}))
	if res.Success || res.Error != "You are not allowed to access resource: ui" {
		t.Fatalf("unexpected %+v", res)
	}
}

func TestRole_MultipleResourcesAND(t *testing.T) {
	role1 := newAC().NewRole(access.Statements{"project": {"create", "update"}, "ui": {"view"}})
	if !role1.Authorize(access.Req(map[string][]string{"project": {"create"}, "ui": {"view"}})).Success {
		t.Fatal("both allowed should succeed")
	}
	res := role1.Authorize(access.Req(map[string][]string{"project": {"create"}, "ui": {"edit"}}))
	if res.Success || res.Error != `unauthorized to access resource "ui"` {
		t.Fatalf("unexpected %+v", res)
	}
}

func TestRole_MultipleResourcesOR(t *testing.T) {
	role1 := newAC().NewRole(access.Statements{"project": {"create"}})
	// one allowed resource is enough with OR
	res := role1.Authorize(access.Req(map[string][]string{"project": {"create"}, "ui": {"view"}}), access.OR)
	if !res.Success {
		t.Fatalf("expected OR success, got %+v", res)
	}
	// none allowed -> "Not authorized"
	res = role1.Authorize(access.Req(map[string][]string{"project": {"delete"}, "ui": {"view"}}), access.OR)
	if res.Success || res.Error != access.ErrNotAuthorized {
		t.Fatalf("unexpected %+v", res)
	}
}

func TestRole_ActionConnectors(t *testing.T) {
	role1 := newAC().NewRole(access.Statements{"project": {"create", "update"}})
	// OR between actions: one of them is granted
	if !role1.Authorize(access.Request{"project": access.AnyOf("create", "delete")}).Success {
		t.Fatal("expected OR actions to succeed")
	}
	// AND between actions: delete is missing
	res := role1.Authorize(access.Request{"project": access.AllOf("create", "delete")})
	if res.Success || res.Error != `unauthorized to access resource "project"` {
		t.Fatalf("unexpected %+v", res)
	}
	// AND by default in object form
	if role1.Authorize(access.Request{"project": {Actions: []string{"create", "delete"}, Connector: ""}}).Success {
		t.Fatal("expected default AND to fail")
	}
	// empty actions in object form fail
	if role1.Authorize(access.Request{"project": access.AnyOf()}).Success {
		t.Fatal("expected empty actions to fail")
	}
}

func TestRole_EmptyRequests(t *testing.T) {
	role1 := newAC().NewRole(access.Statements{"project": {"create"}})
	// an empty array of actions is never authorized
	res := role1.Authorize(access.Req(map[string][]string{"project": {}}))
	if res.Success || res.Error != `unauthorized to access resource "project"` {
		t.Fatalf("unexpected %+v", res)
	}
	// an empty request is never authorized
	res = role1.Authorize(access.Request{})
	if res.Success || res.Error != access.ErrNotAuthorized {
		t.Fatalf("unexpected %+v", res)
	}
}

func TestRole_EmptyStatementListStillKnownResource(t *testing.T) {
	// better-auth: `[]` is truthy, so the resource is "known" and the error is the unauthorized one
	role1 := access.NewRole(access.Statements{"user": {}})
	res := role1.Authorize(access.Req(map[string][]string{"user": {"list"}}))
	if res.Error != `unauthorized to access resource "user"` {
		t.Fatalf("unexpected %+v", res)
	}
}

func TestRequest_JSONForms(t *testing.T) {
	var req access.Request
	if err := json.Unmarshal([]byte(`{"project":["create"],"ui":{"actions":["view","hide"],"connector":"OR"}}`), &req); err != nil {
		t.Fatal(err)
	}
	role1 := newAC().NewRole(access.Statements{"project": {"create"}, "ui": {"hide"}})
	if !role1.Authorize(req).Success {
		t.Fatal("expected success from JSON request")
	}
	out, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"project":["create"],"ui":{"actions":["view","hide"],"connector":"OR"}}` {
		t.Fatalf("unexpected marshal: %s", out)
	}
	// invalid value -> better-auth throws "Invalid access control request"
	if err := json.Unmarshal([]byte(`{"project":"create"}`), &req); err != nil {
		t.Fatal(err)
	}
	if _, err := role1.AuthorizeE(req); !errors.Is(err, access.ErrInvalidRequest) {
		t.Fatalf("expected ErrInvalidRequest, got %v", err)
	}
}

func TestRoles_JSON(t *testing.T) {
	roles, err := access.RolesFromJSON([]byte(`{"admin":{"user":["create","list"]},"user":{"user":[]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !roles["admin"].Authorize(access.Req(map[string][]string{"user": {"list"}})).Success {
		t.Fatal("admin should list")
	}
	if roles["user"].Authorize(access.Req(map[string][]string{"user": {"list"}})).Success {
		t.Fatal("user should not list")
	}
	out, _ := json.Marshal(roles["admin"])
	if string(out) != `{"user":["create","list"]}` {
		t.Fatalf("unexpected %s", out)
	}
	var ac access.AccessControl
	if err := json.Unmarshal([]byte(`{"user":["create"]}`), &ac); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ac.Statements(), access.Statements{"user": {"create"}}) {
		t.Fatalf("unexpected %v", ac.Statements())
	}
}

func TestHasPermission_MultiRole(t *testing.T) {
	roles := access.Roles{
		"user":  access.NewRole(access.Statements{"user": {}}),
		"admin": access.NewRole(access.Statements{"user": {"list"}}),
	}
	req := access.Req(map[string][]string{"user": {"list"}})
	if !access.HasPermission(roles, "user,admin", req) {
		t.Fatal("multi-role should grant through admin")
	}
	if access.HasPermission(roles, "user", req) {
		t.Fatal("user alone should not")
	}
	if access.HasPermission(roles, "ghost", req) {
		t.Fatal("unknown role should not")
	}
	if access.HasPermission(roles, "admin", access.Request{}) {
		t.Fatal("empty request should not")
	}
}

func TestStatements_MergeAndValidate(t *testing.T) {
	merged := access.Statements{"member": {"create"}}.Merge(access.Statements{"member": {"create", "delete"}, "team": {"create"}})
	want := access.Statements{"member": {"create", "delete"}, "team": {"create"}}
	if !reflect.DeepEqual(merged, want) {
		t.Fatalf("merge: got %v", merged)
	}
	ac := newAC()
	if got := ac.InvalidResources(access.Statements{"project": {"create"}, "billing": {"x"}}); !reflect.DeepEqual(got, []string{"billing"}) {
		t.Fatalf("invalid resources: %v", got)
	}
	if err := ac.Validate(access.Statements{"project": {"fly"}}); err == nil {
		t.Fatal("expected unknown action error")
	}
	if err := ac.Validate(access.Statements{"project": {"create"}}); err != nil {
		t.Fatal(err)
	}
}

func TestSplitRoles(t *testing.T) {
	if got := access.SplitRoles("admin, user,,"); !reflect.DeepEqual(got, []string{"admin", "user"}) {
		t.Fatalf("got %v", got)
	}
}
