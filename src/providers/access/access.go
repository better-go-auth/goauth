// Package access is a Go port of better-auth's `access` plugin (better-auth/plugins/access):
// createAccessControl, ac.newRole and role.authorize with the same AND/OR semantics and the
// same error messages. The admin and organization plugins build their permission checks on it.
//
// Usage (mirrors the TypeScript config):
//
//	ac := access.NewAccessControl(access.Statements{
//		"project": {"create", "share", "update", "delete"},
//	})
//	editor := ac.NewRole(access.Statements{"project": {"create", "update"}})
//	res := editor.Authorize(access.Req(map[string][]string{"project": {"create"}}))
//	// res.Success == true
//
// Differences with better-auth that are inherent to Go:
//   - Go maps have no insertion order, so a multi-resource request is evaluated in sorted
//     resource order. This only matters for which error message is returned when several
//     resources fail; the success/failure result is identical.
package access

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Connector joins the results of several checks: AND (all must pass) or OR (any may pass).
type Connector string

const (
	// AND requires every requested resource (or action) to be allowed. It is the default.
	AND Connector = "AND"
	// OR requires at least one requested resource (or action) to be allowed.
	OR Connector = "OR"
)

// Error messages returned by Role.Authorize; identical to better-auth's.
const (
	// errNotAllowedResource is returned (AND connector) when the role has no statement for the resource.
	errNotAllowedResource = "You are not allowed to access resource: %s"
	// errUnauthorizedResource is returned (AND connector) when the role lacks a requested action.
	errUnauthorizedResource = `unauthorized to access resource "%s"`
	// ErrNotAuthorized is the generic failure message (OR connector, empty requests).
	ErrNotAuthorized = "Not authorized"
)

// ErrInvalidRequest mirrors better-auth's BetterAuthError("Invalid access control request").
var ErrInvalidRequest = errors.New("Invalid access control request")

// Statements maps a resource to the actions defined (or granted) on it,
// e.g. {"user": ["create", "list"], "session": ["revoke"]}.
type Statements map[string][]string

// Clone returns a deep copy of the statements.
func (s Statements) Clone() Statements {
	if s == nil {
		return nil
	}
	out := make(Statements, len(s))
	for k, v := range s {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// Resources returns the resource names, sorted.
func (s Statements) Resources() []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Has reports whether action is listed for resource.
func (s Statements) Has(resource, action string) bool {
	for _, a := range s[resource] {
		if a == action {
			return true
		}
	}
	return false
}

// Merge returns a new Statements holding the union of s and other (actions de-duplicated,
// order preserved: s's actions first). This is how better-auth merges dynamic organization
// roles into the predefined role with the same name.
func (s Statements) Merge(other Statements) Statements {
	out := s.Clone()
	if out == nil {
		out = Statements{}
	}
	for res, actions := range other {
		seen := make(map[string]bool, len(out[res])+len(actions))
		merged := make([]string, 0, len(out[res])+len(actions))
		for _, a := range append(append([]string(nil), out[res]...), actions...) {
			if !seen[a] {
				seen[a] = true
				merged = append(merged, a)
			}
		}
		out[res] = merged
	}
	return out
}

// ActionRequest is the value side of an authorize request. In better-auth it is either an
// array of actions (all required) or an object {actions, connector}. Both JSON forms are
// accepted when unmarshalling; an array is marshalled back as an array.
type ActionRequest struct {
	Actions []string
	// Connector applies between the actions of this resource. Empty means AND.
	Connector Connector
	// object records that the request used the {actions, connector} form (affects marshalling only).
	object bool
	// invalid records a JSON value that is neither an array nor an object.
	invalid bool
}

// Actions builds an array-form ActionRequest (every action required).
func Actions(actions ...string) ActionRequest {
	return ActionRequest{Actions: actions}
}

// AnyOf builds an object-form ActionRequest with the OR connector.
func AnyOf(actions ...string) ActionRequest {
	return ActionRequest{Actions: actions, Connector: OR, object: true}
}

// AllOf builds an object-form ActionRequest with the AND connector.
func AllOf(actions ...string) ActionRequest {
	return ActionRequest{Actions: actions, Connector: AND, object: true}
}

// UnmarshalJSON accepts `["a","b"]` or `{"actions":["a"],"connector":"OR"}`.
func (a *ActionRequest) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	// Step 1: array form
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var arr []string
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return err
		}
		*a = ActionRequest{Actions: arr}
		return nil
	}
	// Step 2: object form
	if len(trimmed) > 0 && trimmed[0] == '{' {
		var obj struct {
			Actions   []string  `json:"actions"`
			Connector Connector `json:"connector"`
		}
		if err := json.Unmarshal(trimmed, &obj); err != nil {
			return err
		}
		*a = ActionRequest{Actions: obj.Actions, Connector: obj.Connector, object: true}
		return nil
	}
	// Step 3: anything else is an invalid request (better-auth throws at authorize time)
	*a = ActionRequest{invalid: true}
	return nil
}

// MarshalJSON writes the array form unless the request was built in object form.
func (a ActionRequest) MarshalJSON() ([]byte, error) {
	actions := a.Actions
	if actions == nil {
		actions = []string{}
	}
	if a.object || a.Connector != "" {
		connector := a.Connector
		if connector == "" {
			connector = AND
		}
		return json.Marshal(struct {
			Actions   []string  `json:"actions"`
			Connector Connector `json:"connector"`
		}{actions, connector})
	}
	return json.Marshal(actions)
}

// Request is the argument of Role.Authorize: resource -> requested actions.
type Request map[string]ActionRequest

// Req converts the common `{resource: [actions]}` shape into a Request.
func Req(m map[string][]string) Request {
	out := make(Request, len(m))
	for k, v := range m {
		out[k] = ActionRequest{Actions: v}
	}
	return out
}

// Resources returns the requested resources in evaluation (sorted) order.
func (r Request) Resources() []string {
	out := make([]string, 0, len(r))
	for k := range r {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Flatten lists every requested (resource, action) pair as "resource:action", in evaluation order.
func (r Request) Flatten() []string {
	var out []string
	for _, res := range r.Resources() {
		for _, a := range r[res].Actions {
			out = append(out, res+":"+a)
		}
	}
	return out
}

// AuthorizeResponse mirrors better-auth's `{ success, error }` authorize result.
type AuthorizeResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// Checker abstracts a permission source so the authorize algorithm can run on things that
// are not plain statement maps (e.g. goauth's legacy organization role rules).
type Checker interface {
	// HasResource reports whether any statement exists for resource.
	HasResource(resource string) bool
	// Allows reports whether action is granted on resource.
	Allows(resource, action string) bool
}

// Evaluate runs better-auth's role.authorize algorithm against an arbitrary Checker.
// It returns ErrInvalidRequest for a malformed action request (better-auth throws).
func Evaluate(c Checker, request Request, connector ...Connector) (AuthorizeResponse, error) {
	conn := AND
	if len(connector) > 0 && connector[0] != "" {
		conn = connector[0]
	}
	success := false
	// Step 1: walk every requested resource
	for _, resource := range request.Resources() {
		req := request[resource]
		// Step 2: unknown resource -> immediate failure for AND, skip for OR
		if !c.HasResource(resource) {
			if conn == AND {
				return AuthorizeResponse{Success: false, Error: fmt.Sprintf(errNotAllowedResource, resource)}, nil
			}
			success = false
			continue
		}
		// Step 3: evaluate the actions of this resource
		if req.invalid {
			return AuthorizeResponse{}, ErrInvalidRequest
		}
		allowed := func(action string) bool { return c.Allows(resource, action) }
		switch {
		case !req.object:
			// array form: non-empty and every action allowed
			success = len(req.Actions) > 0 && every(req.Actions, allowed)
		case len(req.Actions) == 0:
			success = false
		case req.Connector == OR:
			success = some(req.Actions, allowed)
		default:
			success = every(req.Actions, allowed)
		}
		// Step 4: short-circuit according to the outer connector
		if success && conn == OR {
			return AuthorizeResponse{Success: true}, nil
		}
		if !success && conn == AND {
			return AuthorizeResponse{Success: false, Error: fmt.Sprintf(errUnauthorizedResource, resource)}, nil
		}
	}
	// Step 5: final verdict (empty requests are not authorized)
	if success {
		return AuthorizeResponse{Success: true}, nil
	}
	return AuthorizeResponse{Success: false, Error: ErrNotAuthorized}, nil
}

func every(items []string, f func(string) bool) bool {
	for _, i := range items {
		if !f(i) {
			return false
		}
	}
	return true
}

func some(items []string, f func(string) bool) bool {
	for _, i := range items {
		if f(i) {
			return true
		}
	}
	return false
}

// Role is better-auth's role(): a set of granted statements with an authorize method.
type Role struct {
	statements Statements
}

// NewRole mirrors better-auth's exported `role(statements)`.
func NewRole(statements Statements) Role {
	return Role{statements: statements.Clone()}
}

// Statements returns a copy of the role's granted statements.
func (r Role) Statements() Statements { return r.statements.Clone() }

// HasResource implements Checker.
func (r Role) HasResource(resource string) bool {
	_, ok := r.statements[resource]
	return ok
}

// Allows implements Checker.
func (r Role) Allows(resource, action string) bool { return r.statements.Has(resource, action) }

// Authorize mirrors better-auth's role.authorize(request, connector = "AND").
// A malformed request (better-auth throws) yields Success=false with ErrInvalidRequest's text.
func (r Role) Authorize(request Request, connector ...Connector) AuthorizeResponse {
	res, err := Evaluate(r, request, connector...)
	if err != nil {
		return AuthorizeResponse{Success: false, Error: err.Error()}
	}
	return res
}

// AuthorizeE is Authorize that surfaces ErrInvalidRequest as an error, like better-auth throwing.
func (r Role) AuthorizeE(request Request, connector ...Connector) (AuthorizeResponse, error) {
	return Evaluate(r, request, connector...)
}

// MarshalJSON writes the role as its statements object.
func (r Role) MarshalJSON() ([]byte, error) {
	if r.statements == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(map[string][]string(r.statements))
}

// UnmarshalJSON reads a role from a statements object, e.g. {"user": ["list"]}.
func (r *Role) UnmarshalJSON(data []byte) error {
	var s Statements
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	r.statements = s
	return nil
}

// AccessControl is better-auth's createAccessControl() result: the full statement set
// (every resource and action that exists) and a newRole factory.
type AccessControl struct {
	statements Statements
}

// NewAccessControl mirrors better-auth's createAccessControl(statements).
func NewAccessControl(statements Statements) *AccessControl {
	return &AccessControl{statements: statements.Clone()}
}

// NewRole mirrors ac.newRole(statements). Like better-auth it does not validate the
// statements against the access control; use Validate for that.
func (ac *AccessControl) NewRole(statements Statements) Role {
	return NewRole(statements)
}

// Statements returns a copy of all defined statements.
func (ac *AccessControl) Statements() Statements {
	if ac == nil {
		return nil
	}
	return ac.statements.Clone()
}

// InvalidResources returns the resources of s that are not defined on the access control
// (better-auth's organization checkForInvalidResources). Sorted.
func (ac *AccessControl) InvalidResources(s Statements) []string {
	var out []string
	for _, res := range s.Resources() {
		if _, ok := ac.statements[res]; !ok {
			out = append(out, res)
		}
	}
	return out
}

// Validate reports an error when s uses a resource or action not defined on the access control.
// This is a goauth helper (TypeScript enforces it at compile time).
func (ac *AccessControl) Validate(s Statements) error {
	for _, res := range s.Resources() {
		defined, ok := ac.statements[res]
		if !ok {
			return fmt.Errorf("access: unknown resource %q", res)
		}
		for _, a := range s[res] {
			if !contains(defined, a) {
				return fmt.Errorf("access: unknown action %q on resource %q", a, res)
			}
		}
	}
	return nil
}

// MarshalJSON writes the access control as its statements object.
func (ac *AccessControl) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string][]string(ac.statements))
}

// UnmarshalJSON reads the access control from a statements object.
func (ac *AccessControl) UnmarshalJSON(data []byte) error {
	var s Statements
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	ac.statements = s
	return nil
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// Roles maps role names to roles, like the `roles` option of the admin/organization plugins.
type Roles map[string]Role

// RolesFromJSON parses `{"admin": {"user": ["create"]}, "user": {"user": []}}`.
func RolesFromJSON(data []byte) (Roles, error) {
	var out Roles
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// SplitRoles splits better-auth's comma-separated multi-role string ("admin,user").
// Whitespace around names is trimmed and empty names are dropped.
func SplitRoles(role string) []string {
	parts := strings.Split(role, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// HasPermission reports whether any of the comma-separated roles in role is granted the
// request by roles (better-auth's admin/organization hasPermission loop).
func HasPermission(roles Roles, role string, request Request) bool {
	if len(request) == 0 {
		return false
	}
	for _, name := range SplitRoles(role) {
		if r, ok := roles[name]; ok && r.Authorize(request).Success {
			return true
		}
	}
	return false
}
