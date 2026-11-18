package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/models"
	scimdtos "github.com/better-go-auth/goauth/src/plugins/scim/dtos"
)

// ─── PATCH ───────────────────────────────────────────────────────────────────

// patchResources are the pending changes of a PATCH: user fields (name, email) and account fields (accountId).
type patchResources struct {
	user    map[string]string
	account map[string]string
}

// patchMapping is one entry of better-auth's userPatchMappings.
type patchMapping struct {
	resource string // "user" or "account"
	target   string
	mapValue func(user *models.User, value string, res patchResources) string
}

// currentName is resources.user.name ?? user.name.
func currentName(user *models.User, res patchResources) string {
	if n, ok := res.user["name"]; ok {
		return n
	}
	return user.Name
}

// userPatchMappings are better-auth's PATCH paths.
var userPatchMappings = map[string]patchMapping{
	"/name/formatted": {resource: "user", target: "name", mapValue: func(_ *models.User, v string, _ patchResources) string { return v }},
	"/name/givenName": {resource: "user", target: "name", mapValue: func(u *models.User, v string, res patchResources) string {
		family := strings.TrimSpace(strings.Join(splitAfterFirst(currentName(u, res)), " "))
		return fullName(u.Email, &scimdtos.SCIMName{GivenName: v, FamilyName: family})
	}},
	"/name/familyName": {resource: "user", target: "name", mapValue: func(u *models.User, v string, res patchResources) string {
		cur := currentName(u, res)
		words := strings.Split(cur, " ")
		given := strings.Join(words[:len(words)-1], " ")
		if given == "" {
			given = cur
		}
		return fullName(u.Email, &scimdtos.SCIMName{GivenName: strings.TrimSpace(given), FamilyName: v})
	}},
	"/externalId": {resource: "account", target: "accountId", mapValue: func(_ *models.User, v string, _ patchResources) string { return v }},
	"/userName":   {resource: "user", target: "email", mapValue: func(_ *models.User, v string, _ patchResources) string { return strings.ToLower(v) }},
}

// splitAfterFirst is name.split(" ").slice(1).
func splitAfterFirst(name string) []string {
	parts := strings.Split(name, " ")
	return parts[1:]
}

// normalizePath turns "name.givenName" / "/name.givenName" into "/name/givenName".
func normalizePath(path string) string {
	return "/" + strings.ReplaceAll(strings.TrimPrefix(path, "/"), ".", "/")
}

// patchValueString is how a JSON scalar becomes the stored string.
func patchValueString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case nil:
		return ""
	}
	return fmt.Sprint(v)
}

// applyMapping is better-auth's applyMapping (an "add" equal to the current user value is a no-op).
func applyMapping(user *models.User, res patchResources, path string, value any, op string) {
	m, ok := userPatchMappings[normalizePath(path)]
	if !ok {
		return
	}
	newValue := m.mapValue(user, patchValueString(value), res)
	if op == "add" && m.resource == "user" {
		current := user.Name
		if m.target == "email" {
			current = user.Email
		}
		if current == newValue {
			return
		}
	}
	if m.resource == "user" {
		res.user[m.target] = newValue
	} else {
		res.account[m.target] = newValue
	}
}

// orderedObject is a JSON object with its keys in document order (JavaScript's Object.entries order).
type orderedObject []orderedField

type orderedField struct {
	Key   string
	Value any
}

// decodeOrdered decodes JSON keeping object key order (objects become orderedObject).
func decodeOrdered(raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return decodeValue(dec)
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			var obj orderedObject
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, _ := kt.(string)
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				obj = append(obj, orderedField{Key: key, Value: v})
			}
			_, err := dec.Token()
			return obj, err
		case '[':
			var arr []any
			for dec.More() {
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			_, err := dec.Token()
			return arr, err
		}
	case json.Number:
		return t.String(), nil
	}
	return tok, nil
}

// applyPatchValue walks nested objects ({"name": {"givenName": "x"}} → "name.givenName") in key order.
func applyPatchValue(user *models.User, res patchResources, value any, op, path string) {
	if obj, ok := value.(orderedObject); ok {
		for _, f := range obj {
			next := f.Key
			if path != "" {
				next = path + "." + f.Key
			}
			applyPatchValue(user, res, f.Value, op, next)
		}
		return
	}
	if path != "" {
		applyMapping(user, res, path, value, op)
	}
}

// buildUserPatch is better-auth's buildUserPatch: the user and account changes of add / replace operations.
func buildUserPatch(user *models.User, ops []scimdtos.SCIMPatchOperation) (map[string]string, map[string]string) {
	res := patchResources{user: map[string]string{}, account: map[string]string{}}
	for _, op := range ops {
		if op.Op != "add" && op.Op != "replace" {
			continue
		}
		applyPatchValue(user, res, op.Value, op.Op, op.Path)
	}
	return res.user, res.account
}

// ─── filters ─────────────────────────────────────────────────────────────────

// filterPattern is better-auth's SCIMFilterRegex.
var filterPattern = regexp.MustCompile(`(?i)^\s*([^\s]+)\s+(eq|ne|co|sw|ew|pr)\s*(?:("[^"]*"|[^\s]+))?\s*$`)

// filterAttributes maps SCIM attributes to user fields (only userName → email).
var filterAttributes = map[string]string{"userName": "email"}

// filterError is the SCIM invalidFilter error.
func filterError(detail string) error {
	return NewSCIMError(http.StatusBadRequest, detail, "invalidFilter")
}

// parseUserFilter is better-auth's parseSCIMAPIUserFilter: `userName eq "value"` (case-insensitive value).
func parseUserFilter(filter string) ([]adapter.Where, error) {
	if filter == "" {
		return nil, nil
	}
	// Step 1: the expression
	m := filterPattern.FindStringSubmatch(filter)
	if m == nil || m[1] == "" || m[2] == "" || m[3] == "" {
		return nil, filterError("Invalid filter expression")
	}
	attribute, op, value := m[1], strings.ToLower(m[2]), m[3]
	if op != "eq" {
		return nil, filterError(`The operator "` + op + `" is not supported`)
	}
	// Step 2: the attribute (userName is not case exact)
	field, ok := filterAttributes[attribute]
	if !ok {
		return nil, filterError(`The attribute "` + attribute + `" is not supported`)
	}
	value = strings.ToLower(strings.ReplaceAll(value, `"`, ""))
	return []adapter.Where{{Field: field, Value: value}}, nil
}
