package services

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	scimdtos "github.com/better-go-auth/goauth/src/plugins/scim/dtos"
)

// zodEmail is zod 4's z.email() pattern.
var zodEmail = regexp.MustCompile(`^(?:[A-Za-z0-9_'+\-\.]*)[A-Za-z0-9_+-]@(?:[A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$`)

// jsType names a decoded JSON value like zod's "received ..." messages.
func jsType(v any, present bool) string {
	if !present {
		return "undefined"
	}
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case float64, json.Number:
		return "number"
	case bool:
		return "boolean"
	case []any:
		return "array"
	}
	return "object"
}

// issues collects zod-style validation messages ("[body.path] message").
type issues []string

func (is *issues) add(path, msg string) { *is = append(*is, "["+path+"] "+msg) }

// err returns better-call's 400 VALIDATION_ERROR, or nil.
func (is issues) err() error {
	if len(is) == 0 {
		return nil
	}
	return autherr.New("VALIDATION_ERROR", strings.Join(is, "; "), http.StatusBadRequest)
}

// expectString validates an optional (or required) string field.
func expectString(is *issues, m map[string]any, key, path string, required bool) (string, bool) {
	v, ok := m[key]
	if !ok && !required {
		return "", false
	}
	s, isStr := v.(string)
	if !isStr {
		is.add(path, "Invalid input: expected string, received "+jsType(v, ok))
		return "", false
	}
	return s, true
}

// ParseUserInput validates a SCIM user body like better-auth's APIUserSchema (zod) and decodes it.
func ParseUserInput(raw []byte) (*scimdtos.SCIMUserInput, error) {
	// Step 1: an object
	var m map[string]any
	var is issues
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		var v any
		_ = json.Unmarshal(raw, &v)
		is.add("body", "Invalid input: expected object, received "+jsType(v, len(strings.TrimSpace(string(raw))) > 0))
		return nil, is.err()
	}
	out := &scimdtos.SCIMUserInput{}
	// Step 2: userName (required, lowercase)
	if s, ok := expectString(&is, m, "userName", "body.userName", true); ok {
		if s != strings.ToLower(s) {
			is.add("body.userName", "Invalid lowercase")
		}
		out.UserName = s
	}
	// Step 3: externalId
	if s, ok := expectString(&is, m, "externalId", "body.externalId", false); ok {
		out.ExternalID = &s
	}
	// Step 4: name
	if v, ok := m["name"]; ok {
		nm, isObj := v.(map[string]any)
		if !isObj {
			is.add("body.name", "Invalid input: expected object, received "+jsType(v, true))
		} else {
			out.Name = &scimdtos.SCIMName{}
			if s, ok := expectString(&is, nm, "formatted", "body.name.formatted", false); ok {
				out.Name.Formatted = s
			}
			if s, ok := expectString(&is, nm, "givenName", "body.name.givenName", false); ok {
				out.Name.GivenName = s
			}
			if s, ok := expectString(&is, nm, "familyName", "body.name.familyName", false); ok {
				out.Name.FamilyName = s
			}
		}
	}
	// Step 5: emails
	if v, ok := m["emails"]; ok {
		arr, isArr := v.([]any)
		if !isArr {
			is.add("body.emails", "Invalid input: expected array, received "+jsType(v, true))
		}
		for i, item := range arr {
			p := "body.emails." + strconv.Itoa(i)
			em, isObj := item.(map[string]any)
			if !isObj {
				is.add(p, "Invalid input: expected object, received "+jsType(item, true))
				continue
			}
			e := scimdtos.SCIMEmail{}
			if s, ok := expectString(&is, em, "value", p+".value", true); ok {
				if !zodEmail.MatchString(s) || strings.HasPrefix(s, ".") || strings.Contains(s, "..") {
					is.add(p+".value", "Invalid email address")
				}
				e.Value = s
			}
			if pv, ok := em["primary"]; ok {
				b, isBool := pv.(bool)
				if !isBool {
					is.add(p+".primary", "Invalid input: expected boolean, received "+jsType(pv, true))
				} else {
					e.Primary = &b
				}
			}
			out.Emails = append(out.Emails, e)
		}
	}
	if err := is.err(); err != nil {
		return nil, err
	}
	return out, nil
}

// ParsePatchInput validates a PatchOp body like better-auth's patchSCIMUserBodySchema.
func ParsePatchInput(raw []byte) ([]scimdtos.SCIMPatchOperation, error) {
	var m map[string]any
	var is issues
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		is.add("body", "Invalid input: expected object, received undefined")
		return nil, is.err()
	}
	// Step 1: schemas must include the PatchOp URN
	sv, ok := m["schemas"]
	arr, isArr := sv.([]any)
	if !isArr {
		is.add("body.schemas", "Invalid input: expected array, received "+jsType(sv, ok))
	} else {
		found := false
		for i, x := range arr {
			s, isStr := x.(string)
			if !isStr {
				is.add("body.schemas."+strconv.Itoa(i), "Invalid input: expected string, received "+jsType(x, true))
				continue
			}
			if s == PatchOpSchema {
				found = true
			}
		}
		if !found && len(is) == 0 {
			is.add("body.schemas", "Invalid schemas for PatchOp")
		}
	}
	// Step 2: the operations (op defaults to "replace", lower-cased)
	var ops []scimdtos.SCIMPatchOperation
	ov, ok := m["Operations"]
	list, isList := ov.([]any)
	if !isList {
		is.add("body.Operations", "Invalid input: expected array, received "+jsType(ov, ok))
	}
	for i, item := range list {
		p := "body.Operations." + strconv.Itoa(i)
		om, isObj := item.(map[string]any)
		if !isObj {
			is.add(p, "Invalid input: expected object, received "+jsType(item, true))
			continue
		}
		op := scimdtos.SCIMPatchOperation{Op: "replace", Value: orderedValue(raw, i)}
		if v, present := om["op"]; present {
			s, isStr := v.(string)
			if !isStr {
				is.add(p+".op", "Invalid input: expected string, received "+jsType(v, true))
			} else {
				op.Op = strings.ToLower(s)
				if op.Op != "replace" && op.Op != "add" && op.Op != "remove" {
					is.add(p+".op", `Invalid option: expected one of "replace"|"add"|"remove"`)
				}
			}
		}
		if s, ok := expectString(&is, om, "path", p+".path", false); ok {
			op.Path = s
		}
		ops = append(ops, op)
	}
	if err := is.err(); err != nil {
		return nil, err
	}
	return ops, nil
}

// orderedValue re-decodes Operations[i].value keeping object key order (PATCH applies nested keys in order).
func orderedValue(raw []byte, i int) any {
	var body struct {
		Operations []map[string]json.RawMessage `json:"Operations"`
	}
	if json.Unmarshal(raw, &body) != nil || i >= len(body.Operations) {
		return nil
	}
	v, ok := body.Operations[i]["value"]
	if !ok {
		return nil
	}
	out, err := decodeOrdered(v)
	if err != nil {
		return nil
	}
	return out
}
