package services

import (
	"reflect"
	"strings"

	"github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/schema"
)

// runtimeDefault is better-auth's placeholder for a default computed at runtime (a function).
const runtimeDefault = "Generated at runtime"

// componentSchemas builds components.schemas like better-auth's generator: one object schema per table of
// getAuthTables (User, Session, Account, Verification and plugin models), keyed by the capitalized logical
// model name, with an `id` string property followed by the model's fields.
func (s *Service) componentSchemas() (map[string]any, error) {
	// Step 1: SetupGoAuth's registry (every installed SchemaProvider), or, when WithSchemaPlugins names
	// plugins explicitly, the registry of the configuration plus those plugin schemas
	extra := map[string]bool{}
	for _, p := range s.cfg.Schemas {
		extra[p.ID] = true
	}
	reg := s.reg
	if reg == nil || len(s.cfg.Schemas) > 0 {
		opts := s.conf.SchemaOptions()
		opts.Plugins = append(opts.Plugins, s.cfg.Schemas...)
		built, err := schema.Build(opts)
		if err != nil {
			return nil, err
		}
		reg = built
	} else {
		// owners other than core, goauth, configuration and the plugins of goauth's typed user/session
		// columns are SchemaProvider plugins: their fields are part of the document
		for _, m := range reg.Models() {
			for _, f := range m.Fields() {
				if !builtinOwner(f.Owner) {
					extra[f.Owner] = true
				}
			}
		}
	}
	// Step 2: one schema per model, with the fields better-auth would know about
	out := map[string]any{}
	for _, m := range reg.Models() {
		properties := map[string]any{"id": map[string]any{"type": "string"}}
		required := []string{}
		for _, f := range m.Fields() {
			if f.Name == "id" || !includeField(m.Name(), f, extra) {
				continue
			}
			properties[f.Name] = fieldSchema(f.Field)
			if f.Required && f.IsInput() {
				required = append(required, f.Name)
			}
		}
		out[capitalize(m.Name())] = map[string]any{"type": "object", "properties": properties, "required": required}
	}
	return out, nil
}

// includeField reports whether a registry field is part of better-auth's schema for this instance: core
// and configuration (additionalFields) fields, fields of the extra plugin schemas, and the user/session
// fields of installed goauth plugins. goauth-only bookkeeping columns are left out.
func includeField(model string, f schema.ResolvedField, extra map[string]bool) bool {
	switch f.Owner {
	case schema.OwnerCore, schema.OwnerConfig:
		return true
	case schema.OwnerGoAuth:
		return false
	}
	if extra[f.Owner] {
		return true
	}
	switch model {
	case schema.ModelUser:
		return dtos.UserFieldInstalled(f.Name)
	case schema.ModelSession:
		return dtos.SessionFieldInstalled(f.Name)
	}
	return false
}

// fieldSchema is better-auth's getFieldSchema: the field type (dates as date-time strings), its default
// ("Generated at runtime" for computed defaults) and readOnly for fields clients cannot set.
func fieldSchema(f schema.Field) map[string]any {
	// Step 1: the type
	out := map[string]any{}
	switch f.Type {
	case schema.Date:
		out["type"], out["format"] = "string", "date-time"
	case schema.Number, schema.Integer:
		out["type"] = "number"
	case schema.Boolean:
		out["type"] = "boolean"
	case schema.StringArray:
		out["type"], out["items"] = "array", map[string]any{"type": "string"}
	case schema.NumberArray:
		out["type"], out["items"] = "array", map[string]any{"type": "number"}
	case schema.JSON:
		out["type"] = "object"
	default:
		out["type"] = "string"
	}
	if len(f.Enum) > 0 {
		out["enum"] = f.Enum
	}
	// Step 2: the default value
	if f.Default != nil {
		if reflect.TypeOf(f.Default).Kind() == reflect.Func {
			out["default"] = runtimeDefault
		} else {
			out["default"] = f.Default
		}
	}
	// Step 3: input: false fields are read-only
	if !f.IsInput() {
		out["readOnly"] = true
	}
	return out
}

// capitalize upper-cases the first letter ("user" → "User", "one-time-token" → "One-time-token").
func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// builtinOwner reports whether owner is core, goauth, configuration or a plugin whose columns goauth's
// models carry as typed fields (includeField decides about those by installation).
func builtinOwner(owner string) bool {
	switch owner {
	case schema.OwnerCore, schema.OwnerGoAuth, schema.OwnerConfig, schema.PluginAdmin, schema.PluginPhoneNumber,
		schema.PluginTwoFactor, schema.PluginUsername, schema.PluginAnonymous, schema.PluginOrg:
		return true
	}
	return false
}
