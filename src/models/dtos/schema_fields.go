package dtos

import (
	"bytes"
	"encoding/json"
	"reflect"
	"sort"
	"sync/atomic"
	"time"

	"github.com/better-go-auth/goauth/src/schema"
)

// Plugin fields of the user and session JSON (better-auth field names).
const (
	// admin plugin
	FieldRole           = "role"
	FieldBanned         = "banned"
	FieldBanReason      = "banReason"
	FieldBanExpires     = "banExpires"
	FieldImpersonatedBy = "impersonatedBy"
	// phone-number plugin
	FieldPhoneNumber         = "phoneNumber"
	FieldPhoneNumberVerified = "phoneNumberVerified"
	// two-factor plugin
	FieldTwoFactorEnabled = "twoFactorEnabled"
	// username plugin
	FieldUsername        = "username"
	FieldDisplayUsername = "displayUsername"
	// anonymous plugin
	FieldIsAnonymous = "isAnonymous"
	// organization plugin
	FieldActiveOrganizationID = "activeOrganizationId"
	FieldActiveTeamID         = "activeTeamId"
)

// outputSchema is the schema API output follows: the registry SetupGoAuth built and the installed plugins.
type outputSchema struct {
	reg *schema.Registry
	// installed holds the IDs of the installed plugins; nil = every plugin owning a registry field.
	installed map[string]bool
}

// output is the process-wide output schema (nil until SetupGoAuth). better-auth's user and session JSON
// contains every returned field of its schema (null when unset): core fields, additionalFields and the
// fields of installed plugins. With several goauth instances in one process the last setup wins.
var output atomic.Pointer[outputSchema]

// SetOutputSchema makes the JSON of UserResponse and SessionData follow reg (better-auth's parseUserOutput /
// parseSessionOutput): every returned field in registry order, null when unset, returned:false fields
// hidden, additional fields from Extra flattened in. installed lists the IDs of the installed plugins: fields
// owned by other plugins (still present in reg when it was built without InstalledPlugins) are only written
// when set. nil installed means every plugin of reg is installed. SetupGoAuth calls it; nil reg restores the
// default (core fields plus the plugin and additional fields that are set).
func SetOutputSchema(reg *schema.Registry, installed []string) {
	if reg == nil {
		output.Store(nil)
		return
	}
	o := &outputSchema{reg: reg}
	if installed != nil {
		o.installed = map[string]bool{}
		for _, id := range installed {
			o.installed[id] = true
		}
	}
	output.Store(o)
}

// OutputSchema returns the registry API output follows (nil before SetupGoAuth).
func OutputSchema() *schema.Registry {
	if o := output.Load(); o != nil {
		return o.reg
	}
	return nil
}

// fieldInstalled reports whether field f of the output schema belongs to the core, goauth, the
// configuration or an installed plugin.
func (o *outputSchema) fieldInstalled(f schema.ResolvedField) bool {
	switch f.Owner {
	case schema.OwnerCore, schema.OwnerGoAuth, schema.OwnerConfig, "":
		return true
	}
	return o.installed == nil || o.installed[f.Owner]
}

// installedField reports whether model.name is a field of an installed plugin (or core) in the output schema.
func installedField(model, name string) bool {
	o := output.Load()
	if o == nil {
		return false
	}
	m, ok := o.reg.Model(model)
	if !ok {
		return false
	}
	f, ok := m.Field(name)
	return ok && o.fieldInstalled(f)
}

// UserFieldInstalled reports whether the user field name (JSON name) is part of the installed schema
// (core, configuration additionalFields or an installed plugin).
func UserFieldInstalled(name string) bool { return installedField(schema.ModelUser, name) }

// SessionFieldInstalled reports whether the session field name (JSON name) is part of the installed schema.
func SessionFieldInstalled(name string) bool { return installedField(schema.ModelSession, name) }

// ─── Encoding ────────────────────────────────────────────────────────────────

// jsonValue converts a record value to what better-auth writes: dates as ISO strings with milliseconds,
// everything else as encoding/json would.
func jsonValue(v any) any {
	switch x := v.(type) {
	case time.Time:
		if x.IsZero() {
			return nil
		}
		return Time(x)
	case *time.Time:
		if x == nil {
			return nil
		}
		return Time(*x)
	case *Time:
		if x == nil {
			return nil
		}
		return *x
	}
	return v
}

// objectWriter writes a JSON object key by key without HTML escaping (like JSON.stringify).
type objectWriter struct {
	buf   bytes.Buffer
	first bool
}

func newObjectWriter() *objectWriter {
	w := &objectWriter{first: true}
	w.buf.WriteByte('{')
	return w
}

// add writes one key/value pair.
func (w *objectWriter) add(key string, v any) error {
	if !w.first {
		w.buf.WriteByte(',')
	}
	w.first = false
	if err := encodeNoEscape(&w.buf, key); err != nil {
		return err
	}
	w.buf.WriteByte(':')
	return encodeNoEscape(&w.buf, jsonValue(v))
}

// bytes closes the object and returns it.
func (w *objectWriter) bytes() []byte {
	w.buf.WriteByte('}')
	return w.buf.Bytes()
}

// encodeNoEscape appends v's JSON without HTML escaping and without the encoder's trailing newline.
func encodeNoEscape(buf *bytes.Buffer, v any) error {
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return err
	}
	buf.Write(bytes.TrimRight(tmp.Bytes(), "\n"))
	return nil
}

// isNil reports whether v is nil or a nil pointer.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}

// marshalRecord writes values (keyed by field name) as model's API output.
//
// With an output schema (SetupGoAuth): every returned field of the model in registry order; a value that is
// missing or nil is written as null (better-auth reads every column, so unset optional fields are null).
// OmitEmpty fields (goauth's own columns) and fields of plugins that are not installed are only written when
// set. Keys that are not fields of the model are dropped (better-auth's output only has schema fields).
//
// Without one (no SetupGoAuth, e.g. unit tests): the always fields, then every other non-empty value in
// name order.
func marshalRecord(model string, always []string, values map[string]any) ([]byte, error) {
	w := newObjectWriter()
	o := output.Load()
	var m *schema.ResolvedModel
	if o != nil {
		m, _ = o.reg.Model(model)
	}
	// Step 1: no output schema: the always fields plus everything that is set
	if m == nil {
		done := map[string]bool{}
		for _, k := range always {
			done[k] = true
			if err := w.add(k, values[k]); err != nil {
				return nil, err
			}
		}
		keys := make([]string, 0, len(values))
		for k := range values {
			if !done[k] {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			if (schema.Field{}).EmptyOutput(values[k]) {
				continue
			}
			if err := w.add(k, values[k]); err != nil {
				return nil, err
			}
		}
		return w.bytes(), nil
	}
	// Step 2: the registry's returned fields, in order
	for _, f := range m.OutputFields() {
		v := values[f.Name]
		// goauth's own columns and fields of plugins that aren't installed only appear when set
		if f.OmitEmpty || !o.fieldInstalled(f) {
			if f.EmptyOutput(v) {
				continue
			}
		}
		if isNil(v) {
			v = nil
		}
		if err := w.add(f.Name, v); err != nil {
			return nil, err
		}
	}
	return w.bytes(), nil
}

// unmarshalExtra decodes the keys of b that are not in static into extra, converting values of known
// registry fields to their canonical Go type (dates become time.Time). null values are skipped.
func unmarshalExtra(model string, b []byte, static map[string]bool) (map[string]any, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	var m *schema.ResolvedModel
	if o := output.Load(); o != nil {
		m, _ = o.reg.Model(model)
	}
	var extra map[string]any
	for k, rv := range raw {
		if static[k] || bytes.Equal(bytes.TrimSpace(rv), []byte("null")) {
			continue
		}
		var v any
		if err := json.Unmarshal(rv, &v); err != nil {
			return nil, err
		}
		// known fields get their logical type (a JSON date string becomes time.Time)
		if m != nil {
			if f, ok := m.Field(k); ok {
				if f.Type == schema.JSON {
					v = json.RawMessage(append([]byte(nil), rv...))
				} else if nv, err := schema.Normalize(f.Type, v); err == nil {
					v = nv
				}
			}
		}
		if extra == nil {
			extra = map[string]any{}
		}
		extra[k] = v
	}
	return extra, nil
}

// ─── User ────────────────────────────────────────────────────────────────────

// userStaticFields are the JSON names of UserResponse's struct fields.
var userStaticFields = map[string]bool{
	"id": true, "name": true, "email": true, "emailVerified": true, "image": true, "createdAt": true, "updatedAt": true,
	FieldRole: true, FieldBanned: true, FieldBanReason: true, FieldBanExpires: true,
	FieldPhoneNumber: true, FieldPhoneNumberVerified: true, FieldTwoFactorEnabled: true,
	FieldUsername: true, FieldDisplayUsername: true, FieldIsAnonymous: true,
}

// userCoreFields are always written, also without an output schema.
var userCoreFields = []string{"id", "name", "email", "emailVerified", "image", "createdAt", "updatedAt"}

// values returns the user as a record keyed by field name: the struct fields, then Extra.
func (u UserResponse) values() map[string]any {
	vals := map[string]any{
		"id": u.ID, "name": u.Name, "email": u.Email, "emailVerified": u.EmailVerified, "image": u.Image,
		"createdAt": u.CreatedAt, "updatedAt": u.UpdatedAt,
		FieldRole: u.Role, FieldBanned: u.Banned, FieldBanReason: u.BanReason, FieldBanExpires: u.BanExpires,
		FieldPhoneNumber: u.PhoneNumber, FieldPhoneNumberVerified: u.PhoneNumberVerified,
		FieldTwoFactorEnabled: u.TwoFactorEnabled, FieldUsername: u.Username, FieldDisplayUsername: u.DisplayUsername,
		FieldIsAnonymous: u.IsAnonymous,
	}
	// the admin plugin reports every role, "user" included; without it the default role is not shown
	if UserFieldInstalled(FieldRole) {
		if u.Role == "" {
			vals[FieldRole] = "user"
		}
	} else if u.Role == "" || u.Role == "user" {
		vals[FieldRole] = nil
	}
	for k, v := range u.Extra {
		if !userStaticFields[k] {
			vals[k] = v
		}
	}
	return vals
}

// MarshalJSON writes better-auth's user shape (see SetOutputSchema): every returned field of the user
// schema, the fields of installed plugins and additionalFields included (false / null when unset).
func (u UserResponse) MarshalJSON() ([]byte, error) {
	return marshalRecord(schema.ModelUser, userCoreFields, u.values())
}

// UnmarshalJSON reads a user written by goauth or a better-auth server (cookie cache, secondary storage):
// known fields into the struct, every other non-null field into Extra.
func (u *UserResponse) UnmarshalJSON(b []byte) error {
	type plain UserResponse
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	extra, err := unmarshalExtra(schema.ModelUser, b, userStaticFields)
	if err != nil {
		return err
	}
	p.Extra = extra
	*u = UserResponse(p)
	return nil
}

// ─── Session ─────────────────────────────────────────────────────────────────

// sessionStaticFields are the JSON names of SessionData's struct fields.
var sessionStaticFields = map[string]bool{
	"id": true, "userId": true, "token": true, "expiresAt": true, "ipAddress": true, "userAgent": true,
	"createdAt": true, "updatedAt": true, FieldImpersonatedBy: true, FieldActiveOrganizationID: true,
	"activeOrganizationRole": true, "activeOrganizationType": true, FieldActiveTeamID: true,
	"deviceToken": true, "deviceId": true, "deviceName": true, "deviceType": true,
}

// sessionCoreFields are always written, also without an output schema.
var sessionCoreFields = []string{"id", "userId", "token", "expiresAt", "ipAddress", "userAgent", "createdAt", "updatedAt"}

// values returns the session as a record keyed by field name: the struct fields, then Extra.
func (s SessionData) values() map[string]any {
	vals := map[string]any{
		"id": s.ID, "userId": s.UserID, "token": s.Token, "expiresAt": s.ExpiresAt, "ipAddress": s.IPAddress,
		"userAgent": s.UserAgent, "createdAt": s.CreatedAt, "updatedAt": s.UpdatedAt,
		FieldImpersonatedBy: s.ImpersonatedBy, FieldActiveOrganizationID: s.ActiveOrganizationID,
		"activeOrganizationRole": s.ActiveOrganizationRole, "activeOrganizationType": s.ActiveOrganizationType,
		FieldActiveTeamID: s.ActiveTeamID, "deviceToken": s.DeviceToken, "deviceId": s.DeviceID,
		"deviceName": s.DeviceName, "deviceType": s.DeviceType,
	}
	for k, v := range s.Extra {
		if !sessionStaticFields[k] {
			vals[k] = v
		}
	}
	return vals
}

// MarshalJSON writes better-auth's session shape (see SetOutputSchema): impersonatedBy (admin),
// activeOrganizationId (organization) and additionalFields are null instead of missing when unset.
// goauth's own session fields (activeOrganizationRole/Type, device fields) are only written when set.
func (s SessionData) MarshalJSON() ([]byte, error) {
	return marshalRecord(schema.ModelSession, sessionCoreFields, s.values())
}

// UnmarshalJSON reads a session written by goauth or a better-auth server: known fields into the struct,
// every other non-null field into Extra.
func (s *SessionData) UnmarshalJSON(b []byte) error {
	type plain SessionData
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	extra, err := unmarshalExtra(schema.ModelSession, b, sessionStaticFields)
	if err != nil {
		return err
	}
	p.Extra = extra
	*s = SessionData(p)
	return nil
}
