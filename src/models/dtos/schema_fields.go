package dtos

import (
	"bytes"
	"encoding/json"
	"sync/atomic"
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

// SchemaFields lists the user and session fields the installed plugins add to better-auth's schema.
type SchemaFields struct {
	User    []string
	Session []string
}

// installedFields is the process-wide set of plugin fields (nil = none). better-auth returns a plugin's
// fields only when the plugin is installed, and then always (false / null when unset), so the JSON of
// UserResponse and SessionData depends on it. SetupGoAuth sets it from the plugins' SchemaFields; with
// several goauth instances in one process the last setup wins.
var installedFields atomic.Pointer[fieldSet]

type fieldSet struct {
	user    map[string]bool
	session map[string]bool
}

// SetInstalledSchemaFields records the plugin fields of the installed plugins (replacing earlier ones).
func SetInstalledSchemaFields(fields ...SchemaFields) {
	set := &fieldSet{user: map[string]bool{}, session: map[string]bool{}}
	for _, f := range fields {
		for _, n := range f.User {
			set.user[n] = true
		}
		for _, n := range f.Session {
			set.session[n] = true
		}
	}
	installedFields.Store(set)
}

// UserFieldInstalled reports whether an installed plugin adds the user field name (JSON name).
func UserFieldInstalled(name string) bool {
	s := installedFields.Load()
	return s != nil && s.user[name]
}

// SessionFieldInstalled reports whether an installed plugin adds the session field name (JSON name).
func SessionFieldInstalled(name string) bool {
	s := installedFields.Load()
	return s != nil && s.session[name]
}

// pluginField is one plugin field of a JSON object: its name, whether the struct marshaled it (it is
// non-zero, so omitempty kept it), and the value to write when the plugin is installed but the field
// was omitted.
type pluginField struct {
	name    string
	present bool
	value   any
}

// withPluginFields marshals v (a type without a MarshalJSON method) and appends every field of an
// installed plugin that omitempty dropped, so installed plugins' fields are always in the output.
func withPluginFields(v any, fields []pluginField, installed func(string) bool) ([]byte, error) {
	// Step 1: the normal JSON (omitempty drops zero plugin fields)
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	// Step 2: collect the dropped fields of installed plugins
	var extra bytes.Buffer
	for _, f := range fields {
		if f.present || !installed(f.name) {
			continue
		}
		val, err := json.Marshal(f.value)
		if err != nil {
			return nil, err
		}
		extra.WriteByte(',')
		extra.WriteString(`"` + f.name + `":`)
		extra.Write(val)
	}
	if extra.Len() == 0 {
		return b, nil
	}
	// Step 3: splice them in before the closing brace ("{}" has no field to put a comma after)
	out := make([]byte, 0, len(b)+extra.Len())
	out = append(out, b[:len(b)-1]...)
	if len(b) == 2 {
		out = append(out, extra.Bytes()[1:]...)
	} else {
		out = append(out, extra.Bytes()...)
	}
	return append(out, '}'), nil
}

// MarshalJSON writes better-auth's user shape: the fields of installed plugins are always present
// (false / null when unset); fields of plugins that are not installed are only written when set.
func (u UserResponse) MarshalJSON() ([]byte, error) {
	type plain UserResponse
	p := plain(u)
	// Step 1: the admin plugin reports every role, "user" included; without it only non-default roles show
	if UserFieldInstalled(FieldRole) {
		if p.Role == "" {
			p.Role = "user"
		}
	} else if p.Role == "user" {
		p.Role = ""
	}
	// Step 2: add the zero-valued fields of installed plugins
	return withPluginFields(p, []pluginField{
		{FieldRole, p.Role != "", nil},
		{FieldBanned, p.Banned, false},
		{FieldBanReason, p.BanReason != nil, nil},
		{FieldBanExpires, p.BanExpires != nil, nil},
		{FieldPhoneNumber, p.PhoneNumber != nil, nil},
		{FieldPhoneNumberVerified, p.PhoneNumberVerified != nil, nil},
		{FieldTwoFactorEnabled, p.TwoFactorEnabled, false},
		{FieldUsername, p.Username != nil, nil},
		{FieldDisplayUsername, p.DisplayUsername != nil, nil},
		{FieldIsAnonymous, p.IsAnonymous, false},
	}, UserFieldInstalled)
}

// MarshalJSON writes better-auth's session shape: impersonatedBy (admin), activeOrganizationId and
// activeTeamId (organization, teams) are null instead of missing when their plugin is installed.
// goauth's own session fields (activeOrganizationRole/Type, device fields) are only written when set.
func (s SessionData) MarshalJSON() ([]byte, error) {
	type plain SessionData
	p := plain(s)
	return withPluginFields(p, []pluginField{
		{FieldImpersonatedBy, p.ImpersonatedBy != nil, nil},
		{FieldActiveOrganizationID, p.ActiveOrganizationID != nil, nil},
		{FieldActiveTeamID, p.ActiveTeamID != nil, nil},
	}, SessionFieldInstalled)
}
