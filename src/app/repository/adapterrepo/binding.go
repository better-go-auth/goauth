package adapterrepo

import (
	"fmt"
	"reflect"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/schema"
)

// goField binds one Go struct field of a model to its registry field.
type goField struct {
	goName string
	field  string
	index  []int
	// zeroDefault is written on create when the Go value is the zero value, reproducing the GORM struct
	// tag defaults (`default:user`) that the column definitions of existing databases have.
	zeroDefault any
}

// binding maps a Go model type to a registry model: static fields by registry name, the rest in Extra.
type binding struct {
	model  *schema.ResolvedModel
	typ    reflect.Type
	fields []goField
	byGo   map[string]int
	static map[string]bool // registry field names that have a Go field
	// unbound are Go fields whose registry field is missing (plugin not installed): never stored, read as zero
	unbound [][]int
}

// staticFields lists, per model, the Go field name → registry field name of every persisted field of the
// Go models (relations such as User.Sessions and the Extra map are not columns).
var staticFields = map[string][][2]string{
	schema.ModelUser: {
		{"ID", "id"}, {"CreatedAt", "createdAt"}, {"UpdatedAt", "updatedAt"},
		{"Name", "name"}, {"Email", "email"}, {"EmailVerified", "emailVerified"}, {"Image", "image"},
		{"Role", "role"}, {"Banned", "banned"}, {"BanReason", "banReason"}, {"BanExpires", "banExpires"},
		{"PhoneNumber", "phoneNumber"}, {"PhoneNumberVerified", "phoneNumberVerified"},
		{"TwoFactorEnabled", "twoFactorEnabled"},
		{"Username", "username"}, {"DisplayUsername", "displayUsername"},
		{"IsAnonymous", "isAnonymous"},
		{"FirstName", "firstName"}, {"LastName", "lastName"}, {"DisplayName", "displayName"}, {"Bio", "bio"},
		{"DateOfBirth", "dateOfBirth"}, {"Gender", "gender"}, {"Locale", "locale"}, {"Timezone", "timezone"},
		{"LastLoginIP", "lastLoginIP"}, {"LastLoginAt", "lastLoginAt"}, {"LastSeen", "lastSeen"}, {"DeletedAt", "deletedAt"},
	},
	schema.ModelSession: {
		{"ID", "id"}, {"CreatedAt", "createdAt"}, {"UpdatedAt", "updatedAt"},
		{"Token", "token"}, {"UserID", "userId"}, {"ExpiresAt", "expiresAt"}, {"IPAddress", "ipAddress"}, {"UserAgent", "userAgent"},
		{"ImpersonatedBy", "impersonatedBy"},
		{"ActiveOrganizationID", "activeOrganizationId"}, {"ActiveOrganizationType", "activeOrganizationType"},
		{"ActiveTeamID", "activeTeamId"}, {"ActiveOrganizationRole", "activeOrganizationRole"},
		{"DeviceToken", "deviceToken"}, {"DeviceID", "deviceId"}, {"DeviceName", "deviceName"}, {"DeviceType", "deviceType"},
		{"LastUsedAt", "lastUsedAt"},
	},
	schema.ModelAccount: {
		{"ID", "id"}, {"CreatedAt", "createdAt"}, {"UpdatedAt", "updatedAt"},
		{"AccountID", "accountId"}, {"ProviderID", "providerId"}, {"UserID", "userId"},
		{"AccessToken", "accessToken"}, {"RefreshToken", "refreshToken"}, {"IDToken", "idToken"},
		{"AccessTokenExpiresAt", "accessTokenExpiresAt"}, {"RefreshTokenExpiresAt", "refreshTokenExpiresAt"},
		{"Scope", "scope"}, {"Password", "password"},
	},
	schema.ModelVerification: {
		{"ID", "id"}, {"CreatedAt", "createdAt"}, {"UpdatedAt", "updatedAt"},
		{"Identifier", "identifier"}, {"Value", "value"}, {"ExpiresAt", "expiresAt"},
		{"UserID", "userId"}, {"CallbackURL", "callbackUrl"},
	},
}

// zeroDefaults are GORM `default:` struct tags of goauth's models: today's rows get them from the column
// definition when the Go value is zero, so the generic path writes them explicitly.
var zeroDefaults = map[string]map[string]any{
	schema.ModelUser: {"Role": "user", "Locale": "en"},
}

// newBinding binds Go type sample (a struct pointer) to model. Go fields whose registry field is missing
// (a plugin column dropped from the registry) are skipped.
func newBinding(reg *schema.Registry, model string, sample any) (*binding, error) {
	m, ok := reg.Model(model)
	if !ok {
		return nil, fmt.Errorf("adapterrepo: registry has no %q model", model)
	}
	typ := reflect.TypeOf(sample).Elem()
	b := &binding{model: m, typ: typ, byGo: map[string]int{}, static: map[string]bool{}}
	for _, pair := range staticFields[model] {
		sf, ok := typ.FieldByName(pair[0])
		if !ok {
			return nil, fmt.Errorf("adapterrepo: %s has no field %s", typ.Name(), pair[0])
		}
		b.static[pair[1]] = true
		if !m.Has(pair[1]) {
			b.unbound = append(b.unbound, sf.Index)
			continue
		}
		b.byGo[pair[0]] = len(b.fields)
		b.fields = append(b.fields, goField{goName: pair[0], field: pair[1], index: sf.Index, zeroDefault: zeroDefaults[model][pair[0]]})
	}
	return b, nil
}

// extraOf returns the Extra map of a model struct.
func extraOf(v reflect.Value) map[string]any {
	f := v.FieldByName("Extra")
	if !f.IsValid() || f.IsNil() {
		return nil
	}
	return f.Interface().(map[string]any)
}

// record converts a model struct (pointer) to a record for create: static fields plus Extra.
func (b *binding) record(ptr any) adapter.Record {
	v := reflect.ValueOf(ptr).Elem()
	rec := adapter.Record{}
	// Step 1: static fields; zero ids and timestamps are left to the factory / defaults
	for _, gf := range b.fields {
		fv := v.FieldByIndex(gf.index)
		if fv.IsZero() {
			switch {
			case gf.field == "id":
				continue
			case gf.zeroDefault != nil:
				rec[gf.field] = gf.zeroDefault
				continue
			}
		}
		rec[gf.field] = value(fv)
	}
	// Step 2: runtime fields (static names always win)
	for k, x := range extraOf(v) {
		if !b.static[k] {
			rec[k] = x
		}
	}
	return rec
}

// value returns the Go value of a struct field, nil for nil pointers.
func value(fv reflect.Value) any {
	if fv.Kind() == reflect.Pointer {
		if fv.IsNil() {
			return nil
		}
		return fv.Elem().Interface()
	}
	return fv.Interface()
}

// fill writes a record into a model struct (pointer): static fields, then every other field into Extra.
func (b *binding) fill(ptr any, rec adapter.Record) error {
	v := reflect.ValueOf(ptr).Elem()
	// Step 1: static fields
	for _, gf := range b.fields {
		if err := setField(v.FieldByIndex(gf.index), rec[gf.field]); err != nil {
			return fmt.Errorf("adapterrepo: %s.%s: %w", b.typ.Name(), gf.goName, err)
		}
	}
	for _, idx := range b.unbound {
		f := v.FieldByIndex(idx)
		f.Set(reflect.Zero(f.Type()))
	}
	// Step 2: runtime fields with a value go to Extra
	var extra map[string]any
	for k, x := range rec {
		if b.static[k] || x == nil {
			continue
		}
		if extra == nil {
			extra = map[string]any{}
		}
		extra[k] = x
	}
	v.FieldByName("Extra").Set(reflect.ValueOf(extra))
	return nil
}

// setField assigns a record value (canonical Go type) to a struct field.
func setField(f reflect.Value, x any) error {
	if x == nil {
		f.Set(reflect.Zero(f.Type()))
		return nil
	}
	target := f
	if f.Kind() == reflect.Pointer {
		target = reflect.New(f.Type().Elem()).Elem()
	}
	xv := reflect.ValueOf(x)
	switch {
	case xv.Type().AssignableTo(target.Type()):
		target.Set(xv)
	case xv.Kind() == reflect.String && target.Kind() == reflect.String,
		xv.Kind() == reflect.Bool && target.Kind() == reflect.Bool,
		(xv.CanInt() || xv.CanFloat()) && (target.CanInt() || target.CanFloat()):
		target.Set(xv.Convert(target.Type()))
	default:
		if t, ok := x.(time.Time); ok && target.Type() == reflect.TypeOf(time.Time{}) {
			target.Set(reflect.ValueOf(t))
			break
		}
		return fmt.Errorf("cannot assign %T to %s", x, f.Type())
	}
	if f.Kind() == reflect.Pointer {
		f.Set(target.Addr())
	}
	return nil
}

// field resolves an update key: a Go field name (what callers use today), a registry field name, or a
// column name (GORM's Updates accepted those too).
func (b *binding) field(key string) (string, bool) {
	if i, ok := b.byGo[key]; ok {
		return b.fields[i].field, true
	}
	if b.model.Has(key) {
		return key, true
	}
	if f, ok := b.model.FieldByColumn(key); ok {
		return f.Name, true
	}
	return "", false
}

// updates converts an update map (Go field names, registry names or columns) to a record.
func (b *binding) updates(data map[string]any) (adapter.Record, error) {
	rec := adapter.Record{}
	for k, x := range data {
		name, ok := b.field(k)
		if !ok {
			return nil, fmt.Errorf("adapterrepo: unknown field %q on %s", k, b.model.Name())
		}
		rec[name] = x
	}
	return rec, nil
}

// bindingSamples are the Go model types New binds to the core registry models.
var bindingSamples = map[string]any{
	schema.ModelUser:         &models.User{},
	schema.ModelSession:      &models.Session{},
	schema.ModelAccount:      &models.Account{},
	schema.ModelVerification: &models.Verification{},
}

// fieldOf returns the Go field name of a model struct pointer.
func fieldOf(ptr any, name string) reflect.Value {
	return reflect.ValueOf(ptr).Elem().FieldByName(name)
}
