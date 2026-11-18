package models

// The Get/SetExtra methods make the core models schema.ExtraGetter / schema.ExtraSetter, so runtime field
// values are read with schema.Get[T](user, "loyaltyTier") and written with schema.Set(user, "loyaltyTier", v).

// GetExtra returns the runtime field value stored under key.
func (u *User) GetExtra(key string) (any, bool) { return getExtra(u.Extra, key) }

// SetExtra stores a runtime field value under key.
func (u *User) SetExtra(key string, value any) { u.Extra = setExtra(u.Extra, key, value) }

// GetExtra returns the runtime field value stored under key.
func (s *Session) GetExtra(key string) (any, bool) { return getExtra(s.Extra, key) }

// SetExtra stores a runtime field value under key.
func (s *Session) SetExtra(key string, value any) { s.Extra = setExtra(s.Extra, key, value) }

// GetExtra returns the runtime field value stored under key.
func (a *Account) GetExtra(key string) (any, bool) { return getExtra(a.Extra, key) }

// SetExtra stores a runtime field value under key.
func (a *Account) SetExtra(key string, value any) { a.Extra = setExtra(a.Extra, key, value) }

// GetExtra returns the runtime field value stored under key.
func (v *Verification) GetExtra(key string) (any, bool) { return getExtra(v.Extra, key) }

// SetExtra stores a runtime field value under key.
func (v *Verification) SetExtra(key string, value any) { v.Extra = setExtra(v.Extra, key, value) }

func getExtra(m map[string]any, key string) (any, bool) {
	v, ok := m[key]
	return v, ok
}

func setExtra(m map[string]any, key string, value any) map[string]any {
	if m == nil {
		m = map[string]any{}
	}
	m[key] = value
	return m
}
