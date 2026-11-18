package services

import (
	"bytes"
	"encoding/json"
	"time"
)

// StatePackage replaces the OAuth `state` sent to the provider by a preview deployment (better-auth's
// statePackage): the provider's original state, the preview's state payload encrypted, and a marker. The
// whole package is encrypted again before it goes into the authorization URL.
type StatePackage struct {
	State        string `json:"state"`
	StateCookie  string `json:"stateCookie"`
	IsOAuthProxy bool   `json:"isOAuthProxy"`
}

// ProxyStateData are the fields of the preview's OAuth state payload the production callback reads
// (better-auth's stateData; other keys are ignored).
type ProxyStateData struct {
	CallbackURL   string  `json:"callbackURL"`
	CodeVerifier  string  `json:"codeVerifier"`
	ErrorURL      string  `json:"errorURL,omitempty"`
	NewUserURL    string  `json:"newUserURL,omitempty"`
	RequestSignUp *bool   `json:"requestSignUp,omitempty"`
	OAuthState    *string `json:"oauthState,omitempty"`
}

// ProfileUserInfo is the provider user in the encrypted profile (better-auth's payload.userInfo).
type ProfileUserInfo struct {
	ID            string  `json:"id"`
	Email         string  `json:"email"`
	Name          string  `json:"name"`
	Image         *string `json:"image,omitempty"`
	EmailVerified bool    `json:"emailVerified"`
}

// ProfileAccount is the provider account in the encrypted profile (better-auth's payload.account).
type ProfileAccount struct {
	ProviderID            string     `json:"providerId"`
	AccountID             string     `json:"accountId"`
	AccessToken           string     `json:"accessToken,omitempty"`
	RefreshToken          string     `json:"refreshToken,omitempty"`
	IDToken               string     `json:"idToken,omitempty"`
	AccessTokenExpiresAt  *time.Time `json:"accessTokenExpiresAt,omitempty"`
	RefreshTokenExpiresAt *time.Time `json:"refreshTokenExpiresAt,omitempty"`
	Scope                 *string    `json:"scope,omitempty"`
}

// ProfilePayload is what the production callback sends to the preview's /oauth-proxy-callback, encrypted, in
// the `profile` query parameter (better-auth's payload). Timestamp is the creation time in milliseconds.
type ProfilePayload struct {
	UserInfo      *ProfileUserInfo `json:"userInfo"`
	Account       *ProfileAccount  `json:"account"`
	State         string           `json:"state"`
	CallbackURL   string           `json:"callbackURL"`
	NewUserURL    string           `json:"newUserURL,omitempty"`
	ErrorURL      string           `json:"errorURL,omitempty"`
	DisableSignUp bool             `json:"disableSignUp"`
	Timestamp     *float64         `json:"timestamp"`
}

// marshalJSON encodes v like JSON.stringify (no HTML escaping, no trailing newline).
func marshalJSON(v any) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	return string(bytes.TrimRight(buf.Bytes(), "\n")), nil
}

// replaceJSONField returns the JSON object body with key set to value, keeping the order of the other keys
// (better-auth's {...signInResponse, url}). ok is false when body is not a JSON object.
func replaceJSONField(body []byte, key string, value any) ([]byte, bool) {
	// Step 1: read the top-level keys in order
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, false
	}
	type field struct {
		key string
		raw json.RawMessage
	}
	var fields []field
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, false
		}
		k, ok := tok.(string)
		if !ok {
			return nil, false
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, false
		}
		fields = append(fields, field{k, raw})
	}
	// Step 2: replace (or append) the key
	encoded, err := marshalJSON(value)
	if err != nil {
		return nil, false
	}
	replaced := false
	for i := range fields {
		if fields[i].key == key {
			fields[i].raw = json.RawMessage(encoded)
			replaced = true
		}
	}
	if !replaced {
		fields = append(fields, field{key, json.RawMessage(encoded)})
	}
	// Step 3: write the object back
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, f := range fields {
		if i > 0 {
			buf.WriteByte(',')
		}
		k, _ := marshalJSON(f.key)
		buf.WriteString(k)
		buf.WriteByte(':')
		buf.Write(f.raw)
	}
	buf.WriteByte('}')
	return buf.Bytes(), true
}
