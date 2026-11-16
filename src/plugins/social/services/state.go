package services

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
)

// Cookie base names of the OAuth state (better-auth's createAuthCookie("state") / ("oauth_state")).
const (
	StateCookie      = "state"
	OAuthStateCookie = "oauth_state"
)

const (
	// stateTTL is the expiresAt stored inside the state (10 minutes).
	stateTTL = 10 * time.Minute
	// stateCookieMaxAge is the signed `state` cookie lifetime of the database strategy.
	stateCookieMaxAge = 300
	// oauthStateCookieMaxAge is the encrypted `oauth_state` cookie lifetime of the cookie strategy.
	oauthStateCookieMaxAge = 600
)

// StateLink is set when the flow links an account to a signed-in user (/link-social).
type StateLink struct {
	Email  string `json:"email"`
	UserID string `json:"userId"`
}

// StateData is better-auth's OAuth state payload.
type StateData struct {
	CallbackURL   string     `json:"callbackURL"`
	CodeVerifier  string     `json:"codeVerifier"`
	ErrorURL      string     `json:"errorURL,omitempty"`
	NewUserURL    string     `json:"newUserURL,omitempty"`
	Link          *StateLink `json:"link,omitempty"`
	ExpiresAt     int64      `json:"expiresAt"`
	RequestSignUp *bool      `json:"requestSignUp,omitempty"`
	OAuthState    string     `json:"oauthState,omitempty"`
	// AdditionalData is the sign-in's additionalData, spread into the payload like better-auth does.
	AdditionalData map[string]any `json:"-"`
}

// marshal spreads AdditionalData first so the state fields always win (better-auth's {...additionalData, ...}).
func (d *StateData) marshal() (string, error) {
	// Step 1: the additional data
	out := map[string]any{}
	for k, v := range d.AdditionalData {
		out[k] = v
	}
	// Step 2: overlay the state fields
	raw, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		return "", err
	}
	for k, v := range fields {
		out[k] = v
	}
	b, err := json.Marshal(out)
	return string(b), err
}

var stateKeys = map[string]bool{"callbackURL": true, "codeVerifier": true, "errorURL": true, "newUserURL": true, "link": true, "expiresAt": true, "requestSignUp": true, "oauthState": true}

// parseStateData decodes and validates a payload (better-auth's stateDataSchema).
func parseStateData(raw string) (*StateData, error) {
	// Step 1: decode the typed fields
	var d StateData
	if err := json.Unmarshal([]byte(raw), &d); err != nil {
		return nil, err
	}
	// Step 2: required fields
	var all map[string]any
	if err := json.Unmarshal([]byte(raw), &all); err != nil {
		return nil, err
	}
	if _, ok := all["callbackURL"].(string); !ok {
		return nil, errors.New("state: callbackURL is required")
	}
	if _, ok := all["codeVerifier"].(string); !ok {
		return nil, errors.New("state: codeVerifier is required")
	}
	if _, ok := all["expiresAt"].(float64); !ok {
		return nil, errors.New("state: expiresAt is required")
	}
	// Step 3: keep the additional data
	for k, v := range all {
		if !stateKeys[k] {
			if d.AdditionalData == nil {
				d.AdditionalData = map[string]any{}
			}
			d.AdditionalData[k] = v
		}
	}
	return &d, nil
}

// StateError is better-auth's StateError: a machine code plus the per-flow error URL when it is known.
type StateError struct {
	Code     string
	ErrorURL string
	Message  string
}

func (e *StateError) Error() string { return e.Message }

const randomAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_"

// randomString is better-auth's generateRandomString (alphabet a-z 0-9 A-Z - _; 64 symbols, so no modulo bias).
func randomString(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("social: crypto/rand failed: " + err.Error())
	}
	for i, b := range buf {
		buf[i] = randomAlphabet[int(b)%len(randomAlphabet)]
	}
	return string(buf)
}

// stateRequest are the request fields that end up in the state.
type stateRequest struct {
	CallbackURL      string
	ErrorCallbackURL string
	NewUserURL       string
	RequestSignUp    bool
	AdditionalData   map[string]any
}

// generatedState is the result of generateState.
type generatedState struct {
	State        string
	CodeVerifier string
	Cookies      []http.Cookie
}

// generateState is better-auth's generateState + generateGenericState.
func (s *Service) generateState(ctx context.Context, link *StateLink, in stateRequest) (*generatedState, error) {
	// Step 1: the callback URL defaults to the app's base URL
	callbackURL := in.CallbackURL
	if callbackURL == "" {
		callbackURL = s.kit.Conf.BaseURL
	}
	if callbackURL == "" {
		return nil, autherr.ErrCallbackURLRequired
	}
	// Step 2: PKCE verifier, the state value and the payload
	data := &StateData{
		CallbackURL:    callbackURL,
		CodeVerifier:   randomString(128),
		ErrorURL:       in.ErrorCallbackURL,
		NewUserURL:     in.NewUserURL,
		Link:           link,
		ExpiresAt:      time.Now().Add(stateTTL).UnixMilli(),
		AdditionalData: in.AdditionalData,
	}
	if in.RequestSignUp {
		data.RequestSignUp = socialconfig.Bool(true)
	}
	state := randomString(32)
	data.OAuthState = state
	payload, err := data.marshal()
	if err != nil {
		return nil, ErrUnableToCreateVerification
	}
	out := &generatedState{State: state, CodeVerifier: data.CodeVerifier}

	// Step 3a: cookie strategy: the whole payload, encrypted, in oauth_state
	if s.cfg.Strategy() == socialconfig.StateCookie {
		enc, err := authcrypto.SymmetricEncrypt(s.kit.Conf.Secret, payload)
		if err != nil {
			return nil, ErrUnableToCreateVerification
		}
		out.Cookies = append(out.Cookies, s.kit.Cookies.Cookie(OAuthStateCookie, enc, oauthStateCookieMaxAge))
		return out, nil
	}

	// Step 3b: database strategy: a signed state cookie + a verification row keyed by the state
	out.Cookies = append(out.Cookies, s.kit.Cookies.SignedCookie(StateCookie, state, stateCookieMaxAge))
	if _, err := s.kit.Repos.UpsertVerificationValue(ctx, &models.Verification{
		Identifier: state,
		Value:      payload,
		ExpiresAt:  time.Now().Add(stateTTL).UTC(),
	}); err != nil {
		return nil, ErrUnableToCreateVerification
	}
	return out, nil
}

// parseState is better-auth's parseGenericState. It returns the cookies to set (the expired state cookie)
// along with the data, or a *StateError.
func (s *Service) parseState(ctx context.Context, state string) (*StateData, []http.Cookie, error) {
	// Step 1: the state parameter is mandatory
	if state == "" {
		return nil, nil, &StateError{Code: "state_not_found", Message: "State not found in OAuth callback"}
	}
	var (
		data    *StateData
		cookies []http.Cookie
	)
	cookieHeader := ""
	if req := s.kit.Request(ctx); req != nil {
		cookieHeader = req.Header.Get("Cookie")
	}

	if s.cfg.Strategy() == socialconfig.StateCookie {
		// Step 2a: cookie strategy: decrypt oauth_state and compare its embedded state
		enc, ok := s.kit.Cookies.ReadCookie(cookieHeader, OAuthStateCookie)
		if !ok || enc == "" {
			return nil, nil, &StateError{Code: "state_mismatch", Message: "State mismatch: auth state cookie not found"}
		}
		plain, err := authcrypto.SymmetricDecrypt(s.kit.Conf.Secret, enc)
		if err == nil {
			data, err = parseStateData(plain)
		}
		if err != nil {
			return nil, nil, &StateError{Code: "state_invalid", Message: "State invalid: Failed to decrypt or parse auth state"}
		}
		if data.OAuthState == "" || data.OAuthState != state {
			return nil, nil, &StateError{Code: "state_mismatch", ErrorURL: data.ErrorURL, Message: "State mismatch: OAuth state parameter does not match stored state"}
		}
		cookies = append(cookies, s.kit.Cookies.ExpireCookie(OAuthStateCookie))
	} else {
		// Step 2b: database strategy: load the verification row
		v, err := pluginkit.AcceptNotFound(s.kit.Repos.FindVerificationValue(ctx, state))
		if err != nil {
			return nil, nil, &StateError{Code: "internal_server_error", Message: err.Error()}
		}
		if v == nil {
			return nil, nil, &StateError{Code: "state_mismatch", Message: "State mismatch: verification not found"}
		}
		data, err = parseStateData(v.Value)
		if err != nil {
			// a schema error is not a StateError upstream, so it maps to internal_server_error
			return nil, nil, &StateError{Code: "internal_server_error", Message: err.Error()}
		}
		if data.OAuthState != "" && data.OAuthState != state {
			return nil, nil, &StateError{Code: "state_mismatch", ErrorURL: data.ErrorURL, Message: "State mismatch: OAuth state parameter does not match stored state"}
		}
		// Step 3b: the signed state cookie binds the flow to the browser that started it
		if !s.cfg.SkipStateCookieCheck {
			if cv, ok := s.kit.Cookies.ReadSigned(cookieHeader, StateCookie); !ok || cv != state {
				return nil, nil, &StateError{Code: "state_mismatch", ErrorURL: data.ErrorURL, Message: "State mismatch: State not persisted correctly"}
			}
		}
		// Step 4b: one-time use
		cookies = append(cookies, s.kit.Cookies.ExpireCookie(StateCookie))
		_ = s.kit.Repos.DeleteVerificationByIdentifier(ctx, state)
	}

	// Step 5: the payload carries its own expiry
	if data.ExpiresAt < time.Now().UnixMilli() {
		return nil, cookies, &StateError{Code: "state_mismatch", ErrorURL: data.ErrorURL, Message: "Invalid state: request expired"}
	}
	return data, cookies, nil
}
