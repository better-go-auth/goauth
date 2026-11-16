package providers

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// ErrClientIDAndSecretRequired mirrors better-auth's CLIENT_ID_AND_SECRET_REQUIRED.
var ErrClientIDAndSecretRequired = errors.New("CLIENT_ID_AND_SECRET_REQUIRED")

// base carries what every built-in provider shares.
type base struct {
	ProviderOptions
	id   string
	name string
}

func (b *base) ID() string   { return b.id }
func (b *base) Name() string { return b.name }

// refresh runs the RefreshAccessToken override or the standard refresh_token grant.
func (b *base) refresh(ctx context.Context, refreshToken, tokenEndpoint string, extra map[string]string) (*OAuth2Tokens, error) {
	if b.RefreshAccessToken != nil {
		return b.RefreshAccessToken(ctx, refreshToken)
	}
	return Refresh(ctx, b.client(), RefreshRequest{
		TokenEndpoint: tokenEndpoint,
		RefreshToken:  refreshToken,
		ClientID:      b.ClientID,
		ClientSecret:  b.ClientSecret,
		Extra:         extra,
	})
}

// exchange runs the standard authorization_code grant.
func (b *base) exchange(ctx context.Context, in ValidateCodeInput, tokenEndpoint string, withVerifier bool) (*OAuth2Tokens, error) {
	x := CodeExchange{
		TokenEndpoint: tokenEndpoint,
		Code:          in.Code,
		RedirectURI:   pick(b.RedirectURI, in.RedirectURI),
		DeviceID:      in.DeviceID,
		ClientID:      b.ClientID,
		ClientSecret:  b.ClientSecret,
	}
	if withVerifier {
		x.CodeVerifier = in.CodeVerifier
	}
	return ExchangeCode(ctx, b.client(), x)
}

// verifyIDToken applies the shared id_token policy (disable flag, override, nonce) around VerifyJWT.
// extra runs provider specific claim checks.
func (b *base) verifyIDToken(ctx context.Context, token, nonce string, check IDTokenCheck, extra func(claims map[string]any) bool) (bool, error) {
	// Step 1: id_token sign-in can be turned off or replaced
	if b.DisableIDTokenSignIn {
		return false, nil
	}
	if b.VerifyIDToken != nil {
		return b.VerifyIDToken(ctx, token, nonce)
	}
	// Step 2: signature + registered claims
	claims, err := VerifyJWT(ctx, b.client(), token, check)
	if err != nil {
		return false, nil
	}
	// Step 3: nonce binding
	if nonce != "" {
		if n, _ := claims["nonce"].(string); n != nonce {
			return false, nil
		}
	}
	// Step 4: provider specific checks
	if extra != nil && !extra(claims) {
		return false, nil
	}
	return true, nil
}

// audiences returns the accepted audiences for id_token verification (the client id).
func (b *base) audiences() []string {
	if b.ClientID == "" {
		return nil
	}
	return []string{b.ClientID}
}

// httpClient exposes the configured HTTP client.
func (b *base) httpClient() *http.Client { return b.client() }

// profileString returns the first non-empty string among keys of profile.
func profileString(profile map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := strings.TrimSpace(stringOf(profile[k])); s != "" {
			return stringOf(profile[k])
		}
	}
	return ""
}
