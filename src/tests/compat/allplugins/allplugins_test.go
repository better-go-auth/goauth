// Package allplugins installs every goauth plugin into one server with Huma's default configuration: no two
// plugins may register response types under the same OpenAPI schema name (Huma's default namer uses the Go
// type name and panics on a duplicate), route path or operation ID.
package allplugins_test

import (
	"context"
	"encoding"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	goauth "github.com/better-go-auth/goauth"
	"github.com/better-go-auth/goauth/src/config"
	plugin "github.com/better-go-auth/goauth/src/plugins"
	accesstoken "github.com/better-go-auth/goauth/src/plugins/access-token"
	accesstokenconfig "github.com/better-go-auth/goauth/src/plugins/access-token/config"
	"github.com/better-go-auth/goauth/src/plugins/admin"
	adminrepo "github.com/better-go-auth/goauth/src/plugins/admin/repository"
	"github.com/better-go-auth/goauth/src/plugins/anonymous"
	anonconfig "github.com/better-go-auth/goauth/src/plugins/anonymous/config"
	"github.com/better-go-auth/goauth/src/plugins/bearer"
	bearerconfig "github.com/better-go-auth/goauth/src/plugins/bearer/config"
	"github.com/better-go-auth/goauth/src/plugins/captcha"
	captchaconfig "github.com/better-go-auth/goauth/src/plugins/captcha/config"
	customsession "github.com/better-go-auth/goauth/src/plugins/custom-session"
	customsessionconfig "github.com/better-go-auth/goauth/src/plugins/custom-session/config"
	emailotp "github.com/better-go-auth/goauth/src/plugins/email-otp"
	emailotpconfig "github.com/better-go-auth/goauth/src/plugins/email-otp/config"
	genericoauth "github.com/better-go-auth/goauth/src/plugins/generic-oauth"
	genericoauthconfig "github.com/better-go-auth/goauth/src/plugins/generic-oauth/config"
	"github.com/better-go-auth/goauth/src/plugins/haveibeenpwned"
	hibpconfig "github.com/better-go-auth/goauth/src/plugins/haveibeenpwned/config"
	jwtplugin "github.com/better-go-auth/goauth/src/plugins/jwt"
	jwtconfig "github.com/better-go-auth/goauth/src/plugins/jwt/config"
	lastloginmethod "github.com/better-go-auth/goauth/src/plugins/last-login-method"
	llmconfig "github.com/better-go-auth/goauth/src/plugins/last-login-method/config"
	magiclink "github.com/better-go-auth/goauth/src/plugins/magic-link"
	magiclinkconfig "github.com/better-go-auth/goauth/src/plugins/magic-link/config"
	multisession "github.com/better-go-auth/goauth/src/plugins/multi-session"
	msconfig "github.com/better-go-auth/goauth/src/plugins/multi-session/config"
	oauthproxy "github.com/better-go-auth/goauth/src/plugins/oauth-proxy"
	oauthproxyconfig "github.com/better-go-auth/goauth/src/plugins/oauth-proxy/config"
	onetap "github.com/better-go-auth/goauth/src/plugins/one-tap"
	onetapconfig "github.com/better-go-auth/goauth/src/plugins/one-tap/config"
	onetimetoken "github.com/better-go-auth/goauth/src/plugins/one-time-token"
	ottconfig "github.com/better-go-auth/goauth/src/plugins/one-time-token/config"
	openapi "github.com/better-go-auth/goauth/src/plugins/open-api"
	openapiconfig "github.com/better-go-auth/goauth/src/plugins/open-api/config"
	"github.com/better-go-auth/goauth/src/plugins/org"
	orgconfig "github.com/better-go-auth/goauth/src/plugins/org/config"
	"github.com/better-go-auth/goauth/src/plugins/passkey"
	pkconfig "github.com/better-go-auth/goauth/src/plugins/passkey/config"
	phonenumber "github.com/better-go-auth/goauth/src/plugins/phone-number"
	phoneconfig "github.com/better-go-auth/goauth/src/plugins/phone-number/config"
	"github.com/better-go-auth/goauth/src/plugins/social"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
	twofactor "github.com/better-go-auth/goauth/src/plugins/two-factor"
	tfconfig "github.com/better-go-auth/goauth/src/plugins/two-factor/config"
	"github.com/better-go-auth/goauth/src/plugins/username"
	usernameconfig "github.com/better-go-auth/goauth/src/plugins/username/config"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// everyPlugin returns one instance of every goauth plugin, with the optional features that register extra
// routes turned on (organization teams and dynamic access control).
func everyPlugin(t *testing.T) []plugin.Plugin {
	t.Helper()
	adminPlugin, err := admin.New(adminrepo.AdminRepositories{})
	require.NoError(t, err)
	orgPlugin, err := org.New(org.OrgOptions{Config: orgconfig.OrgConfig{
		Teams:                &orgconfig.TeamsConfig{Enabled: true},
		DynamicAccessControl: &orgconfig.DynamicAccessControlConfig{Enabled: true},
	}})
	require.NoError(t, err)
	at := accesstokenconfig.DefaultAccessTokenConfig()
	socialPlugin := social.New(socialconfig.SocialConfig{Providers: []providers.Provider{
		providers.Google(providers.GoogleOptions{ProviderOptions: providers.ProviderOptions{ClientID: "google-id", ClientSecret: "google-secret"}}),
	}})
	return []plugin.Plugin{
		socialPlugin,
		bearer.New(bearerconfig.BearerConfig{}),
		accesstoken.New(at),
		jwtplugin.New(jwtconfig.JWTConfig{}),
		adminPlugin,
		orgPlugin,
		anonymous.New(anonconfig.AnonymousConfig{}),
		captcha.New(captchaconfig.CaptchaConfig{Provider: captchaconfig.CloudflareTurnstile, SecretKey: "secret", Endpoints: []string{"/never-protected"}}),
		customsession.New(func(_ context.Context, s *customsessionconfig.Session) (any, error) { return s.Raw, nil }),
		emailotp.New(emailotpconfig.EmailOTPConfig{SendVerificationOTP: func(emailotpconfig.SendVerificationOTPData, *http.Request) error { return nil }}),
		genericoauth.New(genericoauthconfig.Config{Providers: []genericoauthconfig.ProviderConfig{{
			ProviderID: "acme", ClientID: "id", ClientSecret: "secret",
			AuthorizationURL: "https://acme.example/authorize", TokenURL: "https://acme.example/token", UserInfoURL: "https://acme.example/userinfo",
		}}}),
		haveibeenpwned.New(hibpconfig.HaveIBeenPwnedConfig{}),
		lastloginmethod.New(llmconfig.LastLoginMethodConfig{}),
		magiclink.New(magiclinkconfig.MagicLinkConfig{SendMagicLink: func(magiclinkconfig.SendMagicLinkData, *http.Request) error { return nil }}),
		multisession.New(msconfig.MultiSessionConfig{}),
		oauthproxy.New(oauthproxyconfig.OAuthProxyConfig{}, oauthproxy.WithSocial(socialPlugin)),
		onetap.New(onetapconfig.OneTapConfig{}, onetap.WithSocialPlugin(socialPlugin)),
		onetimetoken.New(ottconfig.OneTimeTokenConfig{}),
		openapi.New(openapiconfig.OpenAPIConfig{}),
		passkey.New(pkconfig.PasskeyConfig{RPID: "localhost", RPName: "all plugins", Origin: []string{"http://localhost:3000"}}),
		phonenumber.New(phoneconfig.PhoneNumberConfig{SendOTP: func(phoneconfig.OTPData, *http.Request) error { return nil }}),
		twofactor.New(tfconfig.Config{Issuer: "all plugins"}),
		username.New(usernameconfig.UsernameConfig{}),
	}
}

// setupEveryPlugin runs SetupGoAuth with every plugin on a fresh SQLite database and api.
func setupEveryPlugin(t *testing.T, api huma.API) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(fmt.Sprintf("file:allplugins_%s?mode=memory&cache=shared", uuid.NewString())), &gorm.Config{Logger: logger.Discard})
	require.NoError(t, err)
	_, err = goauth.SetupGoAuth(context.Background(), api, goauth.GoAuthOptions{
		Conn:    db,
		Plugins: everyPlugin(t),
		AuthConfig: config.AuthConfig{
			BaseURL: "http://localhost:3000", Secret: compattest.TestSecret,
			TrustedOrigins: []string{"http://localhost:3000"},
		},
	})
	require.NoError(t, err)
}

// getsRef reports whether Huma's map registry stores typ under its name (named structs that don't provide
// their own schema or unmarshal from text, like time.Time); only those names must be unique.
func getsRef(typ reflect.Type) bool {
	if typ.Kind() != reflect.Struct || typ.Name() == "" || typ == reflect.TypeOf(time.Time{}) {
		return false
	}
	provider := reflect.TypeOf((*huma.SchemaProvider)(nil)).Elem()
	text := reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()
	ptr := reflect.PointerTo(typ)
	return !typ.Implements(provider) && !ptr.Implements(provider) && !typ.Implements(text) && !ptr.Implements(text)
}

// TestSchemaNamesAreUnique lists every Go type goauth registers under each default schema name (a namer
// that never panics records them) and fails with all collisions at once.
func TestSchemaNamesAreUnique(t *testing.T) {
	// Step 1: record name → types while qualifying names so setup completes
	seen := map[string]map[string]bool{}
	cfg := huma.DefaultConfig("names", "1")
	cfg.Components.Schemas = huma.NewMapRegistry("#/components/schemas/", func(typ reflect.Type, hint string) string {
		name := huma.DefaultSchemaNamer(typ, hint)
		for typ.Kind() == reflect.Pointer {
			typ = typ.Elem()
		}
		if getsRef(typ) {
			if seen[name] == nil {
				seen[name] = map[string]bool{}
			}
			seen[name][typ.PkgPath()+"."+typ.Name()] = true
		}
		return typ.PkgPath() + "." + name
	})
	setupEveryPlugin(t, humago.New(http.NewServeMux(), cfg))
	// Step 2: every default name belongs to one type
	var dups []string
	for name, types := range seen {
		if len(types) > 1 {
			list := make([]string, 0, len(types))
			for typ := range types {
				list = append(list, typ)
			}
			sort.Strings(list)
			dups = append(dups, name+": "+strings.Join(list, ", "))
		}
	}
	sort.Strings(dups)
	require.Empty(t, dups, "schema names shared by several Go types")
}

// TestEveryPluginWithHumaDefaults sets every plugin up on an API built with huma.DefaultConfig (the default
// schema namer) and checks that the OpenAPI document (and the open-api plugin's better-auth document) is
// generated.
func TestEveryPluginWithHumaDefaults(t *testing.T) {
	// Step 1: setup must not panic (duplicate schema names) nor fail (duplicate routes)
	mux := http.NewServeMux()
	setupEveryPlugin(t, humago.New(mux, huma.DefaultConfig("all plugins", "1")))

	// Step 2: Huma's OpenAPI document lists the plugin operations
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := http.Get(srv.URL + "/openapi.json")
	require.NoError(t, err)
	defer res.Body.Close()
	require.Equal(t, http.StatusOK, res.StatusCode)
	var doc struct {
		Paths map[string]any `json:"paths"`
	}
	require.NoError(t, json.NewDecoder(res.Body).Decode(&doc))
	for _, path := range []string{
		"/api/auth/organization/create", "/api/auth/organization/create-role", "/api/auth/organization/create-team",
		"/api/auth/sign-in/anonymous", "/api/auth/email-otp/send-verification-otp", "/api/auth/sign-in/magic-link",
		"/api/auth/two-factor/enable", "/api/auth/passkey/list-user-passkeys", "/api/auth/admin/list-users",
		"/api/auth/token", "/api/auth/multi-session/list-device-sessions", "/api/auth/phone-number/send-otp",
	} {
		require.Contains(t, doc.Paths, path)
	}

	// Step 3: the open-api plugin's better-auth document is generated from the same API
	res2, err := http.Get(srv.URL + "/api/auth/open-api/generate-schema")
	require.NoError(t, err)
	defer res2.Body.Close()
	require.Equal(t, http.StatusOK, res2.StatusCode)
}
