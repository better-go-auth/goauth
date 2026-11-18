package services

import (
	"testing"

	"github.com/better-go-auth/goauth/src/plugins/one-tap/config"
	socialconfig "github.com/better-go-auth/goauth/src/plugins/social/config"
	"github.com/better-go-auth/goauth/src/plugins/social/providers"
)

func TestToBoolean(t *testing.T) {
	// better-auth's toBoolean: only true and "true" are true
	cases := map[any]bool{true: true, "true": true, false: false, "false": false, "TRUE": false, "1": false, 1: false, nil: false}
	for in, want := range cases {
		if got := toBoolean(in); got != want {
			t.Errorf("toBoolean(%#v) = %v, want %v", in, got, want)
		}
	}
}

type fakeSocial struct{ cfg socialconfig.SocialConfig }

func (f fakeSocial) Config() socialconfig.SocialConfig { return f.cfg }

func TestClientIDResolution(t *testing.T) {
	google := providers.Google(providers.GoogleOptions{ProviderOptions: providers.ProviderOptions{ClientID: "from-social"}})
	github := providers.GitHub(providers.GitHubOptions{ProviderOptions: providers.ProviderOptions{ClientID: "gh"}})
	// Step 1: the plugin's own client ID wins
	s := &Service{cfg: config.OneTapConfig{ClientID: "own"}, social: fakeSocial{socialconfig.SocialConfig{Providers: []providers.Provider{google}}}}
	if got := s.ClientID(); got != "own" {
		t.Fatalf("own: %q", got)
	}
	// Step 2: else the social plugin's google provider
	s.cfg.ClientID = ""
	if got := s.ClientID(); got != "from-social" {
		t.Fatalf("social: %q", got)
	}
	// Step 3: no google provider, no social plugin: no audience
	s.social = fakeSocial{socialconfig.SocialConfig{Providers: []providers.Provider{github}}}
	if got := s.ClientID(); got != "" {
		t.Fatalf("no google: %q", got)
	}
	s.social = nil
	if got := s.ClientID(); got != "" {
		t.Fatalf("no social: %q", got)
	}
}

func TestDefaults(t *testing.T) {
	c := config.OneTapConfig{}.WithDefaults()
	if c.JWKSURL != config.GoogleJWKSURL || c.HTTPClient == nil {
		t.Fatalf("defaults = %+v", c)
	}
}
