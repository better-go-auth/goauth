package goauth

import (
	"fmt"

	plugin "github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/social"
	socialproviders "github.com/better-go-auth/goauth/src/plugins/social/providers"
)

// socialProviderSource is implemented by plugins whose providers better-auth also registers as social
// providers (generic-oauth: its `init` concatenates them into ctx.socialProviders).
type socialProviderSource interface {
	SocialProviders() []socialproviders.Provider
}

// withSocialPlugin is better-auth's core `socialProviders`: when AuthConfig.SocialProviders is set (or a plugin
// such as generic-oauth contributes providers) the social plugin is installed, so /sign-in/social,
// /callback/{id}, /link-social, /get-access-token, /refresh-token and /account-info exist without passing
// social.New(...) explicitly. It returns the plugin list to initialize.
//
//   - No social plugin passed: one is built from SocialProviders and AuthConfig.Account (social.FromAuthConfig).
//   - A social plugin passed as well: SocialProviders are added to it; a provider id configured in both
//     places is an error (conflicting configuration).
//   - generic-oauth providers are appended unless a provider with the same id is already configured.
func withSocialPlugin(opts GoAuthOptions) ([]plugin.Plugin, error) {
	// Step 1: the explicit social plugin and the providers other plugins contribute
	var explicit *social.Plugin
	var contributed []socialproviders.Provider
	for _, p := range opts.Plugins {
		if p == nil {
			continue
		}
		if sp, ok := p.(*social.Plugin); ok {
			explicit = sp
			continue
		}
		if src, ok := p.(socialProviderSource); ok {
			contributed = append(contributed, src.SocialProviders()...)
		}
	}
	if len(opts.SocialProviders) == 0 && len(contributed) == 0 {
		return opts.Plugins, nil
	}

	// Step 2: the plugin to configure: the explicit one, or one built from the core options
	list := opts.Plugins
	target := explicit
	if target == nil {
		target = social.FromAuthConfig(opts.AuthConfig)
		list = append(append([]plugin.Plugin(nil), opts.Plugins...), target)
	} else if len(opts.SocialProviders) > 0 {
		if err := target.AddProviders(opts.SocialProviders...); err != nil {
			return nil, fmt.Errorf("goauth: AuthConfig.SocialProviders conflicts with the social plugin passed in Plugins: %w", err)
		}
	}

	// Step 3: generic-oauth providers become social providers (ids already configured win)
	for _, p := range contributed {
		if p == nil || target.HasProvider(p.ID()) {
			continue
		}
		if err := target.AddProviders(p); err != nil {
			return nil, fmt.Errorf("goauth: %w", err)
		}
	}
	return list, nil
}
