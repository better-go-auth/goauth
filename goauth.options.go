package goauth

import (
	"errors"
)

// SetDefaults sets sensible default values for unspecified options.
func (opts *GoAuthOptions) SetDefaults() {
	opts.AuthConfig.SetDefaults()
	if opts.SecondaryStorage == nil {
		opts.GoAuth.Session.JWT.CheckRevocation = true
	}
}

// Validate verifies that required options are present and valid.
func (opts *GoAuthOptions) Validate() error {
	if opts.Conn == nil && opts.Repositories == nil {
		return errors.New("goauth: either database connection (Conn) or Repositories must be provided")
	}
	
	return opts.AuthConfig.Validate()
}
