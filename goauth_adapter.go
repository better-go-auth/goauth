package goauth

import (
	"fmt"
	"strings"

	"github.com/better-go-auth/goauth/src/adapter"
	plugin "github.com/better-go-auth/goauth/src/plugins"
)

// adapterIDGenerator returns the id generator GoAuthOptions.Adapter's backend prefers (MongoDB: ObjectId hex
// strings) when the configuration chose none (Advanced.Database.GenerateID and IDFormat unset); nil
// otherwise.
func adapterIDGenerator(opts GoAuthOptions) func() string {
	if opts.Adapter == nil || opts.Advanced.Database.GenerateID != nil || opts.Advanced.Database.IDFormat != "" {
		return nil
	}
	// Step 1: the binder itself, or the backend behind an adapter from adapter.New
	var target any = opts.Adapter
	if u, ok := target.(adapter.Unwrapper); ok {
		target = u.Unwrap()
	}
	// Step 2: its preference
	if p, ok := target.(adapter.IDGeneratorProvider); ok {
		return p.DefaultIDGenerator()
	}
	return nil
}

// GORMRequiredError reports a plugin that still needs a *gorm.DB (InitContext.DB) while goauth runs on
// GoAuthOptions.Adapter without one.
type GORMRequiredError struct {
	// Plugin is the plugin's ID.
	Plugin string
	// Err is what the plugin's Init returned (nil when it initialized but still migrates GORM structs).
	Err error
}

func (e *GORMRequiredError) Error() string {
	msg := fmt.Sprintf("goauth: plugin %q needs a *gorm.DB (GoAuthOptions.Conn): it still stores its tables through GORM "+
		"and can't run on GoAuthOptions.Adapter yet; remove it or run goauth on Conn", e.Plugin)
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns the plugin's error.
func (e *GORMRequiredError) Unwrap() error { return e.Err }

// initWithoutGORM initializes p. With a *gorm.DB (InitContext.DB), or without any adapter, it is p.Init with
// the usual error. On an adapter without GORM (GoAuthOptions.Adapter), a plugin whose Init panics or fails
// about GORM, or that still returns a GORM migrator afterwards, is reported as a *GORMRequiredError naming
// the plugin, instead of a nil-pointer panic later.
func initWithoutGORM(p plugin.Plugin, ictx *plugin.InitContext) (err error) {
	if ictx.DB != nil || ictx.Adapter == nil {
		if err := p.Init(ictx); err != nil {
			return fmt.Errorf("goauth: plugin initialization failed for %s: %w", p.ID(), err)
		}
		return nil
	}
	// Step 1: a panic in Init (typically a nil *gorm.DB) becomes an error
	defer func() {
		if r := recover(); r != nil {
			err = &GORMRequiredError{Plugin: p.ID(), Err: fmt.Errorf("panic during Init: %v", r)}
		}
	}()
	// Step 2: Init errors; plugins that need the DB say so (e.g. "a *gorm.DB is required")
	if err := p.Init(ictx); err != nil {
		if mentionsGORM(err) {
			return &GORMRequiredError{Plugin: p.ID(), Err: err}
		}
		return fmt.Errorf("goauth: plugin initialization failed for %s: %w", p.ID(), err)
	}
	// Step 3: plugins that still AutoMigrate GORM structs can't work without the DB either
	if p.Migrator() != nil {
		return &GORMRequiredError{Plugin: p.ID()}
	}
	return nil
}

// mentionsGORM reports whether an Init error is about the missing *gorm.DB.
func mentionsGORM(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "gorm")
}
