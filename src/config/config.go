package config

import (
	"context"
	"net/http"
	
	"time"

	"github.com/birukbelay/gocmn/src/provider/db"
	"github.com/better-go-auth/goauth/src/plugins"
	"gorm.io/gorm"
)

type GoAuthOptions struct {
	// 	 * Base path for the Better Auth. This is typically
// 	 * the path where the
// 	 * Better Auth routes are mounted.
// 	 *
// 	 * @default "/api/auth"
// 	 */
	BasePath string
	Conn              *gorm.DB
	EmailVerification EmailVerification
	SessionConfig     SessionConfig
	SecondaryStorage  db.KeyValServ
	Plugins           []plugin.Plugin
}
type contextKey string

const httpRequestKey contextKey = "http_request"

// WithHTTPRequest stores the *http.Request in the context.
func WithHTTPRequest(ctx context.Context, req *http.Request) context.Context {
	return context.WithValue(ctx, httpRequestKey, req)
}

// GetHTTPRequest retrieves the *http.Request from the context.
func GetHTTPRequest(ctx context.Context) *http.Request {
	if req, ok := ctx.Value(httpRequestKey).(*http.Request); ok {
		return req
	}
	return nil
}

type SecondaryStorage interface {
	Get(key string) (any, error)
	GetAndDelete(key string) (any, error)
	Set(key string, value string, ttl time.Duration) error
	Delete(key string) error
}

// func (c AuthConfigs) WithDefaults() AuthConfigs {
// 	return c
// }
