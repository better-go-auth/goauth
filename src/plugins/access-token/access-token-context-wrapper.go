package accesstoken

import (
	"context"
	"crypto/tls"
	"io"
	"mime/multipart"
	"net/url"
	"time"

	"github.com/danielgtaylor/huma/v2"
)

// accessTokenContextWrapper intercepts response status/body writes so onBeforeWrite can
// inspect session changes and set response headers (e.g. set-auth-token) before headers flush.
type accessTokenContextWrapper struct {
	inner         huma.Context
	onBeforeWrite func()
	wrote         bool
}

var _ huma.Context = (*accessTokenContextWrapper)(nil)

func (w *accessTokenContextWrapper) flush() {
	if !w.wrote {
		w.wrote = true
		if w.onBeforeWrite != nil {
			w.onBeforeWrite()
		}
	}
}

func (w *accessTokenContextWrapper) Unwrap() huma.Context       { return w.inner }
func (w *accessTokenContextWrapper) Operation() *huma.Operation { return w.inner.Operation() }
func (w *accessTokenContextWrapper) Context() context.Context   { return w.inner.Context() }
func (w *accessTokenContextWrapper) TLS() *tls.ConnectionState  { return w.inner.TLS() }
func (w *accessTokenContextWrapper) Version() huma.ProtoVersion { return w.inner.Version() }
func (w *accessTokenContextWrapper) Method() string             { return w.inner.Method() }
func (w *accessTokenContextWrapper) Host() string               { return w.inner.Host() }
func (w *accessTokenContextWrapper) RemoteAddr() string         { return w.inner.RemoteAddr() }
func (w *accessTokenContextWrapper) URL() url.URL               { return w.inner.URL() }
func (w *accessTokenContextWrapper) Param(name string) string   { return w.inner.Param(name) }
func (w *accessTokenContextWrapper) Query(name string) string   { return w.inner.Query(name) }
func (w *accessTokenContextWrapper) Header(name string) string  { return w.inner.Header(name) }
func (w *accessTokenContextWrapper) EachHeader(cb func(name, value string)) {
	w.inner.EachHeader(cb)
}
func (w *accessTokenContextWrapper) BodyReader() io.Reader { return w.inner.BodyReader() }
func (w *accessTokenContextWrapper) GetMultipartForm() (*multipart.Form, error) {
	return w.inner.GetMultipartForm()
}

func (w *accessTokenContextWrapper) SetReadDeadline(t time.Time) error {
	return w.inner.SetReadDeadline(t)
}
func (w *accessTokenContextWrapper) Status() int { return w.inner.Status() }
func (w *accessTokenContextWrapper) SetStatus(code int) {
	// Flush before setting status so headers can still be modified before the response starts
	w.flush()
	w.inner.SetStatus(code)
}
func (w *accessTokenContextWrapper) SetHeader(name, value string) { w.inner.SetHeader(name, value) }
func (w *accessTokenContextWrapper) AppendHeader(name, value string) {
	w.inner.AppendHeader(name, value)
}

func (w *accessTokenContextWrapper) BodyWriter() io.Writer {
	// Flush before writing body in case SetStatus was not called explicitly
	w.flush()
	return w.inner.BodyWriter()
}
