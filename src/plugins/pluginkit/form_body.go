package pluginkit

import (
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"net/url"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

// maxFormBody caps the form bodies FormBody converts (OAuth style requests are tiny).
const maxFormBody = 1 << 20

// FormBody is a Huma middleware that accepts application/x-www-form-urlencoded bodies like better-call
// (which turns form fields into the body object): the form is converted to a JSON object of strings (the
// first value of each field) before Huma decodes the body. Other content types pass through unchanged.
// OAuth / RFC 8628 clients post their token requests as forms.
func FormBody(ctx huma.Context, next func(huma.Context)) {
	// Step 1: only form bodies are converted
	mt, _, err := mime.ParseMediaType(ctx.Header("Content-Type"))
	if err != nil || mt != "application/x-www-form-urlencoded" {
		next(ctx)
		return
	}
	// Step 2: parse the form (an unreadable body is left to Huma, which reports it)
	raw, err := io.ReadAll(io.LimitReader(ctx.BodyReader(), maxFormBody))
	if err != nil {
		next(ctx)
		return
	}
	values, err := url.ParseQuery(string(raw))
	if err != nil {
		next(&formContext{humaContext: ctx, body: bytes.NewReader(raw)})
		return
	}
	// Step 3: re-encode as JSON and let the endpoint read that
	obj := make(map[string]string, len(values))
	for k, v := range values {
		if len(v) > 0 {
			obj[k] = v[0]
		}
	}
	encoded, _ := json.Marshal(obj)
	next(&formContext{humaContext: ctx, body: bytes.NewReader(encoded), json: true})
}

// humaContext is huma.Context under another name, so embedding it does not hide its Context() method.
type humaContext = huma.Context

// formContext replaces the request body (and, once converted, its content type).
type formContext struct {
	humaContext
	body io.Reader
	json bool
}

// BodyReader returns the replaced body.
func (c *formContext) BodyReader() io.Reader { return c.body }

// Header reports application/json for converted bodies.
func (c *formContext) Header(name string) string {
	if c.json && strings.EqualFold(name, "Content-Type") {
		return "application/json"
	}
	return c.humaContext.Header(name)
}

// EachHeader reports application/json for converted bodies.
func (c *formContext) EachHeader(cb func(name, value string)) {
	c.humaContext.EachHeader(func(name, value string) {
		if c.json && strings.EqualFold(name, "Content-Type") {
			value = "application/json"
		}
		cb(name, value)
	})
}
