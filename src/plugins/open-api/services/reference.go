package services

import (
	"encoding/json"
	"html"
	"strings"
)

// ScalarScriptURL is the Scalar API reference bundle better-auth's page loads.
const ScalarScriptURL = "https://cdn.jsdelivr.net/npm/@scalar/api-reference"

// ReferenceHTML is better-auth's getHTML: a Scalar API reference page embedding the document. The
// document JSON escapes <, > and & as unicode escapes, which keeps a "</script>" inside a description from
// closing the script element; the parsed document is the same.
func ReferenceHTML(document any, theme, nonce string) (string, error) {
	// Step 1: the embedded document
	raw, err := json.Marshal(document)
	if err != nil {
		return "", err
	}
	// Step 2: better-auth's template (theme defaults to "default")
	nonceAttr := ""
	if nonce != "" {
		nonceAttr = `nonce="` + html.EscapeString(nonce) + `"`
	}
	if theme == "" {
		theme = "default"
	}
	return `<!doctype html>
<html>
  <head>
    <title>Scalar API Reference</title>
    <meta charset="utf-8" />
    <meta
      name="viewport"
      content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <script
      id="api-reference"
      type="application/json">
    ` + string(raw) + `
    </script>
	 <script ` + nonceAttr + `>
      var configuration = {
	  	favicon: "data:image/svg+xml;utf8,` + EncodeURIComponent(Logo) + `",
	   	theme: "` + theme + `",
        metaData: {
			title: "Better Auth API",
			description: "API Reference for your Better Auth Instance",
		}
      }

      document.getElementById('api-reference').dataset.configuration =
        JSON.stringify(configuration)
    </script>
	  <script src="` + ScalarScriptURL + `" ` + nonceAttr + `></script>
  </body>
</html>`, nil
}

// EncodeURIComponent is JavaScript's encodeURIComponent: every byte of the UTF-8 encoding is
// percent-encoded except A-Z a-z 0-9 - _ . ! ~ * ' ( ).
func EncodeURIComponent(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(s) * 3 / 2)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("-_.!~*'()", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}
