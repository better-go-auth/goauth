package dtos

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

// JSONString is organization metadata in a request body. better-auth clients send an object
// (`metadata: z.record(...)`), which is stored as its JSON text like better-auth's adapter does; a JSON
// string is stored as is (goauth's older clients sent pre-encoded metadata).
type JSONString string

// UnmarshalJSON stores a JSON string verbatim and any other JSON value as its compact JSON text.
func (j *JSONString) UnmarshalJSON(b []byte) error {
	// Step 1: a JSON string is kept as the stored text
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*j = JSONString(s)
		return nil
	}
	// Step 2: objects (and other values) are stored compacted
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		return err
	}
	*j = JSONString(buf.String())
	return nil
}

// Schema lets Huma accept any JSON value for metadata (an object from better-auth clients, or a string).
func (JSONString) Schema(huma.Registry) *huma.Schema {
	return &huma.Schema{Description: "Organization metadata: a JSON object (stored as JSON text) or a string"}
}

// StringPtr returns the stored text as *string (nil when j is nil).
func (j *JSONString) StringPtr() *string {
	if j == nil {
		return nil
	}
	s := string(*j)
	return &s
}

// MetadataOutput returns stored metadata the way better-auth returns it: the parsed JSON value when the
// stored text is a JSON object, otherwise the text itself (nil when unset).
func MetadataOutput(stored *string) any {
	if stored == nil {
		return nil
	}
	trimmed := strings.TrimSpace(*stored)
	if strings.HasPrefix(trimmed, "{") {
		var v map[string]any
		if err := json.Unmarshal([]byte(trimmed), &v); err == nil {
			return v
		}
	}
	return *stored
}
