package services

import (
	"encoding/json"
	"testing"
)

// FuzzParseStateData decodes arbitrary OAuth state payloads (the JSON stored in the verification row or in
// the encrypted oauth_state cookie, which a TypeScript server may have written): it never panics, accepts
// only payloads with better-auth's required fields, and an accepted payload survives marshal → parse
// unchanged (typed fields and additionalData).
func FuzzParseStateData(f *testing.F) {
	// Step 1: seeds: better-auth's payload, with link and additional data, and broken variants
	f.Add(`{"callbackURL":"/","codeVerifier":"v","expiresAt":1700000000000}`)
	f.Add(`{"callbackURL":"/dash","codeVerifier":"v","errorURL":"/err","newUserURL":"/new","link":{"email":"a@b.c","userId":"u"},"expiresAt":1,"requestSignUp":true,"oauthState":"s","invite":"x","n":[1,2]}`)
	f.Add(`{"callbackURL":1,"codeVerifier":"v","expiresAt":1}`)
	f.Add(`{"callbackURL":"/","codeVerifier":"v","expiresAt":"soon"}`)
	f.Add(`{"callbackURL":"/","codeVerifier":"v","expiresAt":1,"link":"nope"}`)
	f.Add(`[]`)
	f.Add(`null`)
	f.Add(`{"callbackURL":"/","codeVerifier":"v","expiresAt":1e400}`)
	f.Fuzz(func(t *testing.T, raw string) {
		// Step 2: parse
		d, err := parseStateData(raw)
		if err != nil {
			if d != nil {
				t.Fatalf("a rejected payload returned data: %+v", d)
			}
			return
		}
		// Step 3: the required fields were present with the right JSON types
		var all map[string]any
		if json.Unmarshal([]byte(raw), &all) != nil {
			t.Fatalf("accepted a payload that is not a JSON object: %q", raw)
		}
		for key, want := range map[string]string{"callbackURL": "string", "codeVerifier": "string", "expiresAt": "number"} {
			switch all[key].(type) {
			case string:
				if want != "string" {
					t.Fatalf("%s accepted as a string", key)
				}
			case float64:
				if want != "number" {
					t.Fatalf("%s accepted as a number", key)
				}
			default:
				t.Fatalf("%s accepted with type %T", key, all[key])
			}
		}
		// Step 4: marshal and parse again: same state
		out, err := d.marshal()
		if err != nil {
			t.Fatalf("marshal of an accepted state: %v", err)
		}
		again, err := parseStateData(out)
		if err != nil {
			t.Fatalf("re-parse of %q: %v", out, err)
		}
		a, _ := json.Marshal(d)
		b, _ := json.Marshal(again)
		if string(a) != string(b) {
			t.Fatalf("state changed across a round trip:\n%s\n%s", a, b)
		}
		x, _ := json.Marshal(d.AdditionalData)
		y, _ := json.Marshal(again.AdditionalData)
		if string(x) != string(y) {
			t.Fatalf("additional data changed across a round trip:\n%s\n%s", x, y)
		}
	})
}
