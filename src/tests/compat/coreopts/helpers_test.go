// Package coreopts tests better-auth core options ported to goauth end to end (httptest servers built with
// goauth.SetupGoAuth): secret rotation, socialProviders in core, trustedOrigins as a function, dynamic baseURL
// with allowedHosts, advanced.cookies / defaultCookieAttributes, verification.storeIdentifier,
// account.storeAccountCookie and the plugin behaviour fixes of missing-tasks 3.14.
package coreopts

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

const password = "correct-horse-battery"

// call sends a request to s without the cookie jar; headers may set Host, Origin and Cookie.
func call(t *testing.T, s *compattest.Server, method, path string, body any, headers map[string]string) *compattest.Response {
	t.Helper()
	// Step 1: the body
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, s.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Step 2: headers ("Host" sets the request host)
	for k, v := range headers {
		if strings.EqualFold(k, "Host") {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	// Step 3: send without following redirects or storing cookies
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return &compattest.Response{Status: resp.StatusCode, Header: resp.Header, Body: raw}
}

// cookieHeader turns the Set-Cookie entries of r into a Cookie request header (deleted cookies dropped).
func cookieHeader(r *compattest.Response) string {
	var parts []string
	for _, c := range (&http.Response{Header: r.Header}).Cookies() {
		if c.MaxAge < 0 || c.Value == "" {
			continue
		}
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

// setCookie returns the Set-Cookie entry named name.
func setCookie(r *compattest.Response, name string) *http.Cookie {
	for _, c := range (&http.Response{Header: r.Header}).Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// signUp creates a user and returns the response (its cookies are the session).
func signUp(t *testing.T, s *compattest.Server, email string, headers map[string]string) *compattest.Response {
	t.Helper()
	h := map[string]string{"Origin": s.Origin}
	for k, v := range headers {
		h[k] = v
	}
	r := call(t, s, http.MethodPost, "/api/auth/sign-up/email", map[string]any{"email": email, "password": password, "name": "Test"}, h)
	if r.Status != http.StatusOK {
		t.Fatalf("sign-up: %d %s", r.Status, r.Body)
	}
	return r
}

// sessionEmail returns the email of /get-session for cookie ("" when there is no session).
func sessionEmail(t *testing.T, s *compattest.Server, cookie string) string {
	t.Helper()
	r := call(t, s, http.MethodGet, "/api/auth/get-session", nil, map[string]string{"Cookie": cookie})
	if r.Status != http.StatusOK {
		t.Fatalf("get-session: %d %s", r.Status, r.Body)
	}
	var body *struct {
		User struct {
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.Unmarshal(r.Body, &body); err != nil {
		t.Fatalf("get-session body %s: %v", r.Body, err)
	}
	if body == nil {
		return ""
	}
	return body.User.Email
}

// expectCode asserts status and better-auth error code.
func expectCode(t *testing.T, r *compattest.Response, status int, code string) {
	t.Helper()
	if r.Status != status {
		t.Fatalf("status %d, want %d: %s", r.Status, status, r.Body)
	}
	var body struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(r.Body, &body)
	if body.Code != code {
		t.Fatalf("code %q, want %q: %s", body.Code, code, r.Body)
	}
}
