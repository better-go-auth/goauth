package exkit

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
)

// Client is a cookie-aware HTTP client for the example tests. Like a browser it keeps the session
// cookies between requests and sends the Origin header goauth checks on state-changing requests.
type Client struct {
	t       testing.TB
	BaseURL string
	Origin  string
	HTTP    *http.Client
	// Headers are sent with every request (e.g. Authorization for bearer tokens).
	Headers map[string]string
}

// Response is a fully read HTTP response.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// StartTest serves app on an httptest server (closed with the test) and returns a client for it.
func StartTest(t testing.TB, app *App) *Client {
	t.Helper()
	ts := httptest.NewServer(app.Mux)
	t.Cleanup(ts.Close)
	c := &Client{t: t, BaseURL: ts.URL, Origin: app.BaseURL}
	c.Reset()
	return c
}

// Reset gives the client an empty cookie jar (a new "browser").
func (c *Client) Reset() {
	jar, _ := cookiejar.New(nil)
	c.HTTP = &http.Client{
		Jar: jar,
		// redirects are returned to the test so it can check the Location header
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Fork returns a client for the same server with its own cookie jar (a second user).
func (c *Client) Fork() *Client {
	n := &Client{t: c.t, BaseURL: c.BaseURL, Origin: c.Origin}
	n.Reset()
	return n
}

// Do sends a request; body is JSON-encoded unless it is nil.
func (c *Client) Do(method, path string, body any, headers ...map[string]string) *Response {
	c.t.Helper()
	// Step 1: encode the body
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			c.t.Fatalf("exkit: encode body: %v", err)
		}
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, r)
	if err != nil {
		c.t.Fatalf("exkit: new request: %v", err)
	}
	// Step 2: headers (JSON, Origin, client-wide and per-request)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", c.Origin)
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	for _, h := range headers {
		for k, v := range h {
			req.Header.Set(k, v)
		}
	}
	// Step 3: send and read the whole body
	resp, err := c.HTTP.Do(req)
	if err != nil {
		c.t.Fatalf("exkit: %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatalf("exkit: read body: %v", err)
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: raw}
}

// Get sends a GET request.
func (c *Client) Get(path string, headers ...map[string]string) *Response {
	c.t.Helper()
	return c.Do(http.MethodGet, path, nil, headers...)
}

// Post sends a POST request with a JSON body.
func (c *Client) Post(path string, body any, headers ...map[string]string) *Response {
	c.t.Helper()
	return c.Do(http.MethodPost, path, body, headers...)
}

// MustOK fails the test unless the response is 200 and, when v is non-nil, decodes the body into it.
func (c *Client) MustOK(r *Response, v any) *Response {
	c.t.Helper()
	return c.MustStatus(r, http.StatusOK, v)
}

// MustStatus fails the test unless the response has status and, when v is non-nil, decodes the body into it.
func (c *Client) MustStatus(r *Response, status int, v any) *Response {
	c.t.Helper()
	if r.Status != status {
		c.t.Fatalf("status = %d, want %d: %s", r.Status, status, r.Body)
	}
	if v != nil {
		if err := json.Unmarshal(r.Body, v); err != nil {
			c.t.Fatalf("exkit: decode body: %v\n%s", err, r.Body)
		}
	}
	return r
}

// ErrorCode returns the better-auth error code of an error response ("" when absent).
func (r *Response) ErrorCode() string {
	var e struct {
		Code string `json:"code"`
	}
	_ = json.Unmarshal(r.Body, &e)
	return e.Code
}

// Cookie returns the Set-Cookie entry named name, or nil.
func (r *Response) Cookie(name string) *http.Cookie {
	for _, ck := range (&http.Response{Header: r.Header}).Cookies() {
		if ck.Name == name {
			return ck
		}
	}
	return nil
}

// SignUp registers an email/password user and keeps the session cookie in the client.
func (c *Client) SignUp(email, password, name string, extra ...map[string]any) *Response {
	c.t.Helper()
	body := map[string]any{"email": email, "password": password, "name": name}
	for _, e := range extra {
		for k, v := range e {
			body[k] = v
		}
	}
	return c.Post("/api/auth/sign-up/email", body)
}

// SignIn signs an email/password user in and keeps the session cookie in the client.
func (c *Client) SignIn(email, password string) *Response {
	c.t.Helper()
	return c.Post("/api/auth/sign-in/email", map[string]any{"email": email, "password": password})
}
