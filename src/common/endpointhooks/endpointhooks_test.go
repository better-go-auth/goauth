package endpointhooks

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/better-go-auth/goauth/src/models/dtos"
)

func TestResponseHelpers(t *testing.T) {
	r := JSON(http.StatusCreated, map[string]any{"a": "<b>"})
	if r.Status != 201 || !r.IsJSON() || string(r.Body) != "{\"a\":\"<b>\"}\n" {
		t.Fatalf("JSON = %d %q", r.Status, r.Body)
	}
	if r.JSONBody()["a"] != "<b>" {
		t.Fatalf("JSONBody = %v", r.JSONBody())
	}
	r.SetCookie(&http.Cookie{Name: "a", Value: "1"})
	r.SetCookie(&http.Cookie{Name: "b", Value: "2"})
	r.Header.Add("Set-Cookie", "broken")
	if len(r.Cookies()) != 2 {
		t.Fatalf("cookies = %v", r.Cookies())
	}
	r.RemoveCookies("a")
	if cs := r.Cookies(); len(cs) != 1 || cs[0].Name != "b" || len(r.Header.Values("Set-Cookie")) != 2 {
		t.Fatalf("after RemoveCookies: %v", r.Header.Values("Set-Cookie"))
	}
	r.SetJSON([]int{1, 2})
	var v []int
	if err := r.DecodeJSON(&v); err != nil || len(v) != 2 || r.Status != 201 {
		t.Fatalf("SetJSON: %v %v", v, err)
	}
	c := r.Clone()
	c.Header.Set("X", "1")
	c.Body[0] = 'x'
	if r.Header.Get("X") != "" || r.Body[0] == 'x' {
		t.Fatal("Clone shares state")
	}
	if red := Redirect("/x"); red.Status != http.StatusFound || red.Header.Get("Location") != "/x" || red.IsJSON() {
		t.Fatalf("Redirect = %+v", red)
	}
	var nilRes *Response
	if nilRes.IsJSON() || nilRes.JSONBody() != nil || nilRes.Cookies() != nil || nilRes.Clone() != nil {
		t.Fatal("nil response helpers")
	}
}

func TestContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/auth/sign-in/email?x=1", nil)
	req.Header.Set("Cookie", "a=1; b=2")
	sw := &dtos.SessionWithUser{}
	c := NewContext(context.Background(), "/sign-in/email", http.MethodPost, req, func() *dtos.SessionWithUser { return sw })

	// Step 1: the request view is a copy
	c.Headers.Set("X-Changed", "1")
	if req.Header.Get("X-Changed") != "" || c.Query.Get("x") != "1" {
		t.Fatal("headers must be a copy; query parsed")
	}
	if v, ok := c.Cookie("b"); !ok || v != "2" {
		t.Fatalf("Cookie(b) = %q %v", v, ok)
	}
	if _, ok := c.Cookie("zzz"); ok {
		t.Fatal("missing cookie found")
	}
	// Step 2: before the endpoint there is no new session and cookies go to ResponseHeaders
	if c.NewSession() != nil {
		t.Fatal("NewSession before the endpoint")
	}
	c.SetCookie(&http.Cookie{Name: "pre", Value: "1"})
	if c.ResponseHeaders.Get("Set-Cookie") != "pre=1" {
		t.Fatalf("ResponseHeaders = %v", c.ResponseHeaders)
	}
	// Step 3: after the endpoint cookies go to Returned and NewSession is available
	c.Returned = &Response{Status: 200}
	c.SetCookie(&http.Cookie{Name: "post", Value: "1"})
	c.SetCookie(nil)
	if c.Returned.Header.Get("Set-Cookie") != "post=1" || c.NewSession() != sw {
		t.Fatalf("after: %v", c.Returned.Header)
	}
	// Step 4: matchers
	if !MatchPaths("/a", "/sign-in/email")(c) || MatchPaths("/a")(c) || !MatchPrefix("/sign-in/")(c) || MatchPrefix("/x")(c) {
		t.Fatal("matchers")
	}
	if !(Hooks{}).Empty() || (Hooks{Before: []BeforeHook{{}}}).Empty() {
		t.Fatal("Empty")
	}
	// Step 5: a context without request still works
	if c2 := NewContext(context.Background(), "/x", "GET", nil, nil); c2.Headers == nil || c2.Query == nil || c2.NewSession() != nil {
		t.Fatal("nil request")
	}
}
