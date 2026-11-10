package compattest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// bearerTestClient mirrors the cookie-less Bearer + JWT client pattern used in the .mjs compat scripts.
type bearerTestClient struct {
	baseURL    string
	httpClient *http.Client
	bearerTok  string
	lastJWT    string
}

func newBearerTestClient(baseURL string) *bearerTestClient {
	return &bearerTestClient{
		baseURL:    baseURL,
		httpClient: &http.Client{},
	}
}

func (c *bearerTestClient) do(t *testing.T, method, path string, body any) *Response {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, c.baseURL+path, r)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Origin", c.baseURL)
	if c.bearerTok != "" {
		req.Header.Set("Authorization", "Bearer "+c.bearerTok)
	}
	resp, err := c.httpClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	if tok := resp.Header.Get("set-auth-token"); tok != "" {
		c.bearerTok = tok
	}
	if j := resp.Header.Get("set-auth-jwt"); j != "" {
		c.lastJWT = j
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: raw}
}

func (c *bearerTestClient) get(t *testing.T, path string) *Response {
	t.Helper()
	return c.do(t, http.MethodGet, path, nil)
}

func (c *bearerTestClient) post(t *testing.T, path string, body any) *Response {
	t.Helper()
	return c.do(t, http.MethodPost, path, body)
}

