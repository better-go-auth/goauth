// Package onetimetokenclient runs the official better-auth client (oneTimeTokenClient) against goauth.
package onetimetokenclient

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	onetimetoken "github.com/better-go-auth/goauth/src/plugins/one-time-token"
	ottconfig "github.com/better-go-auth/goauth/src/plugins/one-time-token/config"
	"github.com/better-go-auth/goauth/src/plugins/one-time-token/services"
	compattest "github.com/better-go-auth/goauth/src/tests/compat"
)

func newServer(t *testing.T, cfg ottconfig.OneTimeTokenConfig) (*compattest.Server, *onetimetoken.Plugin) {
	t.Helper()
	p := onetimetoken.New(cfg)
	s := compattest.NewServer(t,
		compattest.WithPlugin(p),
		compattest.WithConfig(func(c *config.AuthConfig) {
			c.BaseURL = "http://localhost:3000"
			c.TrustedOrigins = append(c.TrustedOrigins, "http://127.0.0.1:*", "http://localhost:*")
		}),
	)
	// test-only endpoints the script uses to inspect and manipulate stored tokens
	s.Mux.HandleFunc("/test/ott-identifiers", func(w http.ResponseWriter, r *http.Request) {
		var rows []models.Verification
		s.DB.Where("identifier LIKE ?", services.IdentifierPrefix+"%").Find(&rows)
		ids := []string{}
		for _, v := range rows {
			ids = append(ids, v.Identifier)
		}
		writeJSON(w, map[string]any{"identifiers": ids})
	})
	s.Mux.HandleFunc("/test/expire-ott", func(w http.ResponseWriter, r *http.Request) {
		stored, _ := p.Service().StoredToken(r.URL.Query().Get("token"))
		res := s.DB.Model(&models.Verification{}).Where(&models.Verification{Identifier: services.IdentifierPrefix + stored}).
			Update("ExpiresAt", time.Now().Add(-time.Minute).UTC())
		writeJSON(w, map[string]any{"updated": res.RowsAffected})
	})
	s.Mux.HandleFunc("/test/server-ott", func(w http.ResponseWriter, r *http.Request) {
		sw, err := s.Auth.Sessions().Get(r.Context(), strings.TrimSpace(r.URL.Query().Get("sessionToken")))
		if err != nil || sw == nil {
			http.Error(w, "no session", http.StatusNotFound)
			return
		}
		token, err := p.Service().GenerateToken(r.Context(), sw)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]any{"token": token})
	})
	return s, p
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestOfficialClientOneTimeToken(t *testing.T) {
	// Step 1: default (plain storage), hashed storage and client-requests-disabled servers
	s, _ := newServer(t, ottconfig.OneTimeTokenConfig{})
	hashed, _ := newServer(t, ottconfig.OneTimeTokenConfig{StoreToken: ottconfig.StoreTokenConfig{Mode: ottconfig.StoreTokenHashed}})
	disabled, _ := newServer(t, ottconfig.OneTimeTokenConfig{DisableClientRequest: true})

	// Step 2: run the official client script against all three
	compattest.RunNodeClient(t, compattest.ClientDir("client"), "test-one-time-token.mjs", s.URL,
		"GOAUTH_URL_HASHED="+hashed.URL, "GOAUTH_URL_DISABLED="+disabled.URL)
}
