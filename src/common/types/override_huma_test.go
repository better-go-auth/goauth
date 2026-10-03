package types

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
)

type echoInput struct {
	Body struct {
		Email string `json:"email" format:"email"`
	}
}

type echoOutput struct {
	Body struct {
		Email string `json:"email"`
	}
}

func echoHandler(_ context.Context, in *echoInput) (*echoOutput, error) {
	if in.Body.Email == "boom@example.com" {
		return nil, errors.New("boom")
	}
	out := &echoOutput{}
	out.Body.Email = in.Body.Email
	return out, nil
}

func register(api huma.API, path string) {
	huma.Register(api, huma.Operation{Method: http.MethodPost, Path: path}, echoHandler)
}

func decode(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("invalid JSON body %s: %v", body, err)
	}
	return m
}

func TestScopedErrorHandler(t *testing.T) {
	InstallScopedErrorHandler()
	_, host := humatest.New(t)
	register(WrapAPI(host), "/auth/echo")
	register(host, "/host/echo")
	register(WrapAPI(huma.NewGroup(host, "/v1")), "/auth/echo")

	invalid := map[string]any{"email": 123}
	boom := map[string]any{"email": "boom@example.com"}

	t.Run("goauth validation error", func(t *testing.T) {
		for _, path := range []string{"/auth/echo", "/v1/auth/echo"} {
			resp := host.Post(path, invalid)
			if resp.Code != http.StatusBadRequest {
				t.Fatalf("%s: status %d, want 400: %s", path, resp.Code, resp.Body)
			}
			body := decode(t, resp.Body.Bytes())
			if body["code"] != "VALIDATION_ERROR" || !strings.Contains(body["message"].(string), "body.email") {
				t.Fatalf("%s: unexpected body %v", path, body)
			}
		}
	})

	t.Run("goauth unexpected error", func(t *testing.T) {
		resp := host.Post("/auth/echo", boom)
		body := decode(t, resp.Body.Bytes())
		if resp.Code != http.StatusInternalServerError || body["code"] != "INTERNAL_SERVER_ERROR" {
			t.Fatalf("status %d, body %v", resp.Code, body)
		}
	})

	t.Run("host routes keep Huma defaults", func(t *testing.T) {
		resp := host.Post("/host/echo", invalid)
		if resp.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status %d, want 422: %s", resp.Code, resp.Body)
		}
		if ct := resp.Header().Get("Content-Type"); !strings.Contains(ct, "application/problem+json") {
			t.Fatalf("content type %q, want problem+json", ct)
		}
		if body := decode(t, resp.Body.Bytes()); body["code"] != nil {
			t.Fatalf("host error must not use goauth format: %v", body)
		}

		resp = host.Post("/host/echo", boom)
		if body := decode(t, resp.Body.Bytes()); resp.Code != http.StatusInternalServerError || body["code"] != nil {
			t.Fatalf("status %d, body %v", resp.Code, body)
		}
	})

	t.Run("successful requests are untouched", func(t *testing.T) {
		resp := host.Post("/auth/echo", map[string]any{"email": "a@example.com"})
		if resp.Code != http.StatusOK || decode(t, resp.Body.Bytes())["email"] != "a@example.com" {
			t.Fatalf("status %d, body %s", resp.Code, resp.Body)
		}
	})
}

func TestNewError(t *testing.T) {
	err := NewError(http.StatusNotFound, "user not found")
	if err.GetStatus() != http.StatusNotFound {
		t.Fatalf("status %d", err.GetStatus())
	}
	body, _ := json.Marshal(err)
	if string(body) != `{"code":"NOT_FOUND","message":"user not found"}` {
		t.Fatalf("unexpected body %s", body)
	}
	if v := NewError(http.StatusUnprocessableEntity, "validation failed"); v.GetStatus() != http.StatusBadRequest {
		t.Fatalf("422 must map to 400, got %d", v.GetStatus())
	}
}

func TestWrapAPIIdempotent(t *testing.T) {
	_, api := humatest.New(t)
	w := WrapAPI(api)
	if WrapAPI(w) != w {
		t.Fatal("wrapping twice must return the same wrapper")
	}
}
