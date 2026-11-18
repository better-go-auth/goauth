package autherr

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestInternal_HidesCause(t *testing.T) {
	SetExposeRequestID(true)
	defer SetExposeRequestID(false)
	// Step 1: a repository error becomes a generic 500 with a request ID
	ae := Internal(context.Background(), errors.New("gorm/user: create: duplicate key value violates unique constraint"))
	if ae.StatusCode != http.StatusInternalServerError || ae.Code != "INTERNAL_SERVER_ERROR" {
		t.Fatalf("got %d %s", ae.StatusCode, ae.Code)
	}
	if strings.Contains(ae.Message, "gorm") || ae.Message != InternalMessage {
		t.Fatalf("cause leaked: %q", ae.Message)
	}
	if ae.RequestID == "" {
		t.Fatalf("missing request id: %+v", ae)
	}
}

func TestInternal_ReusesRequestIDAndKeepsExpectedErrors(t *testing.T) {
	SetExposeRequestID(true)
	defer SetExposeRequestID(false)
	// Step 1: the incoming request ID is reused
	ctx := WithRequestID(context.Background(), "req-123")
	if got := Internal(ctx, errors.New("boom")).RequestID; got != "req-123" {
		t.Fatalf("request id = %q", got)
	}
	// Step 2: client errors pass through untouched
	expected := Err(http.StatusBadRequest, "INVALID_EMAIL", "Invalid email")
	if got := Internal(ctx, expected); got != expected {
		t.Fatalf("expected error changed: %+v", got)
	}
	// Step 3: explicit 5xx codes keep their code and message but get a request ID
	got := Internal(ctx, ErrFailedToCreateSession)
	if got.Code != ErrFailedToCreateSession.Code || got.Message != ErrFailedToCreateSession.Message || got.RequestID != "req-123" {
		t.Fatalf("5xx code changed: %+v", got)
	}
}

func TestInternal_RequestIDHiddenByDefault(t *testing.T) {
	// better-auth's body is {code, message}: no requestId unless Advanced.GoAuth.ErrorRequestID is on
	ae := Internal(WithRequestID(context.Background(), "req-1"), errors.New("boom"))
	if ae.RequestID != "" || ae.Message != InternalMessage {
		t.Fatalf("request id exposed by default: %+v", ae)
	}
}
