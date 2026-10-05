package compat

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/models"
)

func TestTimeJSON(t *testing.T) {
	ts := Time(time.Date(2026, 1, 2, 3, 4, 5, 678_900_000, time.FixedZone("x", 3600)))
	b, _ := json.Marshal(ts)
	if string(b) != `"2026-01-02T02:04:05.678Z"` {
		t.Fatalf("unexpected %s", b)
	}
	var back Time
	if err := json.Unmarshal(b, &back); err != nil || !time.Time(back).Equal(time.Time(ts).Truncate(time.Millisecond)) {
		t.Fatalf("round trip: %v %v", time.Time(back), err)
	}
}

func TestFromModels(t *testing.T) {
	email := "a@example.com"
	now := time.Now()
	u := &models.User{Base: models.Base{ID: "u1", CreatedAt: &now, UpdatedAt: &now},
		UserDto: models.UserDto{FirstName: "Ada", LastName: "Lovelace", Email: &email}}
	du := UserFromModel(u)
	if du.Name != "Ada Lovelace" || du.Image != nil || du.Email != email {
		t.Fatalf("unexpected user %+v", du)
	}

	tok := "tok"
	s := &models.Session{Base: models.Base{ID: "s1", CreatedAt: &now}, UserID: "u1", Token: tok, ExpiresAt: now}
	ds := SessionFromModel(s)
	b, _ := json.Marshal(SessionWithUser{Session: ds, User: du})
	var m map[string]map[string]any
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"id", "userId", "token", "expiresAt", "ipAddress", "userAgent", "createdAt", "updatedAt"} {
		if _, ok := m["session"][k]; !ok {
			t.Errorf("session.%s missing in %s", k, b)
		}
	}
	if _, ok := m["session"]["impersonatedBy"]; ok {
		t.Error("plugin fields must be omitted when unset")
	}
}
