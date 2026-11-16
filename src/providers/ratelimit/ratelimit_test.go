package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/better-go-auth/goauth/src/providers/sec-storage/memory"
)

func TestAllowFixedWindow(t *testing.T) {
	store, err := memory.NewSecondaryStorage()
	if err != nil {
		t.Fatal(err)
	}
	for name, l := range map[string]*Limiter{"memory": New(nil), "secondary": New(store)} {
		t.Run(name, func(t *testing.T) {
			now := time.Unix(1_700_000_000, 0)
			l.WithClock(func() time.Time { return now })
			rule := Rule{Window: 10 * time.Second, Max: 3}
			ctx := context.Background()

			// the first Max requests pass
			for i := 0; i < 3; i++ {
				if ok, _ := l.Allow(ctx, "1.2.3.4|/x", rule); !ok {
					t.Fatalf("request %d should pass", i+1)
				}
			}
			// the next one is refused with a retry hint inside the window
			ok, retry := l.Allow(ctx, "1.2.3.4|/x", rule)
			if ok || retry < 1 || retry > 10 {
				t.Fatalf("4th request: ok=%v retry=%d", ok, retry)
			}
			// other keys are independent
			if ok, _ := l.Allow(ctx, "5.6.7.8|/x", rule); !ok {
				t.Fatal("other ip should pass")
			}
			// a new window resets the budget
			now = now.Add(11 * time.Second)
			if ok, _ := l.Allow(ctx, "1.2.3.4|/x", rule); !ok {
				t.Fatal("new window should pass")
			}
		})
	}
}

func TestInvalidRuleAllowsEverything(t *testing.T) {
	l := New(nil)
	for i := 0; i < 100; i++ {
		if ok, _ := l.Allow(context.Background(), "k", Rule{}); !ok {
			t.Fatal("zero rule must not limit")
		}
	}
	var nilLimiter *Limiter
	if ok, _ := nilLimiter.Allow(context.Background(), "k", Rule{Window: time.Second, Max: 1}); !ok {
		t.Fatal("nil limiter must not limit")
	}
}
