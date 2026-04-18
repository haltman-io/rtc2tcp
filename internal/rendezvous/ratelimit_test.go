package rendezvous

import (
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestKeyedLimiterAllowsBurstThenThrottles(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	l := newKeyedLimiter(rate.Every(time.Second), 3)

	allowed := 0
	for i := 0; i < 5; i++ {
		if l.Allow("1.2.3.4", now) {
			allowed++
		}
	}
	if allowed != 3 {
		t.Fatalf("first burst allowed %d, want 3", allowed)
	}

	// After 2s we should have accrued 2 more tokens.
	now = now.Add(2 * time.Second)
	recovered := 0
	for i := 0; i < 5; i++ {
		if l.Allow("1.2.3.4", now) {
			recovered++
		}
	}
	if recovered != 2 {
		t.Fatalf("after recovery allowed %d, want 2", recovered)
	}
}

func TestKeyedLimiterIsolatesKeys(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	l := newKeyedLimiter(rate.Every(time.Second), 1)

	if !l.Allow("a", now) {
		t.Fatal("first request for key a should be allowed")
	}
	if l.Allow("a", now) {
		t.Fatal("second request for key a should be throttled")
	}
	if !l.Allow("b", now) {
		t.Fatal("first request for key b should be allowed independent of a")
	}
}

func TestKeyedLimiterCleanupEvictsStaleKeys(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	l := newKeyedLimiter(rate.Every(time.Second), 1)

	_ = l.Allow("old", now)
	_ = l.Allow("recent", now.Add(10*time.Minute))

	if l.Len() != 2 {
		t.Fatalf("Len() = %d, want 2", l.Len())
	}

	evicted := l.Cleanup(now.Add(5 * time.Minute))
	if evicted != 1 {
		t.Fatalf("Cleanup evicted %d, want 1", evicted)
	}
	if l.Len() != 1 {
		t.Fatalf("Len() = %d after cleanup, want 1", l.Len())
	}
	if !l.Allow("recent", now.Add(11*time.Minute)) {
		// Allow is throttled (burst=1, 1 minute apart with every=1s means
		// plenty of recovery, so this should succeed).
		t.Fatal("recent key should still be reachable after cleanup")
	}
}
