package rendezvous

import (
	"io"
	"log"
	"testing"
	"time"

	"rtc2tcp/internal/config"
)

func newTestBroker(t *testing.T, nowFn func() time.Time) *Broker {
	t.Helper()

	b := NewBroker(log.New(io.Discard, "", 0))
	// Shut down the default janitor goroutine before the test mutates
	// internal state. The test drives collectStale directly.
	b.stopOnce.Do(func() { close(b.stop) })
	b.janitor.Wait()

	if nowFn != nil {
		b.now = nowFn
	}
	t.Cleanup(func() {
		// Calling Shutdown after close(b.stop) is a no-op on the stop
		// channel; Wait returns immediately.
	})
	return b
}

func TestCollectStaleEvictsExpiredWaiter(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	b := newTestBroker(t, func() time.Time { return now })
	b.waiterTTL = 1 * time.Minute

	fresh := &peer{
		id:            "fresh-peer",
		mode:          config.ModeConnect,
		rendezvousKey: "token-fresh",
		createdAt:     now.Add(-10 * time.Second),
	}
	stale := &peer{
		id:            "stale-peer",
		mode:          config.ModeExpose,
		rendezvousKey: "token-stale",
		createdAt:     now.Add(-5 * time.Minute),
	}
	b.waiting[fresh.rendezvousKey] = fresh
	b.waiting[stale.rendezvousKey] = stale

	waiters, sessions := b.collectStale()
	if len(sessions) != 0 {
		t.Fatalf("expected no session evictions, got %d", len(sessions))
	}
	if len(waiters) != 1 || waiters[0].id != "stale-peer" {
		t.Fatalf("unexpected waiter eviction: %+v", waiters)
	}
	if _, ok := b.waiting["token-stale"]; ok {
		t.Fatal("stale waiter still present after collectStale")
	}
	if _, ok := b.waiting["token-fresh"]; !ok {
		t.Fatal("fresh waiter was evicted")
	}
}

func TestCollectStaleEvictsExpiredSession(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	b := newTestBroker(t, func() time.Time { return now })
	b.sessionTTL = 10 * time.Minute

	first := &peer{id: "first"}
	second := &peer{id: "second"}
	s := &session{
		id:            "session-stale",
		rendezvousKey: "token-session",
		first:         first,
		second:        second,
		createdAt:     now.Add(-30 * time.Minute),
	}
	b.sessions[s.id] = s
	b.activeKey[s.rendezvousKey] = s.id

	waiters, sessions := b.collectStale()
	if len(waiters) != 0 {
		t.Fatalf("expected no waiter evictions, got %d", len(waiters))
	}
	if len(sessions) != 1 || sessions[0].id != "session-stale" {
		t.Fatalf("unexpected session eviction: %+v", sessions)
	}
	if _, ok := b.sessions["session-stale"]; ok {
		t.Fatal("stale session still present after collectStale")
	}
	if _, ok := b.activeKey["token-session"]; ok {
		t.Fatal("stale session's activeKey entry still present")
	}
}

func TestCollectStaleLeavesFreshStateAlone(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	b := newTestBroker(t, func() time.Time { return now })
	b.waiterTTL = 1 * time.Minute
	b.sessionTTL = 10 * time.Minute

	w := &peer{
		id:            "w",
		mode:          config.ModeConnect,
		rendezvousKey: "tok-w",
		createdAt:     now.Add(-5 * time.Second),
	}
	b.waiting[w.rendezvousKey] = w

	s := &session{
		id:            "s",
		rendezvousKey: "tok-s",
		first:         &peer{id: "sf"},
		second:        &peer{id: "ss"},
		createdAt:     now.Add(-1 * time.Minute),
	}
	b.sessions[s.id] = s
	b.activeKey[s.rendezvousKey] = s.id

	waiters, sessions := b.collectStale()
	if len(waiters) != 0 || len(sessions) != 0 {
		t.Fatalf("unexpected evictions: waiters=%+v sessions=%+v", waiters, sessions)
	}
	if _, ok := b.waiting["tok-w"]; !ok {
		t.Fatal("fresh waiter was evicted")
	}
	if _, ok := b.sessions["s"]; !ok {
		t.Fatal("fresh session was evicted")
	}
	if _, ok := b.activeKey["tok-s"]; !ok {
		t.Fatal("fresh session's activeKey entry was removed")
	}
}

func TestDefaultBrokerTimeouts(t *testing.T) {
	b := NewBroker(log.New(io.Discard, "", 0))
	defer func() {
		b.stopOnce.Do(func() { close(b.stop) })
		b.janitor.Wait()
	}()

	if b.waiterTTL != DefaultWaiterTTL {
		t.Fatalf("default waiterTTL = %v, want %v", b.waiterTTL, DefaultWaiterTTL)
	}
	if b.sessionTTL != DefaultSessionTTL {
		t.Fatalf("default sessionTTL = %v, want %v", b.sessionTTL, DefaultSessionTTL)
	}
	if b.janitorInterval != DefaultJanitorInterval {
		t.Fatalf("default janitorInterval = %v, want %v", b.janitorInterval, DefaultJanitorInterval)
	}
}

func TestGenericBrokerMessageCoversAllCodes(t *testing.T) {
	for _, code := range []string{
		"register-failed",
		"pairing-failed",
		"relay-failed",
		"invalid-signal",
		"unexpected-message",
		"waiter-expired",
		"session-expired",
	} {
		if got := genericBrokerMessage(code); got == "broker error" {
			t.Fatalf("code %q falls through to the generic fallback", code)
		}
	}
	if got := genericBrokerMessage("unknown-code-xyz"); got != "broker error" {
		t.Fatalf("unknown code did not fall through: got %q", got)
	}
}
