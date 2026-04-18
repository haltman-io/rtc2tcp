package rendezvous

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// keyedLimiter wraps a per-key token-bucket rate limiter with lazy
// cleanup of stale keys. It is safe for concurrent use.
//
// The broker uses one instance keyed on the client's source IP to bound
// WebSocket upgrade attempts. A key's limiter is evicted if it has not
// been seen for cleanupAge, which prevents the map from growing
// unbounded under churn.
type keyedLimiter struct {
	rateLimit rate.Limit
	burst     int

	mu   sync.Mutex
	keys map[string]*keyedLimiterEntry
}

type keyedLimiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newKeyedLimiter(r rate.Limit, burst int) *keyedLimiter {
	return &keyedLimiter{
		rateLimit: r,
		burst:     burst,
		keys:      make(map[string]*keyedLimiterEntry),
	}
}

// Allow returns true if a single event for key is permitted at time now
// under the configured rate/burst, and false if the key's bucket is
// exhausted.
func (l *keyedLimiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry, ok := l.keys[key]
	if !ok {
		entry = &keyedLimiterEntry{
			limiter: rate.NewLimiter(l.rateLimit, l.burst),
		}
		l.keys[key] = entry
	}
	entry.lastSeen = now
	return entry.limiter.AllowN(now, 1)
}

// Cleanup evicts any key whose lastSeen is before the given cutoff.
// Callers drive this from a periodic sweep (in the broker: the
// janitor).
func (l *keyedLimiter) Cleanup(cutoff time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()

	evicted := 0
	for k, entry := range l.keys {
		if entry.lastSeen.Before(cutoff) {
			delete(l.keys, k)
			evicted++
		}
	}
	return evicted
}

// Len reports the current number of tracked keys. Intended for tests
// and diagnostics.
func (l *keyedLimiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.keys)
}
