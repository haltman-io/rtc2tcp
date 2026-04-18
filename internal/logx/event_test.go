package logx

import (
	"strings"
	"testing"
)

func TestEventSimpleFields(t *testing.T) {
	got := Event("broker", "registered", "peer_id", "abc", "mode", "connect")
	want := `broker: event=registered peer_id=abc mode=connect`
	if got != want {
		t.Fatalf("\n got:  %s\n want: %s", got, want)
	}
}

func TestEventQuotesValuesWithSpaces(t *testing.T) {
	got := Event("peer", "auth_failure", "err", "read registration: deadline exceeded")
	if !strings.Contains(got, `err="read registration: deadline exceeded"`) {
		t.Fatalf("expected quoted err field: %s", got)
	}
}

func TestEventQuotesValuesWithEquals(t *testing.T) {
	got := Event("broker", "x", "k", "a=b")
	if !strings.Contains(got, `k="a=b"`) {
		t.Fatalf("expected quoted value with =: %s", got)
	}
}

func TestEventQuotesEmptyValue(t *testing.T) {
	got := Event("broker", "x", "k", "")
	if !strings.Contains(got, `k=""`) {
		t.Fatalf("expected quoted empty value: %s", got)
	}
}

func TestEventQuotesQuotesAndBackslashes(t *testing.T) {
	got := Event("broker", "x", "k", `he said "hi"\n`)
	if !strings.Contains(got, `k="he said \"hi\"\\n"`) {
		t.Fatalf("expected escaped value: %s", got)
	}
}

func TestEventLeavesSimpleValuesUnquoted(t *testing.T) {
	got := Event("broker", "x", "k", "127.0.0.1:8080")
	if !strings.Contains(got, "k=127.0.0.1:8080") {
		t.Fatalf("expected unquoted value: %s", got)
	}
	if strings.Contains(got, `"127.0.0.1:8080"`) {
		t.Fatalf("value should not be quoted: %s", got)
	}
}

func TestEventPreservesKeyOrder(t *testing.T) {
	got := Event("broker", "paired",
		"session_id", "S",
		"peer_a", "A",
		"peer_b", "B",
	)
	want := `broker: event=paired session_id=S peer_a=A peer_b=B`
	if got != want {
		t.Fatalf("\n got:  %s\n want: %s", got, want)
	}
}

func TestEventTrailingOddField(t *testing.T) {
	got := Event("broker", "x", "k", "v", "orphan")
	if !strings.Contains(got, "_trailing=orphan") {
		t.Fatalf("expected _trailing surface on odd field: %s", got)
	}
}

func TestEventHonoursPrefix(t *testing.T) {
	got := Event("peer", "session_ready", "session_id", "abc")
	if !strings.HasPrefix(got, "peer: event=session_ready") {
		t.Fatalf("unexpected prefix: %s", got)
	}
}
