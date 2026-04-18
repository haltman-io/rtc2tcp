// Package logx formats structured, grep-friendly log lines used by the
// broker and peer binaries.
//
// Output shape:
//
//	<prefix>: event=<event> k1=<v1> k2=<v2> ...
//
// Values containing spaces, quotes, backslashes, equals signs, or
// control characters are rendered as Go-quoted strings so each field is
// unambiguously parseable. Keys are emitted in the order supplied so
// correlation ids (`session_id`, `peer_id`) can lead every line.
package logx

import (
	"fmt"
	"strconv"
	"strings"
)

// Event formats a structured log line. Pass kv as alternating
// key/value pairs. A trailing odd element is preserved as
// `_trailing=<value>` so a formatting bug stays visible instead of
// swallowing state.
func Event(prefix, event string, kv ...any) string {
	var sb strings.Builder
	sb.WriteString(prefix)
	sb.WriteString(": event=")
	sb.WriteString(event)

	i := 0
	for i+1 < len(kv) {
		sb.WriteByte(' ')
		sb.WriteString(fmt.Sprint(kv[i]))
		sb.WriteByte('=')
		writeValue(&sb, kv[i+1])
		i += 2
	}
	if i < len(kv) {
		sb.WriteString(" _trailing=")
		writeValue(&sb, kv[i])
	}
	return sb.String()
}

func writeValue(sb *strings.Builder, v any) {
	s := fmt.Sprint(v)
	if needsQuote(s) {
		sb.WriteString(strconv.Quote(s))
	} else {
		sb.WriteString(s)
	}
}

func needsQuote(s string) bool {
	if s == "" {
		return true
	}
	for _, r := range s {
		switch {
		case r == ' ', r == '"', r == '\\', r == '=':
			return true
		case r < 0x20, r == 0x7f:
			return true
		}
	}
	return false
}
