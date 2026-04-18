package rendezvous

import "github.com/haltman-io/rtc2tcp/internal/logx"

// FormatEvent emits the broker's structured log format. See
// logx.Event for the exact shape. Exported so
// cmd/rtc2tcp-broker/main.go can emit lifecycle lines in the same
// format as the broker package itself.
func FormatEvent(event string, kv ...any) string {
	return logx.Event("broker", event, kv...)
}
