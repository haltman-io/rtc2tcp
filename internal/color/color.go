// Package color renders terminal output with ANSI colors, degrading
// gracefully when the output stream is not a terminal or the user has
// opted out via NO_COLOR or a caller-supplied flag.
//
// The rules, in order:
//
//   - NO_COLOR environment variable set (any value) => disabled
//     (https://no-color.org)
//   - FORCE_COLOR set              => enabled unconditionally
//   - caller passes enabled=false  => disabled
//   - writer is a non-TTY          => disabled
//   - otherwise                    => enabled
//
// On Windows, modern terminals (Windows Terminal, VS Code, PowerShell
// 7+) honour ANSI escapes natively; older cmd.exe does not, but setting
// NO_COLOR=1 or --no-color handles that cleanly.
package color

import (
	"io"
	"os"
)

// Palette bundles the formatted helpers callers use. All methods are
// safe to call when the palette is disabled; they return the input
// unchanged.
type Palette struct {
	enabled bool
}

// New returns a palette whose output is coloured iff enabled is true.
// Call Detect first to pick a sensible default, then force-override
// with the explicit caller opt-out if needed.
func New(enabled bool) *Palette { return &Palette{enabled: enabled} }

// Enabled reports whether the palette is currently colouring output.
func (p *Palette) Enabled() bool { return p != nil && p.enabled }

// Detect decides whether colours should be enabled for writes to w,
// respecting NO_COLOR / FORCE_COLOR and falling back to a TTY probe.
func Detect(w io.Writer) bool {
	if _, noColor := os.LookupEnv("NO_COLOR"); noColor {
		return false
	}
	if _, force := os.LookupEnv("FORCE_COLOR"); force {
		return true
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

// Style helpers. Each returns s wrapped in the ANSI sequence when the
// palette is enabled, or s unchanged otherwise.
func (p *Palette) Bold(s string) string    { return p.wrap(s, "\x1b[1m") }
func (p *Palette) Dim(s string) string     { return p.wrap(s, "\x1b[2m") }
func (p *Palette) Red(s string) string     { return p.wrap(s, "\x1b[31m") }
func (p *Palette) Green(s string) string   { return p.wrap(s, "\x1b[32m") }
func (p *Palette) Yellow(s string) string  { return p.wrap(s, "\x1b[33m") }
func (p *Palette) Blue(s string) string    { return p.wrap(s, "\x1b[34m") }
func (p *Palette) Magenta(s string) string { return p.wrap(s, "\x1b[35m") }
func (p *Palette) Cyan(s string) string    { return p.wrap(s, "\x1b[36m") }
func (p *Palette) Gray(s string) string    { return p.wrap(s, "\x1b[90m") }

// Semantic helpers, centred on meaning rather than colour name.
func (p *Palette) Info(s string) string    { return p.Cyan(s) }
func (p *Palette) Success(s string) string { return p.Green(s) }
func (p *Palette) Warn(s string) string    { return p.Yellow(s) }
func (p *Palette) Error(s string) string   { return p.Red(s) }
func (p *Palette) Muted(s string) string   { return p.Gray(s) }

func (p *Palette) wrap(s, code string) string {
	if !p.Enabled() {
		return s
	}
	return code + s + "\x1b[0m"
}
