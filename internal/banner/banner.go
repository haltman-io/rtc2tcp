// Package banner renders the rtc2tcp startup banner. Silenced by
// --quiet/--silent on either binary so pipelines and scripted runs
// stay tidy.
package banner

import (
	"fmt"
	"io"
	"strings"

	"rtc2tcp/internal/color"
	"rtc2tcp/internal/config"
)

const (
	ProjectName    = "rtc2tcp"
	Tagline        = "authenticated WebRTC → TCP tunnel"
	Attribution    = "haltman.io"
	AttributionURL = "https://haltman.io/"
	SourceURL      = "https://github.com/haltman-io/rtc2tcp"
)

// asciiLogo is a figlet-style word mark for "rtc2tcp".
const asciiLogo = `      _       ____     _
 _ __| |_ ___|___ \ __| |_ ___ _ __
| '__| __/ __| __) / _` + "`" + ` __/ __| '_ \
| |  | || (__ / __/ (_| || (__| |_) |
|_|   \__\___|_____\__,_\__\___| .__/
                               |_|   `

// Options controls how the banner is rendered. Keep it a plain struct
// so main.go can populate it from parsed flags without a builder.
type Options struct {
	Quiet   bool             // skip the banner entirely
	NoColor bool             // force-disable ANSI even if Detect says TTY
	Build   config.BuildInfo // version/commit to stamp
	Tool    string           // short binary name, e.g. "rtc2tcp-peer"
	Role    string           // optional role tag, e.g. "expose" / "connect"
}

// Print writes the banner to w. Honours Options.Quiet. Safe on a
// non-terminal writer: the colour helpers degrade to plain text.
func Print(w io.Writer, opts Options) {
	if opts.Quiet {
		return
	}
	enabled := !opts.NoColor && color.Detect(w)
	c := color.New(enabled)

	version := strings.TrimSpace(opts.Build.Version)
	if version == "" {
		version = "dev"
	}
	commit := strings.TrimSpace(opts.Build.Commit)
	if commit == "" {
		commit = "unknown"
	}

	for _, line := range strings.Split(asciiLogo, "\n") {
		fmt.Fprintln(w, c.Cyan(line))
	}
	fmt.Fprintln(w)

	tool := strings.TrimSpace(opts.Tool)
	if tool == "" {
		tool = ProjectName
	}
	header := fmt.Sprintf("%s  %s",
		c.Bold(tool),
		c.Muted(fmt.Sprintf("v%s · %s", version, commit)),
	)
	if role := strings.TrimSpace(opts.Role); role != "" {
		header += "  " + c.Cyan("["+role+"]")
	}
	fmt.Fprintln(w, header)

	fmt.Fprintln(w, c.Muted(Tagline))
	fmt.Fprintln(w, c.Muted(Attribution+" · "+SourceURL))
	fmt.Fprintln(w)
}

// VersionLine returns a compact "rtc2tcp-* vX.Y.Z (commit)" string for
// --version output. Never coloured; this is typically grepped.
func VersionLine(tool string, build config.BuildInfo) string {
	version := strings.TrimSpace(build.Version)
	if version == "" {
		version = "dev"
	}
	commit := strings.TrimSpace(build.Commit)
	if commit == "" {
		commit = "unknown"
	}
	return fmt.Sprintf("%s v%s (%s)", tool, version, commit)
}
