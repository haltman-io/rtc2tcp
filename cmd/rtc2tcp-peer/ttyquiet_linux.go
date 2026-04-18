//go:build linux

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// silenceTTYEcho clears the ECHO family of termios lflags on stdin so
// stray keystrokes (arrow keys emitted by terminal click-to-position,
// mouse reporting, hold-down autorepeat, etc.) don't paint visible
// garbage over the peer's output. The TTY stays in canonical mode and
// ISIG is untouched — Ctrl+C, Ctrl+Z, Ctrl+\ still deliver signals
// normally; the peer is not claiming any keystrokes for itself.
//
// Returns a restore function that reverts the TTY to its original
// state. Safe to call multiple times. If stdin isn't a TTY (pipe,
// /dev/null, CI log capture), the function is a no-op and the restore
// is also a no-op.
func silenceTTYEcho() func() {
	fd := int(os.Stdin.Fd())

	original, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return func() {}
	}

	modified := *original
	modified.Lflag &^= unix.ECHO | unix.ECHOE | unix.ECHOK | unix.ECHONL | unix.ECHOCTL | unix.ECHOKE

	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &modified); err != nil {
		return func() {}
	}

	var restored bool
	return func() {
		if restored {
			return
		}
		restored = true
		_ = unix.IoctlSetTermios(fd, unix.TCSETS, original)
	}
}
