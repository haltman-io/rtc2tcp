//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"os"

	"golang.org/x/sys/unix"
)

// silenceTTYEcho — see ttyquiet_linux.go for behaviour. BSD family
// uses TIOCGETA / TIOCSETA instead of Linux's TCGETS / TCSETS.
func silenceTTYEcho() func() {
	fd := int(os.Stdin.Fd())

	original, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		return func() {}
	}

	modified := *original
	modified.Lflag &^= unix.ECHO | unix.ECHOE | unix.ECHOK | unix.ECHONL | unix.ECHOCTL | unix.ECHOKE

	if err := unix.IoctlSetTermios(fd, unix.TIOCSETA, &modified); err != nil {
		return func() {}
	}

	var restored bool
	return func() {
		if restored {
			return
		}
		restored = true
		_ = unix.IoctlSetTermios(fd, unix.TIOCSETA, original)
	}
}
