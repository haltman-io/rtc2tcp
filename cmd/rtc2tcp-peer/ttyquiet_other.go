//go:build !(linux || darwin || freebsd || netbsd || openbsd || dragonfly)

package main

// silenceTTYEcho is a no-op on platforms without termios. On Windows,
// console input is already buffered by the OS line-editor and doesn't
// exhibit the click-to-arrow-key echo pollution seen on Linux/WSL.
func silenceTTYEcho() func() {
	return func() {}
}
