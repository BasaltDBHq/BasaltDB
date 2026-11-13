package main

import "golang.org/x/sys/unix"

// The termios ioctls on macOS.
const (
	ttyGetTermios = unix.TIOCGETA
	ttySetTermios = unix.TIOCSETA
)
