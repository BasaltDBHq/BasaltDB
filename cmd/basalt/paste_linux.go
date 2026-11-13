package main

import "golang.org/x/sys/unix"

// The termios ioctls on Linux.
const (
	ttyGetTermios = unix.TCGETS
	ttySetTermios = unix.TCSETS
)
