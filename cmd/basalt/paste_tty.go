//go:build darwin || linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

// Control bytes the raw read handles itself.
const (
	keyEOF       = 0x04 // Ctrl-D: end of input on an empty line
	keyBackspace = 0x08
	keyDelete    = 0x7f
	// keySpace is the first byte that is not a control byte.
	keySpace = 0x20
)

// readTerminalLine reads one line from the terminal tty after prefix,
// with canonical mode and echo off, so the line has no length limit but
// maxPasted. It echoes what it reads and handles backspace itself, ignores
// other control bytes, and takes Enter (CR or LF) as the end of the line.
// Signals stay on: Ctrl-C ends ctx through the CLI's signal handling. It
// polls every tenth of a second (VMIN 0, VTIME 1) so ctx can end the wait,
// and restores the terminal's modes before it returns.
func readTerminalLine(ctx context.Context, tty *os.File, prefix []byte) (string, error) {
	fd := int(tty.Fd())
	saved, err := unix.IoctlGetTermios(fd, ttyGetTermios)
	if err != nil {
		return "", errNoRawRead
	}
	raw := *saved
	raw.Lflag &^= unix.ICANON | unix.ECHO
	raw.Cc[unix.VMIN] = 0
	raw.Cc[unix.VTIME] = 1
	if err := unix.IoctlSetTermios(fd, ttySetTermios, &raw); err != nil {
		return "", errNoRawRead
	}
	defer func() { _ = unix.IoctlSetTermios(fd, ttySetTermios, saved) }()

	line := append([]byte(nil), prefix...)
	b := make([]byte, 1)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := unix.Read(fd, b)
		switch {
		case errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN):
			continue
		case err != nil:
			return "", fmt.Errorf("read the terminal: %w", err)
		case n == 0:
			continue // no input this tenth of a second
		}
		switch ch := b[0]; {
		case ch == '\r' || ch == '\n':
			echo(fd, "\n")
			return string(line), nil
		case ch == keyEOF && len(line) == 0:
			return "", io.EOF
		case ch == keyDelete || ch == keyBackspace:
			if len(line) > 0 {
				_, size := utf8.DecodeLastRune(line)
				line = line[:len(line)-size]
				echo(fd, "\b \b")
			}
		case ch < keySpace:
			// Other control bytes are not part of a code.
		default:
			if len(line) >= maxPasted {
				return "", fmt.Errorf("the pasted text is longer than %d KiB", maxPasted>>10)
			}
			line = append(line, ch)
			_, _ = unix.Write(fd, b)
		}
	}
}

// echo shows s on the terminal; a terminal that cannot show it loses
// only the echo.
func echo(fd int, s string) {
	_, _ = unix.Write(fd, []byte(s))
}
