package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
)

// maxPasted bounds a pasted line. The longest code a page shows is a few
// KiB; the bound only stops a stuck paste from growing without end.
const maxPasted = 64 << 10

// errNoRawRead is readTerminalLine on a platform where basalt does not set
// the terminal's modes itself: the paste is then read as any other line.
var errNoRawRead = errors.New("raw terminal reads are not supported here")

// pasted reads a pasted code (CONTRACT.md, CLI, Pasted codes). At a
// terminal it reads the line with canonical mode off, its own echo and
// backspace, since a canonical-mode line holds only 1024 bytes on macOS
// (MAX_CANON) and a code is longer; it restores the terminal's modes when
// it returns, and returns ctx's error when ctx ends first. Without a
// terminal it reads a line. Surrounding space is trimmed.
func (c *cliIO) pasted(ctx context.Context) (string, error) {
	if c.terminal == nil {
		return c.line()
	}
	// A line the line reader already holds is read from it; bytes it holds
	// without a newline start the paste.
	var prefix []byte
	if n := c.stdin.Buffered(); n > 0 {
		held, _ := c.stdin.Peek(n) // n bytes are buffered: no error
		if bytes.IndexByte(held, '\n') >= 0 {
			return c.line()
		}
		prefix = append(prefix, held...)
		_, _ = c.stdin.Discard(n)
	}
	s, err := readTerminalLine(ctx, c.terminal, prefix)
	if errors.Is(err, errNoRawRead) {
		rest, err := c.line()
		return strings.TrimSpace(string(prefix) + rest), err
	}
	return strings.TrimSpace(s), err
}
