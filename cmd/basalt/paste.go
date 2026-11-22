package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync"
)

// maxPasted bounds a pasted line. The longest code a page shows is a few
// KiB; the bound only stops a stuck paste from growing without end.
const maxPasted = 64 << 10

// errNoRawRead is readTerminalLine on a platform where basalt does not set
// the terminal's modes itself: the paste is then read as any other line.
var errNoRawRead = errors.New("raw terminal reads are not supported here")

// rawLineReader reads one line from a terminal with canonical mode off
// (readTerminalLine; tests replace it).
type rawLineReader func(ctx context.Context, tty *os.File, prefix []byte) (string, error)

// pasted reads a pasted code (CONTRACT.md, CLI, Pasted codes). At a
// terminal it reads the line with canonical mode off, its own echo and
// backspace, since a canonical-mode line holds only 1024 bytes on macOS
// (MAX_CANON) and a code is longer; it restores the terminal's modes when
// it returns, and returns ctx's error when ctx ends first. Without a
// terminal, or where the terminal's modes cannot be set, it reads a line,
// which ctx cannot stop. Surrounding space is trimmed.
func (c *cliIO) pasted(ctx context.Context) (string, error) {
	return c.pasteLine(ctx, func() {})
}

// pasteLine is pasted; it calls blocking just before a read that ctx
// cannot stop (a plain line read).
func (c *cliIO) pasteLine(ctx context.Context, blocking func()) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if c.terminal == nil {
		blocking()
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
	read := c.rawRead
	if read == nil {
		read = readTerminalLine
	}
	s, err := read(ctx, c.terminal, prefix)
	if errors.Is(err, errNoRawRead) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		blocking()
		rest, err := c.line()
		return strings.TrimSpace(string(prefix) + rest), err
	}
	return strings.TrimSpace(s), err
}

// paste is one result of a background paste read.
type paste struct {
	code string
	err  error
}

// pasteInBackground reads a pasted code while the command waits for
// something else (the page's hand-back or relay). It skips empty lines and
// sends the first code or read error on the channel. stop ends the read:
// it waits until the read has restored the terminal's modes, but never for
// a plain line read, which cannot be stopped and is left to end with its
// input.
func (c *cliIO) pasteInBackground(ctx context.Context) (pastes <-chan paste, stop func()) {
	ctx, cancel := context.WithCancel(ctx)
	out := make(chan paste, 1)
	released := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(released) }) }
	go func() {
		defer release()
		for {
			code, err := c.pasteLine(ctx, release)
			if err != nil || code != "" {
				out <- paste{code, err}
				return
			}
		}
	}()
	return out, func() {
		cancel()
		<-released
	}
}
