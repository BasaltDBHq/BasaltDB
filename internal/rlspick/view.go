package rlspick

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// ErrCanceled is returned by Run when the person ends the checklist with
// Ctrl-C or Ctrl-D, or the input ends before Enter.
var ErrCanceled = errors.New("canceled")

const (
	esc   = 0x1b
	ctrlC = 0x03
	ctrlD = 0x04
	// groupSize is the digits between thousands separators.
	groupSize = 3
	// footerRows are the lines around the checklist: blank, summary, and
	// the blank line after the header.
	footerRows = 4
	minRows    = 5
)

// Key is one key the checklist understands.
type Key int

// The keys.
const (
	KeyUp Key = iota + 1
	KeyDown
	KeyRight
	KeyLeft
	KeySpace
	KeySchema
	KeyEnter
	KeyCancel
)

// Press applies one key to the model; it reports whether the key confirms.
func (m *Model) Press(k Key) (confirmed bool) {
	switch k {
	case KeyUp:
		m.Up()
	case KeyDown:
		m.Down()
	case KeyRight:
		m.Open()
	case KeyLeft:
		m.Close()
	case KeySpace:
		m.Toggle()
	case KeySchema:
		m.ToggleSchema()
	case KeyEnter:
		return true
	case KeyCancel:
	}
	return false
}

// ParseKeys turns terminal bytes into keys. An escape sequence cut off at
// the end of b is returned as rest, to be put in front of the next read.
func ParseKeys(b []byte) (keys []Key, rest []byte) {
	for i := 0; i < len(b); i++ {
		switch c := b[i]; c {
		case esc:
			if i+2 >= len(b) {
				return keys, b[i:]
			}
			if b[i+1] == '[' || b[i+1] == 'O' {
				switch b[i+2] {
				case 'A':
					keys = append(keys, KeyUp)
				case 'B':
					keys = append(keys, KeyDown)
				case 'C':
					keys = append(keys, KeyRight)
				case 'D':
					keys = append(keys, KeyLeft)
				}
				i += 2
			}
		case ' ':
			keys = append(keys, KeySpace)
		case 'a', 'A':
			keys = append(keys, KeySchema)
		case 'k':
			keys = append(keys, KeyUp)
		case 'j':
			keys = append(keys, KeyDown)
		case 'l':
			keys = append(keys, KeyRight)
		case 'h':
			keys = append(keys, KeyLeft)
		case '\r', '\n':
			keys = append(keys, KeyEnter)
		case ctrlC, ctrlD:
			keys = append(keys, KeyCancel)
		}
	}
	return keys, nil
}

// clean replaces control characters, which a database name may hold.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) {
			return '?'
		}
		return r
	}, s)
}

func commas(n int64) string {
	s := fmt.Sprint(n)
	for i := len(s) - groupSize; i > 0; i -= groupSize {
		s = s[:i] + "," + s[i:]
	}
	return s
}

func plural(n int64, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", one)
	}
	return fmt.Sprintf("%s %s", commas(n), many)
}

// View is the checklist's lines below the header: at most height rows of
// schemas and tables around the cursor, a blank line and the summary line.
// Each line is cut to width columns (0: not cut).
func (m *Model) View(width, height int) []string {
	type line struct{ left, right string }
	vis := m.visible()
	lines := make([]line, 0, len(vis))
	leftW, rightW := 0, 0
	for i, r := range vis {
		g := m.groups[r.g]
		var mark, body, right string
		cursor := "  "
		if i == m.cursor {
			cursor = "› "
		}
		if r.t < 0 {
			var rows int64
			for _, t := range g.tables {
				rows += t.rows
			}
			box := map[checkState]string{none: "[ ]", some: "[-]", all: "[x]"}[g.state()]
			mark = cursor + box + " "
			body = clean(g.schema)
			if !g.open {
				body += "  (collapsed, → to open)"
			}
			right = plural(int64(len(g.tables)), "table", "tables") + "  " + plural(rows, "row", "rows")
		} else {
			t := g.tables[r.t]
			box := "[ ]"
			if t.checked {
				box = "[x]"
			}
			mark = cursor + "  " + box + " "
			body = clean(t.name)
			right = commas(t.rows)
		}
		l := line{mark + body, right}
		lines = append(lines, l)
		leftW = max(leftW, utf8.RuneCountInString(l.left))
		rightW = max(rightW, utf8.RuneCountInString(l.right))
	}
	start, end := 0, len(lines)
	if height > 0 && len(lines) > height {
		start = min(max(m.cursor-height/2, 0), len(lines)-height)
		end = start + height
	}
	out := make([]string, 0, end-start+2)
	for _, l := range lines[start:end] {
		pad := leftW - utf8.RuneCountInString(l.left) + 2 + rightW - utf8.RuneCountInString(l.right)
		s := l.left + strings.Repeat(" ", pad) + l.right
		out = append(out, cut(s, width))
	}
	c, n := m.Counts()
	out = append(out, "", cut(fmt.Sprintf("%d of %d checked · Enter to confirm", c, n), width))
	return out
}

func cut(s string, width int) string {
	if width <= 0 || utf8.RuneCountInString(s) <= width {
		return s
	}
	r := []rune(s)
	return string(r[:width-1]) + "…"
}

// Run draws header and the checklist on out and drives m with the keys
// read from in until Enter (nil) or Ctrl-C and the end of in
// (ErrCanceled). The terminal must already be in raw mode: lines end in
// CR LF. height is the terminal's height in rows, 0 when unknown.
func Run(in io.Reader, out io.Writer, m *Model, header []string, width, height int) (err error) {
	budget := 0
	if height > 0 {
		budget = max(height-len(header)-footerRows, minRows)
	}
	prev := 0
	draw := func() {
		var b strings.Builder
		if prev > 1 {
			fmt.Fprintf(&b, "\x1b[%dA", prev-1)
		}
		b.WriteString("\r\x1b[J")
		lines := make([]string, 0, len(header)+8)
		for _, h := range header {
			lines = append(lines, cut(h, width))
		}
		lines = append(lines, "")
		lines = append(lines, m.View(width, budget)...)
		b.WriteString(strings.Join(lines, "\r\n"))
		prev = len(lines)
		_, _ = io.WriteString(out, b.String())
	}
	_, _ = io.WriteString(out, "\x1b[?25l")
	defer func() {
		_, _ = io.WriteString(out, "\x1b[?25h\r\n")
	}()
	draw()
	var held []byte
	buf := make([]byte, 64)
	for {
		n, rerr := in.Read(buf)
		keys, rest := ParseKeys(append(held, buf[:n]...))
		held = append([]byte(nil), rest...)
		for _, k := range keys {
			if k == KeyCancel {
				return ErrCanceled
			}
			if m.Press(k) {
				draw()
				return nil
			}
		}
		if len(keys) > 0 {
			draw()
		}
		if rerr != nil {
			return ErrCanceled
		}
	}
}
