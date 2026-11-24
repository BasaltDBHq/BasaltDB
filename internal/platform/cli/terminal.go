package cli

import (
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// TerminalWidth is w's width in columns when it is a terminal, else 0.
func TerminalWidth(w io.Writer) int {
	f, ok := w.(*os.File)
	if !ok {
		return 0
	}
	cols, _, err := term.GetSize(int(f.Fd()))
	if err != nil {
		return 0
	}
	return cols
}

// IsTerminal reports whether w is a terminal.
func IsTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// WantsJSON is true when args carry --json (or -json), with or without a value.
func WantsJSON(args []string) bool {
	for _, a := range args {
		if a == "--json" || a == "-json" || strings.HasPrefix(a, "--json=") || strings.HasPrefix(a, "-json=") {
			return true
		}
	}
	return false
}

// ConfigArg is the value of the last -config or --config flag in args,
// before a "--", and whether there is one.
func ConfigArg(args []string) (string, bool) {
	path, given := "", false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		name, value, inline := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") || name != "config" {
			continue
		}
		switch {
		case inline:
			path, given = value, true
		case i+1 < len(args):
			path, given = args[i+1], true
			i++
		}
	}
	return path, given
}
