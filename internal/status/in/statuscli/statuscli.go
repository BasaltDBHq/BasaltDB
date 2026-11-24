// Package statuscli is the status commands of the CLI: basalt version and
// the newer-release line every command prints.
package statuscli

import (
	"context"
	"fmt"
	"io"

	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/status"
)

const (
	ansiYellow = "\x1b[33m"
	ansiRed    = "\x1b[31m"
	ansiReset  = "\x1b[0m"
)

// RunVersion is basalt version.
func RunVersion(_ context.Context, _ []string, io cli.Stdio) int {
	fmt.Fprintln(io.Out, "basalt "+buildinfo.Version)
	return cli.ExitOK
}

// PrintUpdateLine writes n's line to w: yellow, or red for a security
// release, only when w is a terminal and NO_COLOR is not set.
func PrintUpdateLine(w io.Writer, getenv func(string) string, n *status.UpdateNotice) {
	if n == nil {
		return
	}
	line := n.Line
	if getenv("NO_COLOR") == "" && cli.IsTerminal(w) {
		color := ansiYellow
		if n.Security {
			color = ansiRed
		}
		line = color + line + ansiReset
	}
	fmt.Fprintln(w, line)
}
