package cli

import (
	"context"
	"io"
)

// Stdio is the process's standard streams, passed to every command.
type Stdio struct {
	In       io.Reader
	Out, Err io.Writer
}

// Command is one entry of the command table.
type Command struct {
	Name, Summary string
	Run           func(ctx context.Context, args []string, io Stdio) int
	// Hidden keeps the command out of the help listing; it still runs.
	Hidden bool
}
