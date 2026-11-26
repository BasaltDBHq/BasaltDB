package cli

import (
	"context"
	"fmt"
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

// CommandName is the command a command line runs, for a crash report: only
// a name from cmds, never an argument; "" when args names none.
func CommandName(args []string, cmds []Command) string {
	if len(args) == 0 {
		return ""
	}
	for _, cmd := range cmds {
		if cmd.Name == args[0] {
			return cmd.Name
		}
	}
	return ""
}

// Fail prints err for command name on w and returns the error exit code.
func Fail(w io.Writer, name string, err error) int {
	fmt.Fprintf(w, "basalt %s: %v\n", name, err)
	return ExitError
}
