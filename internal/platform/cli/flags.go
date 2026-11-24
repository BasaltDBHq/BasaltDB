// Package cli is the basalt command line's shell: exit codes, flag
// parsing and terminal-safe text, shared by every command.
package cli

import (
	"errors"
	"flag"
	"fmt"
)

// Exit codes (CONTRACT.md).
const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2
)

// ErrUsage marks an error as a usage error (exit 2).
var ErrUsage = errors.New("usage")

// FlagSetMade, when set, sees every flag set NewFlagSet makes. Only the
// surface test sets it, to read the flags the binary really has
// (contract/surface.json).
var FlagSetMade func(*flag.FlagSet)

// NewFlagSet makes the flag set of a command or subcommand. Every command
// makes its flag set here, so the surface test sees all of them.
func NewFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	if FlagSetMade != nil {
		FlagSetMade(fs)
	}
	return fs
}

// Parse parses args and refuses positional arguments.
func Parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %w", ErrUsage, err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: unexpected argument %q", ErrUsage, fs.Arg(0))
	}
	return nil
}
