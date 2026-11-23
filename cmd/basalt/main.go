// Command basalt is the BasaltDB binary: the edge engine, the MCP shim and
// the person's CLI. Milestone M1 adds init, log and the MCP shim; M2 adds
// approve; M3 adds revert. See CONTRACT.md.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/basaltdbhq/basaltdb/internal/lib/buildinfo"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	std := stdio{in: os.Stdin, out: os.Stdout, err: os.Stderr}
	note := startUpdateNotice(ctx, os.Args[1:], std, os.Getenv)
	code := runGuarded(ctx, os.Args[1:], std)
	note()
	stop()
	os.Exit(code)
}

// stdio is the process's standard streams, passed to every command.
type stdio struct {
	in       io.Reader
	out, err io.Writer
}

type command struct {
	name, summary string
	run           func(ctx context.Context, args []string, io stdio) int
	// hidden keeps the command out of the help listing; it still runs.
	hidden bool
}

func commands() []command {
	return []command{
		{"engine", "Run the engine service in the foreground", runEngine, true},
		{"mcp", "MCP server for an agent: relays stdio to the engine", runMCP, false},
		{"service", "Install the engine service (install)", runService, false},
		{"init", "Start setup: install the engine service when needed, then print and open the setup link", withIO(newIO, runInitCommand), false},
		{"version", "Print the version", runVersion, false},
		{"help", "Show this help", nil, false},
	}
}

// runInitCommand is basalt init for the command table: init --remote
// reaches the adapters through appSetupHost.
func runInitCommand(c *cliIO, args []string) int { return runInit(c, appSetupHost{}, args) }

func run(ctx context.Context, args []string, io stdio) int {
	if len(args) == 0 {
		usage(io.err)
		return cli.ExitUsage
	}
	switch args[0] {
	case "help", "-h", "--help":
		usage(io.out)
		return cli.ExitOK
	case "--version":
		return runVersion(ctx, nil, io)
	}
	useTrustDir(args[1:])
	for _, cmd := range commands() {
		if cmd.name == args[0] && cmd.run != nil {
			return cmd.run(ctx, args[1:], io)
		}
	}
	fmt.Fprintf(io.err, "basalt: unknown command %q\n\n", args[0])
	usage(io.err)
	return cli.ExitUsage
}

func runVersion(_ context.Context, _ []string, io stdio) int {
	fmt.Fprintln(io.out, "basalt "+buildinfo.Version)
	return cli.ExitOK
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "basalt - the action ledger for AI agents on your Postgres")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage: basalt <command> [flags]")
	fmt.Fprintln(w)
	for _, cmd := range commands() {
		if cmd.hidden {
			continue
		}
		fmt.Fprintf(w, "  %-10s %s\n", cmd.name, cmd.summary)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, cli.ManyAgentsHelp)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Exit codes: 0 ok, 1 error, 2 usage error.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, cli.AgentsHelp)
}

// fail prints err for command name and returns the error exit code.
func fail(w io.Writer, name string, err error) int {
	fmt.Fprintf(w, "basalt %s: %v\n", name, err)
	return cli.ExitError
}
