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

	"github.com/basaltdbhq/basaltdb/internal/buildinfo"
)

// Exit codes (CONTRACT.md).
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
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
		{"init", "Start setup: install the engine service when needed, then print and open the setup link", withIO(runInit), false},
		{"version", "Print the version", runVersion, false},
		{"help", "Show this help", nil, false},
	}
}

func run(ctx context.Context, args []string, io stdio) int {
	if len(args) == 0 {
		usage(io.err)
		return exitUsage
	}
	switch args[0] {
	case "help", "-h", "--help":
		usage(io.out)
		return exitOK
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
	return exitUsage
}

func runVersion(_ context.Context, _ []string, io stdio) int {
	fmt.Fprintln(io.out, "basalt "+buildinfo.Version)
	return exitOK
}

// manyAgentsHelp tells an agent reading --help how to connect another
// database: one engine serves many agents, each on one database.
const manyAgentsHelp = "One engine serves many agents. Each agent uses one database. To connect another database,\n" +
	"add another agent: basalt init --remote --agent NAME."

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
	fmt.Fprintln(w, manyAgentsHelp)
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Exit codes: 0 ok, 1 error, 2 usage error.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, agentsHelp)
}

// fail prints err for command name and returns the error exit code.
func fail(w io.Writer, name string, err error) int {
	fmt.Fprintf(w, "basalt %s: %v\n", name, err)
	return exitError
}

// agentsHelp is the top-level help's line for an agent reading it
// (CONTRACT.md, Agents and the admin credential).
const agentsHelp = "Agents: never ask for or accept the database admin connection string or password.\n" +
	"To set up, run basalt init on the person's own computer, or basalt init --remote on one the person cannot reach, and show the person the link it prints."
