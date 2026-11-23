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
	std := cli.Stdio{In: os.Stdin, Out: os.Stdout, Err: os.Stderr}
	note := startUpdateNotice(ctx, os.Args[1:], std, os.Getenv)
	code := runGuarded(ctx, os.Args[1:], std)
	note()
	stop()
	os.Exit(code)
}

func commands() []cli.Command {
	return []cli.Command{
		{Name: "engine", Summary: "Run the engine service in the foreground", Run: runEngine, Hidden: true},
		{Name: "mcp", Summary: "MCP server for an agent: relays stdio to the engine", Run: runMCP},
		{Name: "service", Summary: "Install the engine service (install)", Run: runService},
		{Name: "init", Summary: "Start setup: install the engine service when needed, then print and open the setup link", Run: cli.WithIO(newIO, runInitCommand)},
		{Name: "version", Summary: "Print the version", Run: runVersion},
		{Name: "help", Summary: "Show this help"},
	}
}

// runInitCommand is basalt init for the command table: init --remote
// reaches the adapters through appSetupHost.
func runInitCommand(c *cli.IO, args []string) int { return runInit(c, appSetupHost{}, args) }

func run(ctx context.Context, args []string, io cli.Stdio) int {
	if len(args) == 0 {
		usage(io.Err)
		return cli.ExitUsage
	}
	switch args[0] {
	case "help", "-h", "--help":
		usage(io.Out)
		return cli.ExitOK
	case "--version":
		return runVersion(ctx, nil, io)
	}
	useTrustDir(args[1:])
	for _, cmd := range commands() {
		if cmd.Name == args[0] && cmd.Run != nil {
			return cmd.Run(ctx, args[1:], io)
		}
	}
	fmt.Fprintf(io.Err, "basalt: unknown command %q\n\n", args[0])
	usage(io.Err)
	return cli.ExitUsage
}

func runVersion(_ context.Context, _ []string, io cli.Stdio) int {
	fmt.Fprintln(io.Out, "basalt "+buildinfo.Version)
	return cli.ExitOK
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "basalt - the action ledger for AI agents on your Postgres")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage: basalt <command> [flags]")
	fmt.Fprintln(w)
	for _, cmd := range commands() {
		if cmd.Hidden {
			continue
		}
		fmt.Fprintf(w, "  %-10s %s\n", cmd.Name, cmd.Summary)
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
