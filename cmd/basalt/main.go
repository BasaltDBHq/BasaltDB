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
	code := run(ctx, os.Args[1:], stdio{in: os.Stdin, out: os.Stdout, err: os.Stderr})
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
}

func commands() []command {
	return []command{
		{"engine", "Run the engine service in the foreground (or list | revoke the recorded engines)", runEngine},
		{"mcp", "MCP server for an agent: relays stdio to the engine", runMCP},
		{"service", "Install or uninstall the engine service (install | uninstall)", runService},
		{"init", "Install the guard in Postgres and add an agent to the engine config", withIO(runInit)},
		{"log", "Show an agent's change records", withIO(runLog)},
		{"access", "List the tables an agent can read, can write and is not granted", withIO(runAccess)},
		{"approve", "Relay the code the approval page gave you to Postgres (or --show a held write's link)", withIO(runApprove)},
		{"revert", "Revert a change, run or task with your passkey; people's later edits are kept", withIO(runRevert)},
		{"tunnel", "Print the commands that publish the engine's direct listener through your own tunnel, and check the address", withIO(runTunnel)},
		{"portal", "Check the hosted portal's pages against this binary's copy (verify)", withIO(runPortal)},
		{"passkey", "List, check or remove your passkeys (list | check | remove <id>)", withIO(runPasskey)},
		{"status", "Show what is ready for an agent and what to fix, with the commands", withIO(runStatus)},
		{"classify", "Suggest and confirm the PII class of every column the agents can read", withIO(runClassify)},
		{"upgrade", "Add the guard migrations this build has and the database lacks", withIO(runUpgrade)},
		{"uninstall", "Remove the guard, its ledger and its roles from Postgres", withIO(runUninstall)},
		{"version", "Print the version", runVersion},
		{"help", "Show this help", nil},
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

func usage(w io.Writer) {
	fmt.Fprintln(w, "basalt - the action ledger for AI agents on your Postgres")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage: basalt <command> [flags]")
	fmt.Fprintln(w)
	for _, cmd := range commands() {
		fmt.Fprintf(w, "  %-10s %s\n", cmd.name, cmd.summary)
	}
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
	"To set up, run basalt init --remote and give the person the setup code it prints."
