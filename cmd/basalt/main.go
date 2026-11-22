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
}

func commands() []command {
	return []command{
		{"engine", "Run the engine service in the foreground (or revoke a recorded engine)", runEngine},
		{"mcp", "MCP server for an agent: relays stdio to the engine", runMCP},
		{"service", "Install or uninstall the engine service (install | uninstall)", runService},
		{"init", "Install the guard in Postgres and add an agent to the engine config", withIO(runInit)},
		{"approve", "Relay the code the approval page gave you to Postgres (or --show a held write's link)", withIO(runApprove)},
		{"revert", "Revert a change, run or task with your passkey; people's later edits are kept", withIO(runRevert)},
		{"passkey", "List, check or remove your passkeys (list | check | remove <id>)", withIO(runPasskey)},
		{"classify", "Suggest and confirm the PII class of every column the agents can read", withIO(runClassify)},
		{"upgrade", "Add the guard migrations this build has and the database lacks", withIO(runUpgrade)},
		{"uninstall", "Remove the guard, its ledger and its roles from Postgres", withIO(runUninstall)},
		{"trust", "List and change which root certificates verify a database host (list | add | pin | remove | disable)", withIO(runTrust)},
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
	"To set up, run basalt init --remote and give the person the setup code it prints."
