package main

import (
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/rlspick"
)

// runInit: basalt init. --remote makes a connect-only setup code for an
// agent-operated engine and --setup-code is the laptop half (both removed
// with the CLI cut); without them, init starts the local setup
// (runInitLocal), which never reads the admin connection string.
func runInit(c *cliIO, args []string) int {
	if isRemote(args) {
		return runInitRemote(c, args)
	}
	if isSetupCode(args) {
		return runInitSetupCode(c, args)
	}
	return runInitLocal(c, args)
}

// AgentRLSMode is the value of --agent-rls: what init does about agent
// tables where row-level security hides every row from the agent role.
// CLI input spelling only (AGENTS.md, Wire format): it is never stored;
// the ledger records the policy itself (AGENT_POLICY_ADDED).
type AgentRLSMode string

// --agent-rls values.
const (
	// AgentRLSAsk shows a checklist at a terminal, or reads one line from
	// piped input (the default).
	AgentRLSAsk AgentRLSMode = "ask"
	// AgentRLSAllRows adds the agent policy on every such table, for scripts.
	AgentRLSAllRows AgentRLSMode = "all-rows"
	// AgentRLSNone never adds an agent policy and does not ask.
	AgentRLSNone AgentRLSMode = "none"
)

// String implements flag.Value.
func (a *AgentRLSMode) String() string { return string(*a) }

// Set implements flag.Value: ask, all-rows, none, or a list of tables
// (schema.table, schema.* separated by commas).
func (a *AgentRLSMode) Set(v string) error {
	switch AgentRLSMode(v) {
	case AgentRLSAsk, AgentRLSAllRows, AgentRLSNone:
	default:
		if _, err := rlspick.ParseList(v); err != nil {
			return fmt.Errorf("must be %s, %s, %s or a list like us.*,public.orders: %w", AgentRLSAsk, AgentRLSAllRows, AgentRLSNone, err)
		}
	}
	*a = AgentRLSMode(v)
	return nil
}

// isList is true when the mode is a list of tables.
func (a AgentRLSMode) isList() bool {
	return a != AgentRLSAsk && a != AgentRLSAllRows && a != AgentRLSNone
}

// shellQuote quotes s for a POSIX shell when it has anything but plain
// path characters.
func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./:=@") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// invokingUser is the person running init: under sudo, the user who ran
// sudo, not root.
func invokingUser() (string, error) {
	if name := os.Getenv("SUDO_USER"); name != "" && os.Geteuid() == 0 {
		return name, nil
	}
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

// stateDirName is the engine's state directory next to a per-user config.
const stateDirName = "state"

// flagDevLocalPages is init's and service install's development exception.
const flagDevLocalPages = "dev-local-pages"

// printWarningLines prints each warning on its own line.
func printWarningLines(w io.Writer, warnings []string) {
	for _, warning := range warnings {
		fmt.Fprintf(w, "basalt: warning: %s\n", warning)
	}
}
