package main

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/pgcatalog"
)

// runAccess: basalt access (CONTRACT.md, CLI). Lists the tables the agent
// can read, can write and is not granted, with the command that would grant
// each. It prints names the describe tool only counts, so it is the person's
// command and no MCP tool.
func runAccess(c *cliIO, args []string) int {
	fs := c.flags("access")
	name := fs.String("agent", "", "the agent whose access to list")
	configPath := fs.String("config", config.DefaultPath(runtime.GOOS), "engine config file")
	asJSON := fs.Bool("json", false, "print the three lists as JSON")
	if err := parse(fs, args); err != nil {
		return c.fail(err)
	}
	if !config.ValidAgentName(*name) {
		return c.fail(fmt.Errorf("%w: give --agent NAME", errUsage))
	}
	l, err := openLedger(c, *name, "", *configPath)
	if err != nil {
		return c.fail(err)
	}
	defer l.close()
	access, err := l.ListAccess(c.ctx)
	if err != nil {
		return c.fail(err)
	}
	if *asJSON {
		enc := json.NewEncoder(c.stdout)
		enc.SetIndent("", "  ")
		return exitCode(c, enc.Encode(struct {
			Read       []string `json:"read"`
			Write      []string `json:"write"`
			NotGranted []string `json:"notGranted"`
		}{orEmpty(access.Read), orEmpty(access.Write), orEmpty(access.NotGranted)}))
	}
	cmds, known := accessCommands(c, *name, *configPath)
	printAccess(c.stdout, access, cmds, known)
	return exitOK
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// accessCommands are the agent's commands built from its saved init flags,
// and whether those flags were read. In service mode the person usually
// cannot read engine.json; a command built without them would reset the
// agent's saved flags, so the caller then prints only the flag to add.
func accessCommands(c *cliIO, name, configPath string) (cmds agent.Commands, known bool) {
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return agent.Commands{}, false
	}
	cfg, err := config.Load(abs)
	if err != nil {
		return agent.Commands{}, false
	}
	for _, a := range cfg.Agents {
		if a.Name != name {
			continue
		}
		cmds, err := agent.NewCommands(name, abs, c.goos, a.InitArgs)
		if err != nil {
			return agent.Commands{}, false
		}
		return cmds.OperatedBy(cfg.OperatedBy), true
	}
	return agent.Commands{}, false
}

func printAccess(w io.Writer, a pgcatalog.Access, cmds agent.Commands, known bool) {
	several := schemaCount(a) > 1
	section := func(title string, tables []string, suffix func(string) string) {
		fmt.Fprintln(w, title)
		if len(tables) == 0 {
			fmt.Fprintln(w, "  none")
			return
		}
		last := ""
		for _, t := range tables {
			schema, _, _ := strings.Cut(t, ".")
			if several && schema != last {
				fmt.Fprintf(w, "  %s\n", schema)
				last = schema
			}
			indent := "  "
			if several {
				indent = "    "
			}
			fmt.Fprintf(w, "%s%s%s\n", indent, t, suffix(t))
		}
	}
	none := func(string) string { return "" }
	section("Can read", a.Read, none)
	fmt.Fprintln(w)
	section("Can write", a.Write, none)
	fmt.Fprintln(w)
	section("Not granted", a.NotGranted, func(t string) string {
		grant := cmds.Grant
		if cmds.AgentOperated() {
			grant = cmds.RemoteGrant
		}
		if !known {
			grant = func(flag, table string) (string, error) {
				if _, err := (agent.Commands{}).Grant(flag, table); err != nil {
					return "", err
				}
				return "--" + flag + "=" + table, nil
			}
		}
		cmd, err := grant("read", t)
		if err != nil { // agent.ErrBadTable: not a plain schema.table
			return "  grant by hand"
		}
		return "  " + cmd
	})
	if !known && len(a.NotGranted) > 0 {
		fmt.Fprintln(w, "Add this flag to the basalt init command you set this agent up with.")
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "These names are not shown to the agent.")
}

func schemaCount(a pgcatalog.Access) int {
	seen := map[string]bool{}
	for _, list := range [][]string{a.Read, a.Write, a.NotGranted} {
		for _, t := range list {
			schema, _, _ := strings.Cut(t, ".")
			seen[schema] = true
		}
	}
	return len(seen)
}
