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
	cmds, err := accessCommands(c, *name, *configPath)
	if err != nil {
		return c.fail(err)
	}
	printAccess(c.stdout, access, cmds)
	return exitOK
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// accessCommands are the agent's commands with its saved init flags when the
// config can be read; in service mode it is the engine's, so the grant
// command then carries only the agent and the table.
func accessCommands(c *cliIO, name, configPath string) (agent.Commands, error) {
	var initArgs []string
	abs, err := filepath.Abs(configPath)
	if err == nil {
		if cfg, err := config.Load(abs); err == nil {
			for _, a := range cfg.Agents {
				if a.Name == name {
					initArgs = a.InitArgs
				}
			}
		}
		configPath = abs
	}
	cmds, err := agent.NewCommands(name, configPath, c.goos, initArgs)
	if err != nil {
		return agent.NewCommands(name, configPath, c.goos, nil)
	}
	return cmds, nil
}

func printAccess(w io.Writer, a pgcatalog.Access, cmds agent.Commands) {
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
		cmd, err := cmds.Grant("read", t)
		if err != nil { // agent.ErrBadTable: not a plain schema.table
			return "  grant by hand"
		}
		return "  " + cmd
	})
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
