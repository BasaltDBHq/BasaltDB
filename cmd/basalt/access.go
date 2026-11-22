package main

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/pgcatalog"
)

// runAccess: basalt access (CONTRACT.md, CLI). Lists the tables the agent
// can read, can write and is not granted. It prints names the describe tool only counts, so it is the person's
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
	*configPath = configOrFallback(c.host, fs, *configPath)
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
	printAccess(c.stdout, access)
	return exitOK
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func printAccess(w io.Writer, a pgcatalog.Access) {
	several := schemaCount(a) > 1
	section := func(title string, tables []string) {
		fmt.Fprintln(w, title)
		if len(tables) == 0 {
			fmt.Fprintln(w, "  none")
			return
		}
		last := ""
		for _, t := range tables {
			schema, _, _ := strings.Cut(t, ".")
			if several && schema != last {
				printLine(w, "  "+schema)
				last = schema
			}
			indent := "  "
			if several {
				indent = "    "
			}
			printLine(w, indent+t)
		}
	}
	section("Can read", a.Read)
	fmt.Fprintln(w)
	section("Can write", a.Write)
	fmt.Fprintln(w)
	section("Not granted", a.NotGranted)
	if len(a.NotGranted) > 0 {
		fmt.Fprintln(w, accessGrantHint)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "These names are not shown to the agent.")
}

// accessGrantHint says how a table is granted: on the setup page the
// agent's basalt init links to, never with a command the person runs.
const accessGrantHint = "To give the agent one of these tables, ask the agent: it gives you a link where you pick the tables."

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
