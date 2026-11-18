package main

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
)

// databaseOut is where an agent's database is: its name and host, never a
// user, port, password or credential path (CONTRACT.md, CLI, basalt status).
type databaseOut struct {
	Host string `json:"host"`
	Name string `json:"name"`
}

// agentRow is one agent in the listing basalt status prints without
// --agent when the engine has several.
type agentRow struct {
	Agent    string `json:"agent"`
	Host     string `json:"host"`
	Database string `json:"database"`
	// Problem says why host and database are empty: the agent's credential
	// could not be read or parsed. Never the file's contents.
	Problem string `json:"problem,omitempty"`
}

// agentsOut is basalt status --json without --agent when the engine has
// several agents.
type agentsOut struct {
	Agents     []agentRow `json:"agents"`
	ConfigPath string     `json:"configPath"`
}

const agentsHint = "basalt status --agent NAME prints one agent's full report."

// agentMarkerNote is the line an agent gets instead of the listing.
const agentMarkerNote = "The person can see every agent and its database by running basalt status in their own terminal."

// connDatabase is the host and database name a connection string names.
func connDatabase(dsn string) (databaseOut, error) {
	cc, err := pgconn.ParseConfig(dsn)
	if err != nil {
		return databaseOut{}, fmt.Errorf("the credential is not a connection string")
	}
	return databaseOut{Host: cc.Host, Name: cc.Database}, nil
}

// listAgentsStatus is basalt status with no --agent and several agents, run
// by a person: each agent with its database name and host. In service mode
// the engine answers over the person socket.
func listAgentsStatus(c *cliIO, configPath string) (agentsOut, error) {
	if configPath == config.DefaultPath(c.goos) && c.engine.unitInstalled() && c.getenv(envAgentURL) == "" {
		dtos, err := person.Client{Path: c.engine.personSocket}.Agents(c.ctx)
		if err != nil {
			return agentsOut{}, personError(c, "NAME", err)
		}
		rows := make([]agentRow, 0, len(dtos))
		for _, d := range dtos {
			rows = append(rows, agentRow{Agent: d.Agent, Host: d.Host, Database: d.Database})
		}
		return agentsOut{Agents: rows, ConfigPath: configPath}, nil
	}
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return agentsOut{}, err
	}
	cfg, err := loadEngineConfig(c, abs)
	if err != nil {
		return agentsOut{}, err
	}
	rows := make([]agentRow, 0, len(cfg.Agents))
	for _, a := range cfg.Agents {
		row := agentRow{Agent: a.Name}
		dsn, err := cfg.credential(a.Store.CredentialFile)
		if err == nil {
			var d databaseOut
			if d, err = connDatabase(dsn); err == nil {
				row.Host, row.Database = d.Host, d.Name
			}
		}
		if err != nil {
			row.Problem = withoutPath(err).Error()
		}
		rows = append(rows, row)
	}
	return agentsOut{Agents: rows, ConfigPath: abs}, nil
}

func printAgents(w io.Writer, o agentsOut) {
	var b strings.Builder
	width := len("AGENT")
	hostWidth := len("HOST")
	for _, r := range o.Agents {
		width = max(width, len(r.Agent))
		hostWidth = max(hostWidth, len(r.Host))
	}
	fmt.Fprintf(&b, "%-*s  %-*s  %s\n", width, "AGENT", hostWidth, "HOST", "DATABASE")
	for _, r := range o.Agents {
		if r.Problem != "" {
			fmt.Fprintf(&b, "%-*s  (%s)\n", width, r.Agent, r.Problem)
			continue
		}
		fmt.Fprintf(&b, "%-*s  %-*s  %s\n", width, r.Agent, hostWidth, r.Host, r.Database)
	}
	fmt.Fprintf(&b, "\n%s\n", agentsHint)
	fmt.Fprint(w, terminalText(b.String()))
}

func printAgentsJSON(w io.Writer, o agentsOut) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(o)
}
