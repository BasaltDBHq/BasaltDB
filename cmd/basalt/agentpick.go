package main

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
)

// needsAgent reports whether nothing names the agent: no --agent, no
// credential given and no BASALT_DATABASE_URL.
func (c *cliIO) needsAgent(agent, credFile string) bool {
	return agent == "" && credFile == "" && c.paths.credFile == "" && c.getenv(envAgentURL) == ""
}

// configuredAgents are the agents this person can name: in service mode
// the agent sockets in the engine's socket directory (the person cannot
// read engine.json, but can list that directory), else the agents of the
// engine config.
func (c *cliIO) configuredAgents(configPath string) ([]string, error) {
	if configPath == c.systemConfig() && c.engine.unitInstalled() {
		entries, err := os.ReadDir(filepath.Dir(c.engine.personSocket))
		if err != nil {
			return nil, err
		}
		var names []string
		for _, e := range entries {
			name, ok := strings.CutSuffix(e.Name(), ".sock")
			if ok && e.Type()&os.ModeSocket != 0 && config.ValidAgentName(name) {
				names = append(names, name)
			}
		}
		return names, nil
	}
	cfg, err := loadEngineConfig(c, configPath)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(cfg.Agents))
	for _, a := range cfg.Agents {
		names = append(names, a.Name)
	}
	return names, nil
}

// errNoAgentNamed is the usage error when the agent cannot be picked.
var errNoAgentNamed = fmt.Errorf("%w: give --agent or %s", errUsage, envAgentURL)

// pickAgent is the agent a code belongs to when the person named none:
// the only configured agent, else the one whose ledger owns the item the
// code signs (owns opens that agent's ledger and looks the item up). item
// names it in messages ("approval <id>"). When no agent could be asked
// (the engine stopped), it returns the first agent's error.
func pickAgent(c *cliIO, configPath, item string, owns func(agent string) (bool, error)) (string, error) {
	names, err := c.configuredAgents(configPath)
	if err != nil || len(names) == 0 {
		return "", errNoAgentNamed
	}
	if len(names) == 1 {
		return names[0], nil
	}
	slices.Sort(names)
	var found []string
	var firstErr error
	failed := 0
	for _, n := range names {
		ok, err := owns(n)
		if err != nil {
			// That agent cannot be read now; another may own it.
			failed++
			firstErr = cmp.Or(firstErr, err)
			continue
		}
		if ok {
			found = append(found, n)
		}
	}
	switch {
	case len(found) == 1:
		return found[0], nil
	case len(found) > 1:
		return "", fmt.Errorf("%w: %s is in the ledgers of %s; give --agent", errUsage, item, strings.Join(found, ", "))
	case failed == len(names):
		return "", firstErr
	}
	return "", fmt.Errorf("no agent here holds %s (the engine serves %s)", item, strings.Join(names, ", "))
}

// ownsApproval reports whether agent's ledger holds approval id.
func ownsApproval(c *cliIO, configPath string, id uuid.UUID) func(string) (bool, error) {
	return func(agent string) (bool, error) {
		l, err := openLedger(c, agent, "", configPath)
		if err != nil {
			return false, err
		}
		defer l.close()
		_, err = l.FindApproval(c.ctx, id)
		if errors.Is(err, ledger.ErrApprovalNotFound) {
			return false, nil
		}
		return err == nil, err
	}
}

// ownsRevert reports whether agent prepared revert id.
func ownsRevert(c *cliIO, configPath string, id uuid.UUID) func(string) (bool, error) {
	return func(agent string) (bool, error) {
		l, err := openLedger(c, agent, "", configPath)
		if err != nil {
			return false, err
		}
		defer l.close()
		_, err = l.FindRevert(c.ctx, id)
		if errors.Is(err, ledger.ErrRevertNotFound) {
			return false, nil
		}
		return err == nil, err
	}
}
