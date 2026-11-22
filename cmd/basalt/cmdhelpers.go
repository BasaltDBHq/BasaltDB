package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// revertPoll is how often a waiting command reads whether the person signed.
const revertPoll = time.Second

// timeLayout is how a command states a deadline.
const timeLayout = "2006-01-02 15:04 UTC"

// agentURL finds the agent's connection string: --credential-file, then
// the credential file of --agent in the engine config, then
// BASALT_DATABASE_URL. A flag always wins over the environment. A
// credential file readable by group or others is refused. As root, the
// files are read without following links (loadEngineConfig).
func agentURL(c *cliIO, agent, credFile, configPath string) (string, error) {
	if credFile != "" {
		return readCredentialFlag(c, credFile)
	}
	if agent != "" {
		return agentConfigURL(c, agent, configPath)
	}
	if v := c.getenv(envAgentURL); v != "" {
		return v, nil
	}
	return "", fmt.Errorf("%w: give --agent or %s", errUsage, envAgentURL)
}

// agentConfigURL reads the credential file the engine config names for agent.
func agentConfigURL(c *cliIO, agent, configPath string) (string, error) {
	cfg, err := loadEngineConfig(c, configPath)
	if err != nil {
		return "", err
	}
	for _, a := range cfg.Agents {
		if a.Name == agent {
			return cfg.credential(a.Store.CredentialFile)
		}
	}
	return "", errAgentNotInConfig(agent, configPath)
}

// configOrFallback is the config a person command reads: the --config value,
// or, when --config was not given, perUserConfigFallback of the default.
func configOrFallback(h host, fs *flag.FlagSet, path string) string {
	given := false
	fs.Visit(func(fl *flag.Flag) { given = given || fl.Name == "config" })
	if given {
		return path
	}
	return perUserConfigFallback(h, path)
}

// perUserConfigFallback is the config a command reads when --config is not
// given: the system path, unless this is not root, nothing is installed
// there, and init left a config in the user's own config directory.
func perUserConfigFallback(h host, system string) string {
	if h.Euid() == 0 {
		return system
	}
	if _, err := os.Stat(system); !errors.Is(err, fs.ErrNotExist) {
		return system
	}
	base, err := h.UserConfigDir()
	if err != nil {
		return system
	}
	user := filepath.Join(base, perUserDirName, "engine.json")
	if _, err := os.Stat(user); err != nil {
		return system
	}
	return user
}

func printJSONValue(c *cliIO, v any) int {
	enc := json.NewEncoder(c.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return c.fail(err)
	}
	return exitOK
}
