package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	credFileURL  = "postgres://from-credential-file"
	agentCfgURL  = "postgres://from-agent-config"
	envURL       = "postgres://from-environment"
	testAgentKey = "bot"
)

// writeAgentFixture writes a credential file for --credential-file and an
// engine config naming a second credential file for --agent bot.
func writeAgentFixture(t *testing.T) (credFile, configPath string) {
	t.Helper()
	dir := t.TempDir()
	credFile = filepath.Join(dir, "direct.url")
	require.NoError(t, os.WriteFile(credFile, []byte(credFileURL+"\n"), 0o600))
	agentFile := filepath.Join(dir, "bot.url")
	require.NoError(t, os.WriteFile(agentFile, []byte(agentCfgURL+"\n"), 0o600))
	raw, err := json.Marshal(map[string]any{
		"socketDir": "/tmp/basalt-test", // short: the config check bounds socket paths
		"agents": []map[string]any{{
			"name": testAgentKey, "osUser": "tester", "store": map[string]string{"kind": "POSTGRES", "credentialFile": agentFile},
		}},
	})
	require.NoError(t, err)
	configPath = filepath.Join(dir, "engine.json")
	require.NoError(t, os.WriteFile(configPath, raw, 0o600))
	return credFile, configPath
}

func TestAgentURLPrecedence(t *testing.T) {
	t.Parallel()
	credFile, configPath := writeAgentFixture(t)
	env := func(k string) string {
		if k == envAgentURL {
			return envURL
		}
		return ""
	}
	noEnv := func(string) string { return "" }

	tests := []struct {
		name     string
		getenv   func(string) string
		agent    string
		credFile string
		want     string
	}{
		{"credential file beats env", env, "", credFile, credFileURL},
		{"agent beats env", env, testAgentKey, "", agentCfgURL},
		{"credential file beats agent", env, testAgentKey, credFile, credFileURL},
		{"env alone is used", env, "", "", envURL},
		{"agent without env", noEnv, testAgentKey, "", agentCfgURL},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &cliIO{host: newFakeHost(t), getenv: tc.getenv}
			got, err := agentURL(c, tc.agent, tc.credFile, configPath)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestAgentURLNothingGiven(t *testing.T) {
	t.Parallel()
	c := &cliIO{host: newFakeHost(t), getenv: func(string) string { return "" }}
	_, err := agentURL(c, "", "", "")
	require.ErrorIs(t, err, errUsage)
}

func TestAgentURLUnknownAgentIgnoresEnv(t *testing.T) {
	t.Parallel()
	_, configPath := writeAgentFixture(t)
	c := &cliIO{host: newFakeHost(t), getenv: func(string) string { return envURL }}
	_, err := agentURL(c, "nobody", "", configPath)
	require.ErrorContains(t, err, `agent "nobody" is not in`)
}
