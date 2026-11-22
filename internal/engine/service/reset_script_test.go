package service_test

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/service"
)

// The reset's script is built from constants only: it checks, changing
// nothing, that the engine's folders are its own and that there is a setup
// to reset, then deletes the setup's files and restarts the engine. It
// names no database, no agent and nothing from the environment.
func TestResetScriptIsBuiltFromConstants(t *testing.T) {
	t.Parallel()
	for _, v := range []struct {
		goos          string
		checks, steps []string
	}{
		{"linux", []string{
			`[ -n "$engine_uid" ]`, `check_dir /etc/basalt "$engine_uid"`, "no_link /etc/basalt/engine.json",
			"[ -f /etc/basalt/engine.json ]", "for d in /etc/basalt/agents /etc/basalt/trust.d; do", "SYS_UID_MAX",
		}, []string{
			"for unit in /etc/systemd/system/basalt-plugin-*.service; do",
			"rm -f /etc/basalt/engine.json\n",
			"rm -f /etc/basalt/agents/*.url /etc/basalt/agents/*.url.pending",
			"rm -f /etc/basalt/trust.d/pin-*.json /etc/basalt/trust.d/pin-*.pem",
			"systemctl restart basalt-engine.service",
		}},
		{"darwin", []string{
			`[ -n "$engine_uid" ]`, `check_dir '/Library/Application Support/Basalt' "$engine_uid"`,
			"no_link '/Library/Application Support/Basalt/engine.json'",
		}, []string{
			"for unit in /Library/LaunchDaemons/dev.basaltdb.plugin-*.plist; do",
			"rm -f '/Library/Application Support/Basalt/engine.json'\n",
			"rm -f '/Library/Application Support/Basalt/agents'/*.url",
			"rm -f '/Library/Application Support/Basalt/trust.d'/pin-*.json",
			"launchctl kickstart -k system/dev.basaltdb.engine",
		}},
	} {
		t.Run(v.goos, func(t *testing.T) {
			t.Parallel()
			script, err := service.ResetScript(v.goos)
			require.NoError(t, err)
			again, err := service.ResetScript(v.goos)
			require.NoError(t, err)
			require.Equal(t, script, again, "nothing varies between runs")
			_, rest, ok := strings.Cut(script, service.ScriptHelpersEnd)
			require.True(t, ok)
			pre, after, ok := strings.Cut(rest, service.ScriptPreflightEnd)
			require.True(t, ok)
			for _, c := range v.checks {
				require.Contains(t, pre, c)
			}
			for _, s := range v.steps {
				require.Contains(t, after, s)
			}
			for _, never := range []string{"rm ", "systemctl", "launchctl", "userdel", "dscl . -delete"} {
				require.NotContains(t, pre, never, "the checks change nothing")
			}
			for _, never := range []string{"--agent", "postgres", "psql", "$HOME", "$PWD", "userdel", "dscl . -delete", "remove_dir /", "rm -rf"} {
				require.NotContains(t, after, never, "a reset touches no database, user or other folder")
			}
			out, err := exec.Command("/bin/sh", "-n", "-c", script).CombinedOutput()
			require.NoError(t, err, "the script parses: %s", out)
		})
	}
	_, err := service.ResetScript("windows")
	require.Error(t, err)
}
