package osservice_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

// epochConfigs are engine.json files with the breaking epoch each has. The
// shape 0.0.1's basalt init wrote: socketDir, the agent's own
// credentialFile and initArgs, no store; with --remote it also wrote
// directAddr.
var epochConfigs = map[string]struct {
	json  string
	epoch int
}{
	"0.0.1, service": {`{
  "socketDir": "/Library/Application Support/Basalt/run",
  "agents": [
    {
      "name": "demo_bot",
      "osUser": "alice",
      "credentialFile": "/Library/Application Support/Basalt/agents/demo_bot.url",
      "initArgs": ["--demo"]
    }
  ],
  "limits": {},
  "pagesUrl": "http://localhost:8787",
  "mode": "SERVICE",
  "personUids": [501]
}`, 0},
	"0.0.1, --remote": {`{
  "socketDir": "/home/bot/.config/basalt/run",
  "agents": [{"name": "bot", "osUser": "bot", "credentialFile": "/home/bot/.config/basalt/agents/bot.url"}],
  "limits": {},
  "pagesUrl": "https://portal.basaltvault.app",
  "directAddr": "0.0.0.0:7443",
  "operatedBy": "AGENT"
}`, 0},
	"today's shape, before the field": {`{
  "socketDir": "/Library/Application Support/Basalt/run",
  "agents": [
    {
      "name": "demo_bot",
      "osUser": "alice",
      "store": {
        "kind": "POSTGRES",
        "credentialFile": "/Library/Application Support/Basalt/agents/demo_bot.url"
      }
    }
  ],
  "limits": {},
  "pagesUrl": "http://localhost:8787",
  "mode": "SERVICE"
}`, 1},
	"today's shape, written now": {`{
  "breaking": 1,
  "socketDir": "/run/basalt",
  "agents": [{"name": "bot", "osUser": "bot", "store": {"kind": "POSTGRES", "credentialFile": "/etc/basalt/agents/bot.url"}}],
  "limits": {}
}`, 1},
	"an explicit epoch below": {`{
  "breaking": 0,
  "socketDir": "/run/basalt",
  "agents": [{"name": "bot", "osUser": "bot", "store": {"kind": "POSTGRES", "credentialFile": "/etc/basalt/agents/bot.url"}}],
  "limits": {}
}`, 0},
	"a later epoch": {`{
  "breaking": 2,
  "socketDir": "/run/basalt",
  "agents": [],
  "limits": {}
}`, 2},
}

// The script's config_epoch and config.EpochOf give each config the same
// breaking epoch: the scripts reset exactly the configs basalt refuses as
// older.
func TestConfigEpochMatchesTheConfigPackage(t *testing.T) {
	t.Parallel()
	helpers := osservice.BreakingHelpers()
	for name, c := range epochConfigs {
		path := filepath.Join(t.TempDir(), "engine.json")
		require.NoError(t, os.WriteFile(path, []byte(c.json), 0o600))
		require.Equal(t, c.epoch, config.EpochOf([]byte(c.json)), name)
		out, err := exec.Command("/bin/sh", "-c", helpers+`config_epoch "$1"`, "sh", path).CombinedOutput()
		require.NoError(t, err, "%s: %s", name, out)
		require.Equal(t, strconv.Itoa(c.epoch), strings.TrimSpace(string(out)), name)
	}
}

// The install and restart scripts reset a config from before the last
// breaking release, after their checks: they stop and remove the engine's
// and plugins' units, move the config folder to the first free .old name
// (never deleting it) and say where; the restart then installs the service
// again instead of restarting it.
func TestTheScriptsResetAConfigFromBeforeTheLastBreakingRelease(t *testing.T) {
	t.Parallel()
	for goos, v := range map[string]struct{ dir, stop, unit string }{
		"darwin": {"'/Library/Application Support/Basalt'", "launchctl bootout system/dev.basaltdb.engine", "rm -f /Library/LaunchDaemons/dev.basaltdb.engine.plist"},
		"linux":  {"/etc/basalt", "systemctl disable --now basalt-engine.service", "rm -f /etc/systemd/system/basalt-engine.service"},
	} {
		install, err := osservice.InstallScript(goos, dialogSource)
		require.NoError(t, err)
		restart, err := osservice.RestartScript(goos, dialogSource)
		require.NoError(t, err)
		for name, script := range map[string]string{"install": install, "restart": restart} {
			checks, body, ok := strings.Cut(script, osservice.ScriptPreflightEnd)
			require.True(t, ok)
			require.NotContains(t, checks, "config_epoch "+v.dir, "%s %s: the checks change nothing", goos, name)
			for _, step := range []string{
				`[ "$epoch" -lt 1 ]`, v.stop, v.unit, "old=" + v.dir + ".old\n", `old=` + v.dir + `.old.$n`,
				"mv " + v.dir + ` "$old"`, osservice.BreakingResetLine,
			} {
				require.Contains(t, body, step, "%s %s", goos, name)
			}
			require.NotContains(t, body, "rm -rf "+v.dir, "the folder is moved, never deleted")
			require.Less(t, strings.Index(body, "breaking_reset=\n"), strings.Index(body, "put_file"), "%s %s: reset before the unit is written", goos, name)
		}
		_, branch, ok := strings.Cut(restart, `if [ -n "$breaking_reset" ]; then`)
		require.True(t, ok)
		require.Contains(t, branch, "put_file "+scriptWordOf(osservice.UnitPath(goos)), "%s: the restart installs the service again after a reset", goos)
	}
}

// scriptWordOf is a path as the scripts write it: single-quoted with a space.
func scriptWordOf(s string) string {
	if strings.Contains(s, " ") {
		return "'" + s + "'"
	}
	return s
}
