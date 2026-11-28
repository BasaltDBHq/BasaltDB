package osservice_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

// The removal script is built from constants, parses, and does nothing
// before every check passed: the config gone, and every folder it removes
// walked from /.
func TestRemoveScriptIsBuiltFromConstants(t *testing.T) {
	t.Parallel()
	for _, v := range []struct {
		goos          string
		checks, steps []string
	}{
		{"linux", []string{
			"[ ! -e /etc/basalt/engine.json ] && [ ! -L /etc/basalt/engine.json ]",
			`check_dir /etc/basalt "$engine_uid"`, `check_dir /var/lib/basalt "$engine_uid"`, `check_dir /run/basalt "$engine_uid"`,
			`check_dir /opt/basalt ""`, `trusted /etc/systemd/system ""`, "SYS_UID_MAX",
		}, []string{
			"systemctl disable --now basalt-engine.service",
			"for unit in /etc/systemd/system/basalt-plugin-*.service; do",
			"rm -f /etc/systemd/system/basalt-engine.service",
			"systemctl daemon-reload",
			"if ( trusted /usr/libexec \"\" ) >/dev/null 2>&1; then\n\trm -f /usr/libexec/basalt /usr/libexec/basalt.basalt-new\n",
			"remove_dir /etc/basalt", "remove_dir /var/lib/basalt", "remove_dir /run/basalt", "remove_dir /opt/basalt",
			"grep '^basalt-plugin-'", `delete_account "$p"`, "delete_account basalt", `[ -z "$kept" ] ||`, `[ -z "$orphaned" ] ||`,
			"systemctl disable --now basalt-remove.path >/dev/null 2>&1 || true\nrm -f /etc/systemd/system/basalt-remove.path /etc/systemd/system/basalt-remove.service /usr/libexec/basalt-remove\n",
		}},
		{"darwin", []string{
			"[ ! -e '/Library/Application Support/Basalt/engine.json' ]",
			`check_dir '/Library/Application Support/Basalt' "$engine_uid"`, `check_dir '/Library/Application Support/Basalt/state' "$engine_uid"`,
			`check_dir /Library/Logs/Basalt "$engine_uid"`, `check_dir /Library/Basalt ""`,
			`trusted /Library/LaunchDaemons ""`, `trusted /etc/newsyslog.d ""`,
		}, []string{
			"launchctl bootout system/dev.basaltdb.engine",
			"for unit in /Library/LaunchDaemons/dev.basaltdb.plugin-*.plist; do",
			`launchctl bootout "system/${label%.plist}"`,
			"rm -f /Library/LaunchDaemons/dev.basaltdb.engine.plist",
			"rm -f /etc/newsyslog.d/basalt-plugin-*.conf",
			"if ( trusted /usr/local/libexec \"\" ) >/dev/null 2>&1; then\n\trm -f /usr/local/libexec/basalt /usr/local/libexec/basalt.basalt-new\n",
			"remove_dir '/Library/Application Support/Basalt'", "remove_dir /Library/Logs/Basalt", "remove_dir /Library/Basalt",
			"for old in /Library/Logs/Basalt.old-*; do",
			"macOS keeps its hidden system accounts",
			"rm -f /Library/LaunchDaemons/dev.basaltdb.remove.plist /usr/local/libexec/basalt-remove /var/log/basalt-remove.log\nlaunchctl bootout system/dev.basaltdb.remove >/dev/null 2>&1 || true\n",
		}},
	} {
		t.Run(v.goos, func(t *testing.T) {
			t.Parallel()
			script, err := osservice.RemoveScript(v.goos)
			require.NoError(t, err)
			_, rest, ok := strings.Cut(script, osservice.ScriptHelpersEnd)
			require.True(t, ok)
			pre, after, ok := strings.Cut(rest, osservice.ScriptPreflightEnd)
			require.True(t, ok)
			for _, c := range v.checks {
				require.Contains(t, pre, c)
			}
			for _, s := range v.steps {
				require.Contains(t, after, s)
			}
			for _, never := range []string{"rm ", "userdel", "dscl . -delete", "systemctl", "launchctl"} {
				require.NotContains(t, pre, never, "the checks change nothing")
			}
			for _, never := range []string{"--agent", "--credential", "postgres", "$HOME", "$PWD", "engine.json\n"} {
				require.NotContains(t, script, never)
			}
			out, err := exec.Command("/bin/sh", "-n", "-c", script).CombinedOutput()
			require.NoError(t, err, "the script parses: %s", out)
		})
	}
	_, err := osservice.RemoveScript("windows")
	require.Error(t, err)
}

// removeHelperScript runs call after the removal script's helpers.
func removeHelperScript(t *testing.T, call string) (string, error) {
	t.Helper()
	script, err := osservice.RemoveScript(runtime.GOOS)
	require.NoError(t, err)
	helpers, _, ok := strings.Cut(script, osservice.ScriptHelpersEnd)
	require.True(t, ok)
	out, err := exec.Command("/bin/sh", "-c", helpers+"\n"+call).CombinedOutput()
	return string(out), err
}

// remove_dir removes a tree without following a link inside it, and
// refuses a symlink in the directory's place.
func TestRemoveScriptRemoveDir(t *testing.T) {
	t.Parallel()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("the service installs on linux and darwin")
	}
	base := t.TempDir()
	keep := filepath.Join(base, "keep")
	require.NoError(t, os.Mkdir(keep, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(keep, "file"), []byte("x"), 0o600))
	tree := filepath.Join(base, "tree")
	require.NoError(t, os.MkdirAll(filepath.Join(tree, "sub"), 0o755))
	require.NoError(t, os.Symlink(keep, filepath.Join(tree, "sub", "link")))

	out, err := removeHelperScript(t, "remove_dir "+shellQuoteTest(tree))
	require.NoError(t, err, out)
	_, err = os.Lstat(tree)
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = os.Stat(filepath.Join(keep, "file"))
	require.NoError(t, err, "a link inside the tree is removed, not followed")

	planted := filepath.Join(base, "planted")
	require.NoError(t, os.Symlink(keep, planted))
	out, err = removeHelperScript(t, "remove_dir "+shellQuoteTest(planted))
	require.Error(t, err)
	require.Contains(t, out, "is a symlink")
	_, err = os.Stat(filepath.Join(keep, "file"))
	require.NoError(t, err)

	// A missing directory is nothing to remove.
	out, err = removeHelperScript(t, "remove_dir "+shellQuoteTest(filepath.Join(base, "none")))
	require.NoError(t, err, out)
}

func TestRemoveScriptNoLogin(t *testing.T) {
	t.Parallel()
	for shell, want := range map[string]bool{"/usr/sbin/nologin": true, "/usr/bin/false": true, "/bin/zsh": false, "": false} {
		_, err := removeHelperScript(t, "no_login "+shellQuoteTest(shell))
		require.Equal(t, want, err == nil, shell)
	}
}
