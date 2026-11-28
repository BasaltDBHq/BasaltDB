package osservice_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

// gateOf is the removal job's gate for goos with its marker moved to
// marker, and id answering uid for the engine's account: everything before
// the removal script's own helpers, then a line that says it went on.
func gateOf(t *testing.T, goos, marker string, uid int) string {
	t.Helper()
	script, err := osservice.RemovalJobScript(goos)
	require.NoError(t, err)
	gate, _, ok := strings.Cut(script, "set -eu\n")
	require.True(t, ok)
	fixed := osservice.RemovalMarker(goos)
	word := fixed
	if strings.Contains(fixed, " ") {
		word = "'" + fixed + "'"
	}
	require.Contains(t, gate, "marker="+word+"\n")
	gate = strings.Replace(gate, "marker="+word+"\n", "marker="+shellQuoteTest(marker)+"\n", 1)
	// The test's stat is this machine's: the gate's own is goos's.
	gate = strings.ReplaceAll(gate, "stat -c %u", "uid_test")
	gate = strings.ReplaceAll(gate, "stat -f %u", "uid_test")
	idFake := "id() { echo " + strconv.Itoa(uid) + "; }\nuid_test() { if stat -c %u \"$1\" 2>/dev/null; then :; else stat -f %u \"$1\"; fi; }\n"
	gate = strings.Replace(gate, "cd /\n", "cd /\n"+idFake, 1)
	return gate + "echo went-on\n"
}

// The job's gate: no marker, nothing; a marker is unlinked before anything
// else on every path, and only a plain file of the engine's account lets
// the removal go on. Its content is never read.
func TestRemovalJobGate(t *testing.T) {
	t.Parallel()
	me := os.Getuid()
	for _, goos := range []string{"linux", "darwin"} {
		for _, v := range []struct {
			name    string
			make    func(t *testing.T, marker string)
			uid     int
			wentOn  bool
			refused bool
		}{
			{"no marker", func(*testing.T, string) {}, me, false, false},
			{"a plain file of the engine's account", func(t *testing.T, m string) {
				require.NoError(t, os.WriteFile(m, []byte("anything; rm -rf /\n"), 0o600))
			}, me, true, false},
			{"a file of another account", func(t *testing.T, m string) {
				require.NoError(t, os.WriteFile(m, nil, 0o600))
			}, me + 1, false, true},
			{"a symlink to a file", func(t *testing.T, m string) {
				target := filepath.Join(filepath.Dir(m), "target")
				require.NoError(t, os.WriteFile(target, nil, 0o600))
				require.NoError(t, os.Symlink(target, m))
			}, me, false, true},
			{"a dangling symlink", func(t *testing.T, m string) {
				require.NoError(t, os.Symlink(filepath.Join(filepath.Dir(m), "nowhere"), m))
			}, me, false, true},
			{"a folder", func(t *testing.T, m string) {
				require.NoError(t, os.Mkdir(m, 0o700))
			}, me, false, true},
		} {
			dir := t.TempDir()
			marker := filepath.Join(dir, "remove-requested")
			v.make(t, marker)
			out, err := runShell(t, gateOf(t, goos, marker, v.uid))
			if v.refused {
				require.Error(t, err, "%s %s: %s", goos, v.name, out)
				require.Contains(t, out, "so nothing was removed", "%s %s", goos, v.name)
			} else {
				require.NoError(t, err, "%s %s: %s", goos, v.name, out)
			}
			require.Equal(t, v.wentOn, strings.Contains(out, "went-on"), "%s %s: %s", goos, v.name, out)
			if v.name != "a folder" {
				_, err := os.Lstat(marker)
				require.ErrorIs(t, err, os.ErrNotExist, "%s %s: the marker is unlinked", goos, v.name)
			}
			if v.name == "a symlink to a file" {
				require.FileExists(t, filepath.Join(dir, "target"), "%s: the link's target stays", goos)
			}
		}
	}
}

// The job's script is the gate, then the removal script; it names no
// input, parses, and removes the job itself last.
func TestRemovalJobScript(t *testing.T) {
	t.Parallel()
	for goos, last := range map[string]string{
		"linux":  "",
		"darwin": "launchctl bootout system/dev.basaltdb.remove >/dev/null 2>&1 || true\n",
	} {
		script, err := osservice.RemovalJobScript(goos)
		require.NoError(t, err)
		require.True(t, strings.HasPrefix(script, "#!/bin/sh\n"), goos)
		remove, err := osservice.RemoveScript(goos)
		require.NoError(t, err)
		require.True(t, strings.HasSuffix(script, remove), "%s: the removal script follows the gate", goos)
		require.Less(t, strings.Index(script, `rm -f "$marker"`), strings.Index(script, "set -eu"), goos)
		for _, never := range []string{"$1", "$@", "$*", "read ", "cat \"$marker\"", "$HOME", "$PWD"} {
			gate, _, _ := strings.Cut(script, "set -eu\n")
			require.NotContains(t, gate, never, "%s: the gate reads no input", goos)
		}
		if last != "" {
			require.True(t, strings.HasSuffix(script, last), "%s: unloading the job itself is the last command", goos)
		}
		out, err := exec.Command("/bin/sh", "-n", "-c", script).CombinedOutput()
		require.NoError(t, err, "%s: the script parses: %s", goos, out)
	}
	_, err := osservice.RemovalJobScript("windows")
	require.Error(t, err)
}

// The install writes the job's script and units, root's, after the engine
// starts, and loads them: a .path unit on the marker on Linux, a
// LaunchDaemon watching it on macOS, both running /bin/sh on the script.
func TestInstallScriptWritesTheRemovalJob(t *testing.T) {
	t.Parallel()
	for goos, want := range map[string][]string{
		"linux": {
			"systemctl enable --now basalt-engine.service\n",
			"put_file /usr/libexec/basalt-remove <<'END_OF_REMOVAL_JOB'\n#!/bin/sh\n",
			"put_file /etc/systemd/system/basalt-remove.service <<'END_OF_REMOVAL_UNIT'\n",
			"Type=oneshot\nExecStart=/bin/sh /usr/libexec/basalt-remove\n",
			"put_file /etc/systemd/system/basalt-remove.path <<'END_OF_REMOVAL_UNIT'\n",
			"PathExists=/var/lib/basalt/remove-requested\nUnit=basalt-remove.service\n",
			"systemctl daemon-reload\nsystemctl enable --now basalt-remove.path\n",
		},
		"darwin": {
			"launchctl enable system/dev.basaltdb.engine\n",
			"put_file /usr/local/libexec/basalt-remove <<'END_OF_REMOVAL_JOB'\n#!/bin/sh\n",
			"put_file /Library/LaunchDaemons/dev.basaltdb.remove.plist <<'END_OF_REMOVAL_UNIT'\n",
			"<string>/bin/sh</string>\n\t\t<string>/usr/local/libexec/basalt-remove</string>",
			"<key>WatchPaths</key>\n\t<array>\n\t\t<string>/Library/Application Support/Basalt/state/remove-requested</string>",
			"launchctl bootout system/dev.basaltdb.remove >/dev/null 2>&1 || true\nlaunchctl bootstrap system /Library/LaunchDaemons/dev.basaltdb.remove.plist\n",
		},
	} {
		script, err := osservice.InstallScript(goos, dialogSource)
		require.NoError(t, err)
		_, body, ok := strings.Cut(script, osservice.ScriptPreflightEnd)
		require.True(t, ok)
		at := -1
		for _, w := range want {
			i := strings.Index(body, w)
			require.Greater(t, i, at, "%s: %q comes after the step before it", goos, w)
			at = i
		}
		require.NotContains(t, body, "RunAtLoad</key>\n\t<true/>\n\t<key>WatchPaths", goos)
	}
}
