package osservice_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/osservice"
)

const dialogBinary = "/usr/local/bin/basalt"

func TestInstallScriptIsBuiltFromConstants(t *testing.T) {
	t.Parallel()
	for _, v := range []struct {
		goos, unitPath, start string
		want                  []string
	}{
		{"linux", osservice.SystemdUnitPath, "systemctl enable --now " + osservice.SystemdUnitName, []string{
			"useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin basalt",
			"make_dir /etc/basalt 0750 basalt basalt",
			"make_root_dir /opt/basalt 0755",
			"make_root_dir /opt/basalt/run 0755",
			"ExecStart=/usr/local/bin/basalt engine --config /etc/basalt/engine.json --supervise\n",
		}},
		{"darwin", osservice.LaunchdPlist, "launchctl bootstrap system " + osservice.LaunchdPlist, []string{
			"dscl . -create /Users/_basalt UniqueID \"$id\"",
			"make_dir '/Library/Application Support/Basalt' 0755 _basalt _basalt",
			"make_dir '/Library/Application Support/Basalt/run' 0755 _basalt _basalt",
			"make_dir '/Library/Application Support/Basalt/state' 0750 _basalt _basalt",
			"make_dir /Library/Logs/Basalt 0755 0 0",
			"make_root_dir /Library/Basalt 0755",
			"<string>/usr/local/bin/basalt</string>\n\t\t<string>engine</string>\n\t\t<string>--config</string>\n\t\t<string>/Library/Application Support/Basalt/engine.json</string>\n\t\t<string>--supervise</string>",
		}},
	} {
		t.Run(v.goos, func(t *testing.T) {
			t.Parallel()
			script, err := osservice.InstallScript(v.goos, dialogBinary)
			require.NoError(t, err)
			for _, w := range append(v.want, "put_file "+shellWord(v.unitPath), v.start, "PATH=/usr/bin:/bin:/usr/sbin:/sbin\n", "cd /\n") {
				require.Contains(t, script, w)
			}
			// The script carries nothing an agent chooses: no agent, no
			// credential, no flag but the unit's fixed ones.
			for _, never := range []string{"--agent", "--credential", "--init-arg", "--os-user", "--person-uid", "--pages-url", "postgres", "$HOME", "$PWD"} {
				require.NotContains(t, script, never)
			}
			again, err := osservice.InstallScript(v.goos, dialogBinary)
			require.NoError(t, err)
			require.Equal(t, script, again, "the same machine and binary make the same script")

			out, err := exec.Command("/bin/sh", "-n", "-c", script).CombinedOutput()
			require.NoError(t, err, "the script parses: %s", out)
		})
	}
}

// Every check runs before the script creates anything: a refused folder or
// account never leaves a new OS user or folder behind.
func TestInstallScriptChecksBeforeItCreates(t *testing.T) {
	t.Parallel()
	for _, v := range []struct {
		goos   string
		checks []string
	}{
		{"linux", []string{
			"check_dir /etc/basalt \"$engine_uid\"", "trusted /etc/systemd/system \"\"", "no_link /etc/systemd/system/basalt-engine.service",
			"SYS_UID_MAX", "getent group basalt", "getent passwd basalt",
		}},
		{"darwin", []string{
			"check_dir '/Library/Application Support/Basalt' \"$engine_uid\"", "check_dir '/Library/Application Support/Basalt/run' \"$engine_uid\"",
			"check_dir '/Library/Application Support/Basalt/state' \"$engine_uid\"", "check_dir /Library/Logs/Basalt \"$engine_uid\"",
			"no_link /Library/Logs/Basalt/engine.log", "trusted /Library/LaunchDaemons \"\"", "no_link /Library/LaunchDaemons/dev.basaltdb.engine.plist",
			"-ge 300", "-le 499", "dscl . -read /Groups/_basalt", "dscl . -read /Users/_basalt UserShell",
		}},
	} {
		script, err := osservice.InstallScript(v.goos, dialogBinary)
		require.NoError(t, err)
		_, rest, ok := strings.Cut(script, osservice.ScriptHelpersEnd)
		require.True(t, ok)
		checks, _, ok := strings.Cut(rest, osservice.ScriptPreflightEnd)
		require.True(t, ok)
		for _, c := range append(v.checks, "bin=/usr/local/bin/basalt\n", `[ "$(uid_of "$bin")" = 0 ]`) {
			require.Contains(t, checks, c, v.goos)
		}
		for _, change := range []string{"useradd", "dscl . -create", "make_dir", "mkdir", "put_file", "chown", "chmod", "systemctl", "launchctl", ": >"} {
			require.NotContains(t, checks, change, "%s: the checks change nothing", v.goos)
		}
	}
}

// shellWord is s as the script writes a constant path.
func shellWord(s string) string {
	if strings.Contains(s, " ") {
		return "'" + s + "'"
	}
	return s
}

// The script makes the plugin base the service install makes.
func TestInstallScriptMakesThePluginBase(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"linux", "darwin"} {
		base, err := osservice.PluginBase(goos)
		require.NoError(t, err)
		run, err := osservice.PluginRunDir(goos)
		require.NoError(t, err)
		script, err := osservice.InstallScript(goos, dialogBinary)
		require.NoError(t, err)
		require.Contains(t, script, "make_root_dir "+base+" 0755", goos)
		require.Contains(t, script, "make_root_dir "+run+" 0755", goos)
	}
}

func TestInstallScriptRefusesAnUnsafeBinaryPath(t *testing.T) {
	t.Parallel()
	for _, bin := range []string{
		"basalt", "relative/basalt", "/usr/local/bin/../bin/basalt", "/usr/local/bin/basalt'; rm -rf /; '",
		"/opt/my basalt/basalt", "/usr/local/bin/basalt\nExecStartPre=/bin/sh", "/usr/local/bin/$(id)", "/usr/local/bin/`id`",
		"/usr/local/bin/basalt\\", "/usr/local/bin/a\"b",
	} {
		_, err := osservice.InstallScript("linux", bin)
		require.Error(t, err, bin)
	}
	_, err := osservice.InstallScript("windows", dialogBinary)
	require.Error(t, err)
}

func TestDialogCommand(t *testing.T) {
	t.Parallel()
	argv, err := osservice.DialogCommand("darwin", osservice.ResetPrompt, "echo hi")
	require.NoError(t, err)
	require.Equal(t, []string{
		"/usr/bin/osascript", "-e", "on run argv", "-e", "do shell script (item 1 of argv) with prompt (item 2 of argv) with administrator privileges", "-e", "end run", "echo hi", osservice.ResetPrompt,
	}, argv, "the script and the prompt go as arguments, never inside AppleScript text")

	argv, err = osservice.DialogCommand("linux", osservice.ResetPrompt, "echo hi")
	require.NoError(t, err)
	require.Equal(t, []string{"/usr/bin/pkexec", "--disable-internal-agent", "/bin/sh", "-c", "echo hi"}, argv,
		"no text prompt: only the desktop's dialog answers")

	_, err = osservice.DialogCommand("windows", osservice.ResetPrompt, "echo hi")
	require.Error(t, err)
}

// Each action's prompt names it in capitals and says when to cancel, so an
// unexpected dialog reads as one to cancel.
func TestDialogPromptsNameTheirAction(t *testing.T) {
	t.Parallel()
	for prompt, action := range map[string]string{osservice.InstallPrompt: "INSTALL", osservice.RemovePrompt: "REMOVE", osservice.ResetPrompt: "RESET"} {
		require.Contains(t, prompt, "BasaltDB wants to "+action+" ")
		require.Contains(t, prompt, "Cancel unless you just ")
		require.NotContainsf(t, prompt, `"`, "the prompt is an AppleScript argument; keep it plain: %s", prompt)
	}
	require.Contains(t, osservice.ResetPrompt, "No, this isn't mine")
}

func TestDialogError(t *testing.T) {
	t.Parallel()
	require.NoError(t, osservice.DialogError("linux", 0, "", nil))
	run := errors.New("exit status 1")
	for _, v := range []struct {
		goos   string
		code   int
		stderr string
		is     error
	}{
		{"linux", 126, "", osservice.ErrDialogCancelled},
		{"linux", 127, "Error executing command as another user: No authentication agent found.", osservice.ErrNoDialog},
		{"darwin", 1, "0:58: execution error: User canceled. (-128)", osservice.ErrDialogCancelled},
		{"darwin", 1, "execution error: No user interaction allowed. (-1713)", osservice.ErrNoDialog},
		{"darwin", 1, "execution error: basalt: /etc is owned by uid 501, not root (1)", osservice.ErrDialogScript},
		{"linux", 1, "basalt: /etc/basalt is writable by group or others", osservice.ErrDialogScript},
	} {
		err := osservice.DialogError(v.goos, v.code, v.stderr, run)
		require.ErrorIs(t, err, v.is, "%s %d %q", v.goos, v.code, v.stderr)
	}
}

// helperScript runs one of the script's helpers on a real directory tree;
// the policy is that of the script, with the test's own uid standing in for
// the engine's.
func helperScript(t *testing.T, call string) (string, error) {
	t.Helper()
	script, err := osservice.InstallScript(runtime.GOOS, dialogBinary)
	require.NoError(t, err)
	helpers, _, ok := strings.Cut(script, osservice.ScriptHelpersEnd)
	require.True(t, ok)
	out, err := exec.Command("/bin/sh", "-c", helpers+"\n"+call).CombinedOutput()
	return string(out), err
}

// trustedBase is a fresh directory whose ancestors the script's walk
// accepts (root's or this user's, not writable by group or others), or the
// test is skipped where the test machine has none.
func trustedBase(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	dir, err := os.MkdirTemp(wd, "dialog-test-")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	require.NoError(t, os.Chmod(dir, 0o755))
	resolved, err := filepath.EvalSymlinks(dir)
	require.NoError(t, err)
	if out, err := helperScript(t, "trusted "+shellQuoteTest(resolved)+" "+strconv.Itoa(os.Getuid())); err != nil {
		t.Skipf("the checkout's folders are not trusted here: %s", out)
	}
	return resolved
}

func shellQuoteTest(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// A command the script cannot find exits 127, which pkexec uses for "no
// dialog": the script ends with 1 instead.
func TestScriptNeverExitsWithPkexecCodes(t *testing.T) {
	t.Parallel()
	for _, call := range []string{"basalt-no-such-command", "exit 126", "fail stop"} {
		out, err := helperScript(t, call)
		var exitErr *exec.ExitError
		require.ErrorAs(t, err, &exitErr, out)
		require.Equal(t, 1, exitErr.ExitCode(), call)
	}
}

// skipAsRoot: the walk tests stand this user in for the engine's, and
// root passes every owner check.
func skipAsRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("run as root: every directory passes the owner check")
	}
}

func TestScriptTrustedWalk(t *testing.T) {
	t.Parallel()
	skipAsRoot(t)
	base := trustedBase(t)
	me := strconv.Itoa(os.Getuid())

	// A directory owned by someone else (here: this user, with no engine
	// uid allowed) is refused.
	out, err := helperScript(t, "trusted "+shellQuoteTest(base)+" ''")
	require.Error(t, err)
	require.Contains(t, out, "not root")

	open := filepath.Join(base, "open")
	require.NoError(t, os.Mkdir(open, 0o755))
	require.NoError(t, os.Chmod(open, 0o777))
	out, err = helperScript(t, "trusted "+shellQuoteTest(filepath.Join(open, "x"))+" "+me)
	require.Error(t, err)
	require.Contains(t, out, "writable by group or others")

	// A symlink root does not own is never followed.
	target := filepath.Join(base, "target")
	require.NoError(t, os.Mkdir(target, 0o755))
	link := filepath.Join(base, "link")
	require.NoError(t, os.Symlink(target, link))
	out, err = helperScript(t, "trusted "+shellQuoteTest(filepath.Join(link, "x"))+" "+me)
	require.Error(t, err)
	require.Contains(t, out, "symlink root does not own")

	// A missing directory below trusted ones is fine: make_dir makes it.
	_, err = helperScript(t, "trusted "+shellQuoteTest(filepath.Join(target, "new", "deeper"))+" "+me)
	require.NoError(t, err)
}

func TestScriptMakeDir(t *testing.T) {
	t.Parallel()
	skipAsRoot(t)
	base := trustedBase(t)
	me := strconv.Itoa(os.Getuid())
	gid := strconv.Itoa(os.Getgid())

	made := filepath.Join(base, "made")
	out, err := helperScript(t, "engine_uid="+me+"; make_dir "+shellQuoteTest(made)+" 0750 "+me+" "+gid)
	require.NoError(t, err, out)
	info, err := os.Lstat(made)
	require.NoError(t, err)
	require.True(t, info.IsDir())
	require.Equal(t, os.FileMode(0o750), info.Mode().Perm())

	// A symlink where the directory goes is refused, not followed.
	target := filepath.Join(base, "elsewhere")
	require.NoError(t, os.Mkdir(target, 0o755))
	planted := filepath.Join(base, "planted")
	require.NoError(t, os.Symlink(target, planted))
	out, err = helperScript(t, "engine_uid="+me+"; make_dir "+shellQuoteTest(planted)+" 0750 "+me+" "+gid)
	require.Error(t, err)
	require.Contains(t, out, "symlink root does not own")
}

func TestScriptPutFile(t *testing.T) {
	t.Parallel()
	skipAsRoot(t)
	base := trustedBase(t)
	// put_file wants a directory only root can change: this user's own
	// stands in for root's by allowing its uid as the engine's.
	path := filepath.Join(base, "unit")
	out, err := helperScript(t, "engine_uid=x; trusted() { :; }; put_file "+shellQuoteTest(path)+" <<'EOF'\nhello\nEOF")
	require.NoError(t, err, out)
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "hello\n", string(b))
	info, err := os.Lstat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o644), info.Mode().Perm())

	other := filepath.Join(base, "other")
	require.NoError(t, os.WriteFile(other, nil, 0o600))
	planted := filepath.Join(base, "planted")
	require.NoError(t, os.Symlink(other, planted))
	out, err = helperScript(t, "trusted() { :; }; put_file "+shellQuoteTest(planted)+" <<'EOF'\nx\nEOF")
	require.Error(t, err)
	require.Contains(t, out, "is a symlink")
	b, err = os.ReadFile(other)
	require.NoError(t, err)
	require.Empty(t, b, "the link's target is untouched")
}
