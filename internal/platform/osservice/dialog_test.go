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

	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

const dialogBinary = "/usr/local/bin/basalt"

// dialogSum and dialogSize stand in for the running basalt's SHA-256 and
// size.
var dialogSum = strings.Repeat("ab", 32)

const dialogSize = 4096

// dialogSource is a basalt the person's account may own, as Homebrew's is:
// the script copies it to the service's own path.
var dialogSource = osservice.Source{Path: dialogBinary, SHA256: dialogSum, Size: dialogSize}

func TestInstallScriptIsBuiltFromConstants(t *testing.T) {
	t.Parallel()
	for _, v := range []struct {
		goos, unitPath, start string
		want                  []string
	}{
		{"linux", osservice.SystemdUnitPath, "systemctl enable --now " + servicespec.SystemdUnitName, []string{
			"useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin basalt",
			"make_dir /etc/basalt 0750 basalt basalt",
			"make_root_dir /opt/basalt 0755",
			"make_root_dir /opt/basalt/run 0755",
			"ExecStart=/usr/libexec/basalt engine --config /etc/basalt/engine.json --supervise\n",
			"make_root_dir /usr/libexec 0755\ncopy_binary \"$src\" /usr/libexec/basalt " + dialogSum + " 4096\n",
		}},
		{"darwin", osservice.LaunchdPlist, "launchctl bootstrap system " + osservice.LaunchdPlist, []string{
			"dscl . -create /Users/_basalt UniqueID \"$id\"",
			"make_dir '/Library/Application Support/Basalt' 0755 _basalt _basalt",
			"make_dir '/Library/Application Support/Basalt/run' 0755 _basalt _basalt",
			"make_dir '/Library/Application Support/Basalt/state' 0750 _basalt _basalt",
			"make_dir /Library/Logs/Basalt 0755 0 0",
			"make_root_dir /Library/Basalt 0755",
			"make_root_dir /usr/local 0755\nmake_root_dir /usr/local/libexec 0755\ncopy_binary \"$src\" /usr/local/libexec/basalt " + dialogSum + " 4096\n",
			"<string>/usr/local/libexec/basalt</string>\n\t\t<string>engine</string>\n\t\t<string>--config</string>\n\t\t<string>/Library/Application Support/Basalt/engine.json</string>\n\t\t<string>--supervise</string>",
		}},
	} {
		t.Run(v.goos, func(t *testing.T) {
			t.Parallel()
			script, err := osservice.InstallScript(v.goos, dialogSource)
			require.NoError(t, err)
			for _, w := range append(v.want, "put_file "+shellWord(v.unitPath), v.start, "PATH=/usr/bin:/bin:/usr/sbin:/sbin\n", "cd /\n") {
				require.Contains(t, script, w)
			}
			// The script carries nothing an agent chooses: no agent, no
			// credential, no flag but the unit's fixed ones.
			for _, never := range []string{"--agent", "--credential", "--init-arg", "--os-user", "--person-uid", "--pages-url", "postgres", "$HOME", "$PWD"} {
				require.NotContains(t, script, never)
			}
			again, err := osservice.InstallScript(v.goos, dialogSource)
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
		script, err := osservice.InstallScript(v.goos, dialogSource)
		require.NoError(t, err)
		_, rest, ok := strings.Cut(script, osservice.ScriptHelpersEnd)
		require.True(t, ok)
		checks, _, ok := strings.Cut(rest, osservice.ScriptPreflightEnd)
		require.True(t, ok)
		dest := osservice.ServiceBinary(v.goos)
		for _, c := range append(v.checks, "src='/usr/local/bin/basalt'\n", `[ -f "$src" ] || fail`, "( trusted "+filepath.Dir(dest)+" \"\" ) ||\n", "no_link "+dest+"\n") {
			require.Contains(t, checks, c, v.goos)
		}
		for _, change := range []string{"useradd", "dscl . -create", "make_dir", "make_root_dir", "copy_binary", "mkdir", "put_file", "chown", "chmod", "systemctl", "launchctl", ": >"} {
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
		script, err := osservice.InstallScript(goos, dialogSource)
		require.NoError(t, err)
		require.Contains(t, script, "make_root_dir "+base+" 0755", goos)
		require.Contains(t, script, "make_root_dir "+run+" 0755", goos)
	}
}

func TestInstallScriptRefusesAnUnsafeBinaryPath(t *testing.T) {
	t.Parallel()
	for _, bin := range []string{
		"basalt", "relative/basalt", "/usr/local/bin/../bin/basalt", "/usr/local/bin/basalt\nExecStartPre=/bin/sh", "/usr/local/bin/basalt\r",
	} {
		_, err := osservice.InstallScript("linux", osservice.Source{Path: bin, SHA256: dialogSum, Size: dialogSize})
		require.Error(t, err, bin)
	}
	for _, sum := range []string{"", "AB" + dialogSum[2:], dialogSum + "\nid", dialogSum[1:]} {
		_, err := osservice.InstallScript("linux", osservice.Source{Path: dialogBinary, SHA256: sum})
		require.Error(t, err, sum)
	}
	for _, size := range []int64{0, -1} {
		_, err := osservice.InstallScript("linux", osservice.Source{Path: dialogBinary, SHA256: dialogSum, Size: size})
		require.Error(t, err, size)
	}
	_, err := osservice.InstallScript("windows", dialogSource)
	require.Error(t, err)
}

// A source path with shell characters is one quoted word: it is only ever
// read, and never reaches the unit.
func TestInstallScriptQuotesTheSourcePath(t *testing.T) {
	t.Parallel()
	for _, bin := range []string{
		"/usr/local/bin/basalt'; rm -rf /; '", "/opt/my basalt/basalt", "/usr/local/bin/$(id)", "/usr/local/bin/`id`", "/usr/local/bin/basalt\\", "/usr/local/bin/a\"b",
	} {
		script, err := osservice.InstallScript("linux", osservice.Source{Path: bin, SHA256: dialogSum, Size: dialogSize})
		require.NoError(t, err, bin)
		_, rest, ok := strings.Cut(script, osservice.ScriptHelpersEnd)
		require.True(t, ok)
		line, _, _ := strings.Cut(rest, "\n")
		out, err := exec.Command("/bin/sh", "-c", line+"\nprintf %s \"$src\"").Output()
		require.NoError(t, err, bin)
		require.Equal(t, bin, string(out), "the source is the one word it names")
		require.Contains(t, script, "ExecStart=/usr/libexec/basalt engine ", bin)
	}
}

// Run from the service's own copy, the script copies nothing and checks
// that copy as it did any binary before.
func TestInstallScriptRunFromTheServiceCopyCopiesNothing(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"linux", "darwin"} {
		dest := osservice.ServiceBinary(goos)
		script, err := osservice.InstallScript(goos, osservice.Source{Path: dest, SHA256: dialogSum, Size: dialogSize})
		require.NoError(t, err)
		require.NotContains(t, script, "copy_binary \"")
		require.NotContains(t, script, "src=")
		checks, _, ok := strings.Cut(script, osservice.ScriptPreflightEnd)
		require.True(t, ok)
		require.Contains(t, checks, "bin="+dest+"\n", goos)
		require.Contains(t, checks, `[ "$(uid_of "$bin")" = 0 ]`, goos)
	}
}

func TestDialogCommand(t *testing.T) {
	t.Parallel()
	argv, err := osservice.DialogCommand("darwin", servicespec.ResetPrompt, "echo hi")
	require.NoError(t, err)
	require.Equal(t, []string{
		"/usr/bin/osascript", "-e", "on run argv", "-e", "do shell script (item 1 of argv) with prompt (item 2 of argv) with administrator privileges", "-e", "end run", "echo hi", servicespec.ResetPrompt,
	}, argv, "the script and the prompt go as arguments, never inside AppleScript text")

	argv, err = osservice.DialogCommand("linux", servicespec.ResetPrompt, "echo hi")
	require.NoError(t, err)
	require.Equal(t, []string{"/usr/bin/pkexec", "--disable-internal-agent", "/bin/sh", "-c", "echo hi"}, argv,
		"no text prompt: only the desktop's dialog answers")

	_, err = osservice.DialogCommand("windows", servicespec.ResetPrompt, "echo hi")
	require.Error(t, err)
}

// Each action's prompt names it in capitals and says when to cancel, so an
// unexpected dialog reads as one to cancel.
func TestDialogPromptsNameTheirAction(t *testing.T) {
	t.Parallel()
	for prompt, action := range map[string]string{servicespec.InstallPrompt: "INSTALL", servicespec.RemovePrompt: "REMOVE", servicespec.ResetPrompt: "RESET", servicespec.RestartPrompt: "RESTART"} {
		require.Contains(t, prompt, "BasaltDB wants to "+action+" ")
		require.Contains(t, prompt, "Cancel unless you just ")
		require.NotContainsf(t, prompt, `"`, "the prompt is an AppleScript argument; keep it plain: %s", prompt)
	}
	require.Contains(t, servicespec.ResetPrompt, "No, this isn't mine")
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
		{"linux", 126, "", servicespec.ErrDialogCancelled},
		{"linux", 127, "Error executing command as another user: No authentication agent found.", servicespec.ErrNoDialog},
		{"darwin", 1, "0:58: execution error: User canceled. (-128)", servicespec.ErrDialogCancelled},
		{"darwin", 1, "execution error: No user interaction allowed. (-1713)", servicespec.ErrNoDialog},
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
	script, err := osservice.InstallScript(runtime.GOOS, dialogSource)
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

// The restart script restarts the service with one fixed command per
// platform when basalt runs from the service's copy; from anywhere else it
// copies that basalt over the copy first, checked as the install does.
// Either way, a config from before the last breaking release is not
// restarted onto: the script resets it and installs the service again
// instead (breaking_script_test.go). No other platform has one.
func TestRestartScript(t *testing.T) {
	t.Parallel()
	for goos, restart := range map[string]string{
		"darwin": "launchctl kickstart -k system/" + servicespec.LaunchdLabel + "\n",
		"linux":  "systemctl restart " + servicespec.SystemdUnitName + "\n",
	} {
		for name, src := range map[string]osservice.Source{
			"from the service's copy": {Path: osservice.ServiceBinary(goos), SHA256: dialogSum, Size: dialogSize},
			"from elsewhere":          dialogSource,
		} {
			got, err := osservice.RestartScript(goos, src)
			require.NoError(t, err)
			checks, body, ok := strings.Cut(got, osservice.ScriptPreflightEnd)
			require.True(t, ok)
			require.True(t, strings.HasSuffix(body, "else\n"+restart+"fi\n"), "%s %s: the restart is the branch without a reset", goos, name)
			require.Contains(t, checks, "breaking_reset=\n", "%s %s: the verdict is a check", goos, name)
			reset := strings.Index(body, `if [ -n "$breaking_reset" ]; then`)
			require.GreaterOrEqual(t, reset, 0, "%s %s: the reset step", goos, name)
			if src.Path == dialogSource.Path {
				require.Contains(t, checks, "src='/usr/local/bin/basalt'\n")
				require.Contains(t, body, "copy_binary \"$src\" "+osservice.ServiceBinary(goos)+" "+dialogSum+" 4096\n")
				require.Less(t, strings.Index(body, "copy_binary"), reset, "copied before the reset and the restart")
			} else {
				require.NotContains(t, body, "copy_binary")
			}
			out, err := exec.Command("/bin/sh", "-n", "-c", got).CombinedOutput()
			require.NoError(t, err, "the script parses: %s", out)
		}
	}
	_, err := osservice.RestartScript("linux", osservice.Source{Path: "relative", SHA256: dialogSum, Size: dialogSize})
	require.Error(t, err)
	_, err = osservice.RestartScript("windows", dialogSource)
	require.Error(t, err)
}

// sha256_of, which copy_binary checks the copy with, prints the SHA-256
// ReadSource reads, on this system's own tool.
func TestScriptSHA256MatchesReadSource(t *testing.T) {
	t.Parallel()
	bin := filepath.Join(t.TempDir(), "basalt")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\necho basalt\n"), 0o600))
	src, err := osservice.ReadSource(bin)
	require.NoError(t, err)
	require.Equal(t, bin, src.Path)
	out, err := helperScript(t, "sha256_of "+bin)
	require.NoError(t, err, out)
	require.Equal(t, src.SHA256+"\n", out)
	_, err = osservice.ReadSource(filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)
}
