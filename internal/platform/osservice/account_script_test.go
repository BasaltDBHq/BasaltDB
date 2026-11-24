package osservice_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

// These tests run parts of the generated scripts with dscl, id, getent,
// userdel, groupdel, pgrep and chown replaced by shell functions: nothing
// touches the machine's accounts.

// runShell runs script with /bin/sh and returns its combined output.
func runShell(t *testing.T, script string) (string, error) {
	t.Helper()
	out, err := exec.Command("/bin/sh", "-c", script).CombinedOutput()
	return string(out), err
}

// fakeAccounts keeps a user and a group as files in a temp dir: present
// while the file exists. user is how the user delete goes: "" deletes it,
// "stuck" fails and keeps it (as macOS does, for example without Full Disk
// Access), "errgone" deletes it but fails; groupStuck fails the group
// delete.
func fakeAccounts(t *testing.T, goos, name string, groupExists bool, user string, groupStuck bool) (fakes, log string) {
	t.Helper()
	dir := t.TempDir()
	userFile, group := filepath.Join(dir, "user"), filepath.Join(dir, "group")
	log = filepath.Join(dir, "log")
	require.NoError(t, os.WriteFile(userFile, nil, 0o600))
	if groupExists {
		require.NoError(t, os.WriteFile(group, nil, 0o600))
	}
	del := func(file, mode string) string {
		switch mode {
		case "stuck":
			return "return 1"
		case "errgone":
			return "rm -f " + shellQuoteTest(file) + "; return 1"
		}
		return "rm -f " + shellQuoteTest(file)
	}
	groupMode := ""
	if groupStuck {
		groupMode = "stuck"
	}
	fakes = "pgrep() { return 1; }\n"
	if goos == "darwin" {
		fakes += `dscl() {
	echo "dscl $*" >>` + shellQuoteTest(log) + `
	case "$2 $3" in
	"-delete /Users/` + name + `") ` + del(userFile, user) + ` ;;
	"-read /Users/` + name + `") [ -e ` + shellQuoteTest(userFile) + ` ] ;;
	"-delete /Groups/` + name + `") ` + del(group, groupMode) + ` ;;
	"-read /Groups/` + name + `") [ -e ` + shellQuoteTest(group) + ` ] ;;
	*) return 99 ;;
	esac
}
`
		return fakes, log
	}
	fakes += `userdel() { echo "userdel $*" >>` + shellQuoteTest(log) + `; ` + del(userFile, user) + `; }
groupdel() { echo "groupdel $*" >>` + shellQuoteTest(log) + `; ` + del(group, groupMode) + `; }
getent() {
	case "$1 $2" in
	"passwd ` + name + `") [ -e ` + shellQuoteTest(userFile) + ` ] ;;
	"group ` + name + `") [ -e ` + shellQuoteTest(group) + ` ] ;;
	*) return 2 ;;
	esac
}
`
	return fakes, log
}

// The removal deletes an OS user's group only once the user is gone: a
// user it cannot delete keeps its group, so the pair an install takes over
// stays whole, and a group left without its user is named.
func TestRemoveScriptDeletesTheGroupOnlyAfterItsUser(t *testing.T) {
	t.Parallel()
	for _, goos := range []string{"linux", "darwin"} {
		script, err := osservice.RemoveScript(goos)
		require.NoError(t, err)
		helpers, _, ok := strings.Cut(script, osservice.ScriptHelpersEnd)
		require.True(t, ok)
		deleteUser, deleteGroup := "userdel", "groupdel"
		if goos == "darwin" {
			deleteUser, deleteGroup = "dscl . -delete /Users/", "dscl . -delete /Groups/"
		}
		for _, v := range []struct {
			name              string
			groupExists       bool
			user              string
			groupStuck        bool
			wantLog           []string
			wantKept, wantOrp string
		}{
			{"both deleted", true, "", false, []string{deleteUser, deleteGroup}, "", ""},
			{"the user stays", true, "stuck", false, []string{deleteUser}, " acct", ""},
			{"the delete failed but the user is gone", true, "errgone", false, []string{deleteUser, deleteGroup}, "", ""},
			{"the group went with the user", false, "", false, []string{deleteUser}, "", ""},
			{"the group stays", true, "", true, []string{deleteUser, deleteGroup}, "", " acct"},
		} {
			fakes, log := fakeAccounts(t, goos, "acct", v.groupExists, v.user, v.groupStuck)
			out, err := runShell(t, helpers+fakes+`delete_account acct; echo "kept=[$kept] orphaned=[$orphaned]"`)
			require.NoError(t, err, "%s %s: %s", goos, v.name, out)
			raw, _ := os.ReadFile(log)
			var calls []string
			for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
				if strings.Contains(line, "-delete") || strings.HasPrefix(line, "userdel") || strings.HasPrefix(line, "groupdel") {
					calls = append(calls, strings.ReplaceAll(strings.ReplaceAll(line, "acct", ""), "  ", " "))
				}
			}
			require.Len(t, calls, len(v.wantLog), "%s %s: %v", goos, v.name, calls)
			for i, want := range v.wantLog {
				require.Equal(t, strings.TrimSpace(want), strings.TrimSpace(calls[i]), "%s %s", goos, v.name)
			}
			require.Contains(t, out, "kept=["+v.wantKept+"] orphaned=["+v.wantOrp+"]", "%s %s", goos, v.name)
		}
	}
}

// The service stops before its processes are waited for and its user is
// deleted. A user kept with its group is said at the end (on macOS on
// stdout: the dialog drops a script's stderr when it succeeds), and a group
// left without its user fails the script.
func TestRemoveScriptOrder(t *testing.T) {
	t.Parallel()
	for goos, steps := range map[string][]string{
		"linux":  {"systemctl disable --now basalt-engine.service", "remove_dir /etc/basalt", "delete_account basalt\n", "[ -z \"$kept\" ] ||\n\techo ", "[ -z \"$orphaned\" ] ||\n\tfail "},
		"darwin": {"launchctl bootout system/dev.basaltdb.engine", "remove_dir '/Library/Application Support/Basalt'", "delete_account _basalt\n", "[ -z \"$kept\" ] ||\n\techo ", "[ -z \"$orphaned\" ] ||\n\tfail "},
	} {
		script, err := osservice.RemoveScript(goos)
		require.NoError(t, err)
		helpers, body, ok := strings.Cut(script, osservice.ScriptPreflightEnd)
		require.True(t, ok)
		at := -1
		for _, s := range steps {
			i := strings.Index(body, s)
			require.Greater(t, i, at, "%s: %q comes after the step before it", goos, s)
			at = i
		}
		_, kept, _ := strings.Cut(body, "[ -z \"$kept\" ] ||\n")
		kept, _, _ = strings.Cut(kept, "\n")
		require.Contains(t, kept, "the next install uses it again", goos)
		require.Equal(t, goos == "linux", strings.HasSuffix(kept, ">&2"), "%s: on macOS the note goes to stdout", goos)
		_, fn, ok := strings.Cut(helpers, "delete_account() {")
		require.True(t, ok, goos)
		wait := strings.Index(fn, `pgrep -U "$1"`)
		user, group := strings.Index(fn, `userdel "$1"`), strings.Index(fn, `groupdel "$1"`)
		if goos == "darwin" {
			user, group = strings.Index(fn, `dscl . -delete "/Users/$1"`), strings.Index(fn, `dscl . -delete "/Groups/$1"`)
		}
		require.True(t, wait >= 0 && wait < user && user < group, "%s: wait, then the user, then the group", goos)
	}
}

// The removal deletes every folder the engine used: on macOS its run and
// state folders live in the config folder it removes whole, so a reinstall
// never finds a root-owned leftover there.
func TestRemoveScriptRemovesTheEngineFolders(t *testing.T) {
	t.Parallel()
	configDir := filepath.Dir(config.DefaultPath("darwin"))
	for _, d := range []string{config.DefaultSocketDir("darwin"), config.DefaultStateDir("darwin")} {
		require.True(t, strings.HasPrefix(d, configDir+"/"), d)
	}
	script, err := osservice.RemoveScript("darwin")
	require.NoError(t, err)
	require.Contains(t, script, "remove_dir "+shellWord(configDir)+"\n")
	script, err = osservice.RemoveScript("linux")
	require.NoError(t, err)
	for _, d := range []string{filepath.Dir(config.DefaultPath("linux")), config.DefaultSocketDir("linux"), config.DefaultStateDir("linux")} {
		require.Contains(t, script, "remove_dir "+shellWord(d)+"\n")
	}
}

// accountBlock is the install preflight's account check, which reads the
// accounts and changes nothing.
func accountBlock(t *testing.T, goos string) (helpers, block string) {
	t.Helper()
	script, err := osservice.InstallScript(goos, dialogSource)
	require.NoError(t, err)
	helpers, rest, ok := strings.Cut(script, osservice.ScriptHelpersEnd)
	require.True(t, ok)
	start := strings.Index(rest, "engine_uid=\nmake_group=\n")
	require.GreaterOrEqual(t, start, 0)
	end := strings.Index(rest[start:], "\ncheck_dir ")
	require.Greater(t, end, 0)
	return helpers, rest[start : start+end+1]
}

// An engine user in the system range whose group is missing (a removal
// that deleted the group but not the user) gets its group back with the
// user's own gid; a user outside the range, or a gid another group holds,
// is refused.
func TestInstallScriptRecreatesAMissingGroup(t *testing.T) {
	t.Parallel()
	darwinFakes := func(uid, gid string, groupExists bool, other string) string {
		has := ""
		if groupExists {
			has = "1"
		}
		return `id() { [ "$1" = -u ] && echo ` + uid + `; }
dscl() {
	case "$2 $3 ${4:-}" in
	"-read /Users/_basalt UserShell") echo "UserShell: /usr/bin/false" ;;
	"-read /Users/_basalt PrimaryGroupID") echo "PrimaryGroupID: ` + gid + `" ;;
	"-read /Groups/_basalt ") [ -n "` + has + `" ] ;;
	"-list /Groups PrimaryGroupID") printf 'staff 20\n%s\n' "` + other + `" ;;
	*) echo "unexpected dscl $*" >&2; return 99 ;;
	esac
}
`
	}
	linuxFakes := func(uid, gid string, groupExists bool, other string) string {
		has := ""
		if groupExists {
			has = "1"
		}
		return `id() { case $1 in -u) echo ` + uid + ` ;; -g) echo ` + gid + ` ;; esac; }
getent() {
	case "$1 $2" in
	"passwd basalt") echo "basalt:x:` + uid + `:` + gid + `::/nonexistent:/usr/sbin/nologin" ;;
	"group basalt") [ -n "` + has + `" ] ;;
	"group ` + gid + `") [ -n "` + other + `" ] ;;
	*) return 2 ;;
	esac
}
`
	}
	for _, v := range []struct {
		goos, name, uid, gid string
		groupExists          bool
		other, want, refused string
	}{
		{"darwin", "missing group", "305", "305", false, "", "uid=305 gid=305 make=1", ""},
		{"darwin", "group there", "305", "305", true, "", "uid=305 gid= make=", ""},
		{"darwin", "gid taken", "305", "305", false, "other 305", "", "belongs to another group"},
		{"darwin", "gid outside the range", "305", "20", false, "", "", "is not a system id"},
		{"darwin", "user outside the range", "501", "20", false, "", "", "not a system account (300 to 499)"},
		{"linux", "missing group", "998", "998", false, "", "uid=998 gid=998 make=1", ""},
		{"linux", "group there", "998", "998", true, "", "uid=998 gid=998 make=", ""},
		{"linux", "gid taken", "998", "998", false, "1", "", "belongs to another group"},
		{"linux", "user outside the range", "1001", "1001", false, "", "", "not a system account"},
	} {
		helpers, block := accountBlock(t, v.goos)
		fakes := linuxFakes(v.uid, v.gid, v.groupExists, v.other)
		if v.goos == "darwin" {
			fakes = darwinFakes(v.uid, v.gid, v.groupExists, v.other)
		}
		out, err := runShell(t, helpers+fakes+"engine_gid=\n"+block+`echo "uid=$engine_uid gid=$engine_gid make=$make_group"`)
		if v.refused != "" {
			require.Error(t, err, "%s %s: %s", v.goos, v.name, out)
			require.Contains(t, out, v.refused, "%s %s", v.goos, v.name)
			continue
		}
		require.NoError(t, err, "%s %s: %s", v.goos, v.name, out)
		require.Contains(t, out, v.want, "%s %s", v.goos, v.name)
	}

	// The group is made, with that gid, before the first folder is given
	// to the user.
	for goos, create := range map[string]string{
		"darwin": "elif [ -n \"$make_group\" ]; then\n\tdscl . -create /Groups/_basalt\n\tdscl . -create /Groups/_basalt PrimaryGroupID \"$engine_gid\"\nfi\n",
		"linux":  "elif [ -n \"$make_group\" ]; then\n\tgroupadd --system --gid \"$engine_gid\" basalt\nfi\n",
	} {
		script, err := osservice.InstallScript(goos, dialogSource)
		require.NoError(t, err)
		_, body, ok := strings.Cut(script, osservice.ScriptPreflightEnd)
		require.True(t, ok)
		i := strings.Index(body, create)
		require.GreaterOrEqual(t, i, 0, goos)
		require.Less(t, i, strings.Index(body, "make_dir "), goos)
	}
}

// make_dir gives a root-owned folder left by an install that stopped (the
// config folder, run, state) to the engine user when it holds nothing but
// folders, refuses one holding files, and removes a folder it made but
// could not give away.
func TestScriptMakeDirTakesOverARootLeftover(t *testing.T) {
	t.Parallel()
	skipAsRoot(t)
	base := trustedBase(t)
	me := strconv.Itoa(os.Getuid())
	stat := "stat -c %u"
	if runtime.GOOS == "darwin" {
		stat = "stat -f %u"
	}
	// rootOwned stands in for root as the owner of dir; chown only logs.
	fakes := func(dir string) string {
		return `uid_of() { case $1 in ` + shellQuoteTest(dir) + `) echo 0 ;; *) ` + stat + ` "$1" ;; esac; }
chown() { echo "chown $*"; }
`
	}

	left := filepath.Join(base, "left")
	require.NoError(t, os.MkdirAll(filepath.Join(left, "run"), 0o700))
	out, err := helperScript(t, fakes(left)+"engine_uid="+me+"; make_dir "+shellQuoteTest(left)+" 0750 _basalt _basalt")
	require.NoError(t, err, out)
	require.Contains(t, out, "chown -h _basalt:_basalt "+left)
	info, err := os.Lstat(left)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o750), info.Mode().Perm())

	run := filepath.Join(left, "run")
	out, err = helperScript(t, fakes(run)+"engine_uid="+me+"; make_dir "+shellQuoteTest(run)+" 0755 _basalt _basalt")
	require.NoError(t, err, out)
	require.Contains(t, out, "chown -h _basalt:_basalt "+run, "the leftover run folder is the engine's again")

	require.NoError(t, os.WriteFile(filepath.Join(left, "run", "file"), []byte("x"), 0o600))
	out, err = helperScript(t, fakes(left)+"engine_uid="+me+"; make_dir "+shellQuoteTest(left)+" 0750 _basalt _basalt")
	require.Error(t, err)
	require.Contains(t, out, "holds files")
	require.NotContains(t, out, "chown -h")

	// A folder the engine already owns is left as it is.
	mine := filepath.Join(base, "mine")
	require.NoError(t, os.Mkdir(mine, 0o755))
	out, err = helperScript(t, fakes("/nowhere")+"engine_uid="+me+"; make_dir "+shellQuoteTest(mine)+" 0750 _basalt _basalt")
	require.NoError(t, err, out)
	require.NotContains(t, out, "chown")

	// Root's own folders (OWNER 0) are never handed over.
	out, err = helperScript(t, fakes(left)+"engine_uid="+me+"; rm -f "+shellQuoteTest(filepath.Join(left, "run", "file"))+"; make_dir "+shellQuoteTest(left)+" 0755 0 0")
	require.NoError(t, err, out)
	require.NotContains(t, out, "chown")

	made := filepath.Join(base, "made")
	out, err = helperScript(t, "chown() { return 1; }; engine_uid="+me+"; make_dir "+shellQuoteTest(made)+" 0750 _basalt _basalt")
	require.Error(t, err)
	require.Contains(t, out, "could not be given to _basalt:_basalt")
	_, err = os.Lstat(made)
	require.ErrorIs(t, err, os.ErrNotExist, "no root-owned folder is left for the next try")
}
