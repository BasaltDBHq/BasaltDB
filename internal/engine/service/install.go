package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
)

// File modes for what install writes.
const (
	unitFileMode  = 0o644
	configDirMode = 0o750
	openDirMode   = 0o755
	// privateDirMode is the agents directory holding credential files.
	privateDirMode = 0o700
	// engineLogMode is the macOS engine log's mode: the engine's user's
	// alone, as its umask would make it.
	engineLogMode = 0o600

	// rootUser is root's name, as a step names an owner.
	rootUser = "root"

	// darwinIDMin and darwinIDMax bound the uid/gid picked for the engine's
	// user on macOS: below 500 keeps it a hidden system account, at or
	// above 300 stays clear of Apple's own accounts.
	darwinIDMin = 300
	darwinIDMax = 499

	// dsclFields is a "name id" line of dscl -list output.
	dsclFields = 2
)

// System is what install and uninstall need from the machine.
type System interface {
	UserExists(name string) bool
	// InGroup reports whether an OS user is in a group, as its primary or a
	// supplementary group; a group that does not exist has no one in it.
	InGroup(name, group string) (bool, error)
	// Exists reports whether a file exists (an installed unit).
	Exists(path string) bool
	Output(ctx context.Context, args ...string) (string, error)
	Run(ctx context.Context, args ...string) error
	// WriteFile writes a file without following links; owner, when set, is
	// the OS user that owns the new file.
	WriteFile(path string, data []byte, mode os.FileMode, owner string) error
	// CreateFile makes an empty file owned by owner with mode when it is
	// missing and keeps an existing one's content (a log a service appends
	// to), in a directory only root can change, without following a link;
	// it refuses a path that is not a plain file.
	CreateFile(path string, mode os.FileMode, owner string) error
	// Mkdir makes a directory (or takes over an existing real one) without
	// following a link; it refuses a symlink. group, when set, is its group
	// instead of owner's.
	Mkdir(path string, mode os.FileMode, owner, group string) error
	Remove(path string) error
	// RemoveTree removes a directory and everything in it without
	// following a link; a missing one is not an error.
	RemoveTree(path string) error
	// CheckBinary refuses a binary anyone but root could change.
	CheckBinary(path string) error
}

// StepKind is one kind of install step.
type StepKind string

// Step kinds.
const (
	StepRun    StepKind = "RUN"
	StepWrite  StepKind = "WRITE"
	StepRemove StepKind = "REMOVE"
	StepMkdir  StepKind = "MKDIR"
	// StepRemoveTree removes a directory and what is in it.
	StepRemoveTree StepKind = "REMOVE_TREE"
	// StepCreate makes an empty file when it is missing and keeps an
	// existing one's content; either way it gets Mode and Owner.
	StepCreate StepKind = "CREATE"
)

// Step is one action of an install or uninstall plan.
type Step struct {
	Kind    StepKind
	Args    []string // StepRun
	Path    string   // StepWrite, StepCreate, StepRemove
	Content string   // StepWrite; never printed (a credential can be one)
	// Mode is the StepWrite or StepCreate file mode; zero means a unit
	// file's 0644.
	Mode os.FileMode
	// Owner is the OS user that owns what StepWrite, StepCreate or StepMkdir
	// makes.
	Owner string
	// Group is StepMkdir's group; empty is Owner's.
	Group string
	// BestEffort marks a step whose failure does not stop the plan: Apply
	// names it as skipped and goes on (an uninstall's service-manager
	// commands where no service manager runs).
	BestEffort bool
	// Note marks a step whose failure is expected in some setups: Apply
	// names it as skipped with the note and goes on, and the plan still
	// succeeds.
	Note string
}

// String is the step as a person reads it before it runs.
func (s Step) String() string {
	switch s.Kind {
	case StepWrite:
		return "write " + s.Path
	case StepCreate:
		return fmt.Sprintf("create -m %04o -o %s %s (kept when it exists)", modeBits(s.fileMode()), s.Owner, strings.Join(quoteArgs([]string{s.Path}), ""))
	case StepRemove:
		return "rm -f " + s.Path
	case StepRemoveTree:
		return "rm -rf " + strings.Join(quoteArgs([]string{s.Path}), "")
	case StepMkdir:
		owner := s.Owner
		if owner == "" {
			owner = rootUser
		}
		group := ""
		if s.Group != "" {
			group = " -g " + s.Group
		}
		return fmt.Sprintf("mkdir -m %04o -o %s%s %s", modeBits(s.Mode), owner, group, strings.Join(quoteArgs([]string{s.Path}), ""))
	case StepRun:
		return strings.Join(quoteArgs(s.Args), " ")
	}
	return string(s.Kind)
}

// fileMode is a StepWrite or StepCreate file's mode: Mode, or a unit
// file's 0644 when it is zero.
func (s Step) fileMode() os.FileMode {
	if s.Mode == 0 {
		return unitFileMode
	}
	return s.Mode
}

// modeBits is m as the octal number chmod takes, setgid included.
func modeBits(m os.FileMode) uint32 {
	bits := uint32(m.Perm())
	if m&os.ModeSetgid != 0 {
		bits |= 0o2000
	}
	return bits
}

func quoteArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if strings.ContainsAny(a, " \t\"'") {
			a = strconv.Quote(a)
		}
		out = append(out, a)
	}
	return out
}

func run(args ...string) Step { return Step{Kind: StepRun, Args: args} }

// tryRun is run with BestEffort set.
func tryRun(args ...string) Step { return Step{Kind: StepRun, Args: args, BestEffort: true} }

// mkdir is a step making a directory owned by user without following a link
// (install -d would follow one the engine user planted).
func mkdir(mode os.FileMode, user, path string) Step {
	return Step{Kind: StepMkdir, Path: path, Mode: mode, Owner: user}
}

// Validate checks the spec can be installed.
func (s Spec) Validate() error {
	switch {
	case s.GOOS != goosLinux && s.GOOS != goosDarwin:
		return fmt.Errorf("the engine service installs on linux and darwin, not %s", s.GOOS)
	case !filepath.IsAbs(s.Binary):
		return fmt.Errorf("binary path %q must be absolute", s.Binary)
	case !filepath.IsAbs(s.ConfigPath):
		return fmt.Errorf("config path %q must be absolute", s.ConfigPath)
	case s.User == "" || s.User == rootUser:
		return errors.New("the engine needs its own OS user, not root")
	}
	return nil
}

// InstallPlan returns the steps that create the engine's user if missing,
// its directories, and the unit, then start the service.
func InstallPlan(ctx context.Context, sys System, s Spec) ([]Step, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	if err := sys.CheckBinary(s.Binary); err != nil {
		return nil, err
	}
	if len(s.Plugins) > 0 {
		if err := s.pluginHost().validate(); err != nil {
			return nil, err
		}
	}
	if s.GOOS == goosDarwin {
		return darwinInstall(ctx, sys, s)
	}
	return linuxInstall(sys, s)
}

// pluginSteps make the plugin base, then every local plugin entry's user,
// socket directory and unit (CONTRACT.md, Plugins, Isolation and trust).
func pluginSteps(sys System, s Spec, ids *idAllocator) ([]Step, error) {
	steps, err := PluginBaseSteps(s.GOOS)
	if err != nil {
		return nil, err
	}
	more, err := pluginEntriesSteps(sys, s.pluginHost(), s.Plugins, ids)
	if err != nil {
		return nil, err
	}
	return append(steps, more...), nil
}

func linuxInstall(sys System, s Spec) ([]Step, error) {
	var steps []Step
	if !sys.UserExists(s.User) {
		steps = append(steps, run("useradd", "--system", "--user-group", "--no-create-home",
			"--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", s.User))
	}
	installed := sys.Exists(SystemdUnitPath)
	steps = append(steps, mkdir(configDirMode, s.User, filepath.Dir(s.ConfigPath)))
	steps = append(steps, fileSteps(s)...)
	steps = append(steps,
		Step{Kind: StepWrite, Path: SystemdUnitPath, Content: SystemdUnit(s)},
		run("systemctl", "daemon-reload"),
	)
	if installed {
		// Already running: restart so it reads the new config.
		steps = append(steps, run("systemctl", "enable", SystemdUnitName), run("systemctl", "restart", SystemdUnitName))
	} else {
		steps = append(steps, run("systemctl", "enable", "--now", SystemdUnitName))
	}
	// The plugin units are bound to the engine's: they go after it.
	plugins, err := pluginSteps(sys, s, nil)
	if err != nil {
		return nil, err
	}
	return append(steps, plugins...), nil
}

// fileSteps write the spec's files (the engine config, an agent's
// credential) owned by the engine's user, each directory first.
func fileSteps(s Spec) []Step {
	var steps []Step
	made := map[string]bool{filepath.Dir(s.ConfigPath): true}
	for _, f := range s.Files {
		if dir := filepath.Dir(f.Path); !made[dir] {
			made[dir] = true
			// Not install -d: it follows a symlinked directory the engine user planted.
			steps = append(steps, mkdir(privateDirMode, s.User, dir))
		}
		// The owner is set on the new file's descriptor before it is renamed
		// into place, so no step changes the owner of a path.
		steps = append(steps, Step{Kind: StepWrite, Path: f.Path, Content: string(f.Content), Mode: config.FileMode, Owner: s.User})
	}
	return steps
}

func darwinInstall(ctx context.Context, sys System, s Spec) ([]Step, error) {
	var steps []Step
	var ids *idAllocator
	if !sys.UserExists(s.User) || len(s.Plugins) > 0 {
		var err error
		if ids, err = newIDAllocator(ctx, sys); err != nil {
			return nil, err
		}
	}
	if !sys.UserExists(s.User) {
		id, err := ids.next()
		if err != nil {
			return nil, err
		}
		steps = append(steps, darwinAccountSteps(s.User, strconv.Itoa(id), "BasaltDB engine")...)
	}
	configDir := filepath.Dir(s.ConfigPath)
	installed := sys.Exists(LaunchdPlist)
	steps = append(steps,
		// The config dir stays traversable: the socket dir lives inside it,
		// and credential files inside are 0600.
		mkdir(openDirMode, s.User, configDir),
		mkdir(runtimeDirMode, s.User, config.DefaultSocketDir(goosDarwin)),
		// The log directory is root's, so the plugins' logs below it are out
		// of the engine user's reach; the engine's own log in it is that
		// user's, made before the daemon loads.
		mkdir(openDirMode, "", darwinLogDir),
		Step{Kind: StepCreate, Path: darwinLogFile, Mode: engineLogMode, Owner: s.User},
		mkdir(darwinStateDirMode, s.User, config.DefaultStateDir(goosDarwin)),
	)
	steps = append(steps, fileSteps(s)...)
	plugins, err := pluginSteps(sys, s, ids)
	if err != nil {
		return nil, err
	}
	steps = append(steps, plugins...)
	steps = append(steps, Step{Kind: StepWrite, Path: LaunchdPlist, Content: LaunchdDaemon(s)})
	if installed {
		// Already loaded: restart so it reads the new config.
		return append(steps, run("launchctl", "kickstart", "-k", "system/"+LaunchdLabel)), nil
	}
	return append(steps,
		run("launchctl", "bootstrap", "system", LaunchdPlist),
		run("launchctl", "enable", "system/"+LaunchdLabel),
	), nil
}

// darwinAccountSteps create a hidden macOS system account and its group,
// both named name, with id as uid and gid.
func darwinAccountSteps(name, id, realName string) []Step {
	userPath, groupPath := "/Users/"+name, "/Groups/"+name
	return []Step{
		run("dscl", ".", "-create", groupPath),
		run("dscl", ".", "-create", groupPath, "PrimaryGroupID", id),
		run("dscl", ".", "-create", userPath),
		run("dscl", ".", "-create", userPath, "UniqueID", id),
		run("dscl", ".", "-create", userPath, "PrimaryGroupID", id),
		run("dscl", ".", "-create", userPath, "UserShell", "/usr/bin/false"),
		run("dscl", ".", "-create", userPath, "NFSHomeDirectory", "/var/empty"),
		run("dscl", ".", "-create", userPath, "RealName", realName),
		run("dscl", ".", "-create", userPath, "IsHidden", "1"),
	}
}

// PickFreeID returns the lowest id in the system-account range that does not
// appear in dscl -list output (lines of "name id").
func PickFreeID(dsclOutput string) (int, error) {
	return freeID(usedIDs(dsclOutput))
}

// usedIDs are the ids in dscl -list output.
func usedIDs(dsclOutput string) map[int]bool {
	used := map[int]bool{}
	for line := range strings.SplitSeq(dsclOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) < dsclFields {
			continue
		}
		if id, err := strconv.Atoi(fields[len(fields)-1]); err == nil {
			used[id] = true
		}
	}
	return used
}

// freeID is the lowest id in the system-account range not in used.
func freeID(used map[int]bool) (int, error) {
	for id := darwinIDMin; id <= darwinIDMax; id++ {
		if !used[id] {
			return id, nil
		}
	}
	return 0, fmt.Errorf("no free system id between %d and %d", darwinIDMin, darwinIDMax)
}

// UninstallPlan returns the steps that stop the service and remove its unit.
// The user, config and credentials stay; basalt init owns them. The
// service-manager commands are best effort, so the unit is removed even
// where systemd or launchd does not run (a container). Without a unit file
// the service is not installed: there is nothing to stop, so running
// uninstall again does not fail on systemd's "Unit file does not exist" or
// launchd's "not loaded".
//
// Every local plugin entry's unit, socket directory and OS user go too,
// then the plugin base's run directory and the base itself when nothing
// else is left in them: installed copies and trusted keys stay, as the
// config does.
func UninstallPlan(sys System, s Spec) ([]Step, error) {
	var steps []Step
	switch s.GOOS {
	case goosLinux:
		if sys.Exists(SystemdUnitPath) {
			steps = append(steps, tryRun("systemctl", "disable", "--now", SystemdUnitName))
		}
		steps = append(steps, Step{Kind: StepRemove, Path: SystemdUnitPath}, tryRun("systemctl", "daemon-reload"))
	case goosDarwin:
		if sys.Exists(LaunchdPlist) {
			steps = append(steps, tryRun("launchctl", "bootout", "system/"+LaunchdLabel))
		}
		steps = append(steps, Step{Kind: StepRemove, Path: LaunchdPlist})
	default:
		return nil, fmt.Errorf("the engine service installs on linux and darwin, not %s", s.GOOS)
	}
	plugins, err := pluginUninstallSteps(sys, s.GOOS, s.Plugins)
	if err != nil {
		return nil, err
	}
	return append(steps, plugins...), nil
}

// ErrStepsSkipped is Apply's error, after every step ran, when a
// BestEffort step failed.
var ErrStepsSkipped = errors.New("some steps were skipped")

// Apply prints every step to out, then runs them in order unless dryRun.
// A failed BestEffort step is named on out as skipped, with its error, and
// the rest still run; Apply then returns ErrStepsSkipped.
func Apply(ctx context.Context, sys System, steps []Step, dryRun bool, out io.Writer) error {
	for _, st := range steps {
		fmt.Fprintln(out, "  "+st.String())
	}
	if dryRun {
		return nil
	}
	var skipped []string
	for _, st := range steps {
		err := applyStep(ctx, sys, st)
		switch {
		case err == nil:
		case st.Note != "":
			fmt.Fprintf(out, "  skipped %s: %s (%v)\n", st, st.Note, err)
		case st.BestEffort:
			fmt.Fprintf(out, "  skipped %s: %v\n", st, err)
			skipped = append(skipped, st.String())
		default:
			return fmt.Errorf("%s: %w", st, err)
		}
	}
	if len(skipped) > 0 {
		return fmt.Errorf("%w: %s", ErrStepsSkipped, strings.Join(skipped, "; "))
	}
	return nil
}

// Settle is Apply's error as the command reports it: steps skipped where
// no service manager runs are expected and are not an error; skipped where
// one runs, the command fails after doing the rest.
func Settle(err error, sys System, goos string) error {
	if errors.Is(err, ErrStepsSkipped) && !ManagerRunning(sys, goos) {
		return nil
	}
	return err
}

// systemdRunning is the directory systemd creates when it is the running
// init system (sd_booted).
const systemdRunning = "/run/systemd/system"

// ManagerRunning reports whether the platform's service manager runs here:
// systemd booted on Linux; launchd always runs on macOS. Where it does not
// (a container without systemd), a skipped service-manager step is
// expected.
func ManagerRunning(sys System, goos string) bool {
	if goos == goosDarwin {
		return true
	}
	return sys.Exists(systemdRunning)
}

func applyStep(ctx context.Context, sys System, st Step) error {
	switch st.Kind {
	case StepRun:
		return sys.Run(ctx, st.Args...)
	case StepWrite:
		return sys.WriteFile(st.Path, []byte(st.Content), st.fileMode(), st.Owner)
	case StepCreate:
		return sys.CreateFile(st.Path, st.fileMode(), st.Owner)
	case StepMkdir:
		return sys.Mkdir(st.Path, st.Mode, st.Owner, st.Group)
	case StepRemoveTree:
		return sys.RemoveTree(st.Path)
	case StepRemove:
		err := sys.Remove(st.Path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return fmt.Errorf("unknown step kind %q", st.Kind)
}
