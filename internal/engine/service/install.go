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
	// Exists reports whether a file exists (an installed unit).
	Exists(path string) bool
	Output(ctx context.Context, args ...string) (string, error)
	Run(ctx context.Context, args ...string) error
	// WriteFile writes a file without following links; owner, when set, is
	// the OS user that owns the new file.
	WriteFile(path string, data []byte, mode os.FileMode, owner string) error
	// Mkdir makes a directory (or takes over an existing real one) without
	// following a link; it refuses a symlink.
	Mkdir(path string, mode os.FileMode, owner string) error
	Remove(path string) error
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
)

// Step is one action of an install or uninstall plan.
type Step struct {
	Kind    StepKind
	Args    []string // StepRun
	Path    string   // StepWrite, StepRemove
	Content string   // StepWrite; never printed (a credential can be one)
	// Mode is the StepWrite file mode; zero means a unit file's 0644.
	Mode os.FileMode
	// Owner is the OS user that owns what StepWrite or StepMkdir makes.
	Owner string
}

// String is the step as a person reads it before it runs.
func (s Step) String() string {
	switch s.Kind {
	case StepWrite:
		return "write " + s.Path
	case StepRemove:
		return "rm -f " + s.Path
	case StepMkdir:
		return fmt.Sprintf("mkdir -m %04o -o %s %s", s.Mode, s.Owner, strings.Join(quoteArgs([]string{s.Path}), ""))
	case StepRun:
		return strings.Join(quoteArgs(s.Args), " ")
	}
	return string(s.Kind)
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
	case s.User == "" || s.User == "root":
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
	if s.GOOS == goosDarwin {
		return darwinInstall(ctx, sys, s)
	}
	return linuxInstall(sys, s), nil
}

func linuxInstall(sys System, s Spec) []Step {
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
		return append(steps, run("systemctl", "enable", SystemdUnitName), run("systemctl", "restart", SystemdUnitName))
	}
	return append(steps, run("systemctl", "enable", "--now", SystemdUnitName))
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
	if !sys.UserExists(s.User) {
		id, err := darwinFreeID(ctx, sys)
		if err != nil {
			return nil, err
		}
		steps = append(steps, darwinUserSteps(s.User, strconv.Itoa(id))...)
	}
	configDir := filepath.Dir(s.ConfigPath)
	installed := sys.Exists(LaunchdPlist)
	steps = append(steps,
		// The config dir stays traversable: the socket dir lives inside it,
		// and credential files inside are 0600.
		mkdir(openDirMode, s.User, configDir),
		mkdir(runtimeDirMode, s.User, config.DefaultSocketDir(goosDarwin)),
		mkdir(configDirMode, s.User, darwinLogDir),
		mkdir(darwinStateDirMode, s.User, config.DefaultStateDir(goosDarwin)),
	)
	steps = append(steps, fileSteps(s)...)
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

func darwinUserSteps(name, id string) []Step {
	userPath, groupPath := "/Users/"+name, "/Groups/"+name
	return []Step{
		run("dscl", ".", "-create", groupPath),
		run("dscl", ".", "-create", groupPath, "PrimaryGroupID", id),
		run("dscl", ".", "-create", userPath),
		run("dscl", ".", "-create", userPath, "UniqueID", id),
		run("dscl", ".", "-create", userPath, "PrimaryGroupID", id),
		run("dscl", ".", "-create", userPath, "UserShell", "/usr/bin/false"),
		run("dscl", ".", "-create", userPath, "NFSHomeDirectory", "/var/empty"),
		run("dscl", ".", "-create", userPath, "RealName", "BasaltDB engine"),
		run("dscl", ".", "-create", userPath, "IsHidden", "1"),
	}
}

// darwinFreeID picks one id free as both a uid and a gid.
func darwinFreeID(ctx context.Context, sys System) (int, error) {
	users, err := sys.Output(ctx, "dscl", ".", "-list", "/Users", "UniqueID")
	if err != nil {
		return 0, fmt.Errorf("list users: %w", err)
	}
	groups, err := sys.Output(ctx, "dscl", ".", "-list", "/Groups", "PrimaryGroupID")
	if err != nil {
		return 0, fmt.Errorf("list groups: %w", err)
	}
	return PickFreeID(users + "\n" + groups)
}

// PickFreeID returns the lowest id in the system-account range that does not
// appear in dscl -list output (lines of "name id").
func PickFreeID(dsclOutput string) (int, error) {
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
	for id := darwinIDMin; id <= darwinIDMax; id++ {
		if !used[id] {
			return id, nil
		}
	}
	return 0, fmt.Errorf("no free system id between %d and %d", darwinIDMin, darwinIDMax)
}

// UninstallPlan returns the steps that stop the service and remove its unit.
// The user, config and credentials stay; basalt init owns them.
func UninstallPlan(s Spec) ([]Step, error) {
	switch s.GOOS {
	case goosLinux:
		return []Step{
			run("systemctl", "disable", "--now", SystemdUnitName),
			{Kind: StepRemove, Path: SystemdUnitPath},
			run("systemctl", "daemon-reload"),
		}, nil
	case goosDarwin:
		return []Step{
			run("launchctl", "bootout", "system/"+LaunchdLabel),
			{Kind: StepRemove, Path: LaunchdPlist},
		}, nil
	}
	return nil, fmt.Errorf("the engine service installs on linux and darwin, not %s", s.GOOS)
}

// Apply prints every step to out, then runs them in order unless dryRun.
func Apply(ctx context.Context, sys System, steps []Step, dryRun bool, out io.Writer) error {
	for _, st := range steps {
		fmt.Fprintln(out, "  "+st.String())
	}
	if dryRun {
		return nil
	}
	for _, st := range steps {
		if err := applyStep(ctx, sys, st); err != nil {
			return fmt.Errorf("%s: %w", st, err)
		}
	}
	return nil
}

func applyStep(ctx context.Context, sys System, st Step) error {
	switch st.Kind {
	case StepRun:
		return sys.Run(ctx, st.Args...)
	case StepWrite:
		mode := st.Mode
		if mode == 0 {
			mode = unitFileMode
		}
		return sys.WriteFile(st.Path, []byte(st.Content), mode, st.Owner)
	case StepMkdir:
		return sys.Mkdir(st.Path, st.Mode, st.Owner)
	case StepRemove:
		err := sys.Remove(st.Path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return fmt.Errorf("unknown step kind %q", st.Kind)
}
