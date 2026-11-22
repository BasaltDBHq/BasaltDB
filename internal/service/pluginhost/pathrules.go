package pluginhost

import (
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// PathRules is the port for the path rule: who may write the directories and
// files the host trusts (CONTRACT.md, Plugins, Where plugins live). The rule
// reads the file system, so an outbound adapter (adapter/outbound/pluginpath)
// implements it and the app installs it with UsePathRules.
type PathRules interface {
	// Owner is the uid the rule requires for mode.
	Owner(mode Mode) (uint32, error)
	// CurrentUID is the engine's own uid.
	CurrentUID() (uint32, error)
	// NoFollowFlags are the flags to open a file without following a symlink.
	NoFollowFlags() int
	// RuleRefusal is a refusal for who can write path, with what was found.
	RuleRefusal(path, why string, kind PathFaultKind, fi fs.FileInfo, owners ...uint32) *VerifyError
	CheckAbove(base string, owner uint32) error
	CheckStrict(p string, owner uint32) (fs.FileInfo, error)
	CheckStrictInfo(p string, fi fs.FileInfo, owner uint32) error
	CheckUnder(owner uint32, dirs ...string) error
	CheckSocketBase(dir string) error
	CheckSocketBaseInfo(dir string, fi fs.FileInfo) error
}

type rulesHolder struct{ r PathRules }

var rulesInUse atomic.Pointer[rulesHolder]

// UsePathRules installs the path rule. Until it is called every check
// refuses: the host never trusts a path without the rule.
func UsePathRules(r PathRules) { rulesInUse.Store(&rulesHolder{r: r}) }

func rules() PathRules {
	if h := rulesInUse.Load(); h != nil && h.r != nil {
		return h.r
	}
	return refusingRules{}
}

// errNoPathRules is what every check returns while no rule is installed.
var errNoPathRules = pathRefusal("", "cannot be checked: no path rule is installed")

// refusingRules refuses every check; it stands in until UsePathRules.
type refusingRules struct{}

func (refusingRules) Owner(Mode) (uint32, error)  { return 0, errNoPathRules }
func (refusingRules) CurrentUID() (uint32, error) { return 0, errNoPathRules }
func (refusingRules) NoFollowFlags() int          { return os.O_RDONLY }
func (refusingRules) RuleRefusal(path, why string, _ PathFaultKind, _ fs.FileInfo, _ ...uint32) *VerifyError {
	return pathRefusal(path, why)
}
func (refusingRules) CheckAbove(string, uint32) error { return errNoPathRules }
func (refusingRules) CheckStrict(string, uint32) (fs.FileInfo, error) {
	return nil, errNoPathRules
}
func (refusingRules) CheckStrictInfo(string, fs.FileInfo, uint32) error { return errNoPathRules }
func (refusingRules) CheckUnder(uint32, ...string) error                { return errNoPathRules }
func (refusingRules) CheckSocketBase(string) error                      { return errNoPathRules }
func (refusingRules) CheckSocketBaseInfo(string, fs.FileInfo) error     { return errNoPathRules }

var (
	pathRefusal = pluginmodel.PathRefusal

	ruleRefusal = func(path, why string, kind PathFaultKind, fi fs.FileInfo, owners ...uint32) *VerifyError {
		return rules().RuleRefusal(path, why, kind, fi, owners...)
	}
	checkAbove      = func(base string, owner uint32) error { return rules().CheckAbove(base, owner) }
	checkStrict     = func(p string, owner uint32) (fs.FileInfo, error) { return rules().CheckStrict(p, owner) }
	checkStrictInfo = func(p string, fi fs.FileInfo, owner uint32) error { return rules().CheckStrictInfo(p, fi, owner) }
	checkUnder      = func(owner uint32, dirs ...string) error { return rules().CheckUnder(owner, dirs...) }
	currentUID      = func() (uint32, error) { return rules().CurrentUID() }
)

func noFollowFlags() int { return rules().NoFollowFlags() }

func requiredOwner(mode Mode) (uint32, error) { return rules().Owner(mode) }

// CheckSocketBase applies the path rule to a socket base directory.
func CheckSocketBase(dir string) error { return rules().CheckSocketBase(dir) }

// CheckSocketBaseInfo is CheckSocketBase's rule for dir alone, judged from fi.
func CheckSocketBaseInfo(dir string, fi fs.FileInfo) error {
	return rules().CheckSocketBaseInfo(dir, fi)
}

// The root-owned base directory of plugins in service mode, per OS. It holds
// the installed copies and the trust store side by side. The config directory
// is not used in service mode: it may belong to the engine's OS user, which
// must not be able to change what is installed or trusted.
const (
	linuxServiceBase  = "/opt/basalt"
	darwinServiceBase = "/Library/Basalt"
	goosDarwin        = "darwin"
)

// base is the directory the plugin root and the trust store sit in: the
// service base per OS in service mode, the config directory (the directory
// that holds engine.json) in same-user mode. Another mode is refused.
func base(mode Mode, goos, configDir string) (string, error) {
	switch mode {
	case pluginmodel.ModeService:
		if goos == goosDarwin {
			return darwinServiceBase, nil
		}
		return linuxServiceBase, nil
	case pluginmodel.ModeSameUser, "":
		return configDir, nil
	default:
		return "", pluginmodel.ErrUnknownMode
	}
}

// Root is the directory installed copies live under: /opt/basalt/plugins on
// Linux and /Library/Basalt/plugins on macOS in service mode,
// <configDir>/plugins in same-user mode.
func Root(mode Mode, goos, configDir string) (string, error) {
	b, err := base(mode, goos, configDir)
	if err != nil {
		return "", err
	}
	return filepath.Join(b, pluginmodel.PluginsDirName), nil
}

// TrustDir is the trust store's directory, next to Root:
// /opt/basalt/plugin-trust on Linux and /Library/Basalt/plugin-trust on macOS
// in service mode, <configDir>/plugin-trust in same-user mode.
func TrustDir(mode Mode, goos, configDir string) (string, error) {
	b, err := base(mode, goos, configDir)
	if err != nil {
		return "", err
	}
	return filepath.Join(b, pluginmodel.TrustDirName), nil
}
