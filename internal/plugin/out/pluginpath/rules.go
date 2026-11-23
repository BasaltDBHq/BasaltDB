package pluginpath

import (
	"io/fs"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// Rules is the path rule as the plugin host's port (plugin.PathRules):
// each method is the package function of the same name.
type Rules struct{}

func (Rules) Owner(m pluginmodel.Mode) (uint32, error) { return Owner(m) }
func (Rules) CurrentUID() (uint32, error)              { return CurrentUID() }
func (Rules) NoFollowFlags() int                       { return NoFollowFlags }
func (Rules) RuleRefusal(path, why string, kind pluginmodel.PathFaultKind, fi fs.FileInfo, owners ...uint32) *pluginmodel.VerifyError {
	return RuleRefusal(path, why, kind, fi, owners...)
}
func (Rules) CheckAbove(base string, owner uint32) error { return CheckAbove(base, owner) }
func (Rules) CheckStrict(p string, owner uint32) (fs.FileInfo, error) {
	return CheckStrict(p, owner)
}

func (Rules) CheckStrictInfo(p string, fi fs.FileInfo, owner uint32) error {
	return CheckStrictInfo(p, fi, owner)
}
func (Rules) CheckUnder(owner uint32, dirs ...string) error { return CheckUnder(owner, dirs...) }
func (Rules) CheckSocketBase(dir string) error              { return CheckSocketBase(dir) }
func (Rules) CheckSocketBaseInfo(dir string, fi fs.FileInfo) error {
	return CheckSocketBaseInfo(dir, fi)
}
