package plugin

import (
	"errors"
	"path/filepath"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// goosLinux is the other OS plugin units run on (goosDarwin is in
// plugins_service.go).
const goosLinux = "linux"

var errUserClash = errors.New("two plugin entries would share an OS user")

// HostFor is the plugin host of the engine configured by cfg (at
// configPath, on goos), run as engineUser: what its plugin units hide.
func HostFor(cfg config.Config, goos, configPath, engineUser string) servicespec.PluginHost {
	h := servicespec.PluginHost{
		GOOS: goos, EngineUser: engineUser, ConfigDir: filepath.Dir(configPath),
		StateDir: cfg.StateDirFor(goos), SocketDir: cfg.SocketDir,
	}
	if h.SocketDir == "" {
		h.SocketDir = config.DefaultSocketDir(goos)
	}
	// Every agent's credential file. A remote entry's auth.credentialFile is
	// not listed: the engine reads it only when it is the engine user's
	// alone (mode 0600 or narrower), so no plugin user can, and listing it
	// would make adding a remote entry change every local entry's unit.
	for _, a := range cfg.Agents {
		h.CredentialFiles = append(h.CredentialFiles, a.Store.CredentialFile)
	}
	return h
}

// EntryFor is config entry p, its installed copy verified as v, as its
// unit runs it; false for a remote entry, which has no unit.
func EntryFor(p config.Plugin, v pluginmodel.Verified) (servicespec.PluginEntry, bool) {
	l := v.Manifest.Endpoint.Local
	if l == nil {
		return servicespec.PluginEntry{}, false
	}
	k := p.Key()
	e := servicespec.PluginEntry{
		Name: k.Name, Instance: k.Instance, Dir: v.Dir, Command: l.Command, Args: l.Args,
		Egress: v.Manifest.Network.Egress, Enabled: p.Enabled,
	}
	if r := v.Manifest.Resources; r != nil {
		e.MemoryMB = r.MemoryMB
	}
	return e, true
}

// UserClash is the first other entry in others whose OS user is the same
// as entry (name, instance)'s on Linux or macOS, or nil. Two entries never
// share a user: basalt plugin add refuses one that would.
func UserClash(name, instance string, others []pluginmodel.EntryKey) *pluginmodel.EntryKey {
	for _, o := range others {
		if o.Name == name && o.Instance == instance {
			continue
		}
		for _, goos := range []string{goosLinux, goosDarwin} {
			if servicespec.PluginUser(goos, o.Name, o.Instance) == servicespec.PluginUser(goos, name, instance) {
				return &o
			}
		}
	}
	return nil
}

// planUnit is the unit local entry p needs, verified as v; a remote entry
// has none. It fails when the entry's names or unit cannot be rendered, or
// when another configured entry would share its OS user.
func (ep *Plugins) planUnit(p config.Plugin, v pluginmodel.Verified) (pluginmodel.UnitPlan, error) {
	entry, local := EntryFor(p, v)
	if !local {
		return pluginmodel.UnitPlan{}, nil
	}
	k := p.Key()
	if UserClash(k.Name, k.Instance, ep.allKeys) != nil {
		// Two entries would share an OS user, socket and directory.
		return pluginmodel.UnitPlan{}, errUserClash
	}
	return ep.unitHost.RenderUnit(entry)
}

// PluginNetwork is how a local entry's network is recorded on goos in
// service mode: ENFORCED with an empty egress on Linux (it runs without
// network), DECLARED with a non-empty one, NOT_ENFORCED on macOS.
func PluginNetwork(goos string, egress []string) string {
	switch {
	case goos == goosDarwin:
		return "NOT_ENFORCED"
	case len(egress) == 0:
		return "ENFORCED"
	}
	return "DECLARED"
}
