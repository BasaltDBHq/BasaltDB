package osservice

import (
	"errors"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// PluginUnitHost is the plugin units a service engine expects, as the plugin
// host's port (engine.UnitHost): the engine configured by one config, run as
// one OS user.
type PluginUnitHost struct {
	host PluginHost
	goos string
}

// NewPluginUnitHost is the unit host of the engine configured by cfg (at
// configPath, on goos), run as engineUser.
func NewPluginUnitHost(cfg config.Config, goos, configPath, engineUser string) PluginUnitHost {
	return PluginUnitHost{host: HostFor(cfg, goos, configPath, engineUser), goos: goos}
}

// EngineUser is the OS user the engine runs as; its group reaches the
// plugins' socket directories.
func (h PluginUnitHost) EngineUser() string { return h.host.EngineUser }

// Plan is the unit local entry p needs, verified as v. local is false for a
// remote entry, which has no unit. It fails when the entry's names or unit
// cannot be rendered, or when another of allKeys would share its OS user.
func (h PluginUnitHost) Plan(p config.Plugin, v pluginmodel.Verified, allKeys []pluginmodel.EntryKey) (plan pluginmodel.UnitPlan, local bool, err error) {
	entry, local := EntryFor(p, v)
	if !local {
		return pluginmodel.UnitPlan{}, false, nil
	}
	k := p.Key()
	names, err := NamesFor(h.goos, k.Name, k.Instance)
	if err != nil {
		return pluginmodel.UnitPlan{}, true, err
	}
	if UserClash(k.Name, k.Instance, allKeys) != nil {
		// Two entries would share an OS user, socket and directory.
		return pluginmodel.UnitPlan{}, true, errUserClash
	}
	want, err := PluginUnit(h.host, entry)
	if err != nil {
		return pluginmodel.UnitPlan{}, true, err
	}
	return pluginmodel.UnitPlan{File: want, Unit: names.Unit, UnitPath: names.UnitPath, User: names.User, Socket: names.Socket}, true, nil
}

// UserInGroup says that the plugin's OS user is in the engine's group and how
// to take it out.
func (h PluginUnitHost) UserInGroup(pluginUser string) string {
	return PluginUserInGroup(h.goos, pluginUser, h.host.EngineUser)
}

var errUserClash = errors.New("two plugin entries would share an OS user")
