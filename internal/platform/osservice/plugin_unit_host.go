package osservice

import (
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// PluginUnitHost is the plugin units a service engine expects, as the plugin
// service's port (plugin.UnitHost): the engine on one host, run as one OS
// user.
type PluginUnitHost struct {
	host servicespec.PluginHost
}

// NewPluginUnitHost is the unit host of the engine on host
// (plugin.HostFor).
func NewPluginUnitHost(host servicespec.PluginHost) PluginUnitHost {
	return PluginUnitHost{host: host}
}

// EngineUser is the OS user the engine runs as; its group reaches the
// plugins' socket directories.
func (h PluginUnitHost) EngineUser() string { return h.host.EngineUser }

// RenderUnit is the unit local entry e needs: its file and its names. It
// fails when the entry's names or unit cannot be rendered.
func (h PluginUnitHost) RenderUnit(e servicespec.PluginEntry) (pluginmodel.UnitPlan, error) {
	names, err := NamesFor(h.host.GOOS, e.Name, e.Instance)
	if err != nil {
		return pluginmodel.UnitPlan{}, err
	}
	want, err := PluginUnit(h.host, e)
	if err != nil {
		return pluginmodel.UnitPlan{}, err
	}
	return pluginmodel.UnitPlan{File: want, Unit: names.Unit, UnitPath: names.UnitPath, User: names.User, Socket: names.Socket}, nil
}

// UserInGroup says that the plugin's OS user is in the engine's group and how
// to take it out.
func (h PluginUnitHost) UserInGroup(pluginUser string) string {
	return PluginUserInGroup(h.host.GOOS, pluginUser, h.host.EngineUser)
}
