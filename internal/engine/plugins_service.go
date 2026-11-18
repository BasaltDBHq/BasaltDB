package engine

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/user"
	"strconv"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// Why a service engine does not reach a local entry's unit.
const (
	whyNoUnit = "its service unit is not installed, or does not run this entry's verified copy with the isolation this engine " +
		"expects; the person runs sudo basalt service install to write it again"
	whyUnitUser = "its service unit's OS user is missing, root or the engine's own"
)

// maxUnitBytes bounds the unit file the engine reads.
const maxUnitBytes = 64 << 10

// unitSource is how a service engine finds its plugins' units and users;
// tests replace it.
type unitSource struct {
	readUnit   func(path string) ([]byte, error)
	lookupUID  func(name string) (int, error)
	engineUser func() (string, error)
	// checkAgents is plugin.CheckAgentUsers.
	checkAgents func(engineGroup string, agentOSUsers map[string]string) error
}

func osUnitSource() *unitSource {
	return &unitSource{
		readUnit: func(path string) ([]byte, error) {
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			return io.ReadAll(io.LimitReader(f, maxUnitBytes+1))
		},
		lookupUID: func(name string) (int, error) {
			u, err := user.Lookup(name)
			if err != nil {
				return 0, err
			}
			return strconv.Atoi(u.Uid)
		},
		engineUser: func() (string, error) {
			u, err := user.Current()
			if err != nil {
				return "", err
			}
			return u.Username, nil
		},
		checkAgents: plugin.CheckAgentUsers,
	}
}

// serviceTarget is a local entry's unit as a service engine reaches it:
// the socket the unit hands the plugin and the OS user it runs as.
type serviceTarget struct {
	socket string
	uid    uint32
}

// errNoEngineUser: the engine's own OS user cannot be read, so the units it
// expects cannot be rendered.
var errNoEngineUser = errors.New("plugin: the engine's OS user cannot be looked up")

// serviceRefusal is why local entry p, verified as v, cannot be reached by
// this service engine, "" when it can; then ep.targets holds its socket and
// OS user (CONTRACT.md, Plugins, Service units). The installed unit must be
// byte for byte the one this engine would write for the entry and its
// verified copy, so a unit that runs another copy, misses a credential file
// or lost its isolation is never connected to; its OS user must exist and
// be neither root nor the engine's user.
func (ep *enginePlugins) serviceRefusal(p config.Plugin, v plugin.Verified) string {
	k := p.Key()
	entry, local := service.EntryFor(p, v)
	if !local {
		return ""
	}
	names, err := service.NamesFor(ep.o.goos, k.Name, k.Instance)
	if err != nil {
		return whyNoUnit
	}
	if ep.unitHostErr != nil {
		return whyNoUnit
	}
	want, err := service.PluginUnit(ep.unitHost, entry)
	if err != nil {
		return whyNoUnit
	}
	got, err := ep.units().readUnit(names.UnitPath)
	if err != nil || !bytes.Equal(got, []byte(want)) {
		return whyNoUnit
	}
	uid, err := ep.units().lookupUID(names.User)
	if err != nil || uid <= 0 || uid == ep.o.euid {
		return whyUnitUser
	}
	ep.targets[k] = serviceTarget{socket: names.Socket, uid: uint32(uid)}
	return ""
}

// units is the unit source: the options' in tests, the machine's otherwise.
func (ep *enginePlugins) units() *unitSource {
	if ep.o.units != nil {
		return ep.o.units
	}
	return osUnitSource()
}

// initServiceUnits reads, once, what a service engine's plugin units must
// hold: its own OS user (whose group reaches their sockets) and the paths
// they hide, from cfg at configPath.
func (ep *enginePlugins) initServiceUnits(cfg config.Config, configPath string) {
	ep.targets = map[plugin.EntryKey]serviceTarget{}
	name, err := ep.units().engineUser()
	if err != nil {
		ep.unitHostErr = errNoEngineUser
		return
	}
	ep.unitHost = service.HostFor(cfg, ep.o.goos, configPath, name)
}

// checkServiceAgents refuses every local entry when an agent's OS user is
// in the engine's group, which reaches every plugin socket: those entries
// are not started, and status shows PLUGIN_NOT_TRUSTED.
func (ep *enginePlugins) checkServiceAgents(cfg config.Config) {
	if len(ep.targets) == 0 {
		return
	}
	users := make(map[string]string, len(cfg.Agents))
	for _, a := range cfg.Agents {
		users[a.Name] = a.OSUser
	}
	err := ep.units().checkAgents(ep.unitHost.EngineUser, users)
	if err == nil {
		return
	}
	ep.log.Error("local plugins not started: the engine's group would let an agent reach their sockets", "err", err)
	kept := ep.entries[:0]
	for _, e := range ep.entries {
		if _, local := ep.targets[e.Key]; local {
			ep.notTrusted[e.Key] = err
			delete(ep.first, e.Key)
			delete(ep.targets, e.Key)
			continue
		}
		kept = append(kept, e)
	}
	ep.entries = kept
}
