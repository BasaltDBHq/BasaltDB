package plugin

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/user"
	"strconv"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// Why a service engine does not reach a local entry's unit.
const (
	whyNoUnit = "its service unit is not installed, or does not run this entry's verified copy with the isolation this engine " +
		"expects; the person runs sudo basalt service install to write it again"
	whyUnitUser = "its service unit's OS user is missing, root or the engine's own"
	// whyUnitOverridden: a drop-in or a unit file systemd reads first would
	// change what the unit runs beyond the file the engine compared.
	whyUnitOverridden = "a systemd drop-in or another unit file of the same name changes its service unit; " +
		"the person removes it or masks it with a link to /dev/null of the same name in /etc/systemd/system (systemctl cat names it)"
	whyNoEngineGroup = "the engine's group cannot be looked up, so its socket directory cannot be checked"
	whyUserGroups    = "the groups of its service unit's OS user cannot be read, so it cannot be checked"
	whyUnitUserMoved = "its service unit's OS user or the engine's group is not the one the engine started with; " +
		"the engine reaches it again after a restart"
	// whySocketDir follows a not-ready entry whose socket directory changed.
	whySocketDir = "its socket directory is no longer the plugin user's, in the engine's group and closed to others; " +
		"the person runs sudo basalt service install to make it again"
	// whyNoSocket follows a not-ready entry whose unit never made its socket.
	whyNoSocket = "nothing listens on its socket: in service mode a plugin must listen on the socket " +
		"BASALT_PLUGIN_SOCKET names (a plugin built with the Go SDK does); one that only reads stdin never starts there"
)

// maxUnitBytes bounds the unit file the engine reads.
const maxUnitBytes = 64 << 10

// UnitSource is how a service engine finds its plugins' units and users;
// tests replace it.
type UnitSource struct {
	ReadUnit   func(path string) ([]byte, error)
	LookupUID  func(name string) (int, error)
	EngineUser func() (string, error)
	// checkAgents is CheckAgentUsers.
	CheckAgents func(engineGroup string, agentOSUsers map[string]string) error
	// inGroup is service.InGroup: whether an OS user is in a group.
	InGroup func(name, group string) (bool, error)
	// lookupGID is a group's id.
	LookupGID func(group string) (int, error)
	// overrides is service.SystemdOverridesOnMachine (Linux only).
	Overrides func(unit string) ([]string, error)
}

func osUnitSource(p Ports) *UnitSource {
	return &UnitSource{
		ReadUnit: func(path string) ([]byte, error) {
			f, err := os.Open(path)
			if err != nil {
				return nil, err
			}
			defer f.Close()
			return io.ReadAll(io.LimitReader(f, maxUnitBytes+1))
		},
		LookupUID: func(name string) (int, error) {
			u, err := user.Lookup(name)
			if err != nil {
				return 0, err
			}
			return strconv.Atoi(u.Uid)
		},
		EngineUser: func() (string, error) {
			u, err := user.Current()
			if err != nil {
				return "", err
			}
			return u.Username, nil
		},
		CheckAgents: CheckAgentUsers,
		InGroup:     p.InGroup,
		LookupGID: func(group string) (int, error) {
			g, err := user.LookupGroup(group)
			if err != nil {
				return 0, err
			}
			return strconv.Atoi(g.Gid)
		},
		Overrides: p.SystemdOverrides,
	}
}

// serviceTarget is a local entry's unit as a service engine reaches it:
// the socket the unit hands the plugin, the OS user it runs as and the
// engine's group, which its socket directory must have.
type serviceTarget struct {
	socket string
	uid    uint32
	gid    uint32
}

const goosDarwin = "darwin"

// errNoEngineUser: the engine's own OS user cannot be read, so the units it
// expects cannot be rendered.
var errNoEngineUser = errors.New("plugin: the engine's OS user cannot be looked up")

// serviceRefusal is why local entry p, verified as v, cannot be reached by
// this service engine, "" when it can; then ep.targets holds its socket and
// OS user (CONTRACT.md, Plugins, Service units). The installed unit must be
// byte for byte the one this engine would write for the entry and its
// verified copy, so a unit that runs another copy, misses a credential file
// or lost its isolation is never connected to; on Linux no drop-in or unit
// file systemd reads first may change it; its OS user must exist, be
// neither root nor the engine's user and not be in the engine's group.
func (ep *Plugins) serviceRefusal(p config.Plugin, v pluginmodel.Verified) string {
	t, why := ep.unitTarget(p, v)
	if why == "" {
		ep.targets[p.Key()] = t
	}
	return why
}

// unitTarget checks local entry p's installed unit against verified copy v
// (serviceRefusal) and returns how to reach it, or why it cannot be. The
// engine runs it at start and again before every connection, so a unit
// changed while the engine runs is caught when the plugin is next reached:
// a changed unit takes effect only when its process starts again, which
// drops the engine's connection.
func (ep *Plugins) unitTarget(p config.Plugin, v pluginmodel.Verified) (serviceTarget, string) {
	if v.Manifest.Endpoint.Local == nil {
		// A remote entry has no unit.
		return serviceTarget{}, ""
	}
	if ep.unitHostErr != nil || ep.unitHost == nil {
		return serviceTarget{}, whyNoUnit
	}
	// The plan fails when the entry's names or unit cannot be rendered, or
	// when two entries would share an OS user, socket and directory.
	names, err := ep.planUnit(p, v)
	if err != nil {
		return serviceTarget{}, whyNoUnit
	}
	src := ep.units()
	got, err := src.ReadUnit(names.UnitPath)
	if err != nil || !bytes.Equal(got, []byte(names.File)) {
		return serviceTarget{}, whyNoUnit
	}
	if ep.o.goos != goosDarwin {
		if found, err := src.Overrides(names.Unit); err != nil || len(found) > 0 {
			return serviceTarget{}, whyUnitOverridden
		}
	}
	uid, err := src.LookupUID(names.User)
	if err != nil || uid <= 0 || uid == ep.o.euid {
		return serviceTarget{}, whyUnitUser
	}
	group := ep.unitHost.EngineUser()
	in, err := src.InGroup(names.User, group)
	if err != nil {
		return serviceTarget{}, whyUserGroups
	}
	if in {
		return serviceTarget{}, ep.unitHost.UserInGroup(names.User)
	}
	gid, err := src.LookupGID(group)
	if err != nil || gid <= 0 {
		return serviceTarget{}, whyNoEngineGroup
	}
	return serviceTarget{socket: names.Socket, uid: uint32(uid), gid: uint32(gid)}, ""
}

// dialFailure is what status adds for a failed connection to a service
// entry, "" when its cause needs no words.
func dialFailure(dialer Dialer, err error) string {
	switch {
	case dialer.NoSocket(err):
		return whyNoSocket
	case dialer.SocketDir(err):
		return whySocketDir
	}
	return ""
}

// recheckUnit runs unitTarget again before a connection to local entry k,
// verified as v, that start reached as t. When the unit or its OS user
// changed since, the entry is refused (status shows why) and not reached.
func (ep *Plugins) recheckUnit(k pluginmodel.EntryKey, v pluginmodel.Verified, t serviceTarget) error {
	now, why := ep.unitTarget(ep.configuredEntry(k), v)
	if why == "" && (now.uid != t.uid || now.gid != t.gid) {
		why = whyUnitUserMoved
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	if why == "" {
		delete(ep.refused, k)
		return nil
	}
	ep.refused[k] = why
	return errors.New("plugin " + k.String() + ": " + why)
}

// units is the unit source: the options' in tests, the machine's otherwise.
func (ep *Plugins) units() *UnitSource {
	if ep.o.units != nil {
		return ep.o.units
	}
	return osUnitSource(ep.o.Ports)
}

// dialer is the options' dialer, which New requires.
func (ep *Plugins) dialer() Dialer { return ep.o.Dialer }

// initServiceUnits reads, once, what a service engine's plugin units must
// hold: its own OS user (whose group reaches their sockets) and the paths
// they hide, from cfg at configPath.
func (ep *Plugins) initServiceUnits(cfg config.Config, configPath string) {
	ep.targets = map[pluginmodel.EntryKey]serviceTarget{}
	for _, p := range cfg.Plugins {
		ep.allKeys = append(ep.allKeys, p.Key())
	}
	name, err := ep.units().EngineUser()
	if err != nil {
		ep.unitHostErr = errNoEngineUser
		return
	}
	ep.unitHost = ep.o.Ports.NewUnitHost(HostFor(cfg, ep.o.goos, configPath, name))
}

// checkServiceAgents refuses every local entry when an agent's OS user is
// in the engine's group, which reaches every plugin socket: those entries
// are not started, and status shows PLUGIN_NOT_TRUSTED.
func (ep *Plugins) checkServiceAgents(cfg config.Config) {
	if len(ep.targets) == 0 {
		return
	}
	users := make(map[string]string, len(cfg.Agents))
	for _, a := range cfg.Agents {
		users[a.Name] = a.OSUser
	}
	err := ep.units().CheckAgents(ep.unitHost.EngineUser(), users)
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
