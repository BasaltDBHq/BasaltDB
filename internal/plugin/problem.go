package plugin

import (
	"errors"
	"os/user"
	"path/filepath"
	"slices"
	"sort"

	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
)

// ProblemNotTrusted is the status problem for an entry the engine refused to
// start (CONTRACT.md, Plugins, Problems and errors): its signature, a file's
// hash or a path's permissions failed, or an agent's OS user is in the
// engine's group, which would let it reach plugin sockets.
const ProblemNotTrusted = "PLUGIN_NOT_TRUSTED"

// AgentInGroupError: an agent's OS user is in the engine's group, so it
// could reach plugin sockets. The engine then starts no plugin.
type AgentInGroupError struct {
	// Agent is the first such agent, by name.
	Agent string
}

// Error implements error. It names the agent, so it goes to the engine's
// own log or that agent's status only.
func (e *AgentInGroupError) Error() string {
	return "plugin: the OS user of agent " + e.Agent + " is in the engine's group"
}

// NotTrustedMessage is the message of the PLUGIN_NOT_TRUSTED problem that
// agent's status shows for entry, which the engine refused with err. It
// names the entry and the failed check (VerifyFailure), never a path a
// plugin could have named. It never names another agent: when another
// agent's OS user is in the engine's group, it says so without the name.
func NotTrustedMessage(entry pluginmodel.EntryKey, err error, agent string) string {
	head := "plugin " + entry.String() + " was not started: "
	var ve *pluginmodel.VerifyError
	var ge *AgentInGroupError
	switch {
	case errors.As(err, &ve):
		return head + VerifyFailure(ve)
	case errors.As(err, &ge) && ge.Agent == agent:
		return head + "this agent's OS user is in the engine's group, so it could reach plugin sockets"
	case errors.As(err, &ge):
		return head + "another agent's OS user is in the engine's group, so it could reach plugin sockets"
	default:
		return head + "it could not be verified"
	}
}

// VerifyFailure describes a refused verification for status and the
// engine's log: which check failed, in fixed words. It names the manifest or
// the signature, and any other path only as "a path": a local plugin runs
// in its installed copy, so a file there may carry a name it chose. The
// full path is for basalt plugin check, on the person's terminal.
func VerifyFailure(ve *pluginmodel.VerifyError) string {
	switch filepath.Base(ve.File) {
	case ManifestFile:
		return "its manifest " + ve.Why
	case SignatureFile:
		return "its signature " + ve.Why
	}
	return "a path in its installed copy, on the way to it or in the trust store " + ve.Why
}

// groupLookup reads an OS user's groups. A variable so tests can give a user
// in a group without changing the system's groups.
type groupLookup func(osUser string) (gids []string, err error)

func systemGroups(osUser string) ([]string, error) {
	u, err := user.Lookup(osUser)
	if err != nil {
		return nil, err
	}
	gids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	return append(gids, u.Gid), nil
}

// errGroupLookup: the engine's group or an agent's OS user cannot be looked
// up, so isolation cannot be shown and no plugin starts.
var errGroupLookup = errors.New("plugin: the engine's group or an agent's OS user cannot be looked up")

// CheckAgentUsers refuses when any agent's OS user is in engineGroup, by
// primary or supplementary group: it returns an *AgentInGroupError naming
// the first such agent by name. agentOSUsers maps an agent to its osUser;
// agents with no osUser are skipped. A user or group that cannot be looked
// up fails closed. The engine starts no plugin while this fails, and status
// shows PLUGIN_NOT_TRUSTED.
func CheckAgentUsers(engineGroup string, agentOSUsers map[string]string) error {
	g, err := user.LookupGroup(engineGroup)
	if err != nil {
		return errGroupLookup
	}
	return checkAgentUsers(g.Gid, agentOSUsers, systemGroups)
}

func checkAgentUsers(gid string, agentOSUsers map[string]string, groups groupLookup) error {
	agents := make([]string, 0, len(agentOSUsers))
	for a := range agentOSUsers {
		agents = append(agents, a)
	}
	sort.Strings(agents)
	for _, a := range agents {
		u := agentOSUsers[a]
		if u == "" {
			continue
		}
		gids, err := groups(u)
		if err != nil {
			return errGroupLookup
		}
		if slices.Contains(gids, gid) {
			return &AgentInGroupError{Agent: a}
		}
	}
	return nil
}
