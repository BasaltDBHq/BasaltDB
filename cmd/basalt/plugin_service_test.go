//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
)

// servicePersonUID is the uid the test's person socket reads for every
// peer: the person, never this process's own uid (which it refuses).
const servicePersonUID uint32 = 4242

// serviceFlow is a flow engine turned into a service engine: mode SERVICE,
// the person socket admitting servicePersonUID, and every plugin command
// run as the person without sudo, over that socket.
type serviceFlow struct {
	*flowEngine
}

func newServiceFlow(t *testing.T) *serviceFlow {
	t.Helper()
	f := newFlowEngine(t, mcpcontract.OperatedByPerson)
	raw, err := os.ReadFile(f.configPath)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	m["mode"], m["personUids"] = "SERVICE", []uint32{servicePersonUID}
	raw, err = json.Marshal(m)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(f.configPath, raw, config.FileMode))
	return &serviceFlow{flowEngine: f}
}

// start runs the service engine with the test's peer uid.
func (s *serviceFlow) start() {
	s.t.Helper()
	t := s.t
	cfg, err := config.Load(s.configPath)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var runErr error
	go func() {
		defer close(done)
		runErr = engine.RunWith(ctx, cfg, s.configPath, slog.New(slog.NewTextHandler(s.log, &slog.HandlerOptions{Level: slog.LevelDebug})),
			engine.RestartOptions{PersonPeerUID: func(*net.UnixConn) (uint32, error) { return servicePersonUID, nil }})
	}()
	s.stop = func() {
		cancel()
		<-done
		s.stop = nil
		require.NoError(t, runErr)
	}
	require.Eventually(t, func() bool {
		c, err := net.Dial("unix", config.PersonSocketPath(s.socketDir))
		if err != nil {
			return false
		}
		_ = c.Close()
		return osHost{}.PagesUp(context.Background(), s.origin)
	}, flowWait, 20*time.Millisecond)
}

// plugin runs basalt plugin args as the person (an agent's environment
// when env is agentEnv), without sudo, on a machine where the engine's
// service is installed.
func (s *serviceFlow) plugin(env map[string]string, args ...string) result {
	s.t.Helper()
	var stdout, stderr bytes.Buffer
	c := newIO(context.Background(), stdio{in: strings.NewReader(""), out: &stdout, err: &stderr}, func(k string) string { return env[k] })
	c.engine = engineAccess{unitInstalled: func() bool { return true }, personSocket: config.PersonSocketPath(s.socketDir), configPath: s.configPath}
	code := runPlugin(c, append(args, "--config", s.configPath))
	return result{code, stdout.String(), stderr.String()}
}

// TestServiceModeCommandsUseThePersonSocket: in service mode, run without
// sudo, add, approve, list, enable, disable and remove go through the
// person socket: an agent's add opens an approval, nothing is written to
// engine.json, and turning it off ends the approval.
func TestServiceModeCommandsUseThePersonSocket(t *testing.T) {
	s := newServiceFlow(t)
	s.start()
	before, err := os.ReadFile(s.configPath)
	require.NoError(t, err)

	r := s.plugin(agentEnv, "add", s.source("1.0.0"), "--agents", "product_a,product_b", "--json")
	_, a := s.opened(r)
	require.True(t, strings.HasPrefix(a.URL, s.origin+"/plugins/"+a.ApprovalID+"#s="), "a short link on the engine's local pages: %s", a.URL)
	req, b := s.pageRequest(a)
	require.Equal(t, "UNKNOWN", b.Signer)

	after, err := os.ReadFile(s.configPath)
	require.NoError(t, err)
	require.Equal(t, before, after, "engine.json is untouched")

	r = s.plugin(agentEnv, "list", "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, `"source": "ENGINE"`)
	require.Contains(t, r.stdout, `"state": "PENDING"`)
	// Isolation and health are what the engine reports over the socket.
	var listed struct {
		Plugins []struct {
			Health    string `json:"health"`
			Isolation struct {
				Files, Network string
			} `json:"isolation"`
		} `json:"plugins"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &listed), r.stdout)
	require.Len(t, listed.Plugins, 1)
	require.Equal(t, person.HealthNotStarted, listed.Plugins[0].Health, "not approved yet")
	require.Equal(t, "NONE", listed.Plugins[0].Isolation.Files)
	require.Equal(t, "NOT_ENFORCED", listed.Plugins[0].Isolation.Network)
	r = s.plugin(agentEnv, "list")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, "isolation files NONE, network NOT_ENFORCED  health NOT_STARTED\n")

	// The person pastes the page's code; the agent relays it.
	r = s.plugin(agentEnv, "approve", s.paste(req), "--json")
	require.Equal(t, exitOK, r.code, r.stdout+r.stderr)
	require.Contains(t, r.stdout, `"status": "APPROVED"`)

	// The wait reads what the engine serves through PLUGIN_LIST.
	r = s.plugin(agentEnv, "enable", "acme-ner", "--approval-id", a.ApprovalID, "--wait", "3", "--json")
	var w waitResult
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &w), r.stdout+r.stderr)
	require.Contains(t, []string{waitRunning, waitNotRunning}, w.State, "signed: running, or not run on this machine")

	r = s.plugin(agentEnv, "disable", "acme-ner")
	require.Equal(t, exitOK, r.code, r.stderr)
	r = s.plugin(agentEnv, "list", "--json")
	require.Contains(t, r.stdout, `"enabled": false`)
	require.Contains(t, r.stdout, `"state": "ENDED"`)

	// Turning it on again opens a new approval: the old one never serves.
	r = s.plugin(agentEnv, "enable", "acme-ner", "--json")
	_, again := s.opened(r)
	require.NotEqual(t, a.ApprovalID, again.ApprovalID)

	r = s.plugin(agentEnv, "remove", "acme-ner")
	require.Equal(t, exitOK, r.code, r.stderr)
	r = s.plugin(agentEnv, "list", "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.NotContains(t, r.stdout, "acme-ner")
	after, err = os.ReadFile(s.configPath)
	require.NoError(t, err)
	require.Equal(t, before, after, "engine.json is untouched")
	_, err = os.Stat(filepath.Join(s.base, "config", "plugins"))
	require.ErrorIs(t, err, os.ErrNotExist, "nothing in the config directory's plugin root")
}

// TestSocketWaitStates: the service-mode wait reads PLUGIN_LIST: RUNNING
// only when every agent an approval names is served READY on it; pending,
// replaced and ended approvals are told apart, and an agent whose state
// could not be read decides nothing.
func TestSocketWaitStates(t *testing.T) {
	id, other := uuid.New(), uuid.New()
	listed := func(states map[string]string, ids map[string]uuid.UUID, serving ...person.PluginServing) *person.PluginListed {
		l := &person.PluginListed{Serving: serving}
		for _, a := range []string{"a", "b"} {
			st := person.PluginAgentStatus{Agent: a, State: states[a]}
			if x, ok := ids[a]; ok {
				st.ApprovalID = &x
			}
			l.Approval.Agents = append(l.Approval.Agents, st)
		}
		return l
	}
	both := map[string]uuid.UUID{"a": id, "b": id}

	l := listed(map[string]string{"a": stateApproved, "b": stateApproved}, both,
		person.PluginServing{Agent: "a", ApprovalID: &id, Ready: true}, person.PluginServing{Agent: "b", ApprovalID: &id, Ready: true})
	ws, signed, open := socketWaitStates([]uuid.UUID{id}, l)
	require.True(t, signed)
	require.True(t, open)
	require.True(t, socketServedOn(l, ws))

	// Served on another approval, or not READY: not running yet.
	l.Serving[1].ApprovalID = &other
	require.False(t, socketServedOn(l, ws))
	l.Serving[1].ApprovalID, l.Serving[0].Ready = &id, false
	require.False(t, socketServedOn(l, ws))

	_, signed, open = socketWaitStates([]uuid.UUID{id}, listed(map[string]string{"a": stateApproved, "b": statePending}, both))
	require.False(t, signed)
	require.True(t, open)
	_, signed, open = socketWaitStates([]uuid.UUID{id}, listed(map[string]string{"a": stateEnded, "b": stateEnded}, both))
	require.False(t, signed)
	require.False(t, open)
	// Replaced: no agent's newest is it any more.
	ws, _, open = socketWaitStates([]uuid.UUID{id}, listed(map[string]string{"a": statePending, "b": statePending}, map[string]uuid.UUID{"a": other, "b": other}))
	require.False(t, open)
	require.Equal(t, stateCancelled, ws[0].State)
	// An agent not read decides nothing.
	ws, signed, open = socketWaitStates([]uuid.UUID{id}, listed(map[string]string{"a": stateUnavailable, "b": stateUnavailable}, nil))
	require.False(t, signed)
	require.True(t, open)
	require.Equal(t, stateNone, ws[0].State)
}
