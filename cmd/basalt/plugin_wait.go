package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// Waiting for a plugin to run (CONTRACT.md, Plugin approval commands, The
// wait), in the manner of write's waitForApproval: by default add and
// enable hand the link over at once; the agent shows it, then runs enable
// with --approval-id in the same turn, which returns as soon as the running
// engine serves the plugin on that approval, or when the wait ends.
const (
	// maxWaitSeconds bounds --wait: an agent's client moves a command still
	// running after about 2 minutes to the background.
	maxWaitSeconds = 110
	// defaultRepeatWait is --wait's default with --approval-id.
	defaultRepeatWait = 90
	// waitPoll is how often the wait reads the approvals and the engine's
	// state.
	waitPoll = time.Second
)

// What a wait found (api/plugin/approval/wait.schema.json, state).
const (
	waitRunning    = "RUNNING"
	waitWaiting    = "WAITING"
	waitNotRunning = "NOT_RUNNING"
	waitEnded      = "ENDED"
)

// waitResult is basalt plugin enable --approval-id --json, and add or enable
// with --wait when the plugin runs before the wait ends.
type waitResult struct {
	Name          string         `json:"name"`
	Instance      string         `json:"instance"`
	State         string         `json:"state"`
	Approvals     []waitApproval `json:"approvals"`
	PersonMessage string         `json:"personMessage"`
	NextSteps     []mcp.NextStep `json:"nextSteps"`
}

// waitApproval is one approval's state, with the entry's agents it names.
type waitApproval struct {
	ApprovalID string   `json:"approvalId"`
	State      string   `json:"state"`
	Agents     []string `json:"agents"`
}

// waitFlag is --wait: seconds, from 0 to maxWaitSeconds; -1 when not given.
func waitFlag(s int) error {
	if s < -1 || s > maxWaitSeconds {
		return fmt.Errorf("%w: --wait is seconds from 0 to %d", errUsage, maxWaitSeconds)
	}
	return nil
}

// parseApprovalIDs is --approval-id: one or more approval ids, comma
// separated.
func parseApprovalIDs(s string) ([]uuid.UUID, error) {
	var out []uuid.UUID
	for _, part := range splitList(s) {
		id, err := uuid.Parse(part)
		if err != nil {
			return nil, fmt.Errorf("%w: --approval-id takes the approvalId values add or enable printed, comma separated", errUsage)
		}
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: --approval-id takes at least one approvalId", errUsage)
	}
	return out, nil
}

// waitCommand is the command that waits for entry k's approvals ids.
func (e *pluginEnv) waitCommand(k plugin.EntryKey, ids []uuid.UUID) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, id.String())
	}
	return e.command("enable", append(entryArgs(k), "--approval-id", strings.Join(parts, ","), "--json")...)
}

// waitAgent is one listed agent's connection for the wait.
type waitAgent struct {
	name string
	conn *pgx.Conn
}

// waitForRunning waits up to d for entry k to run on approvals ids: every
// approval signed, and the running engine serving the entry, READY, to each
// listed agent an approval names, on that approval. It opens nothing and
// writes nothing. It returns at once when an approval is no longer open,
// or when they are all signed and the engine is not running.
func (e *pluginEnv) waitForRunning(k plugin.EntryKey, ids []uuid.UUID, d time.Duration) (waitResult, error) {
	// engine.json as it is now: add and enable wrote the entry after the
	// command read it.
	ec, err := loadEngineConfig(e.c, e.configPath)
	if err != nil {
		return waitResult{}, err
	}
	e.cfg = ec.Config
	p, err := e.entry(k)
	if err != nil {
		return waitResult{}, err
	}
	if !e.cfg.PluginRequiresApproval(p) {
		return waitResult{}, fmt.Errorf("%w: plugin %s does not require approval, so there is no approval to wait for", errUsage, k)
	}
	var agents []waitAgent
	defer func() {
		for _, a := range agents {
			_ = a.conn.Close(context.WithoutCancel(e.c.ctx))
		}
	}()
	for _, name := range p.Agents {
		conn, err := e.connectAgent(name)
		if err != nil {
			continue // its database is down: its approvals stay unknown
		}
		agents = append(agents, waitAgent{name: name, conn: conn})
	}
	deadline := e.c.now().Add(d)
	for {
		approvals, signed, open := e.readWaitApprovals(k, ids, agents)
		eng := runningEngine(e.cfg.SocketDir)
		switch {
		case !open:
			return e.waitOutcome(k, waitEnded, approvals, eng)
		case signed && e.servedOn(k, approvals, eng):
			return e.waitOutcome(k, waitRunning, approvals, eng)
		case signed && !eng.Reachable && !eng.Unknown:
			return e.waitOutcome(k, waitNotRunning, approvals, eng)
		}
		if !e.c.now().Add(waitPoll).Before(deadline) {
			state := waitWaiting
			if signed {
				state = waitNotRunning
			}
			return e.waitOutcome(k, state, approvals, eng)
		}
		select {
		case <-e.c.ctx.Done():
			return waitResult{}, e.c.ctx.Err()
		case <-time.After(waitPoll):
		}
	}
}

// readWaitApprovals reads each approval through the listed agents'
// connections: its state, and the agents it names. signed: all are signed
// and not ended for an agent they name; open: none expired, was replaced,
// ended or is unknown to every listed agent.
func (e *pluginEnv) readWaitApprovals(k plugin.EntryKey, ids []uuid.UUID, agents []waitAgent) ([]waitApproval, bool, bool) {
	out := make([]waitApproval, 0, len(ids))
	signed, open := true, true
	// The newest approval of the entry naming each agent: the one the engine
	// decides by.
	newest := map[string]uuid.UUID{}
	for _, a := range agents {
		ctx, cancel := context.WithTimeout(e.c.ctx, databaseTimeout)
		recs, err := guard.ReadPluginApprovals(ctx, a.conn)
		cancel()
		if err != nil {
			continue
		}
		for _, r := range recs {
			if r.Name == k.Name && r.Instance == k.Instance {
				newest[a.name] = r.ApprovalID
			}
		}
	}
	for _, id := range ids {
		w := waitApproval{ApprovalID: id.String(), State: stateNone, Agents: []string{}}
		for _, a := range agents {
			ctx, cancel := context.WithTimeout(e.c.ctx, databaseTimeout)
			rec, ok, err := guard.ReadPluginApproval(ctx, a.conn, id)
			cancel()
			if err != nil || !ok || rec.Name != k.Name || rec.Instance != k.Instance || !rec.NamesCaller {
				continue
			}
			w.Agents = append(w.Agents, a.name)
			switch {
			case newest[a.name] != id:
				w.State = stateCancelled // a newer approval decides for this agent
			case w.State == stateCancelled:
			case rec.Status == guard.PluginApprovalStatusApproved && rec.Ended():
				w.State = stateEnded
			case w.State == stateEnded:
			case rec.Status == guard.PluginApprovalStatusApproved:
				w.State = stateApproved
			case rec.Status == guard.PluginApprovalStatusPending && e.c.now().Before(rec.ExpiresAt):
				w.State = statePending
			case rec.Status == guard.PluginApprovalStatusCancelled:
				w.State = stateCancelled
			default:
				w.State = stateExpired
			}
		}
		switch w.State {
		case stateApproved:
		case statePending:
			signed = false
		default:
			signed, open = false, false
		}
		out = append(out, w)
	}
	return out, signed, open
}

// stateCancelled: a newer approval for the entry replaced it.
const stateCancelled = "CANCELLED"

// servedOn reports whether the running engine serves entry k, READY, to
// every agent an approval names, on that approval: its state file says so
// and was written by the engine that holds the engine lock now.
func (e *pluginEnv) servedOn(k plugin.EntryKey, approvals []waitApproval, eng engineOut) bool {
	if !eng.Reachable {
		return false
	}
	st, err := engine.ReadPluginServing(e.cfg.StateDirFor(e.c.goos))
	if err != nil || st.EnginePID != eng.PID {
		return false
	}
	i := slices.IndexFunc(st.Entries, func(s engine.PluginServingEntry) bool { return s.Name == k.Name && s.Instance == k.Instance })
	if i < 0 || !st.Entries[i].Ready {
		return false
	}
	served := st.Entries[i].Agents
	for _, a := range approvals {
		for _, name := range a.Agents {
			if !slices.Contains(served, engine.PluginServingAgent{Agent: name, ApprovalID: a.ApprovalID}) {
				return false
			}
		}
	}
	return true
}

// waitOutcome is the wait's result for state: what the person reads and
// what the agent does next.
func (e *pluginEnv) waitOutcome(k plugin.EntryKey, state string, approvals []waitApproval, eng engineOut) (waitResult, error) {
	res := waitResult{Name: k.Name, Instance: k.Instance, State: state, Approvals: approvals}
	p, _ := e.entry(k)
	var named []string
	for _, a := range approvals {
		for _, n := range a.Agents {
			if !slices.Contains(named, n) {
				named = append(named, n)
			}
		}
	}
	cmdAgent := p.Agents[0]
	if len(named) > 0 {
		cmdAgent = named[0]
	}
	cmds, err := e.commandsFor(cmdAgent)
	steps := agent.NewSteps()
	switch state {
	case waitRunning:
		res.PersonMessage = fmt.Sprintf("The plugin %s runs now for %s.", k.Name, listText(named, ""))
		steps.Stop("Done: the plugin runs. Tell the person, and do not wait again.")
	case waitWaiting:
		res.PersonMessage = fmt.Sprintf("The plugin %s waits for your approval. Open the link you were given and approve it with your passkey: it starts within seconds.", k.Name)
		steps.TellAgent("Tell the agent once you approved, or give it the basalt-plugin.1. code the page shows.")
		steps.EndTurn("Do not wait again in this turn: end it. When the person says they approved, run this same command again; " +
			"when they paste a basalt-plugin.1. code, run basalt plugin approve with it first.")
	case waitNotRunning:
		if err == nil && !eng.Reachable && !eng.Unknown {
			start := cmds.EngineRestart()
			res.PersonMessage = fmt.Sprintf("You approved the plugin %s, but the engine is not running, so it does not run yet.", k.Name)
			steps.MachineCommand(cmds, start, "Start the engine: it starts the plugin.", "Start the engine: it starts the plugin.")
			if !cmds.AgentOperated() {
				res.PersonMessage += " Start the engine: " + start
			}
		} else {
			res.PersonMessage = fmt.Sprintf("You approved the plugin %s, but the engine does not run it yet.", k.Name)
			steps.CallTool("status", map[string]any{}, "Call status: it says why the plugin does not run, and what to do.")
		}
	default: // waitEnded
		enable := e.command("enable", append(entryArgs(k), "--"+flagApproveWithPasskey, "--json")...)
		res.PersonMessage = fmt.Sprintf("The approval of the plugin %s is no longer open: it expired, a newer one replaced it, or it ended. Nothing runs from it.", k.Name)
		steps.MachineCommand(cmds, enable, "Run this to open a new approval; it prints a new link.",
			"Run this to open a new approval; hand its link to the person.")
	}
	if err != nil {
		return waitResult{}, err
	}
	built, err := steps.Build()
	if err != nil {
		return waitResult{}, err
	}
	res.NextSteps = built
	return res, nil
}

// printWait prints a wait's result: with asJSON the result, else
// personMessage. A wait that ended with the plugin not running, or its
// approval no longer open, exits 1.
func (e *pluginEnv) printWait(res waitResult, asJSON bool) error {
	if asJSON {
		printJSONValue(e.c, res)
	} else {
		fmt.Fprintln(e.c.stdout, res.PersonMessage)
	}
	switch res.State {
	case waitNotRunning, waitEnded:
		return errWaitNotRunning
	}
	return nil
}

// errWaitNotRunning ends a wait whose plugin does not run: exit 1, the
// result already printed.
var errWaitNotRunning = errors.New("the plugin does not run")

// enableWait is basalt plugin enable --approval-id: the repeat call that
// waits for the plugin to run, opening nothing.
func (e *pluginEnv) enableWait(k plugin.EntryKey, ids []uuid.UUID, wait int, asJSON bool) error {
	if e.cfg.Service() {
		return errApprovalInServiceMode("--approval-id")
	}
	if wait < 0 {
		wait = defaultRepeatWait
	}
	res, err := e.waitForRunning(k, ids, time.Duration(wait)*time.Second)
	if err != nil {
		return err
	}
	return e.printWait(res, asJSON)
}

// openedIDs are the approvals a result opened.
func openedIDs(res approvalResult) []uuid.UUID {
	var out []uuid.UUID
	for _, a := range res.Approvals {
		if id, err := uuid.Parse(a.ApprovalID); err == nil {
			out = append(out, id)
		}
	}
	return out
}

// handOverOrWait is handOver, after a wait when wait > 0: a plugin that runs
// before the wait ends prints the wait's result; otherwise the approval
// result with its links, as without the wait.
func (e *pluginEnv) handOverOrWait(k plugin.EntryKey, res approvalResult, wait int, asJSON bool) error {
	ids := openedIDs(res)
	if wait > 0 && len(ids) > 0 {
		w, err := e.waitForRunning(k, ids, time.Duration(wait)*time.Second)
		if err == nil && w.State == waitRunning {
			return e.printWait(w, asJSON)
		}
	}
	return e.handOver(res, asJSON)
}
