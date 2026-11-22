package app

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/osservice"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/service/agent"
	"github.com/basaltdbhq/basaltdb/internal/service/pluginhost"
)

// pluginEventTimeout bounds one agent's plugin events at start: reading
// its ledger and writing what changed. The agents' pools connect lazily, so
// a database that is down fails here.
const pluginEventTimeout = 15 * time.Second

// Why an entry that verified is not served to one agent: its record could
// not be written to that agent's ledger (unrecordedWhy). Each ends with
// what to do; the engine writes the record at its next start.
const (
	whyNoPluginEvents = "this agent's guard is older than schema version 3, so its plugin record could not be written; " +
		"update it through the link basalt init prints for this agent, then restart the engine"
	whyNoGuard = "this agent's database has no guard, so its plugin record could not be written; " +
		"install the guard, then restart the engine"
	whyNotAdmitted = "this agent is served status only until its guard or setup is ready, so its plugin record was not written; " +
		"restart the engine once it is"
	whyRefused       = "the guard refused its plugin record (see the engine's log); restart the engine once it is fixed"
	whyKeyNotTrusted = "the key that signed it is no longer in the trust store, so it is not served; " +
		"put the key back in the trust store, or disable the plugin, then restart the engine"
	whyTrustUnread = "the trust store could not be read, so the record of the key that signed it was not written; " +
		"restart the engine once the trust store can be read"
	whyUnreachable = "its plugin record could not be written to this agent's ledger; " +
		"restart the engine once the agent's database is reachable"
)

// SQLSTATEs that say the guard is older than schema version 3 or missing.
const (
	sqlstateUndefinedFunction = "42883"
	sqlstateUndefinedTable    = "42P01"
	sqlstateInvalidSchemaName = "3F000"
)

// errNotAdmitted: the agent is served status only (agent.Service.Admit).
var errNotAdmitted = errors.New("the agent is served status only")

// unrecordedWhy is why a record could not be written, for the agent's
// status: never the error's text, which could name a value.
func unrecordedWhy(err error) string {
	var pg *pgconn.PgError
	if errors.Is(err, errNotAdmitted) {
		return whyNotAdmitted
	}
	if !errors.As(err, &pg) {
		return whyUnreachable
	}
	switch pg.Code {
	case sqlstateUndefinedFunction:
		return whyNoPluginEvents
	case sqlstateUndefinedTable, sqlstateInvalidSchemaName:
		return whyNoGuard
	}
	if _, ok := guard.CodeOf(err); ok {
		return whyRefused
	}
	return whyUnreachable
}

// transientErr reports whether err says only that the database did not
// answer: no connection, a timeout, a connection lost. Any other failure,
// a Postgres error, a refusal to admit the agent or a reply the engine
// cannot read, decides.
func transientErr(err error) bool {
	var (
		pg   *pgconn.PgError
		conn *pgconn.ConnectError
		ne   net.Error
	)
	switch {
	case err == nil, errors.As(err, &pg), errors.Is(err, errNotAdmitted):
		return false
	case errors.As(err, &conn), errors.As(err, &ne), errors.Is(err, action.ErrUnavailable),
		errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled),
		errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF), pgconn.SafeToRetry(err), pgconn.Timeout(err):
		return true
	}
	return false
}

// pluginLedger is one agent's ledger as the plugin event writer reaches it:
// the agent's own connection, and the engine's admission of the agent
// (nil admits it). An agent served status only (no guard, an outdated one,
// a pending setup) gets no plugin record and no plugin.
type pluginLedger struct {
	db    guard.Querier
	admit func(context.Context) error
}

// pluginAdmit is svc's admission for plugin records: errNotAdmitted when
// the agent is served status only (no guard, an outdated one, a pending
// setup), the probe's error when its database does not answer.
func pluginAdmit(svc *agent.Service) func(context.Context) error {
	return func(ctx context.Context) error {
		err := svc.Admit(ctx)
		var te *mcp.ToolError
		var se *agent.SetupError
		if errors.As(err, &te) || errors.As(err, &se) {
			return fmt.Errorf("%w: %w", errNotAdmitted, err)
		}
		return err
	}
}

// unrecordedEntry is a served entry withheld from one agent, and why: its
// record could not be written (unrecordedWhy), or it requires approval and
// has no matching one. code is the status problem, PLUGIN_UNAVAILABLE when
// empty.
type unrecordedEntry struct {
	key  pluginhost.EntryKey
	why  string
	code string
	// transient: the database did not answer, so nothing was decided
	// (transientErr).
	transient bool
}

// pluginWant is the plugin state the engine records in each agent's ledger
// at start (CONTRACT.md, Plugins, In the ledger).
type pluginWant struct {
	// served are the entries each configured agent is served now, with the
	// detail its ledger records of each.
	served map[string]map[pluginhost.EntryKey]guard.PluginDetail
	// held are entries enabled and listed for an agent that this engine does
	// not start (verification failed, or it may not run here): their
	// record is left as it is, so a passing failure writes nothing, unless
	// the key that signed it is no longer recorded as trusted.
	held map[string]map[pluginhost.EntryKey]bool
	// approval are the enabled entries that require a plugin approval
	// (config.Config.PluginRequiresApproval), served or held: one is served
	// to an agent only on a matching signed approval, in place of the trust
	// record, and settings are what that approval binds of each.
	approval map[pluginhost.EntryKey]bool
	settings map[pluginhost.EntryKey]guard.PluginSettings
	// trust is the trust store's state.
	trust trustWant
	// frozen are a service engine's config entries while it runs: held,
	// their records always kept (pluginWatch.wanted).
	frozen map[pluginhost.EntryKey]bool
}

// trustWant is what the trust store holds besides the built-in keys
// (plugin.BuiltInKey), which no ledger records.
type trustWant struct {
	// read: the trust store could be read. Without it no trust event is
	// written, and an entry whose added key the ledger does not record is
	// withheld.
	read bool
	// added are the keys the person added.
	added []string
}

// wantedPlugins is what each agent of cfg should have on record: the
// entries ep starts (none when ep is nil), the ones it holds back, and the
// trust store's keys.
func wantedPlugins(cfg config.Config, ep *enginePlugins, trust trustWant) pluginWant {
	mode, goos := pluginhost.ModeSameUser, runtime.GOOS
	if ep != nil {
		mode, goos = ep.mode, ep.o.goos
	}
	var kept func(pluginhost.EntryKey) bool
	if ep != nil {
		cfg, kept = ep.startCfg, ep.isKept
	}
	return wantedFrom(cfg, ep.startedCopy, mode, goos, trust, kept)
}

// wantedFrom is wantedPlugins with the verified copy of each started entry
// given by copyOf (false: it is not started) and the engine's mode and OS:
// the one derivation of what each agent should have on record, at start
// and while the engine runs (pluginWatch).
//
// kept reports an engine-kept entry (nil: none): it always requires
// approval and runs as the engine's own child, so it is recorded with
// same-user isolation (CONTRACT.md, Plugin approval in service mode).
func wantedFrom(cfg config.Config, copyOf func(pluginhost.EntryKey) (pluginhost.Verified, bool), mode pluginhost.Mode, goos string, trust trustWant, kept func(pluginhost.EntryKey) bool) pluginWant {
	w := pluginWant{
		served:   make(map[string]map[pluginhost.EntryKey]guard.PluginDetail, len(cfg.Agents)),
		held:     make(map[string]map[pluginhost.EntryKey]bool, len(cfg.Agents)),
		approval: map[pluginhost.EntryKey]bool{},
		settings: map[pluginhost.EntryKey]guard.PluginSettings{},
		trust:    trust,
	}
	for _, a := range cfg.Agents {
		w.served[a.Name], w.held[a.Name] = map[pluginhost.EntryKey]guard.PluginDetail{}, map[pluginhost.EntryKey]bool{}
	}
	for _, p := range cfg.Plugins {
		if !p.Enabled {
			continue
		}
		k := p.Key()
		isKept := kept != nil && kept(k)
		required := isKept || cfg.PluginRequiresApproval(p)
		if required {
			w.approval[k], w.settings[k] = true, p.ApprovalSettings()
		}
		v, started := copyOf(k)
		for _, name := range p.Agents {
			if _, ok := w.served[name]; !ok {
				continue // the config refuses an unknown agent; never record one
			}
			if !started {
				w.held[name][k] = true
				continue
			}
			m := mode
			if isKept {
				m = pluginhost.ModeSameUser
			}
			d := pluginDetail(k, v, m, goos)
			if required {
				d = withSigner(d, v)
			}
			w.served[name][k] = d
		}
	}
	return w
}

// startedCopy is the verified copy of an entry ep starts, false when it
// starts none (ep nil, or the entry failed verification or was refused).
// It is read before the supervisor runs, while every started entry still
// has the copy verified at start.
func (ep *enginePlugins) startedCopy(k pluginhost.EntryKey) (pluginhost.Verified, bool) {
	if ep == nil {
		return pluginhost.Verified{}, false
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	v, ok := ep.first[k]
	return v, ok
}

// pluginDetail is what an agent's ledger records of entry k: the manifest's
// identity, hooks, egress and endpoint, and for a local entry its
// isolation. Never a config value, a credential, a path or an agent name.
func pluginDetail(k pluginhost.EntryKey, v pluginhost.Verified, mode pluginhost.Mode, goos string) guard.PluginDetail {
	m := v.Manifest
	d := guard.PluginDetail{
		Name: k.Name, Instance: k.Instance, Version: m.Version,
		ManifestSHA256: v.ManifestSHA256, SignerKeyID: v.SignerKeyID,
		Hooks:  slices.Sorted(maps.Keys(m.Hooks)),
		Egress: append([]string{}, m.Network.Egress...),
	}
	slices.Sort(d.Egress)
	if decl, ok := m.Hooks[string(pluginhost.HookWireDetect)]; ok && len(decl.Roles) > 0 {
		d.Roles = append([]string(nil), decl.Roles...)
		slices.Sort(d.Roles)
	}
	if r := m.Endpoint.Remote; r != nil {
		host, _ := pluginhost.RemoteHostPort(r.URL) // the manifest's rules checked it
		d.Endpoint = guard.PluginEndpoint{Kind: guard.PluginEndpointRemote, Host: host}
		return d
	}
	d.Endpoint = guard.PluginEndpoint{Kind: guard.PluginEndpointLocal}
	d.Isolation = pluginIsolation(mode, goos, m)
	return d
}

// pluginIsolation is what a local entry's record says of its isolation as
// it runs on an engine in mode on goos. In same-user mode it runs as the
// engine's own OS user with the engine's network: files NONE, network
// NOT_ENFORCED. In service mode a served local entry runs under its own
// unit and OS user (the engine starts none otherwise: localRefusal), so
// files OS_USER, and the network the unit gets, from the same rule the unit
// is written by (service.PluginNetwork).
func pluginIsolation(mode pluginhost.Mode, goos string, m pluginhost.Manifest) *guard.PluginIsolation {
	if mode != pluginhost.ModeService {
		return &guard.PluginIsolation{Files: guard.PluginFilesNone, Network: guard.PluginNetworkNotEnforced}
	}
	return &guard.PluginIsolation{Files: guard.PluginFilesOSUser, Network: osservice.PluginNetwork(goos, m.Network.Egress)}
}

// writePluginEvents records in each agent's own ledger what changed since
// the plugin events it already has: the last-seen state is the ledger's,
// so a restart with no change writes nothing and a change made while the
// engine was stopped is recorded now. For each agent:
//   - an entry it is served that its ledger shows disabled or never had:
//     PLUGIN_ENABLED;
//   - one whose detail differs from the last recorded: PLUGIN_CHANGED;
//   - one its ledger shows served that it is no longer served (disabled,
//     removed, or the agent removed from its agents) and that is not held,
//     or is held and the key that signed it is no longer recorded as
//     trusted: PLUGIN_DISABLED, with the detail last recorded;
//   - each added trust key its ledger lacks: PLUGIN_TRUST_ADDED, written
//     first.
//
// Agents run in parallel, each bounded by pluginEventTimeout. It returns,
// per agent, the served entries withheld from it, with why: their record
// could not be written, or they require approval and have no matching one.
// They must not be served to that agent. It also returns, per agent, the
// entries that require approval whose approval matched and whose record
// holds: the only agents such an entry is served to. An agent missing from
// ledgers has no ledger to write to.
func writePluginEvents(ctx context.Context, want pluginWant, ledgers map[string]pluginLedger, log *slog.Logger) map[string]agentPass {
	return checkAgents(ctx, want, ledgers, slices.Collect(maps.Keys(want.served)), pluginEventTimeout, log)
}

// agentPass is what one agent's check decided (writeAgentPluginEvents).
type agentPass struct {
	// withheld are the entries listed for the agent that it is not served,
	// with why; approved are the entries that require approval whose
	// approval matched and whose record holds.
	withheld []unrecordedEntry
	approved []pluginhost.EntryKey
	// approvalIDs is the approval each approved entry matched.
	approvalIDs map[pluginhost.EntryKey]uuid.UUID
	// disables are the PLUGIN_DISABLED records still to write, each the
	// detail last recorded: written after the entry stopped serving the
	// agent (writeDisables), so the ledger never shows an entry not served
	// while it still is.
	disables []guard.PluginDetail
	// reached: the agent's ledger was read. When false nothing was decided
	// and withheld says why for every entry.
	reached bool
}

// unread reports whether the check failed for the agent as a whole, or
// because its database did not answer: the watch then asks it again only
// after a backoff (pluginWatch).
func (p agentPass) unread() bool {
	return !p.reached || slices.ContainsFunc(p.withheld, func(u unrecordedEntry) bool { return u.transient })
}

// checkAgents runs writeAgentPluginEvents for each of names in parallel,
// each bounded by timeout.
func checkAgents(ctx context.Context, want pluginWant, ledgers map[string]pluginLedger, names []string, timeout time.Duration, log *slog.Logger) map[string]agentPass {
	var mu sync.Mutex
	out := make(map[string]agentPass, len(names))
	var wg sync.WaitGroup
	for _, name := range names {
		if _, ok := want.served[name]; !ok {
			continue
		}
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			p := writeAgentPluginEvents(ctx, name, want, ledgers[name], log.With("agent", name))
			mu.Lock()
			out[name] = p
			mu.Unlock()
		})
	}
	wg.Wait()
	return out
}

// writeDisables writes each agent's pending PLUGIN_DISABLED records, each
// agent bounded by timeout. A record that fails is logged; the next check
// writes it again, since the ledger still shows the entry served.
func writeDisables(ctx context.Context, passes map[string]agentPass, ledgers map[string]pluginLedger, timeout time.Duration, log *slog.Logger) bool {
	var wg sync.WaitGroup
	var failed atomic.Bool
	for name, p := range passes {
		if len(p.disables) == 0 || ledgers[name].db == nil {
			continue
		}
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			for _, d := range p.disables {
				if err := guard.RecordPluginEntryEvent(ctx, ledgers[name].db, guard.PluginDisabled, d); err != nil {
					failed.Store(true)
					log.Warn("PLUGIN_DISABLED not recorded; the next check tries again", "agent", name,
						"plugin", pluginhost.EntryKey{Name: d.Name, Instance: d.Instance}.String(), "err", err)
				}
			}
		})
	}
	wg.Wait()
	return !failed.Load()
}

// writeAgentPluginEvents is writePluginEvents for one agent, within ctx's
// deadline: what it is served and withheld, and the PLUGIN_DISABLED
// records it still needs.
func writeAgentPluginEvents(ctx context.Context, name string, want pluginWant, l pluginLedger, log *slog.Logger) agentPass {
	served := slices.SortedFunc(maps.Keys(want.served[name]), compareEntryKeys)
	all := func(err error) agentPass {
		out := make([]unrecordedEntry, 0, len(served))
		for _, k := range served {
			out = append(out, unrecordedEntry{key: k, why: unrecordedWhy(err), transient: transientErr(err)})
		}
		return agentPass{withheld: out}
	}
	if l.db == nil {
		return all(nil)
	}
	if l.admit != nil {
		if err := l.admit(ctx); err != nil {
			if len(served) > 0 {
				log.Warn("plugins not served to this agent: it is not admitted", "err", err)
			}
			return all(err)
		}
	}
	db := l.db
	recs, err := guard.ReadPluginRecords(ctx, db)
	if err != nil {
		if len(served) > 0 {
			log.Error("plugins not served to this agent: its ledger cannot be read", "err", err)
		}
		return all(err)
	}
	last := make(map[pluginhost.EntryKey]guard.PluginRecord, len(recs.Entries))
	for _, r := range recs.Entries {
		last[pluginhost.EntryKey{Name: r.Detail.Name, Instance: r.Detail.Instance}] = r
	}
	recorded, unrecordedKeys := writeTrustEvents(ctx, db, want.trust, recs.TrustKeys, log)
	approvals := &agentApprovals{db: db}
	out := agentPass{reached: true}
	approvedBy := map[pluginhost.EntryKey]uuid.UUID{}
	for _, k := range served {
		d := want.served[name][k]
		if want.approval[k] {
			// The signed approval takes the place of the trust record
			// (CONTRACT.md, Signer states): served only on a match.
			w, ok := approvals.check(ctx, k, d, want.settings[k])
			approvedBy[k] = w.approvalID
			if !ok {
				log.Warn("plugin not served to this agent: "+w.why, "plugin", k.String())
				out.withheld = append(out.withheld, unrecordedEntry{key: k, why: w.why, code: w.code, transient: w.transient})
				// For an approval reason the ledger never shows the entry
				// served after it stopped matching; that ends the approval.
				// A passing failure (old guard, unread approvals) writes
				// nothing.
				if r, ok := last[k]; ok && r.Enabled() && approvalReason(w.code) {
					out.disables = append(out.disables, r.Detail)
				}
				continue
			}
		} else if s := d.SignerKeyID; !recorded[s] && !pluginhost.BuiltInKey(s) {
			// An entry is served only when the ledger records the key that
			// signed it as trusted (a built-in key needs no record): the
			// ledger never shows an entry served without that key.
			why := whyTrustUnread
			if err, ok := unrecordedKeys[s]; ok {
				why = unrecordedWhy(err)
			} else if want.trust.read {
				// The store was read and no longer holds the key (it changed
				// since the entry was verified at start).
				why = whyKeyNotTrusted
			}
			out.withheld = append(out.withheld, unrecordedEntry{key: k, why: why})
			continue
		}
		if kind, ok := entryEvent(last, k, d); ok {
			if err := guard.RecordPluginEntryEvent(ctx, db, kind, d); err != nil {
				log.Error("plugin not served to this agent: its record could not be written", "plugin", k.String(), "event", kind, "err", err)
				out.withheld = append(out.withheld, unrecordedEntry{key: k, why: unrecordedWhy(err), transient: transientErr(err)})
				continue
			}
		}
		if want.approval[k] {
			out.approved = append(out.approved, k)
			if out.approvalIDs == nil {
				out.approvalIDs = map[pluginhost.EntryKey]uuid.UUID{}
			}
			out.approvalIDs[k] = approvedBy[k]
		}
	}
	for _, r := range recs.Entries {
		k := pluginhost.EntryKey{Name: r.Detail.Name, Instance: r.Detail.Instance}
		if _, ok := want.served[name][k]; ok || !r.Enabled() {
			continue
		}
		// A held entry keeps its record, unless the key that signed it is no
		// longer recorded as trusted: the ledger never shows an entry served
		// without that key. An entry that requires approval rests on its
		// approval, not on a key: held, it always keeps its record.
		if s := r.Detail.SignerKeyID; want.held[name][k] && (want.frozen[k] || want.approval[k] || recorded[s] || pluginhost.BuiltInKey(s)) {
			continue
		}
		out.disables = append(out.disables, r.Detail)
	}
	return out
}

// writeTrustEvents writes the agent's trust events, keys before any entry:
// PLUGIN_TRUST_ADDED for each added key the ledger does not record as
// trusted, and PLUGIN_TRUST_REMOVED for each key it records as trusted that
// the trust store does not hold (a key removed, or an event the agent wrote
// itself). Nothing is written when the trust store could not be read. It
// returns the keys the ledger now records as trusted, and why each added key
// it could not record failed. A failed PLUGIN_TRUST_REMOVED (a guard older
// than schema version 4) is logged and tried again at the next start.
func writeTrustEvents(ctx context.Context, db guard.Querier, trust trustWant, onRecord []string, log *slog.Logger) (map[string]bool, map[string]error) {
	recorded := make(map[string]bool, len(onRecord))
	for _, id := range onRecord {
		recorded[id] = true
	}
	unrecorded := map[string]error{}
	if !trust.read {
		return recorded, unrecorded
	}
	for _, id := range trust.added {
		if recorded[id] {
			continue
		}
		if err := guard.RecordPluginTrustAdded(ctx, db, id); err != nil {
			log.Warn("PLUGIN_TRUST_ADDED not recorded; until a later start writes it, plugins signed by this key are not served to this agent", "keyId", id, "err", err)
			unrecorded[id] = err
			continue
		}
		recorded[id] = true
	}
	for _, id := range onRecord {
		if slices.Contains(trust.added, id) || pluginhost.BuiltInKey(id) {
			continue
		}
		if err := guard.RecordPluginTrustRemoved(ctx, db, id); err != nil {
			log.Warn("PLUGIN_TRUST_REMOVED not recorded; the next start tries again", "keyId", id, "err", err)
			continue
		}
		delete(recorded, id)
	}
	return recorded, unrecorded
}

// entryEvent is the event a served entry needs given the agent's last
// records: PLUGIN_ENABLED when there is none or it was disabled,
// PLUGIN_CHANGED when the detail differs, none when it is the same.
func entryEvent(last map[pluginhost.EntryKey]guard.PluginRecord, k pluginhost.EntryKey, d guard.PluginDetail) (guard.PluginEventKind, bool) {
	r, ok := last[k]
	switch {
	case !ok || !r.Enabled():
		return guard.PluginEnabled, true
	case !sameDetail(r.Detail, d):
		return guard.PluginChanged, true
	}
	return "", false
}

// sameDetail compares two details as the ledger stores them.
func sameDetail(a, b guard.PluginDetail) bool {
	if a.Egress == nil {
		a.Egress = []string{}
	}
	if b.Egress == nil {
		b.Egress = []string{}
	}
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}

func compareEntryKeys(a, b pluginhost.EntryKey) int {
	return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Instance, b.Instance))
}

// trustedKeys is the trust store of an engine run with cfg from configPath:
// the keys the person added, or not read, logged, when it cannot be read.
func trustedKeys(cfg config.Config, configPath string, log *slog.Logger) trustWant {
	mode := pluginhost.ModeSameUser
	if cfg.Service() {
		mode = pluginhost.ModeService
	}
	trust, err := pluginhost.NewTrustStore(mode, runtime.GOOS, filepath.Dir(configPath))
	if err != nil {
		log.Warn("plugin trust keys not recorded: the trust store cannot be read", "err", err)
		return trustWant{}
	}
	keys, err := trust.AddedKeys()
	if err != nil {
		log.Warn("plugin trust keys not recorded: the trust store cannot be read", "err", err)
		return trustWant{}
	}
	return trustWant{read: true, added: keys}
}

// recordPluginEvents writes the start's plugin events (writePluginEvents)
// and withholds from each agent the entries whose record failed, before
// any plugin starts. ep is nil when no entry is enabled: removed or
// disabled entries are still recorded then.
func recordPluginEvents(ctx context.Context, cfg config.Config, configPath string, ep *enginePlugins, ledgers map[string]pluginLedger, log *slog.Logger) {
	want := wantedPlugins(cfg, ep, trustedKeys(cfg, configPath, log))
	passes := writePluginEvents(ctx, want, ledgers, log)
	// Nothing runs yet: the records first, so status never shows a withhold
	// the ledger does not record.
	writeDisables(ctx, passes, ledgers, pluginEventTimeout, log)
	ep.withhold(passes)
}

// withhold sets which agents each started entry is served to, before the
// supervisor runs (servedAgents).
func (ep *enginePlugins) withhold(passes map[string]agentPass) {
	if ep == nil {
		return
	}
	ep.mu.Lock()
	defer ep.mu.Unlock()
	ep.setWithheldLocked(passes, nil, nil)
	kept := ep.entries[:0]
	ep.approvedBy = map[pluginhost.EntryKey]map[string]uuid.UUID{}
	for _, e := range ep.entries {
		e.Agents = ep.servedAgentsLocked(e.Key, passes, nil)
		if len(e.Agents) > 0 {
			kept = append(kept, e)
		}
		for _, a := range e.Agents {
			if id, ok := passes[a].approvalIDs[e.Key]; ok {
				if ep.approvedBy[e.Key] == nil {
					ep.approvedBy[e.Key] = map[string]uuid.UUID{}
				}
				ep.approvedBy[e.Key][a] = id
			}
		}
	}
	ep.entries = kept
}

// setWithheldLocked replaces, for each agent of passes whose check read
// what decides (or for every agent when keep is nil, as at start), why
// each entry is withheld from it; an entry frozen reports (nil: none) keeps
// what it had. ep.mu is held.
func (ep *enginePlugins) setWithheldLocked(passes map[string]agentPass, keep func(agentName string) bool, frozen func(pluginhost.EntryKey) bool) {
	if ep.unrecorded == nil {
		ep.unrecorded = map[pluginhost.EntryKey]map[string]withheldWhy{}
	}
	for agentName, p := range passes {
		if keep != nil && keep(agentName) {
			continue
		}
		for k, byAgent := range ep.unrecorded {
			if frozen == nil || !frozen(k) {
				delete(byAgent, agentName)
			}
		}
		for _, u := range p.withheld {
			if ep.unrecorded[u.key] == nil {
				ep.unrecorded[u.key] = map[string]withheldWhy{}
			}
			ep.unrecorded[u.key][agentName] = withheldWhy{code: u.code, why: u.why}
		}
	}
}

// servedAgentsLocked is the one answer to "who is entry k served to" after
// the agents' checks (passes), at start and while the engine runs. An entry
// that does not require approval is served to its listed agents but those
// it is withheld from: whose record could not be written to their ledger
// (the record is part of consent). An entry that requires approval is
// served only to the listed agents whose check found a matching signed
// approval and wrote the record; every other listed agent is withheld. An
// agent without a check in passes is not served, unless kept(agent) says
// to keep what it is served now (only while running, and only when its
// check could not read what decides). The host refuses any call naming a
// withheld agent, an entry left with no agent is not started, and status
// shows the problem for that agent. ep.mu is held.
func (ep *enginePlugins) servedAgentsLocked(k pluginhost.EntryKey, passes map[string]agentPass, kept func(agentName string) bool) []string {
	var out []string
	for _, a := range ep.configuredLocked(k).Agents {
		p, checked := passes[a]
		switch {
		case kept != nil && kept(a):
			out = append(out, a)
		case !checked:
		case ep.approval[k] && !slices.Contains(p.approved, k):
		case slices.ContainsFunc(p.withheld, func(u unrecordedEntry) bool { return u.key == k }):
		default:
			out = append(out, a)
		}
	}
	return out
}

// unrecordedFor is why entry k is withheld from agent name, empty when it
// is not.
func (ep *enginePlugins) unrecordedFor(k pluginhost.EntryKey, name string) withheldWhy {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	return ep.unrecorded[k][name]
}
