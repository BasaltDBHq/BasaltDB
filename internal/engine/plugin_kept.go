package engine

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/keptplugins"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// keptDatabaseTimeout bounds each database's part of a plugin method: the
// 15 seconds of the contract.
const keptDatabaseTimeout = 15 * time.Second

// PLUGIN_REFUSED reasons the plugin methods give besides the store's.
const (
	reasonNameTaken           = "NAME_TAKEN"
	reasonConfigEntry         = "CONFIG_ENTRY"
	reasonUnknownAgent        = "UNKNOWN_AGENT"
	reasonGuardOutdated       = "GUARD_OUTDATED"
	reasonDatabaseUnreachable = "DATABASE_UNREACHABLE"
	reasonTooManyPending      = "TOO_MANY_PENDING"
	reasonEngineIsRoot        = "ENGINE_IS_ROOT"
)

// keptAgent is one agent as the plugin methods reach it: its own pool and
// the database and role its credential names.
type keptAgent struct {
	db       guard.Querier
	host     string
	port     uint16
	database string
	role     string
}

// keptPlugins serves the person socket's plugin methods on a service
// engine (CONTRACT.md, Plugins, Plugin approval in service mode): it keeps
// the engine-kept entries in store and opens their approvals in each listed
// agent's database with that agent's own credential. The methods that
// change entries run one at a time.
type keptPlugins struct {
	store      *keptplugins.Store
	cfg        config.Config
	configPath string
	agents     map[string]keptAgent
	euid       int
	goos       string
	log        *slog.Logger

	mu sync.Mutex
	// changed is called after an entry is written, with the entries as
	// written; it returns once what the engine runs follows them (the
	// watch). nil in tests that run nothing.
	changed func(ctx context.Context)
	// serving is what the running engine serves of entry k; nil serves
	// nothing.
	serving func(k plugin.EntryKey) []person.PluginServing
	// health is what the running engine knows of the entry k, engine-kept
	// (kept) or of engine.json: person.HealthReady and the like; nil runs
	// nothing.
	health func(k plugin.EntryKey, kept bool) string
}

// storeError maps a store refusal to the person socket.
func storeError(err error) error {
	var ke *keptplugins.Error
	if !errors.As(err, &ke) {
		return err
	}
	switch ke.Kind {
	case keptplugins.KindInvalid:
		return &person.Error{Code: person.CodeInvalidArgument, Message: ke.Message}
	case keptplugins.KindNotFound:
		return &person.Error{Code: person.CodeNotFound, Message: ke.Message}
	case keptplugins.KindRefused:
	}
	return person.Refused(ke.Reason, ke.Message)
}

// notAllowed is AGENT_NOT_ALLOWED for a request that reaches an agent
// outside the peer's scope.
func notAllowed(k plugin.EntryKey) error {
	return &person.Error{Code: person.CodeAgentNotAllowed, Message: fmt.Sprintf(
		"this OS user runs agents, so it may change plugin %s only for its own agents, and this request reaches another one; "+
			"run the agent as another OS user (basalt init --os-user) so the person can change every agent's plugins", k)}
}

// UploadBegin is PLUGIN_UPLOAD_BEGIN.
func (s *keptPlugins) UploadBegin(_ context.Context, uid uint32) (person.PluginUploadBeginResult, error) {
	u, err := s.store.Begin(uid)
	if err != nil {
		return person.PluginUploadBeginResult{}, storeError(err)
	}
	return person.PluginUploadBeginResult{UploadID: u.ID, ExpiresAt: u.ExpiresAt, MaxPartBytes: keptplugins.MaxPartBytes, MaxUploadBytes: keptplugins.MaxUploadBytes}, nil
}

// UploadPart is PLUGIN_UPLOAD_PART.
func (s *keptPlugins) UploadPart(_ context.Context, uid uint32, p person.PluginUploadPartParams) (person.PluginUploadPartResult, error) {
	n, err := s.store.Part(uid, p.UploadID, p.Path, p.Offset, p.Data)
	if err != nil {
		return person.PluginUploadPartResult{}, storeError(err)
	}
	return person.PluginUploadPartResult{Path: p.Path, Size: n}, nil
}

// configEntries are the config's entries: the start config's and those
// engine.json holds on disk now, so a hand edit or a sudo add since the
// start is seen. Only the plugins key is read from disk, leniently: a
// file the engine would refuse at load still names its entries. A file
// that cannot be read counts as the start's.
func (s *keptPlugins) configEntries() []config.Plugin {
	out := slices.Clone(s.cfg.Plugins)
	raw, err := os.ReadFile(s.configPath)
	// Only the fields a clash needs: an entry with any other field the
	// engine would refuse still names its (name, instance) and agents.
	var now struct {
		Plugins []struct {
			Name     string   `json:"name"`
			Instance string   `json:"instance"`
			Agents   []string `json:"agents"`
		} `json:"plugins"`
	}
	if err == nil {
		err = json.Unmarshal(raw, &now)
	}
	if err != nil {
		s.log.Warn("engine.json cannot be read for the plugin entries it holds; using the ones it held at start", "err", err)
		return out
	}
	for _, n := range now.Plugins {
		p := config.Plugin{Name: n.Name, Instance: n.Instance, Agents: n.Agents}
		if !slices.ContainsFunc(out, func(q config.Plugin) bool { return q.Key() == p.Key() }) {
			out = append(out, p)
		}
	}
	return out
}

// configEntry is engine.json's entry k, false when it holds none.
func (s *keptPlugins) configEntry(k plugin.EntryKey) (config.Plugin, bool) {
	for _, p := range s.configEntries() {
		if p.Key() == k {
			return p, true
		}
	}
	return config.Plugin{}, false
}

func keptIndex(entries []config.Plugin, k plugin.EntryKey) int {
	return slices.IndexFunc(entries, func(p config.Plugin) bool { return p.Key() == k })
}

// Open is PLUGIN_OPEN (CONTRACT.md, Plugin approval in service mode, The
// methods): the refusals before anything is written, the copy's checks,
// the databases' checks and the approval ends owed, then the copy and the
// entry, then one approval per database.
func (s *keptPlugins) Open(ctx context.Context, uid uint32, scope person.Scope, p person.PluginOpenParams) (person.PluginOpenResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := plugin.EntryKey{Name: p.Name, Instance: p.Instance}
	// The scope first, before the upload is touched: a scoped peer learns
	// nothing it may not reach, not even which agent names exist, and a
	// request refused for its scope leaves its upload where it is.
	if !scope.AllowsAll(p.Agents) {
		return person.PluginOpenResult{}, notAllowed(k)
	}
	var taken *keptplugins.Taken
	if p.UploadID != nil {
		t, err := s.store.Take(uid, *p.UploadID)
		if err != nil {
			return person.PluginOpenResult{}, storeError(err)
		}
		// The upload is removed whatever the rest of this request decides.
		defer t.Release()
		taken = t
	} else if len(p.Executables) > 0 {
		return person.PluginOpenResult{}, &person.Error{
			Code:    person.CodeInvalidArgument,
			Message: "executables is given only with uploadId: an installed copy keeps its modes",
		}
	}
	next := config.Plugin{
		Name: p.Name, Instance: p.Instance, ManifestSHA256: zeroSHA, Enabled: true,
		Agents: slices.Clone(p.Agents), Approval: config.PluginApprovalRequired,
	}
	if err := s.checkRequest(next, p); err != nil {
		return person.PluginOpenResult{}, err
	}
	if c, ok := s.configEntry(k); ok {
		if !scope.AllowsAll(c.Agents) {
			return person.PluginOpenResult{}, notAllowed(k)
		}
		if taken != nil {
			return person.PluginOpenResult{}, person.Refused(reasonNameTaken, fmt.Sprintf(
				"plugin %s is an entry of engine.json (or was when the engine started: one removed since counts until "+
					"the engine restarts); an engine-kept entry cannot have its name and instance. Use another instance, "+
					"or change it by editing engine.json", k))
		}
		return person.PluginOpenResult{}, person.Refused(reasonConfigEntry, fmt.Sprintf(
			"plugin %s is an entry of engine.json; it is changed by editing that file", k))
	}
	entries, err := s.store.Entries(s.cfg)
	if err != nil {
		return person.PluginOpenResult{}, storeError(err)
	}
	var prev *config.Plugin
	if i := keptIndex(entries, k); i >= 0 {
		prev = &entries[i]
	}
	switch {
	case prev == nil && taken == nil:
		return person.PluginOpenResult{}, &person.Error{Code: person.CodeNotFound, Message: fmt.Sprintf("the engine keeps no plugin %s; add it first", k)}
	case prev != nil && !scope.AllowsAll(prev.Agents):
		return person.PluginOpenResult{}, notAllowed(k)
	case prev == nil && len(entries) >= config.MaxKeptPlugins:
		return person.PluginOpenResult{}, person.Refused(keptplugins.ReasonTooLarge, fmt.Sprintf(
			"the engine keeps at most %d plugin entries; remove one first", config.MaxKeptPlugins))
	}
	if p.Settings != nil {
		next.Config, next.TimeoutMs, next.MinConfidence = p.Settings.Config, derefInt(p.Settings.TimeoutMs), p.Settings.MinConfidence
	} else if prev != nil {
		next.Config, next.TimeoutMs, next.MinConfidence = prev.Config, prev.TimeoutMs, prev.MinConfidence
	}

	// The copy: staged from the upload, or the installed one.
	var staged *plugin.Staged
	var v plugin.Verified
	if taken != nil {
		if err := s.refuseLocalAsRoot(taken); err != nil {
			return person.PluginOpenResult{}, err
		}
		// A refusal leaves no directory behind the staging made.
		defer s.store.Tidy(k)
		staged, err = s.store.Stage(taken, p.Name, p.Instance, p.Executables)
		if err != nil {
			return person.PluginOpenResult{}, storeError(err)
		}
		defer func() { _ = staged.Discard() }()
		v = staged.Verified
	} else {
		v, err = s.store.Verify(k, prev.ManifestSHA256)
		if err != nil {
			return person.PluginOpenResult{}, storeError(keptRefusal(err))
		}
		if !v.Manifest.Endpoint.IsRemote() && s.euid == 0 {
			return person.PluginOpenResult{}, engineIsRoot()
		}
	}
	next.ManifestSHA256 = v.ManifestSHA256
	if _, err := next.Entry(v.Manifest); err != nil {
		return person.PluginOpenResult{}, &person.Error{Code: person.CodeInvalidArgument, Message: err.Error()}
	}

	narrowing := prev != nil && prev.Enabled && prev.ManifestSHA256 == next.ManifestSHA256 && sameSettings(*prev, next) &&
		len(next.Agents) < len(prev.Agents) && subsetOf(next.Agents, prev.Agents)
	var groups []*keptGroup
	if !narrowing {
		groups, err = s.groups(ctx, next.Agents)
		if err != nil {
			return person.PluginOpenResult{}, err
		}
	}
	// Ends owed first, before anything is written: an agent the entry did
	// not serve, or no longer serves, never comes back on an old approval,
	// even when the new one cannot be opened afterwards. For an entry that
	// is off or new that is every agent of both lists; for an enabled one,
	// the agents added and the agents removed.
	ends := PluginEndAgents(prev, next.Agents)
	if len(ends) > 0 {
		if err := s.writeOwedEnds(ctx, k, ends); err != nil {
			return person.PluginOpenResult{}, err
		}
	}

	// The write: the copy, the entry, then the old copy goes.
	if staged != nil {
		if v, err = s.store.Commit(staged); err != nil {
			return person.PluginOpenResult{}, storeError(err)
		}
	}
	if narrowing {
		next.Enabled = prev.Enabled
	}
	if err := s.store.Update(s.cfg, func(es []config.Plugin) ([]config.Plugin, error) {
		if i := keptIndex(es, k); i >= 0 {
			es[i] = next
			return es, nil
		}
		return append(es, next), nil
	}); err != nil {
		return person.PluginOpenResult{}, storeError(err)
	}
	if prev != nil && prev.ManifestSHA256 != next.ManifestSHA256 {
		if err := s.store.RemoveCopies(k, next.ManifestSHA256); err != nil {
			s.log.Warn("an old copy of an engine-kept plugin could not be removed; the next start removes it", "plugin", k.String(), "err", err)
		}
	}
	s.applied(ctx)

	out := person.PluginOpenResult{Name: k.Name, Instance: k.Instance, Version: v.Manifest.Version, Narrowed: narrowing, Approvals: []person.PluginOpenedApproval{}}
	if narrowing {
		return out, nil
	}
	out.Approvals = s.openApprovals(ctx, groups, next, v)
	return out, nil
}

// zeroSHA stands in for the copy's hash until the copy is checked.
const zeroSHA = "0000000000000000000000000000000000000000000000000000000000000000"

// checkRequest applies the entry rules to a request's entry before
// anything is read: name and instance, agents (UNKNOWN_AGENT for one the
// engine does not have) and settings.
func (s *keptPlugins) checkRequest(next config.Plugin, p person.PluginOpenParams) error {
	if len(p.Agents) == 0 || len(p.Agents) > 256 {
		return &person.Error{Code: person.CodeInvalidArgument, Message: "agents names 1 to 256 agents"}
	}
	if p.Settings != nil {
		next.Config, next.TimeoutMs, next.MinConfidence = p.Settings.Config, derefInt(p.Settings.TimeoutMs), p.Settings.MinConfidence
	}
	err := s.cfg.CheckKeptPlugins([]config.Plugin{next})
	var ua *config.UnknownAgentError
	switch {
	case err == nil:
		return nil
	case errors.As(err, &ua):
		return person.Refused(reasonUnknownAgent, fmt.Sprintf("agent %q is not one of this engine's agents; nothing was written", ua.Agent))
	}
	return &person.Error{Code: person.CodeInvalidArgument, Message: err.Error()}
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

// refuseLocalAsRoot refuses, before anything is written, the upload of a
// local plugin to an engine running as root (ENGINE_IS_ROOT). A manifest
// that does not parse is left to staging, which names the rule.
func (s *keptPlugins) refuseLocalAsRoot(t *keptplugins.Taken) error {
	if s.euid != 0 {
		return nil
	}
	// A manifest that is missing or does not parse is left to staging,
	// which names the rule it breaks.
	raw, readErr := t.Manifest()
	if readErr == nil {
		if m, err := plugin.ParseManifest(raw); err == nil && !m.Endpoint.IsRemote() {
			return engineIsRoot()
		}
	}
	return nil
}

func engineIsRoot() error {
	return person.Refused(reasonEngineIsRoot, "this engine runs as root, and it never runs a local plugin with root's privileges; "+
		"nothing was written. Run the engine as its own OS user (basalt service install)")
}

// keptRefusal is a verification failure of an installed copy as the store
// maps it.
func keptRefusal(err error) error {
	var ve *plugin.VerifyError
	if !errors.As(err, &ve) {
		return err
	}
	reason := string(ve.Reason)
	if ve.Path != nil {
		reason = keptplugins.ReasonUnsafePath
	}
	return &keptplugins.Error{Kind: keptplugins.KindRefused, Reason: reason, Message: "the installed copy is refused: " + ve.Error() + ". Nothing was written"}
}

// sameSettings reports whether a and b have the same settings.
func sameSettings(a, b config.Plugin) bool {
	ja, errA := json.Marshal(a.ApprovalSettings())
	jb, errB := json.Marshal(b.ApprovalSettings())
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}

// PluginEndAgents are the agents whose old plugin approval of an entry must
// be ended before the entry becomes next (CONTRACT.md, Plugin approval,
// Turning off ends it): for an entry that is off or new, every agent of both
// lists; for an enabled one, the agents added and the agents removed. prev is
// nil for a new entry. The engine and the basalt plugin commands share it.
func PluginEndAgents(prev *config.Plugin, next []string) []string {
	if prev == nil || !prev.Enabled {
		return union(agentsOf(prev), next)
	}
	return union(minus(prev.Agents, next), minus(next, prev.Agents))
}

// agentsOf is p's agents, none when p is nil.
func agentsOf(p *config.Plugin) []string {
	if p == nil {
		return nil
	}
	return p.Agents
}

// minus is a without the elements of b, in a's order.
func minus(a, b []string) []string {
	return slices.DeleteFunc(slices.Clone(a), func(x string) bool { return slices.Contains(b, x) })
}

func subsetOf(a, of []string) bool {
	for _, x := range a {
		if !slices.Contains(of, x) {
			return false
		}
	}
	return true
}

func union(a, b []string) []string {
	out := slices.Clone(a)
	for _, x := range b {
		if !slices.Contains(out, x) {
			out = append(out, x)
		}
	}
	return out
}

// applied tells the running engine that the entries changed, and waits
// until what it runs follows them.
func (s *keptPlugins) applied(ctx context.Context) {
	if s.changed != nil {
		s.changed(ctx)
	}
}

// keptGroup is the listed agents of one database, in request order: the
// first opens its approval.
type keptGroup struct {
	host, database string
	port           uint16
	install        uuid.UUID
	agents, roles  []string
}

// groups groups agents by the database their credentials connect to, and
// checks each database within 15 seconds, in parallel: it answers
// (DATABASE_UNREACHABLE) and its guard holds plugin approvals
// (GUARD_OUTDATED). Groups whose guard has the same install id are one
// database.
func (s *keptPlugins) groups(ctx context.Context, agents []string) ([]*keptGroup, error) {
	var groups []*keptGroup
	byKey := map[string]*keptGroup{}
	for _, name := range agents {
		a, ok := s.agents[name]
		if !ok {
			return nil, person.Refused(reasonUnknownAgent, fmt.Sprintf("agent %q is not one of this engine's agents; nothing was written", name))
		}
		key := fmt.Sprintf("%s\x00%d\x00%s", a.host, a.port, a.database)
		g, ok := byKey[key]
		if !ok {
			g = &keptGroup{host: a.host, port: a.port, database: a.database}
			byKey[key] = g
			groups = append(groups, g)
		}
		g.agents = append(g.agents, name)
		g.roles = append(g.roles, a.role)
	}
	errs := make([]error, len(groups))
	var wg sync.WaitGroup
	for i, g := range groups {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, keptDatabaseTimeout)
			defer cancel()
			errs[i] = s.checkDatabase(ctx, g)
		})
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		for _, e := range errs {
			if e != nil {
				return nil, e
			}
		}
	}
	out := make([]*keptGroup, 0, len(groups))
	first := map[uuid.UUID]*keptGroup{}
	for _, g := range groups {
		if into, ok := first[g.install]; ok {
			into.agents = append(into.agents, g.agents...)
			into.roles = append(into.roles, g.roles...)
			continue
		}
		first[g.install] = g
		out = append(out, g)
	}
	return out, nil
}

// checkDatabase reads the guard of g's database through its first agent.
func (s *keptPlugins) checkDatabase(ctx context.Context, g *keptGroup) error {
	name := g.agents[0]
	db := s.agents[name].db
	st, err := guard.AgentStatus(ctx, db, guard.Migrations())
	if err != nil {
		return unreachable(name, err)
	}
	if !holdsPluginApprovals(st) {
		return person.Refused(reasonGuardOutdated, fmt.Sprintf(
			"the guard in the database of agent %s is older than schema version %d, which holds plugin approvals; nothing was written. "+
				"Upgrade it with basalt upgrade --agent %s", name, guard.PluginApprovalsVersion, name))
	}
	if g.install, err = guard.InstallID(ctx, db); err != nil {
		return unreachable(name, err)
	}
	return nil
}

func unreachable(agentName string, err error) error {
	why := "it does not answer"
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		why = "it refused: " + pe.Message
	}
	return person.Refused(reasonDatabaseUnreachable, fmt.Sprintf(
		"the database of agent %s cannot be used (%s); nothing was written. Run the command again once it answers", agentName, why))
}

// holdsPluginApprovals reports whether a guard has plugin approvals.
func holdsPluginApprovals(st guard.Status) bool {
	return st.Installed >= guard.PluginApprovalsVersion &&
		!slices.Contains(st.MissingBreaking, guard.PluginApprovalsVersion) &&
		!slices.Contains(st.MissingNonBreaking, guard.PluginApprovalsVersion)
}

// writeOwedEnds writes, in parallel and each within 15 seconds, every
// PLUGIN_DISABLED agents owe for k (guard.OwedPluginEnd). One that cannot be written
// refuses the request: DATABASE_UNREACHABLE.
func (s *keptPlugins) writeOwedEnds(ctx context.Context, k plugin.EntryKey, agents []string) error {
	errs := s.endAll(ctx, k, agents)
	for _, name := range agents {
		if err := errs[name]; err != nil {
			return unreachable(name, err)
		}
	}
	return nil
}

// endAll writes each agent's owed PLUGIN_DISABLED for k, in parallel, and
// returns the error of each agent whose end could not be read or written.
func (s *keptPlugins) endAll(ctx context.Context, k plugin.EntryKey, agents []string) map[string]error {
	var mu sync.Mutex
	errs := map[string]error{}
	var wg sync.WaitGroup
	for _, name := range agents {
		a, ok := s.agents[name]
		if !ok {
			continue
		}
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, keptDatabaseTimeout)
			defer cancel()
			if err := guard.EndPluginApproval(ctx, a.db, k.Name, k.Instance); err != nil {
				s.log.Warn("PLUGIN_DISABLED of an engine-kept plugin not recorded; it is written before the plugin is turned on again",
					"agent", name, "plugin", k.String(), "err", err)
				mu.Lock()
				errs[name] = err
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	return errs
}

// openApprovals opens one approval per group for entry p and copy v, with
// the first agent's credential, naming every agent of the group.
func (s *keptPlugins) openApprovals(ctx context.Context, groups []*keptGroup, p config.Plugin, v plugin.Verified) []person.PluginOpenedApproval {
	out := make([]person.PluginOpenedApproval, len(groups))
	var wg sync.WaitGroup
	for i, g := range groups {
		wg.Go(func() {
			item := person.PluginOpenedApproval{Database: person.PluginDatabase{Host: g.host, Name: g.database}, Agents: slices.Clone(g.agents)}
			ctx, cancel := context.WithTimeout(ctx, keptDatabaseTimeout)
			defer cancel()
			opened, err := guard.OpenPluginApproval(ctx, s.agents[g.agents[0]].db, PluginApprovalDetail(p.Key(), v, g.roles), p.ApprovalSettings())
			if err != nil {
				item.Refused = keptOpenRefusal(err)
			} else {
				id, at := opened.ID, opened.ExpiresAt.UTC()
				item.ApprovalID, item.ExpiresAt, item.BindingText, item.SettingsText = &id, &at, opened.BindingText, opened.SettingsText
			}
			out[i] = item
		})
	}
	wg.Wait()
	return out
}

// keptOpenRefusal maps a failed open_plugin_approval to its reason.
func keptOpenRefusal(err error) *person.PluginOpenRefusal {
	var pe *pgconn.PgError
	r := &person.PluginOpenRefusal{Reason: reasonDatabaseUnreachable, Message: "the database does not answer"}
	switch {
	case errors.As(err, &pe) && pe.Code == "BS007" && pe.Detail == guard.DetailTooManyPending:
		r.Reason, r.Message = reasonTooManyPending, "8 plugin approvals already wait in this database"
	case errors.As(err, &pe) && pe.Code == "BS007" && pe.Detail == guard.DetailUnknownAgent:
		r.Reason, r.Message = reasonUnknownAgent, "a listed agent is not an agent role of this database"
	case errors.As(err, &pe) && pe.Code == sqlstateUndefinedFunction:
		r.Reason, r.Message = reasonGuardOutdated, fmt.Sprintf("the guard is older than schema version %d", guard.PluginApprovalsVersion)
	case errors.As(err, &pe):
		r.Message = pe.Message
	}
	return r
}

// Disable is PLUGIN_DISABLE.
func (s *keptPlugins) Disable(ctx context.Context, scope person.Scope, p person.PluginEntryParams) (person.PluginEntryResult, error) {
	off := false
	err := s.turnOff(ctx, scope, p, false)
	return person.PluginEntryResult{Name: p.Name, Instance: p.Instance, Enabled: &off}, err
}

// Remove is PLUGIN_REMOVE.
func (s *keptPlugins) Remove(ctx context.Context, scope person.Scope, p person.PluginEntryParams) (person.PluginEntryResult, error) {
	gone := true
	err := s.turnOff(ctx, scope, p, true)
	return person.PluginEntryResult{Name: p.Name, Instance: p.Instance, Removed: &gone}, err
}

// turnOff disables or removes an engine-kept entry, stops it, and ends
// every listed agent's signed approval of it. An end that cannot be written
// now is logged: PLUGIN_OPEN writes it before the entry is turned on again.
func (s *keptPlugins) turnOff(ctx context.Context, scope person.Scope, p person.PluginEntryParams, remove bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := plugin.EntryKey{Name: p.Name, Instance: p.Instance}
	verb := "disable"
	if remove {
		verb = "remove"
	}
	if c, ok := s.configEntry(k); ok {
		if !scope.AllowsAll(c.Agents) {
			return notAllowed(k)
		}
		return person.Refused(reasonConfigEntry, fmt.Sprintf(
			"plugin %s is an entry of engine.json; to %s it, edit that file", k, verb))
	}
	entries, err := s.store.Entries(s.cfg)
	if err != nil {
		return storeError(err)
	}
	i := keptIndex(entries, k)
	if i < 0 {
		return &person.Error{Code: person.CodeNotFound, Message: fmt.Sprintf("the engine keeps no plugin %s", k)}
	}
	prev := entries[i]
	if !scope.AllowsAll(prev.Agents) {
		return notAllowed(k)
	}
	if remove || prev.Enabled {
		if err := s.store.Update(s.cfg, func(es []config.Plugin) ([]config.Plugin, error) {
			j := keptIndex(es, k)
			if j < 0 {
				return es, nil
			}
			if remove {
				return slices.Delete(es, j, j+1), nil
			}
			es[j].Enabled = false
			return es, nil
		}); err != nil {
			return storeError(err)
		}
	}
	// Stopped before the ledger says so.
	s.applied(ctx)
	if remove {
		if err := s.store.RemoveCopies(k, ""); err != nil {
			s.log.Warn("the copies of a removed engine-kept plugin could not be removed; the next start removes them", "plugin", k.String(), "err", err)
		}
	}
	s.endAll(ctx, k, prev.Agents)
	return nil
}

// endDisabled writes, at the engine's start, the PLUGIN_DISABLED records
// every disabled engine-kept entry still owes (a disable whose end could
// not be written). One it cannot write now is written before the entry is
// turned on again (Open).
func (s *keptPlugins) endDisabled(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := s.store.Entries(s.cfg)
	if err != nil {
		return
	}
	for _, p := range entries {
		if !p.Enabled {
			s.endAll(ctx, p.Key(), p.Agents)
		}
	}
}

// Approve is PLUGIN_APPROVE: a relay. Each database is asked in parallel,
// through its agents in name order, for the agent that opened the approval
// (the one whose row carries the binding text), and the signature is
// submitted with that agent's credential: Postgres verifies it.
func (s *keptPlugins) Approve(ctx context.Context, p person.PluginApproveParams) (person.PluginApproveResult, error) {
	byDB := map[string][]string{}
	for _, name := range slices.Sorted(maps.Keys(s.agents)) {
		a := s.agents[name]
		key := fmt.Sprintf("%s\x00%d\x00%s", a.host, a.port, a.database)
		byDB[key] = append(byDB[key], name)
	}
	type found struct {
		agent      string
		unanswered bool
	}
	results := make(chan found, len(byDB))
	var wg sync.WaitGroup
	for _, names := range byDB {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, keptDatabaseTimeout)
			defer cancel()
			for _, name := range names {
				r, ok, err := guard.ReadPluginApproval(ctx, s.agents[name].db, p.ApprovalID)
				switch {
				case err != nil && transientErr(err):
					results <- found{unanswered: true}
					return
				case err != nil || !ok:
					continue
				case r.BindingText != "":
					results <- found{agent: name}
					return
				}
			}
			results <- found{}
		})
	}
	wg.Wait()
	close(results)
	opener, unanswered := "", false
	for f := range results {
		if f.agent != "" {
			opener = f.agent
		}
		unanswered = unanswered || f.unanswered
	}
	switch {
	case opener == "" && unanswered:
		return person.PluginApproveResult{}, &person.Error{Code: person.CodeRefused, Message: "DATABASE_UNREACHABLE: no answering database holds plugin approval " +
			p.ApprovalID.String() + ", and one does not answer; try again once it does"}
	case opener == "":
		return person.PluginApproveResult{}, &person.Error{Code: person.CodeNotFound, Message: "no database of this engine holds plugin approval " + p.ApprovalID.String()}
	}
	ctx, cancel := context.WithTimeout(ctx, keptDatabaseTimeout)
	defer cancel()
	at, err := guard.SubmitPluginApproval(ctx, s.agents[opener].db, guard.PluginApprovalResponse{ApprovalID: p.ApprovalID, Assertion: p.Assertion})
	if err != nil {
		return person.PluginApproveResult{}, err
	}
	return person.PluginApproveResult{ApprovalID: p.ApprovalID, Status: string(guard.PluginApprovalStatusApproved), ApprovedAt: at.UTC()}, nil
}

// List is PLUGIN_LIST: config entries, then engine-kept ones, in name and
// instance order; for a scoped peer only entries naming its agents, and
// only those agents.
func (s *keptPlugins) List(ctx context.Context, scope person.Scope) (person.PluginListResult, error) {
	out := person.PluginListResult{Plugins: []person.PluginListed{}}
	cfgEntries := s.configEntries()
	kept, err := s.store.Entries(s.cfg)
	if err != nil {
		out.Problem = err.Error()
		kept = nil
	}
	reader := newKeptApprovalReader(ctx, s, scope, kept)
	for _, p := range cfgEntries {
		if l, ok := s.listed(p, person.SourceConfig, scope, nil); ok {
			out.Plugins = append(out.Plugins, l)
		}
	}
	for _, p := range kept {
		if l, ok := s.listed(p, person.SourceEngine, scope, reader); ok {
			out.Plugins = append(out.Plugins, l)
		}
	}
	slices.SortFunc(out.Plugins, func(a, b person.PluginListed) int {
		return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Instance, b.Instance))
	})
	return out, nil
}

// listed is entry p as PLUGIN_LIST shows it, false when the scope reaches
// none of its agents.
func (s *keptPlugins) listed(p config.Plugin, source string, scope person.Scope, reader *keptApprovalReader) (person.PluginListed, bool) {
	k := p.Key()
	agents := make([]string, 0, len(p.Agents))
	for _, a := range p.Agents {
		if scope.Allows(a) {
			agents = append(agents, a)
		}
	}
	if len(agents) == 0 && (scope != nil || len(p.Agents) > 0) {
		return person.PluginListed{}, false
	}
	l := person.PluginListed{Name: k.Name, Instance: k.Instance, Source: source, Enabled: p.Enabled, Agents: agents, Health: person.HealthNotStarted}
	if s.health != nil {
		l.Health = s.health(k, source == person.SourceEngine)
	}
	mode, trustMode := plugin.ModeService, plugin.ModeService
	var v plugin.Verified
	var root string
	var err error
	if source == person.SourceEngine {
		mode = plugin.ModeSameUser
		v, err = s.store.Verify(k, p.ManifestSHA256)
	} else {
		root, err = plugin.Root(trustMode, s.goos, filepath.Dir(s.configPath))
		if err == nil {
			var trust plugin.TrustStore
			trust, err = plugin.NewTrustStore(trustMode, s.goos, filepath.Dir(s.configPath))
			if err == nil {
				v, err = plugin.Verify(root, k, p.ManifestSHA256, trust, trustMode)
			}
		}
	}
	if err == nil {
		d := pluginDetail(k, v, mode, s.goos)
		l.Version, l.Signer = v.Manifest.Version, string(v.Signer)
		if v.Signer == plugin.SignerKnown {
			l.SignerKeyID = v.SignerKeyID
		}
		l.Endpoint, err = json.Marshal(d.Endpoint)
		if err == nil && d.Isolation != nil {
			l.Isolation, err = json.Marshal(d.Isolation)
		}
	}
	if err != nil {
		// The copy cannot be verified: what the entry is cannot be shown.
		l.Endpoint = json.RawMessage(`{"kind":"LOCAL"}`)
	}
	if source == person.SourceConfig {
		l.Approval = person.PluginListedApproval{Required: false, Agents: []person.PluginAgentStatus{}}
		for _, a := range agents {
			l.Approval.Agents = append(l.Approval.Agents, person.PluginAgentStatus{Agent: a, State: "NOT_REQUIRED"})
		}
		return l, true
	}
	l.Approval = person.PluginListedApproval{Required: true, Agents: []person.PluginAgentStatus{}}
	for _, a := range agents {
		l.Approval.Agents = append(l.Approval.Agents, reader.stateOf(a, k))
	}
	if s.serving != nil {
		for _, sv := range s.serving(k) {
			if scope.Allows(sv.Agent) {
				l.Serving = append(l.Serving, sv)
			}
		}
	}
	return l, true
}

// keptApprovalReader reads, in parallel and each within 15 seconds, the
// newest approvals of every agent an engine-kept entry lists that the scope
// reaches.
type keptApprovalReader struct {
	read map[string][]guard.PluginApprovalRecord
	ok   map[string]bool
}

func newKeptApprovalReader(ctx context.Context, s *keptPlugins, scope person.Scope, kept []config.Plugin) *keptApprovalReader {
	r := &keptApprovalReader{read: map[string][]guard.PluginApprovalRecord{}, ok: map[string]bool{}}
	want := map[string]bool{}
	for _, p := range kept {
		for _, a := range p.Agents {
			if scope.Allows(a) {
				want[a] = true
			}
		}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for name := range want {
		a, ok := s.agents[name]
		if !ok {
			continue
		}
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(ctx, keptDatabaseTimeout)
			defer cancel()
			v, err := guard.AgentVersion(ctx, a.db)
			if err != nil || v < guard.PluginApprovalsVersion {
				return
			}
			recs, err := guard.ReadPluginApprovals(ctx, a.db)
			if err != nil {
				return
			}
			mu.Lock()
			r.read[name], r.ok[name] = recs, true
			mu.Unlock()
		})
	}
	wg.Wait()
	return r
}

// approvalStateUnavailable is an agent whose approvals could not be read.
const approvalStateUnavailable = "UNAVAILABLE"

// stateOf is agent's newest approval of k as PLUGIN_LIST shows it.
func (r *keptApprovalReader) stateOf(agent string, k plugin.EntryKey) person.PluginAgentStatus {
	st := person.PluginAgentStatus{Agent: agent, State: approvalStateUnavailable}
	if !r.ok[agent] {
		return st
	}
	st.State = "NONE"
	for _, a := range r.read[agent] {
		if a.Name != k.Name || a.Instance != k.Instance || !a.NamesCaller {
			continue
		}
		id, at := a.ApprovalID, a.ExpiresAt.UTC()
		switch {
		case a.Status == guard.PluginApprovalStatusApproved && a.Ended():
			st.State = "ENDED"
		case a.Status == guard.PluginApprovalStatusApproved:
			st.State = "APPROVED"
		case a.Status == guard.PluginApprovalStatusPending:
			st.State, st.ExpiresAt = "PENDING", &at
		case a.Status == guard.PluginApprovalStatusExpired:
			st.State = "EXPIRED"
		default:
			return st
		}
		st.ApprovalID = &id
		return st
	}
	return st
}

// openKeptStore opens a service engine's engine-kept plugins in stateDir:
// the uploads an earlier run left are removed and the copies no entry names
// are swept. A store that cannot be opened is logged and nil: no
// engine-kept entry is served, and the person socket answers the plugin
// methods UNKNOWN_METHOD.
func openKeptStore(cfg config.Config, stateDir string, log *slog.Logger) *keptplugins.Store {
	store, err := keptplugins.New(stateDir, time.Now)
	if err != nil {
		log.Error("engine-kept plugins are not served: the state directory cannot hold them", "err", err)
		return nil
	}
	if entries, err := store.Entries(cfg); err != nil {
		log.Error("the engine-kept plugin entries cannot be used", "err", err)
	} else {
		store.Sweep(entries)
	}
	return store
}

// openKeptPlugins serves the person socket's plugin methods on store, nil
// when there is none. A change applies to what ep runs before the method
// answers, and PLUGIN_LIST says what ep serves.
func openKeptPlugins(cfg config.Config, configPath string, store *keptplugins.Store, ep *enginePlugins, agents map[string]keptAgent, log *slog.Logger) *keptPlugins {
	if store == nil {
		return nil
	}
	return &keptPlugins{
		store: store, cfg: cfg, configPath: configPath, agents: agents, euid: engineEUID(), goos: runtimeGOOS(), log: log,
		changed: ep.applyNow, serving: ep.servingOf, health: ep.healthOf,
	}
}

func runtimeGOOS() string { return runtime.GOOS }
