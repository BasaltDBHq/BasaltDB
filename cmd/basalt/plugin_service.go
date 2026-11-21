package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// Plugin commands in service mode without sudo (CONTRACT.md, Plugin
// approval in service mode, Asking): they never read engine.json, the
// state directory or a credential, and call the engine's person socket.

// maxSourceBytes bounds what basalt plugin add reads of a source: the
// upload's own cap.
const maxSourceBytes = 256 << 20

// pluginViaSocket reports whether a plugin command at configPath goes
// through the person socket: the engine runs as a service (its unit is
// installed), the config is the default one, and the command does not run
// as root (with sudo it acts on config entries, as before).
func (c *cliIO) pluginViaSocket(configPath string) bool {
	want := c.engine.configPath
	if want == "" {
		want = c.systemConfig()
	}
	return c.host.Euid() != 0 && c.engine.unitInstalled != nil && configPath == want && c.engine.unitInstalled()
}

// socketPluginEnv is the plugin environment of a service engine reached
// over its person socket: no engine.json, only the engine's pages.
func socketPluginEnv(c *cliIO) (*pluginEnv, error) {
	client := person.Client{Path: c.engine.personSocket}
	pages, err := client.Pages(c.ctx)
	if err != nil {
		return nil, socketError(c, err)
	}
	return &pluginEnv{
		c: c, configPath: cmpOr(c.engine.configPath, c.systemConfig()), cfg: config.Config{Mode: config.ModeService},
		mode: plugin.ModeService, sock: &client, pages: pages,
	}, nil
}

// socketError says what to do when the person socket does not answer.
func socketError(c *cliIO, err error) error {
	uid := os.Getuid()
	switch {
	case errors.Is(err, person.ErrNotRunning):
		return fmt.Errorf("the engine is not running; ask the person to start it (%s), then run this command again", startCommand(c))
	case errors.Is(err, person.ErrUIDNotAllowed):
		return fmt.Errorf("the engine does not let OS user %d use its person socket, so plugins cannot be added from this user; "+
			"a person adds it in a terminal of their own: sudo basalt init --person-uid %d (an agent never runs this)", uid, uid)
	}
	var pe *person.Error
	if errors.As(err, &pe) && pe.Code == person.CodePluginRefused {
		return socketRefusal(pe)
	}
	return err
}

func startCommand(c *cliIO) string {
	cmds, err := (&pluginEnv{c: c, configPath: c.systemConfig(), cfg: config.Config{Mode: config.ModeService}}).commandsFor("")
	if err != nil {
		return "the engine's service"
	}
	return cmds.EngineRestart()
}

// socketRefusal is the engine's PLUGIN_REFUSED as the command prints it:
// the same-user error body with that reason. The engine's message names
// the rule and what to do; the agent stops and the person decides.
func socketRefusal(pe *person.Error) error {
	r := &pluginRefusedError{reason: pe.Reason, message: pe.Message, person: "Basalt did not add or change the plugin: " + pe.Message}
	r.steps = []mcp.NextStep{
		{Actor: mcp.ActorAgent, Action: mcp.ActionStop, Text: "Stop: the engine refused this plugin change; do not work around it."},
		{Actor: mcp.ActorAgent, Action: mcp.ActionAskPerson, Text: "Show the person the personMessage; only they can decide about this plugin."},
	}
	return r
}

// readSource reads a plugin's source directory for an upload: the
// manifest, its .sig when there is one, and every file the manifest lists,
// each a regular file reached through no symlink, as a same-user install
// reads it. Executables are the listed files with an execute bit.
func readSource(dir string) ([]person.PluginFile, []string, plugin.Manifest, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, nil, plugin.Manifest{}, fmt.Errorf("%s cannot be opened as a directory", dir)
	}
	defer func() { _ = root.Close() }()
	var total int64
	read := func(rel string, limit int64) ([]byte, bool, error) {
		parts := strings.Split(rel, "/")
		for i := 1; i <= len(parts); i++ {
			fi, err := root.Lstat(filepath.FromSlash(path.Join(parts[:i]...)))
			if err != nil {
				return nil, false, fmt.Errorf("%s cannot be read", filepath.Join(dir, rel))
			}
			if fi.Mode()&fs.ModeSymlink != 0 {
				return nil, false, fmt.Errorf("%s is a symlink, which a plugin may not hold", filepath.Join(dir, rel))
			}
		}
		f, err := root.OpenFile(filepath.FromSlash(rel), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, false, fmt.Errorf("%s cannot be opened", filepath.Join(dir, rel))
		}
		defer func() { _ = f.Close() }()
		fi, err := f.Stat()
		if err != nil || !fi.Mode().IsRegular() {
			return nil, false, fmt.Errorf("%s is not a regular file", filepath.Join(dir, rel))
		}
		b, err := io.ReadAll(io.LimitReader(f, limit+1))
		if err != nil || int64(len(b)) > limit {
			return nil, false, fmt.Errorf("%s is too large", filepath.Join(dir, rel))
		}
		total += int64(len(b))
		if total > maxSourceBytes {
			return nil, false, fmt.Errorf("the plugin in %s is over %d bytes", dir, maxSourceBytes)
		}
		return b, fi.Mode().Perm()&0o111 != 0, nil
	}
	manifest, _, err := read(plugin.ManifestFile, plugin.MaxManifestBytes)
	if err != nil {
		return nil, nil, plugin.Manifest{}, err
	}
	m, err := plugin.ParseManifest(manifest)
	if err != nil {
		return nil, nil, plugin.Manifest{}, err
	}
	files := []person.PluginFile{{Path: plugin.ManifestFile, Data: manifest}}
	if _, err := root.Lstat(plugin.SignatureFile); err == nil {
		sig, _, err := read(plugin.SignatureFile, plugin.MaxSignatureFileBytes)
		if err != nil {
			return nil, nil, plugin.Manifest{}, err
		}
		files = append(files, person.PluginFile{Path: plugin.SignatureFile, Data: sig})
	}
	var execs []string
	for _, rel := range slices.Sorted(mapKeys(m.Files)) {
		b, exec, err := read(rel, maxSourceBytes)
		if err != nil {
			return nil, nil, plugin.Manifest{}, err
		}
		files = append(files, person.PluginFile{Path: rel, Data: b})
		if exec {
			execs = append(execs, rel)
		}
	}
	return files, execs, m, nil
}

func mapKeys(m map[string]string) func(func(string) bool) {
	return func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}
}

// addViaSocket is basalt plugin add without sudo in service mode: upload,
// open, hand over the links.
func (e *pluginEnv) addViaSocket(f addFlags) error {
	files, execs, m, err := readSource(f.dir)
	if err != nil {
		var ve *plugin.VerifyError
		if errors.As(err, &ve) {
			return e.verifyRefusal(err, e.againAdd(f, f.agents))
		}
		return err
	}
	id, err := e.sock.PluginUpload(e.c.ctx, files)
	if err != nil {
		return socketError(e.c, err)
	}
	k := plugin.EntryKey{Name: m.Name, Instance: f.instance}
	res, err := e.sock.PluginOpen(e.c.ctx, person.PluginOpenParams{UploadID: &id, Name: k.Name, Instance: k.Instance, Agents: f.agents, Executables: execs})
	if err != nil {
		return socketError(e.c, err)
	}
	return e.openedViaSocket(k, res, f.wait, f.asJSON)
}

// enableViaSocket is basalt plugin enable without sudo: a new approval for
// the installed copy and the entry's agents.
func (e *pluginEnv) enableViaSocket(k plugin.EntryKey, wait int, asJSON bool) error {
	l, err := e.socketEntry(k)
	if err != nil {
		return err
	}
	res, err := e.sock.PluginOpen(e.c.ctx, person.PluginOpenParams{Name: k.Name, Instance: k.Instance, Agents: l.Agents})
	if err != nil {
		return socketError(e.c, err)
	}
	return e.openedViaSocket(k, res, wait, asJSON)
}

// socketEntry is the engine-kept entry k as PLUGIN_LIST shows it.
func (e *pluginEnv) socketEntry(k plugin.EntryKey) (person.PluginListed, error) {
	list, err := e.sock.PluginList(e.c.ctx)
	if err != nil {
		return person.PluginListed{}, socketError(e.c, err)
	}
	for _, l := range list.Plugins {
		if l.Name == k.Name && l.Instance == k.Instance {
			if l.Source == person.SourceConfig {
				return l, fmt.Errorf("plugin %s was added with sudo; change it with sudo basalt plugin", k)
			}
			return l, nil
		}
	}
	return person.PluginListed{}, fmt.Errorf("the engine keeps no plugin %s; basalt plugin list shows the entries, basalt plugin add <dir> --agents NAME,... adds one", k)
}

// openedViaSocket builds, from PLUGIN_OPEN's result, what the same-user
// command prints: the links, personMessage and nextSteps.
func (e *pluginEnv) openedViaSocket(k plugin.EntryKey, res person.PluginOpenResult, wait int, asJSON bool) error {
	if res.Narrowed {
		fmt.Fprintf(e.c.stderr, "basalt: plugin %s now serves only the agents named; nothing to approve, the engine applied it\n", k)
		return nil
	}
	items := make([]openedApproval, 0, len(res.Approvals))
	for _, a := range res.Approvals {
		g := &approvalGroup{host: a.Database.Host, database: a.Database.Name, agents: a.Agents}
		o := openedApproval{group: g}
		if a.Refused != nil {
			o.refused = &approvalRefused{Code: codePluginRefused, Reason: a.Refused.Reason, Message: a.Refused.Message}
			items = append(items, o)
			continue
		}
		if keys, err := e.sock.Agent(g.opener()).ListPasskeys(e.c.ctx); err == nil {
			for _, key := range keys {
				g.passkeys = append(g.passkeys, key.Credential)
			}
		}
		o.opened = guard.PluginApproval{ID: *a.ApprovalID, BindingText: a.BindingText, SettingsText: a.SettingsText, ExpiresAt: *a.ExpiresAt}
		b, err := approval.ParsePluginBinding(a.BindingText)
		if err == nil {
			o.binding = b
			o.url, o.file, err = e.socketLink(g, o.opened)
		}
		if err != nil {
			o.refused = &approvalRefused{Code: codePluginRefused, Reason: reasonDatabaseUnreachable, Message: "the approval was opened but no link could be made: " + err.Error()}
		}
		items = append(items, o)
	}
	out, err := e.approvalOutcome(k, res.Version, items)
	if err != nil {
		return err
	}
	return e.handOverOrWait(k, out, wait, asJSON)
}

// socketLink is the approval's link: a short link through the engine's
// local pages when they answer, else the long link, or the hash link with
// its request file past the link budget.
func (e *pluginEnv) socketLink(g *approvalGroup, opened guard.PluginApproval) (string, *links.RequestFile, error) {
	ids := make([]passkey.Bytes, 0, len(g.passkeys))
	for _, k := range g.passkeys {
		ids = append(ids, k.ID)
	}
	base := e.pages.PagesURL
	if base == "" {
		base = links.DefaultLocal
	}
	long, err := approval.PluginRequest{ApprovalID: opened.ID, Binding: opened.BindingText, Settings: opened.SettingsText, CredentialIDs: ids}.URL(base)
	if err != nil {
		return "", nil, err
	}
	local := ""
	if e.pages.LocalOrigin != "" && e.c.host.PagesUp(e.c.ctx, e.pages.LocalOrigin) {
		local = e.pages.LocalOrigin
	}
	if link := (linkPages{base: base, local: local}).short(e.c, "plugins", opened.ID, opened.BindingText, long); link != long {
		return link, nil, nil
	}
	if len(long) <= e.cfg.LinkBudgetOrDefault() {
		return long, nil, nil
	}
	hash, file, err := links.HashLink(long, links.PluginFile(opened.ID))
	if err != nil {
		return "", nil, err
	}
	return hash, &file, nil
}

// turnOffViaSocket is disable or remove without sudo.
func (e *pluginEnv) turnOffViaSocket(k plugin.EntryKey, remove bool) error {
	p := person.PluginEntryParams{Name: k.Name, Instance: k.Instance}
	var err error
	if remove {
		_, err = e.sock.PluginRemove(e.c.ctx, p)
	} else {
		_, err = e.sock.PluginDisable(e.c.ctx, p)
	}
	if err != nil {
		var pe *person.Error
		if errors.As(err, &pe) && pe.Code == person.CodeNotFound {
			return fmt.Errorf("%s", pe.Message)
		}
		return socketError(e.c, err)
	}
	verb := "disabled"
	if remove {
		verb = "removed"
	}
	fmt.Fprintf(e.c.stderr, "basalt: plugin %s %s; the engine stopped it, and turning it on again needs a new approval\n", k, verb)
	return nil
}

// listViaSocket is basalt plugin list without sudo: config entries and the
// engine's own, as PLUGIN_LIST gives them.
func (e *pluginEnv) listViaSocket(asJSON bool) error {
	list, err := e.sock.PluginList(e.c.ctx)
	if err != nil {
		return socketError(e.c, err)
	}
	if asJSON {
		type item struct {
			listedEntry
			Source    string          `json:"source"`
			Isolation json.RawMessage `json:"isolation,omitempty"`
			Health    string          `json:"health"`
		}
		out := struct {
			Plugins []item `json:"plugins"`
			Problem string `json:"problem,omitempty"`
		}{Plugins: []item{}, Problem: list.Problem}
		for _, l := range list.Plugins {
			out.Plugins = append(out.Plugins, item{listedEntry: listedEntry{Name: l.Name, Instance: l.Instance, Enabled: l.Enabled, Agents: l.Agents, Approval: socketApproval(l)}, Source: l.Source, Isolation: l.Isolation, Health: l.Health})
		}
		printJSONValue(e.c, out)
		return nil
	}
	if list.Problem != "" {
		fmt.Fprintf(e.c.stderr, "basalt: %s\n", terminalText(list.Problem))
	}
	if len(list.Plugins) == 0 {
		fmt.Fprintln(e.c.stderr, "basalt: no plugins; add one with basalt plugin add <dir> --agents NAME,...")
		return nil
	}
	w := e.c.stdout
	for _, l := range list.Plugins {
		state, kind := "disabled", "engine-kept"
		if l.Enabled {
			state = "enabled"
		}
		if l.Source == person.SourceConfig {
			kind = "added with sudo"
		}
		fmt.Fprintf(w, "%s  instance %s  %s  %s\n", l.Name, l.Instance, state, kind)
		fmt.Fprintf(w, "  version %s  signer %s  endpoint %s  isolation %s  health %s\n",
			visibleText(l.Version), visibleText(l.Signer), visibleText(string(l.Endpoint)), socketIsolation(l), visibleText(l.Health))
		fmt.Fprintf(w, "  agents %s\n", listText(l.Agents, "none"))
		writeApproval(e, socketApproval(l))
	}
	return nil
}

// socketIsolation is a listed entry's isolation as the engine reports it.
// A remote entry runs on another host and has none; a local entry whose
// installed copy the engine cannot verify has none to report.
func socketIsolation(l person.PluginListed) string {
	var iso struct {
		Files   string `json:"files"`
		Network string `json:"network"`
	}
	if len(l.Isolation) > 0 && json.Unmarshal(l.Isolation, &iso) == nil && iso.Files != "" {
		return "files " + visibleText(iso.Files) + ", network " + visibleText(iso.Network)
	}
	var endpoint struct {
		Kind string `json:"kind"`
	}
	if json.Unmarshal(l.Endpoint, &endpoint) == nil && endpoint.Kind == "REMOTE" {
		return "none (remote)"
	}
	return "unknown (the installed copy cannot be verified)"
}

func socketApproval(l person.PluginListed) entryApproval {
	out := entryApproval{Required: l.Approval.Required, Agents: []agentApproval{}}
	for _, a := range l.Approval.Agents {
		item := agentApproval{Agent: a.Agent, State: a.State}
		if a.ApprovalID != nil {
			item.ApprovalID = a.ApprovalID.String()
		}
		if a.ExpiresAt != nil {
			item.ExpiresAt = a.ExpiresAt.UTC().Format(time.RFC3339)
		}
		out.Agents = append(out.Agents, item)
	}
	return out
}

// approveViaSocket relays a basalt-plugin.1. code to the engine, which
// submits it with the opener's credential: Postgres verifies it.
func (e *pluginEnv) approveViaSocket(resp approval.PluginApprovalResponse, asJSON bool) error {
	res, err := e.sock.PluginApprove(e.c.ctx, person.NewPluginApproveParams(resp.ApprovalID, resp.Assertion()))
	if err != nil {
		return socketError(e.c, err)
	}
	if asJSON {
		printJSONValue(e.c, approvedJSON{ApprovalID: res.ApprovalID.String(), Status: res.Status, ApprovedAt: res.ApprovedAt.UTC()})
		return nil
	}
	fmt.Fprintf(e.c.stderr, "basalt: plugin approval %s signed; the engine starts the plugin within seconds\n", res.ApprovalID)
	return nil
}

// waitViaSocket is waitForRunning in service mode: the approvals' states
// and what the engine serves, from PLUGIN_LIST, about once a second. A
// list that cannot be read decides nothing; an engine that is not running
// ends it NOT_RUNNING once every approval is signed.
func (e *pluginEnv) waitViaSocket(k plugin.EntryKey, ids []uuid.UUID, d time.Duration) (waitResult, error) {
	deadline := e.c.now().Add(d)
	var last *person.PluginListed
	for {
		ctx, cancel := context.WithDeadline(e.c.ctx, deadline.Add(waitPoll))
		list, err := e.sock.PluginList(ctx)
		cancel()
		eng := engineOut{Reachable: err == nil}
		switch {
		case errors.Is(err, person.ErrNotRunning):
		case err != nil:
			eng.Unknown = true
		default:
			last = nil
			for i := range list.Plugins {
				if list.Plugins[i].Name == k.Name && list.Plugins[i].Instance == k.Instance && list.Plugins[i].Source == person.SourceEngine {
					last = &list.Plugins[i]
				}
			}
			if last == nil {
				return waitResult{}, fmt.Errorf("the engine keeps no plugin %s, so there is no approval to wait for", k)
			}
		}
		approvals, signed, open := socketWaitStates(ids, last)
		served := last != nil && eng.Reachable && socketServedOn(last, approvals)
		switch {
		case !open:
			return e.waitOutcome(k, waitEnded, approvals, eng)
		case signed && served:
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

// socketWaitStates is each approval's state from what PLUGIN_LIST said of
// the entry's agents: an approval is the newest one of the agents whose
// approvalId it is; an agent whose state could not be read decides
// nothing. signed: every approval signed for every agent it names, every
// agent read; open: none expired, replaced or ended.
func socketWaitStates(ids []uuid.UUID, l *person.PluginListed) ([]waitApproval, bool, bool) {
	out := make([]waitApproval, 0, len(ids))
	if l == nil {
		for _, id := range ids {
			out = append(out, waitApproval{ApprovalID: id.String(), State: stateNone, Agents: []string{}})
		}
		return out, false, true
	}
	allRead := !slices.ContainsFunc(l.Approval.Agents, func(a person.PluginAgentStatus) bool { return a.State == stateUnavailable })
	signed, open := allRead, true
	for _, id := range ids {
		w := waitApproval{ApprovalID: id.String(), State: stateCancelled, Agents: []string{}}
		for _, a := range l.Approval.Agents {
			if a.ApprovalID == nil || *a.ApprovalID != id {
				continue
			}
			w.Agents = append(w.Agents, a.Agent)
			switch {
			case a.State == stateEnded || w.State == stateEnded:
				w.State = stateEnded
			case a.State == statePending || w.State == statePending:
				w.State = statePending
			case a.State == stateApproved:
				w.State = stateApproved
			default:
				w.State = stateExpired
			}
		}
		if len(w.Agents) == 0 && !allRead {
			w.State = stateNone
		}
		switch w.State {
		case stateApproved:
		case statePending, stateNone:
			signed = false
		default:
			signed, open = false, false
		}
		out = append(out, w)
	}
	return out, signed, open
}

// socketServedOn: the engine serves the entry, READY, to every agent an
// approval names, on that approval.
func socketServedOn(l *person.PluginListed, approvals []waitApproval) bool {
	for _, a := range approvals {
		for _, name := range a.Agents {
			if !slices.ContainsFunc(l.Serving, func(s person.PluginServing) bool {
				return s.Agent == name && s.Ready && s.ApprovalID != nil && s.ApprovalID.String() == a.ApprovalID
			}) {
				return false
			}
		}
	}
	return true
}

// refuseKeptName refuses, for sudo basalt plugin on a service engine, a
// (name, instance) the engine keeps itself (NAME_TAKEN): k for enable,
// disable and remove, or the plugin in dir with instance for add. It reads
// only the entries' names from the engine's entries file: a regular file
// with one link, not followed through a symlink, of at most 1 MiB, owned by
// the config directory's owner (the engine's user). Any other file refuses
// (UNSAFE_PATH). Same-user mode and a file that does not exist pass.
func (e *pluginEnv) refuseKeptName(k plugin.EntryKey, dir, instance string) error {
	if !e.cfg.Service() || e.c.host.Euid() != 0 {
		return nil
	}
	if dir != "" {
		// A manifest that cannot be read is add's to refuse, with its own
		// reason.
		m, ok := sourceManifest(dir)
		if !ok {
			return nil
		}
		k = plugin.EntryKey{Name: m.Name, Instance: instance}
	}
	file := filepath.Join(e.cfg.StateDirFor(e.c.goos), keptEntriesFile)
	names, err := keptNames(file, filepath.Dir(e.configPath))
	if err != nil {
		return &pluginRefusedError{
			reason: reasonUnsafePath, message: err.Error() + ". Nothing was written",
			person: "Basalt could not read which plugins the engine keeps itself: " + err.Error(),
			steps:  []mcp.NextStep{{Actor: mcp.ActorAgent, Action: mcp.ActionStop, Text: "Stop: the person checks the engine's state directory."}},
		}
	}
	if !slices.Contains(names, k) {
		return nil
	}
	again := strings.Join(append([]string{"basalt plugin remove"}, entryArgs(k)...), " ")
	return &pluginRefusedError{
		reason:  reasonNameTaken,
		message: fmt.Sprintf("plugin %s is one the engine keeps itself, added without sudo; nothing was written", k),
		person:  "The engine keeps this plugin itself. Change it without sudo, or remove it first: " + again,
		steps: []mcp.NextStep{
			{Actor: mcp.ActorAgent, Action: mcp.ActionStop, Text: "Stop: this plugin is one the engine keeps itself."},
			{Actor: mcp.ActorAgent, Action: mcp.ActionAskPerson, Text: "Show the person the personMessage; only they can decide about this plugin."},
		},
	}
}

// keptEntriesFile is the engine's entries file in its state directory.
const keptEntriesFile = "plugins.json"

// reasonNameTaken: a (name, instance) the other kind of entry holds.
const reasonNameTaken = "NAME_TAKEN"

// keptNames reads the (name, instance)s of the engine's entries file, as
// refuseKeptName says. A missing file holds none.
func keptNames(file, configDir string) ([]plugin.EntryKey, error) {
	f, err := os.OpenFile(file, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s cannot be opened, or is a symlink", file)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%s cannot be read", file)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	var ost *syscall.Stat_t
	if owner, err := os.Stat(configDir); err == nil {
		ost, _ = owner.Sys().(*syscall.Stat_t)
	}
	switch {
	case !fi.Mode().IsRegular() || !ok || st.Nlink != 1:
		return nil, fmt.Errorf("%s is not a regular file with one link", file)
	case ost == nil || st.Uid != ost.Uid:
		return nil, fmt.Errorf("%s is not owned by the engine's OS user", file)
	case fi.Size() > 1<<20:
		return nil, fmt.Errorf("%s is over 1 MiB", file)
	}
	raw, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, fmt.Errorf("%s cannot be read", file)
	}
	var entries []struct {
		Name     string `json:"name"`
		Instance string `json:"instance"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("%s is not a JSON array of plugin entries", file)
	}
	out := make([]plugin.EntryKey, 0, len(entries))
	for _, p := range entries {
		out = append(out, plugin.EntryKey{Name: p.Name, Instance: p.Instance})
	}
	return out, nil
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// sourceManifest is the manifest in dir, false when it cannot be read or
// parsed.
func sourceManifest(dir string) (plugin.Manifest, bool) {
	raw, err := readManifest(dir)
	if err != nil {
		return plugin.Manifest{}, false
	}
	m, err := plugin.ParseManifest(raw)
	return m, err == nil
}
