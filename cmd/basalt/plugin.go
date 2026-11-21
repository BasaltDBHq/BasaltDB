package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/person"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// basalt plugin: the person's commands for plugins (CONTRACT.md, Plugins,
// Consent). add and enable show what the plugin may see and where it runs,
// and write engine.json only after the person says yes. Under an agent
// marker, or on an engine an agent operates, add, enable, any widening
// change are refused before anything is written; disable and
// remove stay allowed, since they only narrow.

// pluginUsage names every flag each command takes; a test holds it to that.
const pluginUsage = "basalt plugin list [--json] | " +
	"add <dir> --agents a,b [--instance NAME] [--approve-with-passkey] [--wait SECONDS] [--json] | " +
	"enable <name> [--instance NAME] [--approve-with-passkey] [--approval-id ID[,ID]] [--wait SECONDS] [--json] | " +
	"approve [code] [--agent NAME] [--json] | " +
	"disable <name> [--instance NAME] | check <name> [--instance NAME] [--json] | " +
	"remove <name> [--instance NAME]"

// runPlugin: basalt plugin <command>.
func runPlugin(c *cliIO, args []string) int {
	if len(args) == 0 || helpAsked(args[:1]) {
		return c.fail(fmt.Errorf("%w: %s", errUsage, pluginUsage))
	}
	cmds := map[string]func(*cliIO, []string) int{
		"list": pluginList, "add": pluginAdd, "enable": pluginEnable, "disable": pluginDisable,
		"remove": pluginRemove, "check": pluginCheck, "approve": pluginApprove,
	}
	if run, ok := cmds[args[0]]; ok {
		return run(c, args[1:])
	}
	return c.fail(fmt.Errorf("%w: unknown plugin command %q; %s", errUsage, args[0], pluginUsage))
}

// codePluginRefused is the error code of a refused basalt plugin command.
const codePluginRefused = "PLUGIN_REFUSED"

// Reasons of PLUGIN_REFUSED besides the verification ones
// (plugin.RefusedBadManifest, plugin.RefusedNotTrusted).
const (
	reasonAgentOperated = "AGENT_OPERATED"
	reasonUnknownAgent  = "UNKNOWN_AGENT"
	// reasonUnsafePath: a NOT_TRUSTED verification failure of the path rule
	// (who can write a path, a symlink, an owner), which no key fixes.
	reasonUnsafePath = "UNSAFE_PATH"
)

// pluginRefusedError is a PLUGIN_REFUSED error: a basalt plugin command refused,
// with nothing written. --json prints it as the error body.
type pluginRefusedError struct {
	reason, message, person string
	steps                   []mcp.NextStep
}

func (r *pluginRefusedError) Error() string { return r.message + "\n" + r.person }

func (r *pluginRefusedError) body() *mcp.ToolError {
	return &mcp.ToolError{
		Code: codePluginRefused, Reason: r.reason, Message: r.message,
		PersonMessage: r.person, NextSteps: r.steps, DocsURL: mcp.DocsURL(codePluginRefused),
	}
}

// pluginDone ends a plugin command: a refusal as the JSON error body with
// asJSON, any other error as usual.
func (c *cliIO) pluginDone(err error, asJSON bool) int {
	if err == nil {
		return exitOK
	}
	var r *pluginRefusedError
	if asJSON && errors.As(err, &r) {
		printJSONValue(c, r.body())
		return exitError
	}
	return c.fail(err)
}

// pluginEnv is what every plugin command reads first: engine.json, the
// plugin root and the trust store of its mode.
type pluginEnv struct {
	c          *cliIO
	configPath string
	cfg        config.Config
	// ec reads the agents' credentials, for the approval flow.
	ec    engineConfig
	mode  plugin.Mode
	root  string
	trust plugin.TrustStore
	// sock is the engine's person socket when the command runs in service
	// mode without sudo (plugin_service.go), with the engine's pages; nil
	// otherwise.
	sock  *person.Client
	pages person.PagesDTO
}

func loadPluginEnv(c *cliIO, configPath string) (*pluginEnv, error) {
	abs, err := filepath.Abs(configPath)
	if err != nil {
		return nil, err
	}
	ec, err := loadEngineConfig(c, abs)
	if err != nil {
		return nil, err
	}
	cfg := ec.Config
	mode := plugin.ModeSameUser
	if cfg.Service() {
		mode = plugin.ModeService
	}
	dir := filepath.Dir(abs)
	root, err := plugin.Root(mode, c.goos, dir)
	if err != nil {
		return nil, err
	}
	trust, err := plugin.NewTrustStore(mode, c.goos, dir)
	if err != nil {
		return nil, err
	}
	return &pluginEnv{c: c, configPath: abs, cfg: cfg, ec: ec, mode: mode, root: root, trust: trust}, nil
}

// command is a complete basalt plugin command for this engine.
func (e *pluginEnv) command(sub string, args ...string) string {
	return strings.Join(append([]string{"basalt plugin", sub}, args...), " ")
}

// entryArgs are a command's arguments naming entry k.
func entryArgs(k plugin.EntryKey) []string {
	if k.Instance == plugin.DefaultInstance {
		return []string{k.Name}
	}
	return []string{k.Name, "--instance", k.Instance}
}

// errNeedsSudo: in service mode the plugin root, the trust store and
// engine.json are root's or the engine user's.
func (e *pluginEnv) needsSudo(sub string) error {
	if !e.cfg.Service() || e.c.host.Euid() == 0 {
		return nil
	}
	return fmt.Errorf("this engine runs as a service, so basalt plugin %s writes files only root may write; run it with sudo", sub)
}

// refuseAgentOperated is the AGENT_OPERATED refusal when an agent marker is
// set here or cfg says an agent operates the engine, else nil. again is the
// refused command, for the person to run themselves.
func (e *pluginEnv) refuseAgentOperated(cfg config.Config, sub, again string) error {
	marker := e.c.agentMarker()
	if marker == "" && !cfg.AgentOperated() {
		return nil
	}
	r := &pluginRefusedError{reason: reasonAgentOperated}
	switch {
	case cfg.AgentOperated():
		r.message = fmt.Sprintf("basalt plugin %s is refused: this engine is operatedBy AGENT, so a prompt answered on this machine "+
			"is no proof that a person consented. Nothing was written", sub)
		r.person = "With sudo, plugins cannot be added or enabled on an engine an agent operates. " +
			"Without sudo, basalt plugin add and enable open an approval that you sign with your passkey. " +
			"Disabling and removing a plugin still work."
	default:
		r.message = fmt.Sprintf("basalt plugin %s is refused: %s is set, so an agent is running it. An agent never adds, enables or "+
			"widens a plugin. Nothing was written", sub, marker)
		r.person = "Adding, enabling or widening a plugin needs your consent. " +
			"Run this in a terminal of your own, which no agent reads:\n  " + again
	}
	r.steps = []mcp.NextStep{
		{Actor: mcp.ActorAgent, Action: mcp.ActionStop, Text: "Stop: an agent never adds, enables or widens a plugin."},
		{Actor: mcp.ActorAgent, Action: mcp.ActionAskPerson, Text: "Show the person the personMessage; only they can decide about this plugin."},
	}
	return r
}

// verifyRefusal maps a verification failure to its PLUGIN_REFUSED reason;
// any other error is returned as it is.
func (e *pluginEnv) verifyRefusal(err error, again string) error {
	var ve *plugin.VerifyError
	if !errors.As(err, &ve) {
		return err
	}
	r := &pluginRefusedError{reason: string(ve.Reason), message: "the plugin is refused: " + ve.Error() + ". Nothing was written"}
	if ve.Reason == plugin.RefusedBadManifest {
		r.person = "The plugin was refused because its manifest breaks a rule (" + ve.Why + "). Its publisher must fix the manifest."
		r.steps = []mcp.NextStep{{Actor: mcp.ActorAgent, Action: mcp.ActionStop, Text: "Stop: the plugin's publisher must fix its manifest."}}
		return r
	}
	if ve.Path != nil {
		return pathRuleRefusal(r, ve, again)
	}
	r.person = "The plugin failed verification: " + ve.File + " " + ve.Why + ". Nothing was written."
	stop := "Stop: the plugin failed verification."
	if ve.Why == plugin.WhyKeyNotTrusted {
		r.person = "The plugin was refused: " + ve.File + " " + ve.Why + ", so it is not signed by a key this engine trusts. Nothing was written."
		stop = "Stop: the plugin is not signed by a key this engine trusts."
	}
	r.steps = []mcp.NextStep{{Actor: mcp.ActorAgent, Action: mcp.ActionStop, Text: stop}}
	return r
}

// checkAgents refuses an agent that is not one of the engine's
// (UNKNOWN_AGENT), naming the command again with only the known ones.
func (e *pluginEnv) checkAgents(cfg config.Config, agents []string, again func([]string) string) error {
	known := make([]string, 0, len(agents))
	var unknown string
	for _, a := range agents {
		if cfg.HasAgent(a) {
			known = append(known, a)
		} else if unknown == "" {
			unknown = a
		}
	}
	if unknown == "" {
		return nil
	}
	cmd := again(known)
	return &pluginRefusedError{
		reason:  reasonUnknownAgent,
		message: fmt.Sprintf("the plugin is refused: agent %q is not one of this engine's agents. Nothing was written", unknown),
		person: fmt.Sprintf("%q is not an agent of this engine (its agents: %s). Name only its agents:\n  %s",
			unknown, strings.Join(agentNames(cfg), ", "), cmd),
		steps: []mcp.NextStep{{Actor: mcp.ActorPerson, Action: mcp.ActionRunCommand, Text: "Run the command with --agents naming only this engine's agents.", Command: cmd}},
	}
}

func agentNames(cfg config.Config) []string {
	names := make([]string, 0, len(cfg.Agents))
	for _, a := range cfg.Agents {
		names = append(names, a.Name)
	}
	return names
}

// update writes engine.json under its lock: as root through the config
// directory opened without following a link, else by path.
func (e *pluginEnv) update(ch config.Change) error {
	if e.c.host.Euid() != 0 {
		return config.UpdateConfig(e.configPath, ch)
	}
	dir := filepath.Dir(e.configPath)
	trusted, err := rootTrustedOwner(dir)
	if err != nil {
		return err
	}
	d, err := openRootConfigDir(dir, trusted)
	if err != nil {
		return err
	}
	defer d.close()
	return d.update(filepath.Base(e.configPath), ch)
}

// restart prints the command that makes the engine read engine.json again.
func (e *pluginEnv) restart() { e.restartSo("it reads engine.json again") }

// restartSo prints the engine restart command and why it is needed.
func (e *pluginEnv) restartSo(why string) {
	if len(e.cfg.Agents) == 0 {
		return
	}
	cmds, err := agent.NewCommands(e.cfg.Agents[0].Name, e.configPath, e.c.goos, nil)
	if err != nil {
		return
	}
	if !e.cfg.Service() {
		cmds = cmds.Foreground()
	}
	fmt.Fprintf(e.c.stderr, "basalt: restart the engine so %s:\n  %s\n", why, cmds.EngineRestart())
}

// narrowed says when a change that only narrows (disable, remove, an agent
// removed) takes effect: in same-user mode the running engine applies it
// within seconds (CONTRACT.md, Plugin changes while the engine runs); a
// service engine reads engine.json at start, so it prints the restart.
func (e *pluginEnv) narrowed() {
	if e.cfg.Service() {
		e.restart()
		return
	}
	fmt.Fprintln(e.c.stderr, "basalt: a running engine applies this within a few seconds; no restart is needed")
}

// errChangedMeanwhile: engine.json changed between what the person was
// shown and the write.
var errChangedMeanwhile = errors.New("engine.json changed while you were asked; nothing was written. Run the command again")

// errNoChange ends a write that would change nothing.
var errNoChange = errors.New("nothing to change")

// errDeclined: the person did not say yes.
var errDeclined = errors.New("you did not confirm; nothing was written")

// ask asks the consent question; no answer is no.
func (e *pluginEnv) ask(question string) error {
	ok, err := e.c.confirm(question)
	if err != nil || !ok {
		return errDeclined
	}
	return nil
}

// positionalLast moves the first argument that is neither a flag nor a
// flag's value to the end, after "--", so flags may follow it.
func positionalLast(fs *flag.FlagSet, args []string) []string {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return args
		case takesSeparateValue(fs, a):
			i++
		case !strings.HasPrefix(a, "-") || a == "-":
			rest := append(append([]string{}, args[:i]...), args[i+1:]...)
			return append(rest, "--", a)
		}
	}
	return args
}

// parseOne parses args with exactly one positional argument, what.
func parseOne(fs *flag.FlagSet, args []string, what string) (string, error) {
	if err := fs.Parse(positionalLast(fs, args)); err != nil {
		return "", fmt.Errorf("%w: %w", errUsage, err)
	}
	if fs.NArg() != 1 {
		return "", fmt.Errorf("%w: give %s; %s", errUsage, what, pluginUsage)
	}
	return fs.Arg(0), nil
}

// instanceFlag adds --instance, checked by checkInstance.
func instanceFlag(fs *flag.FlagSet) *string {
	return fs.String("instance", plugin.DefaultInstance, "the entry's instance: lowercase letters, digits and _, starting with a letter")
}

func checkInstance(inst string) error {
	if !validInstance(inst) {
		return fmt.Errorf("%w: --instance must be lowercase letters, digits and _, starting with a letter, at most 32", errUsage)
	}
	return nil
}

func validInstance(s string) bool {
	if len(s) == 0 || len(s) > 32 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	return strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789_") == ""
}

// --- consent ---

// pluginFacts is what the consent screen shows of a verified copy.
type pluginFacts struct {
	version, publisher, signer string
	remote                     bool
	host                       string
	hooks, roles, types        []string
	egress                     []string
}

func factsOf(v plugin.Verified) pluginFacts {
	m := v.Manifest
	f := pluginFacts{version: m.Version, publisher: m.Publisher, signer: v.SignerKeyID, remote: m.Endpoint.IsRemote(), egress: slices.Clone(m.Network.Egress)}
	if f.remote {
		f.host, _ = plugin.RemoteHostPort(m.Endpoint.Remote.URL)
	}
	for name, decl := range m.Hooks {
		f.hooks = append(f.hooks, name)
		f.types = append(f.types, decl.EntityTypes...)
		if plugin.Hook(name) == plugin.HookWireDetect {
			f.roles = append(f.roles, decl.Roles...)
		}
	}
	for _, l := range [][]string{f.hooks, f.roles, f.types, f.egress} {
		sort.Strings(l)
	}
	f.types = slices.Compact(f.types)
	return f
}

func (f pluginFacts) has(h plugin.Hook) bool { return slices.Contains(f.hooks, string(h)) }

func (f pluginFacts) endpoint() string {
	if f.remote {
		return "REMOTE at " + visibleText(f.host) + " (runs on another host)"
	}
	return "LOCAL (runs on this machine)"
}

// listText is the escaped items, or none.
func listText(items []string, none string) string {
	if len(items) == 0 {
		return none
	}
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = visibleText(s)
	}
	return strings.Join(out, ", ")
}

// writeConsent shows the person what the plugin may see and where it
// runs, from the verified copy, with the warnings the contract requires in
// plain words. Every manifest string is escaped: the manifest is the
// publisher's text and must not draw on the screen.
func writeConsent(w io.Writer, k plugin.EntryKey, v plugin.Verified, agents []string, mode plugin.Mode) {
	f := factsOf(v)
	fmt.Fprintf(w, "Plugin %s %s from %s, instance %s\n", k.Name, visibleText(f.version), visibleText(f.publisher), k.Instance)
	fmt.Fprintf(w, "  Signer:       %s\n", f.signer)
	fmt.Fprintf(w, "  Endpoint:     %s\n", f.endpoint())
	hooks := listText(f.hooks, "none")
	if len(f.roles) > 0 {
		hooks += " (roles " + listText(f.roles, "") + ")"
	}
	fmt.Fprintf(w, "  Hooks:        %s\n", hooks)
	fmt.Fprintf(w, "  Entity types: %s\n", listText(f.types, "none"))
	fmt.Fprintf(w, "  Egress:       %s\n", listText(f.egress, "none"))
	fmt.Fprintf(w, "  Agents:       %s\n", listText(agents, "none (the entry serves no agent)"))
	for _, warn := range consentWarnings(f, mode) {
		fmt.Fprintf(w, "  ! %s\n", warn)
	}
}

// deliverConsent is the fixed sentence for approval.deliver, the same words
// as the plugin approval page's (CONTRACT.md, Consent and The plugin
// approval page).
const deliverConsent = "It delivers your approval links. Anyone who can read where it delivers them can see the rows of writes waiting for your approval. Some links carry the whole request, so they can also see what the agent asked to run and why."

func consentWarnings(f pluginFacts, mode plugin.Mode) []string {
	var out []string
	if f.remote {
		out = append(out, "REMOTE: its signature proves who published this endpoint, egress and hooks, not what runs on "+
			visibleText(f.host)+"; what the plugin is sent leaves this machine.")
		if f.has(plugin.HookWireDetect) && slices.Contains(f.roles, plugin.RoleNameCue) {
			out = append(out, "This remote detector declares NAME_CUE: it sees stored values in free text, so with it those values leave this machine.")
		}
	}
	if f.has(plugin.HookApprovalDeliver) {
		out = append(out, "approval.deliver: "+deliverConsent)
	}
	if !f.remote && len(f.egress) > 0 {
		out = append(out, "This local plugin runs with network access: its egress list is declared, not enforced per host.")
	}
	if !f.remote && mode != plugin.ModeService {
		out = append(out, "Same-user mode: the plugin runs as you and can read whatever the engine can.")
	}
	return out
}

// writeChanges shows what a changed entry changes, against the installed
// copy (nil when it no longer verifies) and the entry's agents.
func writeChanges(w io.Writer, prev *plugin.Verified, prevAgents []string, next plugin.Verified, agents []string) {
	fmt.Fprintln(w, "Changes to the existing entry:")
	added, removed := diff(prevAgents, agents)
	if prev == nil {
		fmt.Fprintln(w, "  The installed copy no longer verifies: treat everything above as new.")
	} else {
		a, b := factsOf(*prev), factsOf(next)
		changed := func(what, from, to string) {
			if from != to {
				fmt.Fprintf(w, "  %s: %s -> %s\n", what, from, to)
			}
		}
		changed("Version", visibleText(a.version), visibleText(b.version))
		changed("Manifest", prev.ManifestSHA256, next.ManifestSHA256)
		changed("Signer", a.signer, b.signer)
		changed("Endpoint", a.endpoint(), b.endpoint())
		for _, l := range []struct {
			what     string
			from, to []string
		}{{"hooks", a.hooks, b.hooks}, {"entity types", a.types, b.types}, {"egress", a.egress, b.egress}, {"roles", a.roles, b.roles}} {
			plus, minus := diff(l.from, l.to)
			if len(plus) > 0 {
				fmt.Fprintf(w, "  Adds %s: %s\n", l.what, listText(plus, ""))
			}
			if len(minus) > 0 {
				fmt.Fprintf(w, "  Removes %s: %s\n", l.what, listText(minus, ""))
			}
		}
	}
	if len(added) > 0 {
		fmt.Fprintf(w, "  Adds agents: %s\n", listText(added, ""))
	}
	if len(removed) > 0 {
		fmt.Fprintf(w, "  Removes agents: %s\n", listText(removed, ""))
	}
}

// diff is what to has that from lacks, and what from has that to lacks.
func diff(from, to []string) (added, removed []string) {
	for _, s := range to {
		if !slices.Contains(from, s) {
			added = append(added, s)
		}
	}
	for _, s := range from {
		if !slices.Contains(to, s) {
			removed = append(removed, s)
		}
	}
	return added, removed
}

func sameSet(a, b []string) bool {
	x, y := diff(a, b)
	return len(x) == 0 && len(y) == 0
}

// --- commands ---

func pluginList(c *cliIO, args []string) int {
	fs := c.flags("plugin list")
	configPath, cfgErr := c.findConfig()
	if cfgErr != nil {
		return c.fail(cfgErr)
	}
	asJSON := fs.Bool("json", false, "print the entries as JSON, with each one's approval state per agent")
	if err := parse(fs, args); err != nil {
		return c.fail(err)
	}
	if c.pluginViaSocket(configPath) {
		e, err := socketPluginEnv(c)
		if err != nil {
			return c.fail(err)
		}
		return c.pluginDone(e.listViaSocket(*asJSON), *asJSON)
	}
	e, err := loadPluginEnv(c, configPath)
	if err != nil {
		return c.fail(err)
	}
	if e.cfg.Service() && c.host.Euid() == 0 && !*asJSON {
		defer fmt.Fprintln(c.stdout, "Entries the engine keeps: run basalt plugin list without sudo.")
	}
	approvals := &approvalReader{e: e, read: map[string]agentRecords{}}
	if *asJSON {
		out := struct {
			Plugins []listedEntry `json:"plugins"`
		}{Plugins: []listedEntry{}}
		for _, p := range e.cfg.Plugins {
			k := p.Key()
			out.Plugins = append(out.Plugins, listedEntry{
				Name: k.Name, Instance: k.Instance, Enabled: p.Enabled, Agents: p.Agents, Approval: approvals.approvalOf(p),
			})
		}
		return printJSONValue(c, out)
	}
	if len(e.cfg.Plugins) == 0 {
		fmt.Fprintln(c.stderr, "basalt: no plugins; add one with basalt plugin add <dir> --agents NAME,...")
		return exitOK
	}
	for _, p := range e.cfg.Plugins {
		e.listEntry(p)
		writeApproval(e, approvals.approvalOf(p))
	}
	return exitOK
}

func (e *pluginEnv) listEntry(p config.Plugin) {
	k := p.Key()
	state := "disabled"
	if p.Enabled {
		state = "enabled"
	}
	w := e.c.stdout
	fmt.Fprintf(w, "%s  instance %s  %s\n", k.Name, k.Instance, state)
	v, err := plugin.Verify(e.root, k, p.ManifestSHA256, e.trust, e.mode, plugin.RequireApproval(e.cfg.PluginRequiresApproval(p)))
	if err != nil {
		fmt.Fprintf(w, "  refused: %s\n", terminalText(err.Error()))
	} else {
		f := factsOf(v)
		isolation := "files NONE (same-user mode)"
		switch {
		case f.remote:
			isolation = "none (remote)"
		case e.mode == plugin.ModeService:
			isolation = "files OS_USER"
		}
		fmt.Fprintf(w, "  version %s  signer %s  endpoint %s  isolation %s  health UNKNOWN (the engine reports it)\n",
			visibleText(f.version), f.signer, f.endpoint(), isolation)
	}
	fmt.Fprintf(w, "  agents %s\n", listText(p.Agents, "none"))
}

// addFlags are basalt plugin add's.
type addFlags struct {
	dir      string
	agents   []string
	instance string
	// approve is --approve-with-passkey; asJSON is --json.
	approve, asJSON bool
	// wait is --wait, in seconds: how long add waits for the plugin to run
	// after it opened the approval (plugin_wait.go).
	wait int
}

func pluginAdd(c *cliIO, args []string) int {
	fs := c.flags("plugin add")
	agents := fs.String("agents", "", "the agents the plugin serves, comma-separated (required; the entry's full list)")
	instance := instanceFlag(fs)
	configPath, cfgErr := c.findConfig()
	if cfgErr != nil {
		return c.fail(cfgErr)
	}
	asJSON := fs.Bool("json", false, "print the result, or a refusal's error body, as JSON")
	approve := fs.Bool(flagApproveWithPasskey, false, "open a plugin approval a person signs with a passkey instead of asking here")
	wait := fs.Int("wait", 0, fmt.Sprintf("with an approval, seconds to wait for the plugin to run before printing (0 to %d)", maxWaitSeconds))
	dir, err := parseOne(fs, args, "the plugin's directory")
	if err != nil {
		return c.fail(err)
	}
	if err := waitFlag(*wait); err != nil || *wait < 0 {
		return c.fail(fmt.Errorf("%w: --wait is seconds from 0 to %d", errUsage, maxWaitSeconds))
	}
	given := false
	fs.Visit(func(f *flag.Flag) { given = given || f.Name == "agents" })
	if !given {
		return c.fail(fmt.Errorf("%w: --agents is required: the agents the plugin serves, comma-separated", errUsage))
	}
	f := addFlags{dir: dir, agents: splitList(*agents), instance: *instance, approve: *approve, asJSON: *asJSON, wait: *wait}
	if f.agents == nil {
		f.agents = []string{}
	}
	if len(slices.Compact(slices.Sorted(slices.Values(f.agents)))) != len(f.agents) {
		return c.fail(fmt.Errorf("%w: --agents names an agent twice", errUsage))
	}
	if err := checkInstance(f.instance); err != nil {
		return c.fail(err)
	}
	if f.dir, err = filepath.Abs(f.dir); err != nil {
		return c.fail(err)
	}
	if c.pluginViaSocket(configPath) {
		// --approve-with-passkey is accepted and changes nothing: without
		// sudo every add opens an approval.
		e, err := socketPluginEnv(c)
		if err != nil {
			return c.fail(err)
		}
		return c.pluginDone(e.addViaSocket(f), *asJSON)
	}
	e, err := loadPluginEnv(c, configPath)
	if err != nil {
		return c.fail(err)
	}
	if f.approve && e.cfg.Service() {
		return c.fail(errApprovalInServiceMode("--" + flagApproveWithPasskey))
	}
	if err := e.refuseKeptName(plugin.EntryKey{}, f.dir, f.instance); err != nil {
		return c.pluginDone(err, *asJSON)
	}
	return c.pluginDone(e.add(f), *asJSON)
}

// againAdd is the add command with agents.
func (e *pluginEnv) againAdd(f addFlags, agents []string) string {
	args := []string{shellQuote(f.dir), "--agents", shellQuote(strings.Join(agents, ","))}
	if f.instance != plugin.DefaultInstance {
		args = append(args, "--instance", f.instance)
	}
	return e.command("add", args...)
}

func (e *pluginEnv) add(f addFlags) error {
	if prev := e.existing(f); e.approvalFlow(e.cfg, prev, f.approve) {
		return e.addWithApproval(f, prev)
	}
	again := e.againAdd(f, f.agents)
	if refused := e.refuseAgentOperated(e.cfg, "add", again); refused != nil {
		return e.narrowOnly(f, refused)
	}
	if err := e.checkAgents(e.cfg, f.agents, func(a []string) string { return e.againAdd(f, a) }); err != nil {
		return err
	}
	if err := e.needsSudo("add"); err != nil {
		return err
	}
	staged, err := plugin.Stage(f.dir, e.root, f.instance, e.trust, e.mode)
	if err != nil {
		return e.verifyRefusal(err, again)
	}
	defer func() { _ = staged.Discard() }()
	k := staged.Key
	if err := e.checkUserClash(e.cfg, k); err != nil {
		return err
	}
	var prev *config.Plugin
	var prevCopy *plugin.Verified
	if i := e.cfg.PluginIndex(k); i >= 0 {
		p := e.cfg.Plugins[i]
		prev = &p
		if v, err := plugin.Verify(e.root, k, p.ManifestSHA256, e.trust, e.mode); err == nil {
			prevCopy = &v
		}
	}
	if prev != nil && prevCopy != nil && prev.ManifestSHA256 == staged.ManifestSHA256 &&
		prevCopy.SignerKeyID == staged.SignerKeyID && sameSet(prev.Agents, f.agents) {
		fmt.Fprintf(e.c.stderr, "basalt: plugin %s is installed with this manifest and these agents; nothing changed\n", k)
		return nil
	}
	if prev != nil && prev.Enabled {
		// The entry stays enabled: refuse now what enable would refuse.
		changed := *prev
		if _, err := changed.Entry(staged.Manifest); err != nil {
			return err
		}
	}
	writeConsent(e.c.stderr, k, staged.Verified, f.agents, e.mode)
	question := "Add this plugin? It stays disabled until you enable it."
	if prev != nil {
		writeChanges(e.c.stderr, prevCopy, prev.Agents, staged.Verified, f.agents)
		question = "Change this entry? It stays " + enabledWord(prev.Enabled) + "."
	}
	if err := e.ask(question); err != nil {
		return err
	}
	shown := staged.SignerKeyID
	var written config.Plugin
	var installed plugin.Verified
	err = e.update(config.Change{
		Apply: func(cfg *config.Config) error {
			if refused := e.refuseAgentOperated(*cfg, "add", again); refused != nil {
				return refused
			}
			i := cfg.PluginIndex(k)
			if (i >= 0) != (prev != nil) || (i >= 0 && !samePlugin(cfg.Plugins[i], *prev)) {
				return errChangedMeanwhile
			}
			if err := e.checkAgents(*cfg, f.agents, func(a []string) string { return e.againAdd(f, a) }); err != nil {
				return err
			}
			if err := e.checkUserClash(*cfg, k); err != nil {
				return err
			}
			final, err := staged.Commit()
			if err != nil {
				return e.verifyRefusal(err, again)
			}
			installed = staged.Verified
			installed.Dir = final
			// Commit replaces a copy another key signed; this guards that
			// rule, so what is recorded is always what was shown.
			if staged.SignerKeyID != shown {
				return fmt.Errorf("plugin %s: the installed copy's signer is not the one you were shown; nothing was written", k)
			}
			if i >= 0 {
				cfg.Plugins[i].ManifestSHA256, cfg.Plugins[i].Agents = staged.ManifestSHA256, f.agents
				written = cfg.Plugins[i]
				return nil
			}
			written = config.Plugin{
				Name: k.Name, Instance: k.Instance, ManifestSHA256: staged.ManifestSHA256, Enabled: false, Agents: f.agents,
			}
			cfg.Plugins = append(cfg.Plugins, written)
			return nil
		},
		Written: func(config.Config) { e.sweep(k, staged.ManifestSHA256) },
	})
	if err != nil {
		return err
	}
	if err := e.applyUnit(unitWrite, written, &installed); err != nil {
		return err
	}
	if prev != nil {
		fmt.Fprintf(e.c.stderr, "basalt: plugin %s changed; it stays %s\n", k, enabledWord(prev.Enabled))
	} else {
		fmt.Fprintf(e.c.stderr, "basalt: plugin %s added, disabled. Enable it with:\n  %s\n", k, e.command("enable", entryArgs(k)...))
	}
	e.restart()
	return nil
}

// samePlugin reports whether an entry still is what the person was shown.
func samePlugin(a, b config.Plugin) bool {
	return a.ManifestSHA256 == b.ManifestSHA256 && a.Enabled == b.Enabled && slices.Equal(a.Agents, b.Agents)
}

func enabledWord(on bool) string {
	if on {
		return "enabled"
	}
	return "disabled"
}

// sweep removes the entry's unused copies after a write; a failure only
// leaves them for the next add or remove.
func (e *pluginEnv) sweep(k plugin.EntryKey, keep string) {
	if err := plugin.Sweep(e.root, k, keep, e.mode); err != nil {
		fmt.Fprintf(e.c.stderr, "basalt: unused copies of plugin %s were left in place: %s\n", k, terminalText(err.Error()))
	}
}

// narrowOnly is add under an agent: allowed only to remove agents from an
// existing entry, with the same manifest bytes. The plugin directory's
// manifest is read only to compare its hash with the installed copy's;
// nothing is copied, staged or trusted. Anything else is refused.
func (e *pluginEnv) narrowOnly(f addFlags, refused error) error {
	raw, err := readManifest(f.dir)
	if err != nil {
		return refused
	}
	m, err := plugin.ParseManifest(raw)
	if err != nil {
		return refused
	}
	k := plugin.EntryKey{Name: m.Name, Instance: f.instance}
	i := e.cfg.PluginIndex(k)
	if i < 0 {
		return refused
	}
	sum := sha256.Sum256(raw)
	sha := hex.EncodeToString(sum[:])
	prev := e.cfg.Plugins[i]
	if sha != prev.ManifestSHA256 || !subset(f.agents, prev.Agents) {
		return refused
	}
	if sameSet(prev.Agents, f.agents) {
		fmt.Fprintf(e.c.stderr, "basalt: plugin %s already serves these agents; nothing changed\n", k)
		return nil
	}
	if err := e.needsSudo("add"); err != nil {
		return err
	}
	err = e.update(config.Change{Apply: func(cfg *config.Config) error {
		j := cfg.PluginIndex(k)
		if j < 0 || cfg.Plugins[j].ManifestSHA256 != sha || !subset(f.agents, cfg.Plugins[j].Agents) {
			return refused
		}
		cfg.Plugins[j].Agents = f.agents
		return nil
	}})
	if err != nil {
		return err
	}
	_, removed := diff(prev.Agents, f.agents)
	fmt.Fprintf(e.c.stderr, "basalt: plugin %s no longer serves %s\n", k, listText(removed, ""))
	e.narrowed()
	return nil
}

func subset(a, of []string) bool {
	for _, s := range a {
		if !slices.Contains(of, s) {
			return false
		}
	}
	return true
}

// readManifest reads <dir>/basalt-plugin.json, bounded.
func readManifest(dir string) ([]byte, error) {
	f, err := os.Open(filepath.Join(dir, plugin.ManifestFile))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, plugin.MaxManifestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > plugin.MaxManifestBytes {
		return nil, errors.New("manifest too large")
	}
	return raw, nil
}

// entryFlags parse <name> [--instance NAME] [--config PATH].
func entryFlags(c *cliIO, name string, args []string, withJSON bool) (*pluginEnv, plugin.EntryKey, bool, int) {
	e, k, asJSON, _, code := entryFlagsApprove(c, name, args, withJSON, false)
	return e, k, asJSON, code
}

// entryFlagsApprove is entryFlags, with --approve-with-passkey when
// withApprove.
func entryFlagsApprove(c *cliIO, name string, args []string, withJSON, withApprove bool) (*pluginEnv, plugin.EntryKey, bool, bool, int) {
	return entryFlagsWith(c, name, args, withJSON, withApprove, nil)
}

// entryFlagsWith is entryFlagsApprove with more flags, which extra adds.
func entryFlagsWith(c *cliIO, name string, args []string, withJSON, withApprove bool, extra func(*flag.FlagSet)) (*pluginEnv, plugin.EntryKey, bool, bool, int) {
	fs := c.flags("plugin " + name)
	if extra != nil {
		extra(fs)
	}
	instance := instanceFlag(fs)
	configPath, cfgErr := c.findConfig()
	if cfgErr != nil {
		return nil, plugin.EntryKey{}, false, false, c.fail(cfgErr)
	}
	asJSON, approve := new(bool), new(bool)
	if withJSON {
		asJSON = fs.Bool("json", false, "print the result, or a refusal's error body, as JSON")
	}
	if withApprove {
		approve = fs.Bool(flagApproveWithPasskey, false, "open a plugin approval a person signs with a passkey instead of asking here")
	}
	pluginName, err := parseOne(fs, args, "the plugin's name")
	if err != nil {
		return nil, plugin.EntryKey{}, false, false, c.fail(err)
	}
	if err := checkInstance(*instance); err != nil {
		return nil, plugin.EntryKey{}, false, false, c.fail(err)
	}
	k := plugin.EntryKey{Name: pluginName, Instance: *instance}
	if (name == "enable" || name == "disable" || name == "remove") && c.pluginViaSocket(configPath) {
		e, err := socketPluginEnv(c)
		if err != nil {
			return nil, plugin.EntryKey{}, false, false, c.fail(err)
		}
		return e, k, *asJSON, *approve, -1
	}
	e, err := loadPluginEnv(c, configPath)
	if err != nil {
		return nil, plugin.EntryKey{}, false, false, c.fail(err)
	}
	if *approve && e.cfg.Service() {
		return nil, plugin.EntryKey{}, false, false, c.fail(errApprovalInServiceMode("--" + flagApproveWithPasskey))
	}
	if name == "enable" || name == "disable" || name == "remove" {
		if err := e.refuseKeptName(k, "", ""); err != nil {
			return nil, plugin.EntryKey{}, false, false, c.pluginDone(err, *asJSON)
		}
	}
	return e, k, *asJSON, *approve, -1
}

// entry is the entry k, or an error naming the command that adds it.
func (e *pluginEnv) entry(k plugin.EntryKey) (config.Plugin, error) {
	i := e.cfg.PluginIndex(k)
	if i < 0 {
		return config.Plugin{}, fmt.Errorf("engine.json has no plugin %s; basalt plugin list shows the entries, basalt plugin add <dir> --agents NAME,... adds one", k)
	}
	return e.cfg.Plugins[i], nil
}

func pluginEnable(c *cliIO, args []string) int {
	var wait int
	var ids string
	var flags *flag.FlagSet
	e, k, asJSON, approve, code := entryFlagsWith(c, "enable", args, true, true, func(fs *flag.FlagSet) {
		flags = fs
		fs.IntVar(&wait, "wait", 0, fmt.Sprintf("seconds to wait for the plugin to run (0 to %d; default 0, or %d with --approval-id)", maxWaitSeconds, defaultRepeatWait))
		fs.StringVar(&ids, "approval-id", "", "wait for these approvals (the approvalId values add or enable printed, comma separated) instead of opening a new one")
	})
	if code >= 0 {
		return code
	}
	if err := waitFlag(wait); err != nil || wait < 0 {
		return c.fail(fmt.Errorf("%w: --wait is seconds from 0 to %d", errUsage, maxWaitSeconds))
	}
	// enableWait takes -1 for a --wait that was not given: its default.
	given := false
	flags.Visit(func(f *flag.Flag) { given = given || f.Name == "wait" })
	if !given {
		wait = -1
	}
	if ids != "" {
		if approve {
			return c.fail(fmt.Errorf("%w: --approval-id waits for an approval already open; --%s opens a new one", errUsage, flagApproveWithPasskey))
		}
		parsed, err := parseApprovalIDs(ids)
		if err != nil {
			return c.fail(err)
		}
		return c.pluginDone(e.enableWait(k, parsed, wait, asJSON), asJSON)
	}
	if e.sock != nil {
		return c.pluginDone(e.enableViaSocket(k, max(wait, 0), asJSON), asJSON)
	}
	return c.pluginDone(e.enable(k, approve, max(wait, 0), asJSON), asJSON)
}

func (e *pluginEnv) enable(k plugin.EntryKey, approve bool, wait int, asJSON bool) error {
	if i := e.cfg.PluginIndex(k); i >= 0 && e.approvalFlow(e.cfg, &e.cfg.Plugins[i], approve) {
		return e.enableWithApproval(k, e.cfg.Plugins[i], wait, asJSON)
	}
	if e.approvalFlow(e.cfg, nil, approve) {
		_, err := e.entry(k)
		return err
	}
	again := e.command("enable", entryArgs(k)...)
	if refused := e.refuseAgentOperated(e.cfg, "enable", again); refused != nil {
		return refused
	}
	p, err := e.entry(k)
	if err != nil {
		return err
	}
	if p.Enabled {
		fmt.Fprintf(e.c.stderr, "basalt: plugin %s is already enabled; nothing changed\n", k)
		return nil
	}
	if err := e.needsSudo("enable"); err != nil {
		return err
	}
	v, err := plugin.Verify(e.root, k, p.ManifestSHA256, e.trust, e.mode)
	if err != nil {
		return e.verifyRefusal(err, again)
	}
	if _, err := p.Entry(v.Manifest); err != nil {
		return err
	}
	writeConsent(e.c.stderr, k, v, p.Agents, e.mode)
	if err := e.ask("Enable this plugin for these agents?"); err != nil {
		return err
	}
	err = e.update(config.Change{Apply: func(cfg *config.Config) error {
		if refused := e.refuseAgentOperated(*cfg, "enable", again); refused != nil {
			return refused
		}
		i := cfg.PluginIndex(k)
		if i < 0 || !samePlugin(cfg.Plugins[i], p) {
			return errChangedMeanwhile
		}
		// The copy may have been re-signed since it was shown.
		now, err := plugin.Verify(e.root, k, p.ManifestSHA256, e.trust, e.mode)
		if err != nil {
			return e.verifyRefusal(err, again)
		}
		if now.SignerKeyID != v.SignerKeyID {
			return errChangedMeanwhile
		}
		cfg.Plugins[i].Enabled = true
		p, v = cfg.Plugins[i], now
		return nil
	}})
	if err != nil {
		return err
	}
	if err := e.applyUnit(unitWrite, p, &v); err != nil {
		return err
	}
	fmt.Fprintf(e.c.stderr, "basalt: plugin %s enabled\n", k)
	e.restart()
	return nil
}

func pluginDisable(c *cliIO, args []string) int {
	e, k, _, code := entryFlags(c, "disable", args, false)
	if code >= 0 {
		return code
	}
	if e.sock != nil {
		return c.pluginDone(e.turnOffViaSocket(k, false), false)
	}
	return c.pluginDone(e.setDisabled(k), false)
}

// setDisabled turns k off. It only narrows, so an agent may run it.
func (e *pluginEnv) setDisabled(k plugin.EntryKey) error {
	p, err := e.entry(k)
	if err != nil {
		return err
	}
	if err := e.needsSudo("disable"); err != nil {
		return err
	}
	err = e.update(config.Change{Apply: func(cfg *config.Config) error {
		i := cfg.PluginIndex(k)
		if i < 0 {
			return errChangedMeanwhile
		}
		if !cfg.Plugins[i].Enabled {
			return errNoChange
		}
		cfg.Plugins[i].Enabled = false
		return nil
	}})
	if errors.Is(err, errNoChange) {
		fmt.Fprintf(e.c.stderr, "basalt: plugin %s is already disabled; nothing changed\n", k)
		e.endAfterTurnOff(p)
		return nil
	}
	if err != nil {
		return err
	}
	if err := e.applyUnit(unitStop, p, nil); err != nil {
		return err
	}
	fmt.Fprintf(e.c.stderr, "basalt: plugin %s disabled\n", k)
	e.endAfterTurnOff(p)
	e.narrowed()
	return nil
}

func pluginRemove(c *cliIO, args []string) int {
	e, k, _, code := entryFlags(c, "remove", args, false)
	if code >= 0 {
		return code
	}
	if e.sock != nil {
		return c.pluginDone(e.turnOffViaSocket(k, true), false)
	}
	return c.pluginDone(e.remove(k), false)
}

// remove drops k from engine.json, then its installed copies. It only
// narrows, so an agent may run it.
func (e *pluginEnv) remove(k plugin.EntryKey) error {
	p, err := e.entry(k)
	if err != nil {
		return err
	}
	if err := e.needsSudo("remove"); err != nil {
		return err
	}
	err = e.update(config.Change{
		Apply: func(cfg *config.Config) error {
			i := cfg.PluginIndex(k)
			if i < 0 {
				return errChangedMeanwhile
			}
			cfg.Plugins = slices.Delete(cfg.Plugins, i, i+1)
			return nil
		},
		Written: func(config.Config) { e.sweep(k, "") },
	})
	if err != nil {
		return err
	}
	if err := e.applyUnit(unitRemove, p, nil); err != nil {
		return err
	}
	fmt.Fprintf(e.c.stderr, "basalt: plugin %s removed\n", k)
	e.endAfterTurnOff(p)
	e.narrowed()
	return nil
}
