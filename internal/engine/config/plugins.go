package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// Bounds of a plugin entry (CONTRACT.md, Plugins, Config).
const (
	// MinPluginTimeoutMs and MaxPluginTimeoutMs bound timeoutMs.
	MinPluginTimeoutMs = 50
	MaxPluginTimeoutMs = 60_000
	// MaxPluginConfigBytes bounds config, as compact JSON.
	MaxPluginConfigBytes = 16 << 10
	// maxCredentialPath bounds auth.credentialFile
	// (api/plugin/config.schema.json).
	maxCredentialPath = 4096
)

// Patterns of a plugin entry's name and instance
// (api/plugin/config.schema.json).
var (
	pluginNamePattern     = regexp.MustCompile(`^[a-z][a-z0-9-]{1,39}$`)
	pluginInstancePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	pluginSHA256Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Plugin is one entry of engine.json plugins: an installed plugin copy and
// the agents it serves (CONTRACT.md, Plugins, Config). basalt plugin writes
// it; a person may edit timeoutMs, minConfidence, config and auth.
type Plugin struct {
	// Name is the manifest's name.
	Name string `json:"name"`
	// Instance separates entries of one plugin; empty reads as
	// plugin.DefaultInstance. See Key.
	Instance string `json:"instance,omitempty"`
	// ManifestSHA256 names the installed copy,
	// <root>/<name>/<instance>/<manifestSha256>/.
	ManifestSHA256 string `json:"manifestSha256"`
	Enabled        bool   `json:"enabled"`
	// Agents are the only agents the entry serves. Required: a missing key
	// is refused, an empty list serves none.
	Agents []string `json:"agents"`
	// TimeoutMs is one call's deadline; 0 means the default for the
	// endpoint (see Entry).
	TimeoutMs int `json:"timeoutMs,omitempty"`
	// MinConfidence drops a plugin's spans below it; nil means 0.
	MinConfidence *float64 `json:"minConfidence,omitempty"`
	// Config is passed to the plugin in initialize: a JSON object, never a
	// secret.
	Config json.RawMessage `json:"config,omitempty"`
	// Auth is a remote plugin's credential file.
	Auth *PluginAuth `json:"auth,omitempty"`
	// Approval is PluginApprovalRequired, or empty when the key is absent:
	// with it the engine serves the entry to an agent only with a matching
	// plugin approval signed by a person's passkey (CONTRACT.md, Plugins,
	// Plugin approval). See Config.PluginRequiresApproval.
	Approval PluginApproval `json:"approval,omitempty"`
}

// PluginApproval is a plugin entry's approval key.
type PluginApproval string

// PluginApprovalRequired is the approval key's one value.
const PluginApprovalRequired PluginApproval = "REQUIRED"

// UnmarshalJSON accepts only "REQUIRED": an empty string, null or any other
// value is refused when the config is loaded, never read as no key.
func (a *PluginApproval) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil || s != string(PluginApprovalRequired) {
		return fmt.Errorf("approval must be %q or absent", PluginApprovalRequired)
	}
	*a = PluginApprovalRequired
	return nil
}

// PluginRequiresApproval reports whether entry p requires a plugin approval
// on this engine: it has the approval key, or the engine is agent-operated,
// whatever the key says. Same-user mode only: in service mode nothing
// changes, so no entry requires approval there (and checkPlugin refuses the
// key, as before). The engine, at start, and basalt plugin both decide by
// this.
func (c Config) PluginRequiresApproval(p Plugin) bool {
	if c.Service() {
		return false
	}
	return p.Approval == PluginApprovalRequired || c.AgentOperated()
}

// ApprovalSettings are p's settings as a plugin approval binds them
// (CONTRACT.md, What a plugin approval binds, the settings text): config
// and auth as engine.json holds them, timeoutMs and minConfidence by value,
// each only when the entry sets it, no default filled in. Postgres turns
// the object into the settings text; Go never builds that text.
func (p Plugin) ApprovalSettings() guard.PluginSettings {
	var s guard.PluginSettings
	if len(p.Config) > 0 {
		s.Config = slices.Clone(p.Config)
	}
	if p.Auth != nil {
		s.Auth = &guard.PluginAuth{CredentialFile: p.Auth.CredentialFile}
	}
	if p.TimeoutMs != 0 {
		v := p.TimeoutMs
		s.TimeoutMs = &v
	}
	if p.MinConfidence != nil {
		v := *p.MinConfidence
		s.MinConfidence = &v
	}
	return s
}

// PluginAuth is a remote plugin entry's auth: the file the engine reads its
// bearer token from. The path is never sent to the plugin.
type PluginAuth struct {
	CredentialFile string `json:"credentialFile"`
}

// Key is the entry's (name, instance), with an empty instance read as
// plugin.DefaultInstance.
func (p Plugin) Key() plugin.EntryKey {
	inst := p.Instance
	if inst == "" {
		inst = plugin.DefaultInstance
	}
	return plugin.EntryKey{Name: p.Name, Instance: inst}
}

// ErrAuthNotRemote: auth.credentialFile is set on an entry whose plugin is
// not remote.
var ErrAuthNotRemote = errors.New("auth.credentialFile is for remote plugins only")

// Entry is the host's entry for p, given the manifest of p's verified
// installed copy (plugin.Verify): the timeout resolved to the endpoint's
// default when timeoutMs is unset, and config as "{}" when none. It refuses
// auth on a plugin that is not remote, the one entry rule that needs the
// manifest.
func (p Plugin) Entry(m plugin.Manifest) (plugin.Entry, error) {
	if p.Auth != nil && !m.Endpoint.IsRemote() {
		return plugin.Entry{}, fmt.Errorf("plugin %s: %w", p.Key(), ErrAuthNotRemote)
	}
	cfg := p.Config
	if len(cfg) == 0 {
		cfg = json.RawMessage(`{}`)
	}
	return plugin.Entry{
		Key:      p.Key(),
		Manifest: m,
		Agents:   slices.Clone(p.Agents),
		Timeout:  p.Timeout(m.Endpoint.IsRemote()),
		Config:   cfg,
	}, nil
}

// Timeout is the entry's call deadline: timeoutMs, or the default for a
// remote or a local plugin when it is unset.
func (p Plugin) Timeout(remote bool) time.Duration {
	switch {
	case p.TimeoutMs != 0:
		return time.Duration(p.TimeoutMs) * time.Millisecond
	case remote:
		return plugin.DefaultRemoteTimeout
	}
	return plugin.DefaultLocalTimeout
}

// CredentialFile is auth.credentialFile, or "" when the entry has none.
func (p Plugin) CredentialFile() string {
	if p.Auth == nil {
		return ""
	}
	return p.Auth.CredentialFile
}

// UnknownAgentError is a plugin entry, or a basalt plugin command, naming an
// agent the engine does not have (PLUGIN_REFUSED UNKNOWN_AGENT).
type UnknownAgentError struct {
	Entry plugin.EntryKey
	Agent string
}

func (e *UnknownAgentError) Error() string {
	return fmt.Sprintf("plugin %s: agent %q is not one of this engine's agents", e.Entry, e.Agent)
}

// HasAgent reports whether name is one of c's agents.
func (c Config) HasAgent(name string) bool {
	return slices.ContainsFunc(c.Agents, func(a Agent) bool { return a.Name == name })
}

// PluginIndex is the index of the entry with key k in c.Plugins, or -1.
func (c Config) PluginIndex(k plugin.EntryKey) int {
	return slices.IndexFunc(c.Plugins, func(p Plugin) bool { return p.Key() == k })
}

// checkPlugins applies the entry rules a config can check on its own
// (CONTRACT.md, Plugins, Config). The rules that need the manifest are in
// Entry.
func (c Config) checkPlugins() error {
	seen := map[plugin.EntryKey]bool{}
	for i, p := range c.Plugins {
		if err := c.checkPlugin(p); err != nil {
			return err
		}
		k := p.Key()
		if seen[k] {
			return fmt.Errorf("plugins[%d]: plugin %s is listed twice; name and instance must be unique", i, k)
		}
		seen[k] = true
	}
	return nil
}

func (c Config) checkPlugin(p Plugin) error {
	if !pluginNamePattern.MatchString(p.Name) {
		return errors.New("plugins: an entry's name is not a plugin name (lowercase letters, digits and -, 2 to 40)")
	}
	k := p.Key()
	if !pluginInstancePattern.MatchString(k.Instance) {
		return fmt.Errorf("plugin %s: instance must be lowercase letters, digits and _, starting with a letter, at most 32", p.Name)
	}
	if !pluginSHA256Pattern.MatchString(p.ManifestSHA256) {
		return fmt.Errorf("plugin %s: manifestSha256 is not lowercase hex SHA-256", k)
	}
	if err := c.checkPluginAgents(k, p.Agents); err != nil {
		return err
	}
	if p.TimeoutMs != 0 && (p.TimeoutMs < MinPluginTimeoutMs || p.TimeoutMs > MaxPluginTimeoutMs) {
		return fmt.Errorf("plugin %s: timeoutMs %d is outside %d to %d", k, p.TimeoutMs, MinPluginTimeoutMs, MaxPluginTimeoutMs)
	}
	if mc := p.MinConfidence; mc != nil && (*mc < 0 || *mc > 1) {
		return fmt.Errorf("plugin %s: minConfidence must be from 0 to 1", k)
	}
	if err := CheckPluginConfig(p.Config); err != nil {
		return fmt.Errorf("plugin %s: %w", k, err)
	}
	if p.Auth != nil && (p.Auth.CredentialFile == "" || !filepath.IsAbs(p.Auth.CredentialFile) || len(p.Auth.CredentialFile) > maxCredentialPath) {
		return fmt.Errorf("plugin %s: auth.credentialFile must be an absolute path of at most %d bytes", k, maxCredentialPath)
	}
	switch {
	case p.Approval == "":
	case p.Approval != PluginApprovalRequired:
		return fmt.Errorf("plugin %s: approval must be %q or absent", k, PluginApprovalRequired)
	case c.Service():
		// Plugin approvals are same-user mode only; service mode is unchanged.
		return fmt.Errorf("plugin %s: approval is not served in service mode", k)
	}
	return nil
}

// checkPluginAgents requires agents, each one of c's agents, none twice.
func (c Config) checkPluginAgents(k plugin.EntryKey, agents []string) error {
	if agents == nil {
		return fmt.Errorf("plugin %s: agents is required (an empty list serves none)", k)
	}
	for i, a := range agents {
		if !c.HasAgent(a) {
			return &UnknownAgentError{Entry: k, Agent: a}
		}
		if slices.Contains(agents[:i], a) {
			return fmt.Errorf("plugin %s: agent %q is listed twice", k, a)
		}
	}
	return nil
}

// errPluginConfigSecret refuses a config holding what looks like a
// credential. It never quotes the string.
var errPluginConfigSecret = errors.New("config holds a URL with a user name or password, or password=; " +
	"a plugin reads its credentials from its own file, never from engine.json")

// CheckPluginConfig applies the config rules (CONTRACT.md, Plugins,
// Config): a JSON object of at most MaxPluginConfigBytes as compact JSON,
// with no string (keys included) that parses as a URL with a user name or
// password or holds password= in any case. Empty means none. Errors never
// quote the config.
func CheckPluginConfig(raw json.RawMessage) error {
	if len(raw) == 0 {
		return nil
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return errors.New("config is not valid JSON")
	}
	if compact.Len() > MaxPluginConfigBytes {
		return fmt.Errorf("config is %d bytes as compact JSON; at most %d", compact.Len(), MaxPluginConfigBytes)
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(compact.Bytes()))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return errors.New("config is not valid JSON")
	}
	if _, ok := v.(map[string]any); !ok {
		return errors.New("config must be a JSON object")
	}
	if holdsSecret(v) {
		return errPluginConfigSecret
	}
	return nil
}

// holdsSecret walks v for a string, key or value, that looks like a
// credential.
func holdsSecret(v any) bool {
	switch t := v.(type) {
	case string:
		return secretString(t)
	case map[string]any:
		for k, e := range t {
			if secretString(k) || holdsSecret(e) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(t, holdsSecret)
	}
	return false
}

// secretString reports whether s holds password= in any case, or parses as
// a URL with a user name or password.
func secretString(s string) bool {
	if strings.Contains(strings.ToLower(s), "password=") {
		return true
	}
	u, err := url.Parse(strings.TrimSpace(s))
	return err == nil && u.User != nil
}
