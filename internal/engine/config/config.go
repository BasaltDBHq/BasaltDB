// Package config is the engine's configuration file, written by basalt init:
// where the per-agent sockets live, which OS user may connect to each agent's
// socket, where that agent's scoped Postgres credential is, and the limits on
// agent statements. The shim reads only the default socket directory from
// here and never a credential.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-playground/validator/v10"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/links"
)

// Platform defaults. The engine service runs as its own OS user; the config
// and credential files are readable by that user only.
const (
	linuxConfigPath  = "/etc/basalt/engine.json"
	linuxSocketDir   = "/run/basalt"
	goosDarwin       = "darwin"
	darwinConfigDir  = "/Library/Application Support/Basalt"
	darwinConfigPath = darwinConfigDir + "/engine.json"
	darwinSocketDir  = darwinConfigDir + "/run"
	// linuxStateDir is the systemd StateDirectory of the engine unit.
	linuxStateDir  = "/var/lib/basalt"
	darwinStateDir = darwinConfigDir + "/state"

	// credentialPermMask is the permission bits a credential file must not
	// have: nothing for group or others.
	credentialPermMask = 0o077
	// maxConfigBytes bounds the config and credential files read at start.
	maxConfigBytes = 1 << 20
	socketSuffix   = ".sock"
)

// DefaultPath is the config file location on goos.
func DefaultPath(goos string) string {
	if goos == goosDarwin {
		return darwinConfigPath
	}
	return linuxConfigPath
}

// DefaultSocketDir is the socket directory on goos.
func DefaultSocketDir(goos string) string {
	if goos == goosDarwin {
		return darwinSocketDir
	}
	return linuxSocketDir
}

// DefaultStateDir is the engine's state directory on goos.
func DefaultStateDir(goos string) string {
	if goos == goosDarwin {
		return darwinStateDir
	}
	return linuxStateDir
}

// StateDirFor is c.StateDir, or the default on goos when it is empty.
func (c Config) StateDirFor(goos string) string {
	if c.StateDir != "" {
		return c.StateDir
	}
	return DefaultStateDir(goos)
}

// Config is the engine configuration file.
type Config struct {
	// SocketDir holds one socket per agent, <SocketDir>/<name>.sock.
	SocketDir string  `json:"socketDir" validate:"required"`
	Agents    []Agent `json:"agents" validate:"required,min=1,unique=Name,dive"`
	Limits    Limits  `json:"limits"`
	// StateDir keeps the engine's own state: each agent's last verified
	// ledger chain head. Empty means DefaultStateDir.
	StateDir string `json:"stateDir,omitempty"`
	// PagesURL is the base URL of the approval, revert and registration
	// pages (links): http://localhost:<port> for the engine's own pages,
	// the default (links.DefaultLocal), or the hosted console. See
	// PagesBase.
	PagesURL string `json:"pagesUrl,omitempty"`
	// ApprovalPage is the older key: only its origin is used, when
	// pagesUrl is not set. basalt init writes pagesUrl.
	ApprovalPage string `json:"approvalPage,omitempty" validate:"omitempty,url"`
	// PagesAddr is where the engine serves the approval and revert pages on
	// loopback (see Pages); "off" disables them, empty is the default.
	PagesAddr string `json:"pagesAddr,omitempty"`
	// LinkBudget is the longest long link, in characters of the whole URL,
	// the engine hands an agent as the way to open a page (CONTRACT.md, The
	// link budget). A pointer so that a written 0 is refused rather than read
	// as unset; nil means links.DefaultBudget. See LinkBudgetOrDefault.
	LinkBudget *int `json:"linkBudget,omitempty"`
	// Notify says where the person hears about held writes.
	Notify Notify `json:"notify,omitzero"`
	// OperatedBy is who runs machine steps on this engine's machine:
	// PERSON (also when empty) or AGENT (CONTRACT.md, Who operates the
	// engine).
	OperatedBy string `json:"operatedBy,omitempty" validate:"omitempty,oneof=PERSON AGENT"`
	// Mode is ModeService when basalt init installed the background
	// service, else ModeSameUser (also when empty). Only ModeService opens
	// the person socket.
	Mode Mode `json:"mode,omitempty" validate:"omitempty,oneof=SERVICE SAME_USER"`
	// PersonUIDs are the OS users the person socket admits (owner decision
	// SM-2): the person(s) recorded at basalt init. Empty admits nobody.
	PersonUIDs []uint32 `json:"personUids,omitempty" validate:"unique"`
	// Vault is ON when the engine dials out to the Vault for portal link
	// sessions (CONTRACT.md, Vault channel); OFF, or empty, when it does
	// not. See VaultOn.
	Vault string `json:"vault,omitempty" validate:"omitempty,oneof=ON OFF"`
	// VaultURL overrides the Vault's address for development and tests
	// only: a ws:// URL on a loopback address. Empty is the Vault itself.
	VaultURL string `json:"vaultUrl,omitempty"`
	// PII sizes the PII dictionary and its scan (CONTRACT.md, PII
	// classification, Engine config). Zero fields take the defaults.
	PII PII `json:"pii,omitzero"`
}

// PII is engine.json pii: the dictionary's memory budget and the scan's
// rate. Zero means the default. The budget is at most MaxPIIMemoryMB (64
// GiB), far inside int64 in bytes and in the service unit's 4× limit.
type PII struct {
	MaxMemoryMB       int `json:"maxMemoryMB,omitempty" validate:"gte=0,lte=65536"`
	ScanRowsPerSecond int `json:"scanRowsPerSecond,omitempty" validate:"gte=0"`
}

// PII defaults (CONTRACT.md, PII classification, Engine config).
const (
	DefaultPIIMaxMemoryMB       = 512
	DefaultPIIScanRowsPerSecond = 20_000
	// MaxPIIMemoryMB is the largest pii.maxMemoryMB (64 GiB); the validate
	// tag on PII.MaxMemoryMB holds the same number.
	MaxPIIMemoryMB = 65536
)

// PIIOrDefault is c.PII with zero fields set to the defaults.
func (c Config) PIIOrDefault() PII {
	p := c.PII
	if p.MaxMemoryMB == 0 {
		p.MaxMemoryMB = DefaultPIIMaxMemoryMB
	}
	if p.ScanRowsPerSecond == 0 {
		p.ScanRowsPerSecond = DefaultPIIScanRowsPerSecond
	}
	return p
}

// bytesPerMB converts pii.maxMemoryMB.
const bytesPerMB = 1 << 20

// MaxMemoryBytes is MaxMemoryMB in bytes.
func (p PII) MaxMemoryBytes() int64 { return int64(p.MaxMemoryMB) * bytesPerMB }

// Mode is how the engine runs (owner decision SM-3).
type Mode string

// Modes.
const (
	// ModeService: the engine runs as its own OS user under systemd or
	// launchd, and the person reaches it over the person socket.
	ModeService Mode = "SERVICE"
	// ModeSameUser: the person runs the engine as themselves and the CLI
	// reads the config and the credential directly.
	ModeSameUser Mode = "SAME_USER"
)

// Service reports whether c is a background-service config.
func (c Config) Service() bool {
	return c.Mode == ModeService
}

// PersonSocketName is the person socket's name in the socket directory,
// <SocketDir>/person.sock; no agent may take it.
const PersonSocketName = "person"

// PersonSocketPath is the person socket in socket directory dir.
func PersonSocketPath(dir string) string {
	return SocketPath(dir, PersonSocketName)
}

// AgentOperated reports whether the agent runs this engine's machine steps.
func (c Config) AgentOperated() bool { return c.OperatedBy == mcpcontract.OperatedByAgent }

// Notify configures notifications. Every field is optional.
type Notify struct {
	Telegram *Telegram `json:"telegram,omitempty"`
}

// Telegram sends held-write links through a bot to one chat. The bot token
// sits in its own file, mode 0600, never in this config.
type Telegram struct {
	BotTokenFile string `json:"botTokenFile" validate:"required"`
	ChatID       string `json:"chatId" validate:"required,max=64"`
}

// Agent is one agent the engine serves.
type Agent struct {
	// Name is the agent's name; its Postgres role is basalt_agent_<name>.
	Name string `json:"name" validate:"required,agentname"`
	// OSUser is the only OS user allowed to connect to the agent's socket.
	OSUser string `json:"osUser" validate:"required"`
	// CredentialFile holds the agent role's Postgres URL, mode 0600.
	CredentialFile string `json:"credentialFile" validate:"required"`
	// InitArgs are the flags basalt init was run with for this agent (never
	// the admin connection string, a password or a one-shot flag), so a
	// step can name the init command again. See agent.NewCommands.
	InitArgs []string `json:"initArgs,omitempty"`
	// Setup is the pending setup code basalt init --remote made for this
	// agent; nil when none is pending.
	Setup *Setup `json:"setup,omitempty"`
}

// Setup is an agent's pending setup (CONTRACT.md, basalt init --remote):
// what status and a re-run of init hand out again. Nothing secret: the
// code carries the password's verifier, not the password.
type Setup struct {
	SetupID      string `json:"setupId" validate:"required,uuid"`
	Kind         string `json:"kind" validate:"oneof=INSTALL AGENT UPGRADE"`
	GuardVersion int    `json:"guardVersion" validate:"gte=1"`
	// ExpiresAt is RFC 3339 UTC, whole seconds.
	ExpiresAt   string `json:"expiresAt" validate:"required"`
	Code        string `json:"code" validate:"required"`
	Fingerprint string `json:"fingerprint" validate:"required"`
}

// Expires parses ExpiresAt.
func (s Setup) Expires() (time.Time, error) {
	return time.Parse(time.RFC3339, s.ExpiresAt)
}

// Limits bound agent statements. Zero means the engine default.
type Limits struct {
	StatementTimeoutMs int `json:"statementTimeoutMs,omitempty" validate:"gte=0"`
	ReadRowLimit       int `json:"readRowLimit,omitempty" validate:"gte=0"`
}

// StatementTimeout is the configured time limit, or zero for the default.
func (l Limits) StatementTimeout() time.Duration {
	return time.Duration(l.StatementTimeoutMs) * time.Millisecond
}

// SocketPath is the socket the engine serves agent name on.
func (c Config) SocketPath(name string) string {
	return SocketPath(c.SocketDir, name)
}

// SocketPath is the socket for agent name in dir.
func SocketPath(dir, name string) string {
	return filepath.Join(dir, name+socketSuffix)
}

// maxSocketPath is the longest Unix socket path every supported platform
// binds: sockaddr_un.sun_path is 104 bytes on macOS (108 on Linux),
// including the terminating NUL.
const maxSocketPath = 103

// CheckSocketPath refuses a socket path too long to bind, which the kernel
// reports only as "invalid argument" when the engine starts.
func CheckSocketPath(path string) error {
	if len(path) > maxSocketPath {
		return fmt.Errorf("socket path %s is %d bytes; Unix sockets allow %d: choose a shorter socket directory",
			path, len(path), maxSocketPath)
	}
	return nil
}

// checkSocketPaths runs CheckSocketPath on every agent's socket.
func (c Config) checkSocketPaths() error {
	for _, a := range c.Agents {
		if err := CheckSocketPath(c.SocketPath(a.Name)); err != nil {
			return err
		}
	}
	return nil
}

var validate = newValidator()

func newValidator() *validator.Validate {
	v := validator.New(validator.WithRequiredStructEnabled())
	if err := v.RegisterValidation("agentname", func(fl validator.FieldLevel) bool {
		return ValidAgentName(fl.Field().String())
	}); err != nil {
		panic(err)
	}
	return v
}

// ValidAgentName reports whether name is a valid agent name: the same rule
// the guard applies to role names (lowercase letters, digits and '_',
// starting with a letter, basalt_agent_<name> within 63 bytes), so a name
// the engine accepts is one basalt init can create a role for. "person" is
// the person socket's and is refused.
func ValidAgentName(name string) bool {
	return name != PersonSocketName && guard.ValidAgentName(name)
}

// Load reads and validates the config file at path. Unknown keys are refused.
func Load(path string) (Config, error) {
	return load(path, os.Open)
}

// LoadNoFollow is Load for a root process reading a file in a directory the
// engine's user owns: it refuses a symlink or hardlink at path.
func LoadNoFollow(path string) (Config, error) {
	return load(path, openNoFollow)
}

// LoadOpen is Load with the file opened by open: a root process opens it
// without following links (service.OpenTrustedFile) and checks the open
// file before it is read.
func LoadOpen(path string, open func(string) (*os.File, error)) (Config, error) {
	return load(path, open)
}

func load(path string, open func(string) (*os.File, error)) (Config, error) {
	raw, err := readSmall(path, open)
	if err != nil {
		return Config{}, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	if err := validate.Struct(c); err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	if err := c.checkSocketPaths(); err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	if err := c.checkLinkBudget(); err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	if _, err := c.Pages(); err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	if err := CheckVaultURL(c.VaultURL); err != nil {
		return Config{}, fmt.Errorf("config %s: %w", path, err)
	}
	return c, nil
}

// LinkBudgetOrDefault is the configured link budget, or links.DefaultBudget
// when none is set.
func (c Config) LinkBudgetOrDefault() int {
	if c.LinkBudget == nil {
		return links.DefaultBudget
	}
	return *c.LinkBudget
}

// checkLinkBudget refuses a linkBudget that is not a positive integer.
func (c Config) checkLinkBudget() error {
	if c.LinkBudget == nil || *c.LinkBudget > 0 {
		return nil
	}
	return fmt.Errorf("linkBudget %d is not a positive integer: set it to a number of characters above zero, or remove it for the default %d",
		*c.LinkBudget, links.DefaultBudget)
}

// ReadCredential reads an agent's Postgres URL. It refuses a file that group
// or others can read, so a credential never sits readable by the agent.
func ReadCredential(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if fi.Mode().Perm()&credentialPermMask != 0 {
		return "", fmt.Errorf("credential file %s is mode %o; it must be readable by the engine's user only (0600)", path, fi.Mode().Perm())
	}
	raw, err := readSmall(path, os.Open)
	if err != nil {
		return "", err
	}
	url := strings.TrimSpace(string(raw))
	if url == "" {
		return "", fmt.Errorf("credential file %s is empty", path)
	}
	return url, nil
}

func readSmall(path string, open func(string) (*os.File, error)) ([]byte, error) {
	f, err := open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(raw) > maxConfigBytes {
		return nil, errors.New("file " + path + " is larger than 1 MiB")
	}
	return raw, nil
}
